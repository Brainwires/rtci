//! The client data connection of a TCP allocation (RFC 6062 §4.3 to §4.5).
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use crypto::RTCCryptoProvider;
use log::debug;
use stun::error_code::*;
use stun::fingerprint::FINGERPRINT;
use stun::message::*;
use stun::textattrs::*;
use stun::validated::Rejection;

use super::credential::Credential;
use super::{RequestError, validator};
use crate::proto::connid::ConnectionId;
use shared::error::{Error, Result};
use shared::{TaggedBytesMut, TransportContext, TransportMessage, TransportProtocol};

/// How long the ConnectionBind may go unanswered. The server gives a new peer connection 30
/// seconds to be bound and then closes it (RFC 6062 §5.2, §5.3), so nothing can answer later.
pub const CONNECTION_BIND_TIMEOUT: Duration = Duration::from_secs(30);

/// What a [`DataConnection`] reports.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum DataConnectionEvent {
    /// The server accepted the ConnectionBind: the connection now carries the peer's bytes
    /// and nothing else, both ways (RFC 6062 §4.5).
    Bound,
    /// The ConnectionBind failed, or went unanswered for [`CONNECTION_BIND_TIMEOUT`]. The
    /// connection is of no use; the application closes it.
    BindError(RequestError),
}

enum State {
    /// The ConnectionBind `id` is out.
    Binding {
        id: TransactionId,
        deadline: Instant,
        /// Whether it was already sent again after a 401 / after a 438.
        challenged: bool,
        stale: bool,
    },
    Bound,
    Failed,
    Closed,
}

/// One client data connection of a TCP allocation: a second TCP (or TLS) connection to the
/// TURN server that, once bound, carries one peer's byte stream as it is (RFC 6062 §4.3 to
/// §4.5).
///
/// Made by [`Relay::data_connection`](super::relay::Relay::data_connection) with the
/// CONNECTION-ID of a Connect success response ([`Event::ConnectResponse`](super::Event)) or
/// of a ConnectionAttempt indication ([`Event::ConnectionAttempt`](super::Event)). Sans-I/O:
/// the application opens the connection, to [`Self::server_addr`] and from a local port of
/// its own, and then
///
/// - sends what [`poll_write`](sansio::Protocol::poll_write) gives, the ConnectionBind
///   request first;
/// - hands every chunk it reads to [`handle_read`](sansio::Protocol::handle_read) (the
///   stream as it comes: no framing is expected of the application);
/// - calls [`handle_timeout`](sansio::Protocol::handle_timeout) when
///   [`poll_timeout`](sansio::Protocol::poll_timeout) says;
/// - after [`DataConnectionEvent::Bound`], writes to the peer with
///   [`handle_write`](sansio::Protocol::handle_write) or [`Self::send`], and takes the
///   peer's bytes from [`poll_read`](sansio::Protocol::poll_read).
///
/// Closing the TCP connection ends the peer's connection too (RFC 6062 §4.6). The allocation
/// must be kept refreshed for as long as the data connection is wanted, which the
/// [`Client`](super::Client) that made it does on its control connection.
pub struct DataConnection {
    crypto_provider: Arc<dyn RTCCryptoProvider>,
    server_addr: SocketAddr,
    local_addr: SocketAddr,
    connection_id: ConnectionId,
    software: Software,
    /// The long-term credential of the control connection, as the server's last challenge
    /// on either connection left it; none when the server asked for no credential there.
    credential: Arc<Credential>,
    /// The ConnectionBind that is out, as it was sent.
    request: Message,
    state: State,
    /// The stream so far, until the ConnectionBind response is whole.
    inbound: BytesMut,
    transmits: VecDeque<TaggedBytesMut>,
    reads: VecDeque<BytesMut>,
    events: VecDeque<DataConnectionEvent>,
}

pub(crate) struct DataConnectionConfig {
    pub(crate) crypto_provider: Arc<dyn RTCCryptoProvider>,
    pub(crate) server_addr: SocketAddr,
    pub(crate) local_addr: SocketAddr,
    pub(crate) connection_id: ConnectionId,
    pub(crate) software: Software,
    pub(crate) credential: Arc<Credential>,
}

impl DataConnection {
    /// A data connection that has its ConnectionBind queued.
    pub(crate) fn new(now: Instant, config: DataConnectionConfig) -> Result<Self> {
        let mut connection = DataConnection {
            crypto_provider: config.crypto_provider,
            server_addr: config.server_addr,
            local_addr: config.local_addr,
            connection_id: config.connection_id,
            software: config.software,
            credential: config.credential,
            request: Message::new(),
            state: State::Closed,
            inbound: BytesMut::new(),
            transmits: VecDeque::new(),
            reads: VecDeque::new(),
            events: VecDeque::new(),
        };
        let id = connection.send_bind(now)?;
        connection.state = State::Binding {
            id,
            deadline: now.add(CONNECTION_BIND_TIMEOUT),
            challenged: false,
            stale: false,
        };
        Ok(connection)
    }

    /// The server's transport address: where the application opens this connection to, the
    /// same one the control connection goes to (RFC 6062 §4.3).
    #[must_use]
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// The local address the application said this connection is made from.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The CONNECTION-ID this connection binds.
    #[must_use]
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Whether the server accepted the ConnectionBind, so the connection carries the peer's
    /// bytes.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        matches!(self.state, State::Bound)
    }

    /// Queues `data` for the peer, as it is.
    ///
    /// # Errors
    ///
    /// Fails until the connection is bound, and after it failed or was closed.
    pub fn send(&mut self, now: Instant, data: &[u8]) -> Result<()> {
        if !self.is_bound() {
            return Err(Error::ErrConnClosed);
        }
        self.transmit(now, data);
        Ok(())
    }

    fn transmit(&mut self, now: Instant, data: &[u8]) {
        self.transmits.push_back(TransportMessage {
            now,
            transport: TransportContext {
                local_addr: self.local_addr,
                peer_addr: self.server_addr,
                transport_protocol: TransportProtocol::TCP,
                ecn: None,
            },
            message: BytesMut::from(data),
        });
    }

    /// Queues the ConnectionBind request: the CONNECTION-ID and the credential of the control
    /// connection (RFC 6062 §4.3, §4.4).
    fn send_bind(&mut self, now: Instant) -> Result<TransactionId> {
        let id = TransactionId::new();
        let mut setters: Vec<Box<dyn Setter + '_>> = vec![
            Box::new(id),
            Box::new(MessageType::new(METHOD_CONNECTION_BIND, CLASS_REQUEST)),
            Box::new(self.connection_id),
        ];
        if !self.software.text.is_empty() {
            setters.push(Box::new(self.software.clone()));
        }
        if let Some(authentication) = self.credential.setter(self.crypto_provider.crypto()) {
            setters.push(authentication);
        }
        setters.push(Box::new(FINGERPRINT));
        let mut msg = Message::new();
        msg.build(&setters)?;
        drop(setters);
        self.transmit(now, &msg.raw);
        self.request = msg;
        Ok(id)
    }

    fn fail(&mut self, err: RequestError) {
        debug!("data connection {}: {err}", self.connection_id);
        self.state = State::Failed;
        self.inbound.clear();
        self.events.push_back(DataConnectionEvent::BindError(err));
    }

    /// Takes the ConnectionBind response off the front of the stream, once it is whole.
    fn read_response(&mut self, now: Instant) -> Result<()> {
        loop {
            let State::Binding {
                id,
                deadline,
                challenged,
                stale,
            } = self.state
            else {
                return Ok(());
            };
            if self.inbound.len() < MESSAGE_HEADER_SIZE {
                return Ok(());
            }
            // Until the bind is answered the server sends STUN and nothing else.
            if self.inbound[0] & 0xc0 != 0 || !is_stun_message(&self.inbound) {
                self.fail(RequestError::Failed(Error::ErrNonStunmessage));
                return Err(Error::ErrNonStunmessage);
            }
            let length = usize::from(u16::from_be_bytes([self.inbound[2], self.inbound[3]]));
            let total = MESSAGE_HEADER_SIZE + length;
            if self.inbound.len() < total {
                return Ok(());
            }
            let raw = self.inbound.split_to(total);
            let mut msg = Message::new();
            msg.raw = raw.to_vec();
            if let Err(err) = msg.decode() {
                self.fail(RequestError::Failed(Error::Other(err.to_string())));
                return Err(err);
            }
            // Only the answer to the request that is out counts; a response to one that was
            // sent again, or anything else, is passed over.
            if msg.transaction_id != id
                || msg.typ.method != METHOD_CONNECTION_BIND
                || (msg.typ.class != CLASS_SUCCESS_RESPONSE
                    && msg.typ.class != CLASS_ERROR_RESPONSE)
            {
                debug!("data connection {}: ignoring {msg}", self.connection_id);
                continue;
            }
            // As on the control connection (RFC 8489 §6.3, §9, §9.2.5): the response to a
            // signed request is signed with the same key, and nothing after its integrity
            // attribute is read. This is a reliable transport, so a response that is not
            // authentic ends the transaction at once, as an integrity violation; so does one
            // with an attribute the client has to but does not understand.
            let msg = match self.credential.check_response(
                &msg,
                &validator(),
                self.crypto_provider.crypto(),
            ) {
                Ok(valid) => valid,
                Err(Rejection::IntegrityMissing | Rejection::IntegrityMismatch) => {
                    debug!(
                        "data connection {}: {msg}: integrity attribute missing or wrong",
                        self.connection_id
                    );
                    self.fail(RequestError::Failed(Error::ErrIntegrityMismatch));
                    return Ok(());
                }
                Err(rejection) => {
                    self.fail(RequestError::Failed(Error::Other(rejection.to_string())));
                    return Ok(());
                }
            };

            if msg.typ.class == CLASS_SUCCESS_RESPONSE {
                self.state = State::Bound;
                self.events.push_back(DataConnectionEvent::Bound);
                // Whatever follows the response is the peer's.
                if !self.inbound.is_empty() {
                    let rest = self.inbound.split();
                    self.reads.push_back(rest);
                }
                return Ok(());
            }

            let err = RequestError::of(&msg);
            // The server's nonces may be the connection's own: a 401 or 438 is answered once
            // each with the same request and what the response asks for, by the rules of the
            // control connection (RFC 8489 §9.2.5).
            let again = if err.is(CODE_UNAUTHORIZED) && !challenged {
                Some((true, stale))
            } else if err.is(CODE_STALE_NONCE) && !stale {
                Some((challenged, true))
            } else {
                None
            };
            if let Some((challenged, stale)) = again {
                match self
                    .credential
                    .challenged(&self.request, &msg, self.crypto_provider.crypto())
                {
                    Ok(credential) => {
                        self.credential = Arc::new(credential);
                        let id = self.send_bind(now)?;
                        self.state = State::Binding {
                            id,
                            deadline,
                            challenged,
                            stale,
                        };
                        continue;
                    }
                    Err(refused) => {
                        debug!(
                            "data connection {}: {err} is not answered: {refused}",
                            self.connection_id
                        );
                    }
                }
            }
            self.fail(err);
            return Ok(());
        }
    }
}

impl sansio::Protocol<TaggedBytesMut, TaggedBytesMut, ()> for DataConnection {
    /// The peer's bytes.
    type Rout = BytesMut;
    /// Bytes for the TCP connection to the server.
    type Wout = TaggedBytesMut;
    type Eout = DataConnectionEvent;
    type Error = Error;
    type Time = Instant;

    /// Takes the next chunk read from the TCP connection, whatever its boundaries.
    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<()> {
        match self.state {
            State::Bound => {
                if !msg.message.is_empty() {
                    self.reads.push_back(msg.message);
                }
                Ok(())
            }
            State::Binding { .. } => {
                self.inbound.extend_from_slice(&msg.message);
                self.read_response(msg.now)
            }
            State::Failed | State::Closed => Ok(()),
        }
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.reads.pop_front()
    }

    /// Queues `msg.message` for the peer, as it is. `msg.transport` is not looked at.
    fn handle_write(&mut self, msg: TaggedBytesMut) -> Result<()> {
        self.send(msg.now, &msg.message)
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.transmits.pop_front()
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.events.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if let State::Binding { deadline, .. } = self.state
            && deadline <= now
        {
            self.fail(RequestError::Failed(Error::ErrTimeout));
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        match self.state {
            State::Binding { deadline, .. } => Some(deadline),
            _ => None,
        }
    }

    fn close(&mut self) -> Result<()> {
        self.state = State::Closed;
        self.inbound.clear();
        self.transmits.clear();
        Ok(())
    }
}
