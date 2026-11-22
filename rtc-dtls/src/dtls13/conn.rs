//! A DTLS 1.3 association (RFC 9147): the record layer with its epochs, the reliability of
//! the handshake (flights, retransmission, ACKs: sections 5.7, 5.8 and 7), key updates
//! (section 8), connection id updates (section 9) and alerts. The handshake messages
//! themselves are in [`handshake`](super::handshake).

use super::hello::{ClientOffer, RetryCookie};
use super::key_schedule::{KeySchedule, Transcript};
use super::messages::*;
use super::record::*;
use super::suite::Suite13;
use crate::config::HandshakeConfig;
use crate::conn::{
    FALLBACK_HANDSHAKE_MTU, MAX_PRE_HANDSHAKE_APPLICATION_DATA_BYTES,
    MAX_PRE_HANDSHAKE_APPLICATION_DATA_PACKETS, RETRANSMITS_BEFORE_MTU_BACKOFF,
};
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::signature_hash_algorithm::SignatureHashAlgorithm;
use bytes::BytesMut;
use crypto::{RTCCryptoProvider, SecretVec};
use log::{debug, warn};
use shared::error::{Error, Result};
use shared::replay_detector::{ReplayDetector, SlidingWindowDetector};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The epoch of the handshake traffic keys (RFC 9147 section 6.1).
pub(crate) const EPOCH_HANDSHAKE: u64 = 2;
/// The epoch of the first application traffic keys.
pub(crate) const EPOCH_APPLICATION: u64 = 3;
/// The highest epoch a sender moves to (RFC 9147 section 8).
pub(crate) const MAX_SEND_EPOCH: u64 = (1 << 48) - 1;
/// The most records one transmission of a flight holds (RFC 9147 section 5.8.3).
pub(crate) const MAX_RECORDS_PER_TRANSMISSION: usize = 10;
/// How long the keys of the handshake epoch are kept after the handshake, so that a
/// retransmission of the peer's last flight can be read and answered: twice the maximum
/// segment lifetime of RFC 793 (RFC 9147 section 5.8.1).
pub(crate) const HANDSHAKE_KEYS_LINGER: Duration = Duration::from_secs(240);
/// The least the retransmission timer is set to from a measured round trip (RFC 9147 section
/// 5.8.2 sets none; a handshake over loopback would otherwise retransmit at once).
pub(crate) const MINIMUM_MEASURED_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(100);
/// The longest handshake message taken from plaintext records: the hellos.
const MAX_PLAINTEXT_MESSAGE: usize = 16 * 1024;
/// The longest handshake message taken at all (a certificate chain).
const MAX_MESSAGE: usize = 256 * 1024;
/// How far ahead of the next expected message_seq a message is buffered.
const MESSAGE_SEQ_WINDOW: u16 = 8;
/// The most bytes of handshake messages under reassembly at once.
const MAX_REASSEMBLY_BYTES: usize = 512 * 1024;
/// The most records an outgoing flight remembers having been sent in, for matching ACKs.
const MAX_SENT_RECORDS: usize = 512;
/// The most record numbers kept to acknowledge.
const MAX_ACK_RECORDS: usize = 64;
/// The most protected records held because their keys are not there yet.
const MAX_EARLY_RECORDS: usize = 16;
/// The most RequestConnectionId messages an association answers (RFC 9147 section 9): one
/// more is an excessive number, and ends it with too_many_cids_requested.
pub(crate) const MAX_CONNECTION_ID_REQUESTS: u32 = 32;
/// How many times the current timer value a quiet period lasts before the retransmission
/// timer goes back to its initial value (RFC 9147 section 5.8.2: no less than 10).
const IDLE_TIMER_RESET_FACTOR: u32 = 10;
/// The most spare connection ids kept from the peer's NewConnectionId messages.
const MAX_SPARE_CONNECTION_IDS: usize = 8;

/// Where the handshake stands: what this side waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandshakeState {
    ClientWaitServerHello,
    ClientWaitEncryptedExtensions,
    ClientWaitCertificateOrRequest,
    ClientWaitCertificate,
    ClientWaitCertificateVerify,
    ClientWaitFinished,
    /// The client has sent its certificate and Finished and waits to learn that the server
    /// took them: the ACK of that flight, or anything under the server's application keys.
    ClientWaitConfirmation,
    ServerWaitClientHello,
    ServerWaitCertificate,
    ServerWaitCertificateVerify,
    ServerWaitFinished,
    Established,
}

/// A set of byte ranges, kept sorted and merged.
#[derive(Clone, Debug, Default)]
pub(crate) struct Ranges(Vec<(usize, usize)>);

impl Ranges {
    pub(crate) fn add(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        self.0.push((start, end));
        self.0.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.0.len());
        for (start, end) in self.0.drain(..) {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        self.0 = merged;
    }

    pub(crate) fn covers(&self, length: usize) -> bool {
        length == 0 || self.0 == [(0, length)]
    }

    /// The parts of `0..length` not in the set.
    pub(crate) fn gaps(&self, length: usize) -> Vec<(usize, usize)> {
        let mut gaps = vec![];
        let mut at = 0;
        for (start, end) in &self.0 {
            if *start > at {
                gaps.push((at, (*start).min(length)));
            }
            at = at.max(*end);
        }
        if at < length {
            gaps.push((at, length));
        }
        gaps
    }

    pub(crate) fn contains(&self, start: usize, end: usize) -> bool {
        self.0.iter().any(|(s, e)| *s <= start && end <= *e)
    }
}

/// A handshake message being put together from its fragments (RFC 9147 section 5.5).
struct Reassembly {
    handshake_type: u8,
    data: Vec<u8>,
    received: Ranges,
}

/// One message of an outgoing flight.
pub(crate) struct OutMessage {
    pub(crate) message_seq: u16,
    /// The epoch it is sent in, and sent again in (RFC 9147 section 4.2.1).
    pub(crate) epoch: u64,
    pub(crate) handshake_type: u8,
    pub(crate) body: Vec<u8>,
    /// The bytes of the body the peer has acknowledged.
    acknowledged: Ranges,
}

/// What an outgoing flight is, which decides what ends its retransmission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlightKind {
    /// A flight of the handshake that the peer's next flight answers.
    Handshake,
    /// The client's last flight, which only an ACK answers (RFC 9147 section 7.1).
    ClientFinal,
    KeyUpdate,
    NewConnectionId,
    RequestConnectionId,
}

/// Messages sent together and retransmitted until acknowledged (RFC 9147 section 5.7).
pub(crate) struct Flight {
    pub(crate) kind: FlightKind,
    pub(crate) messages: Vec<OutMessage>,
    /// Which bytes of which message went out in which record, newest last.
    sent: VecDeque<(RecordNumber, usize, usize, usize)>,
    /// Where the next transmission starts when one transmission cannot hold the flight.
    cursor: usize,
    timer: Option<Instant>,
    /// A transmission was made and the timer is to be set from the next `now`.
    arm: bool,
    /// When the flight first went out, if it has not been sent again since.
    first_sent: Option<Instant>,
    retransmissions: usize,
}

impl Flight {
    pub(crate) fn new(kind: FlightKind) -> Self {
        Self {
            kind,
            messages: vec![],
            sent: VecDeque::new(),
            cursor: 0,
            timer: None,
            arm: false,
            first_sent: None,
            retransmissions: 0,
        }
    }

    pub(crate) fn push(&mut self, message_seq: u16, epoch: u64, handshake_type: u8, body: Vec<u8>) {
        self.messages.push(OutMessage {
            message_seq,
            epoch,
            handshake_type,
            body,
            acknowledged: Ranges::default(),
        });
    }

    fn acknowledged(&self) -> bool {
        self.messages
            .iter()
            .all(|message| message.acknowledged.covers(message.body.len()))
    }
}

/// The keys this side protects records of one epoch with.
struct WriteEpoch {
    epoch: u64,
    keys: RecordKeys,
    next_sequence: u64,
}

/// The keys this side reads records of one epoch with.
struct ReadEpoch {
    epoch: u64,
    keys: RecordKeys,
    replay: SlidingWindowDetector,
    /// One more than the highest sequence number deprotected (RFC 9147 section 4.2.2).
    next_expected: u64,
    /// How many records failed authentication under these keys (section 4.5.3).
    failures: u64,
}

/// What became of a record handed to the handshake layer.
#[derive(Default)]
struct RecordOutcome {
    /// A fragment of it was processed or buffered: the record may be acknowledged.
    kept: bool,
    /// It repeated a message already processed: the peer is retransmitting.
    repeated: bool,
    /// It held something other than the next expected piece.
    out_of_order: bool,
}

/// A DTLS 1.3 association.
pub(crate) struct Conn13 {
    pub(crate) cfg: Arc<HandshakeConfig>,
    pub(crate) provider: Arc<dyn RTCCryptoProvider>,
    pub(crate) is_client: bool,

    // What was negotiated.
    pub(crate) suite: Option<Suite13>,
    pub(crate) schedule: Option<KeySchedule>,
    pub(crate) transcript: Transcript,
    pub(crate) srtp_profile: SrtpProtectionProfile,
    pub(crate) peer_certificates: Vec<Vec<u8>>,
    pub(crate) server_name: String,
    pub(crate) client_random: Vec<u8>,
    pub(crate) exporter_secret: Option<SecretVec>,

    // The record layer.
    plaintext_send_sequence: u64,
    plaintext_replay: SlidingWindowDetector,
    write: Vec<WriteEpoch>,
    read: Vec<ReadEpoch>,
    /// The application traffic secrets the current keys of each direction came from, from
    /// which a KeyUpdate derives the next.
    local_traffic_secret: Option<SecretVec>,
    remote_traffic_secret: Option<SecretVec>,
    /// The connection id the peer puts in records to this side (empty: none).
    pub(crate) local_connection_id: Vec<u8>,
    /// The connection id this side puts in records to the peer (empty: none).
    pub(crate) remote_connection_id: Vec<u8>,
    /// Every connection id this side has handed out and still takes records under: the one
    /// of the handshake and those of its NewConnectionId messages.
    accepted_connection_ids: VecDeque<Vec<u8>>,
    /// Both sides sent the connection_id extension.
    pub(crate) connection_ids_negotiated: bool,
    /// The last datagram read held a record that authenticated and was newer than any
    /// before it: what RFC 9146 section 6 asks before a peer's address is updated.
    pub(crate) newest_record_read: bool,
    spare_connection_ids: VecDeque<Vec<u8>>,
    early_records: VecDeque<Vec<u8>>,
    pub(crate) authenticated_records: u64,
    /// The peer has shown it holds the handshake keys, so nothing unprotected is its word
    /// any more.
    peer_uses_keys: bool,

    // Receiving the handshake.
    pub(crate) state: HandshakeState,
    next_receive_seq: u16,
    reassembly: BTreeMap<u16, Reassembly>,

    // Sending the handshake.
    pub(crate) next_send_seq: u16,
    pub(crate) flight: Option<Flight>,
    post_handshake: Vec<Flight>,
    retransmit_interval: Duration,
    handshake_mtu: usize,
    handshake_started: Option<Instant>,
    /// The peer repeated a flight this side has answered: the answer is sent again.
    peer_retransmitted: bool,
    /// Application data has arrived ahead of the peer's Finished, and the flight has been
    /// sent again for it.
    early_data_seen: bool,
    /// A flight was answered or acknowledged: (when it first went out, if never again).
    answered: Option<Option<Instant>>,

    // Acknowledging.
    /// The records of the peer's current flight that were processed or buffered.
    received_records: Vec<RecordNumber>,
    ack_now: bool,
    ack_delayed: bool,
    ack_timer: Option<Instant>,

    // Application data and the association's end.
    incoming: VecDeque<BytesMut>,
    held_application_data: VecDeque<BytesMut>,
    queued_writes: VecDeque<Vec<u8>>,
    pending_records: Vec<Vec<u8>>,
    datagrams: VecDeque<BytesMut>,
    pub(crate) established: bool,
    established_at: Option<Instant>,
    handshake_keys_deadline: Option<Instant>,
    pub(crate) failed: bool,
    pub(crate) closed: bool,
    pub(crate) closed_by_peer: bool,
    fatal_alert_sent: Option<(u8, usize)>,
    /// A KeyUpdate of this side is waiting for its ACK, and whether another was asked for
    /// meanwhile.
    key_update_requested_by_peer: bool,
    connection_id_request_outstanding: bool,
    connection_id_requests_received: u32,
    /// When a flight was last sent, answered or acknowledged.
    last_flight_activity: Option<Instant>,
    flight_activity: bool,
    /// How many records were discarded as invalid: malformed, or failing authentication.
    pub(crate) invalid_records: u64,

    // The client's hello, until the server has answered it.
    pub(crate) offer: Option<ClientOffer>,
    pub(crate) client_hello: Vec<u8>,
    pub(crate) hello_retry_seen: bool,
    pub(crate) offered_extensions: Vec<u16>,
    pub(crate) certificate_requested: Option<Vec<u16>>,
    pub(crate) peer_signature_scheme: Option<SignatureHashAlgorithm>,
    /// The server's: the secret of the cookies of a cookie exchange it runs itself, and the
    /// cookie a caller has already verified for it.
    pub(crate) cookie_secret: Option<SecretVec>,
    pub(crate) verified_retry: Option<(Vec<u8>, RetryCookie)>,
    pub(crate) address_verified: bool,
    pub(crate) client_certificate_expected: bool,
    /// Limits of the AEAD, which a test lowers to reach them.
    pub(crate) confidentiality_limit: Option<u64>,
    pub(crate) integrity_limit: Option<u64>,
}

impl Drop for Conn13 {
    fn drop(&mut self) {
        self.forget_secrets();
    }
}

impl Conn13 {
    pub(crate) fn new(cfg: Arc<HandshakeConfig>, is_client: bool, state: HandshakeState) -> Self {
        let provider = cfg.provider().clone();
        Self {
            provider,
            is_client,
            suite: None,
            schedule: None,
            transcript: Transcript::default(),
            srtp_profile: SrtpProtectionProfile::Unsupported,
            peer_certificates: vec![],
            server_name: String::new(),
            client_random: vec![],
            exporter_secret: None,
            plaintext_send_sequence: 0,
            plaintext_replay: SlidingWindowDetector::new(
                cfg.replay_protection_window,
                MAX_SEQUENCE_NUMBER,
            ),
            write: vec![],
            read: vec![],
            local_traffic_secret: None,
            remote_traffic_secret: None,
            local_connection_id: vec![],
            remote_connection_id: vec![],
            accepted_connection_ids: VecDeque::new(),
            connection_ids_negotiated: false,
            newest_record_read: false,
            spare_connection_ids: VecDeque::new(),
            early_records: VecDeque::new(),
            authenticated_records: 0,
            peer_uses_keys: false,
            state,
            next_receive_seq: 0,
            reassembly: BTreeMap::new(),
            next_send_seq: 0,
            flight: None,
            post_handshake: vec![],
            retransmit_interval: cfg.retransmit_interval,
            handshake_mtu: cfg.maximum_transmission_unit,
            handshake_started: None,
            peer_retransmitted: false,
            early_data_seen: false,
            answered: None,
            received_records: vec![],
            ack_now: false,
            ack_delayed: false,
            ack_timer: None,
            incoming: VecDeque::new(),
            held_application_data: VecDeque::new(),
            queued_writes: VecDeque::new(),
            pending_records: vec![],
            datagrams: VecDeque::new(),
            established: false,
            established_at: None,
            handshake_keys_deadline: None,
            failed: false,
            closed: false,
            closed_by_peer: false,
            fatal_alert_sent: None,
            key_update_requested_by_peer: false,
            connection_id_request_outstanding: false,
            connection_id_requests_received: 0,
            last_flight_activity: None,
            flight_activity: false,
            invalid_records: 0,
            offer: None,
            client_hello: vec![],
            hello_retry_seen: false,
            offered_extensions: vec![],
            certificate_requested: None,
            peer_signature_scheme: None,
            cookie_secret: None,
            verified_retry: None,
            address_verified: false,
            client_certificate_expected: false,
            confidentiality_limit: None,
            integrity_limit: None,
            cfg,
        }
    }

    pub(crate) fn set_next_receive_seq(&mut self, message_seq: u16) {
        self.next_receive_seq = message_seq;
    }

    pub(crate) fn set_plaintext_send_sequence(&mut self, sequence: u64) {
        self.plaintext_send_sequence = sequence;
    }

    pub(crate) fn suite(&self) -> Result<Suite13> {
        self.suite.ok_or(Error::ErrCipherSuiteUnset)
    }

    // ------------------------------------------------------------------------------------
    // Keys and epochs.
    // ------------------------------------------------------------------------------------

    fn record_keys(&self, secret: &[u8]) -> Result<RecordKeys> {
        let schedule = self.schedule.as_ref().ok_or(Error::ErrCipherSuiteUnset)?;
        let keys = schedule.traffic_keys(self.provider.crypto(), secret)?;
        RecordKeys::new(self.provider.crypto(), self.suite()?, &keys)
    }

    /// Starts protecting records of `epoch` with the keys of `secret`.
    pub(crate) fn install_write_epoch(&mut self, epoch: u64, secret: &[u8]) -> Result<()> {
        let keys = self.record_keys(secret)?;
        self.write.push(WriteEpoch {
            epoch,
            keys,
            next_sequence: 0,
        });
        Ok(())
    }

    /// Starts reading records of `epoch` with the keys of `secret`.
    pub(crate) fn install_read_epoch(&mut self, epoch: u64, secret: &[u8]) -> Result<()> {
        let keys = self.record_keys(secret)?;
        self.read.push(ReadEpoch {
            epoch,
            keys,
            replay: SlidingWindowDetector::new(
                self.cfg.replay_protection_window,
                MAX_SEQUENCE_NUMBER,
            ),
            next_expected: 0,
            failures: 0,
        });
        Ok(())
    }

    pub(crate) fn set_application_secrets(&mut self, local: SecretVec, remote: SecretVec) {
        self.local_traffic_secret = Some(local);
        self.remote_traffic_secret = Some(remote);
    }

    /// The highest epoch this side can send in: what ACKs, alerts, application data and
    /// post-handshake messages go out in (RFC 9147 section 7).
    fn send_epoch(&self) -> u64 {
        self.write
            .iter()
            .map(|write| write.epoch)
            .max()
            .unwrap_or(0)
    }

    fn drop_write_epoch(&mut self, epoch: u64) {
        self.write.retain(|write| write.epoch != epoch);
    }

    fn drop_read_epoch(&mut self, epoch: u64) {
        self.read.retain(|read| read.epoch != epoch);
    }

    /// Drops the write keys of application epochs older than the current one that no
    /// unacknowledged message still has to be sent again in.
    fn prune_write_epochs(&mut self) {
        let current = self.send_epoch();
        let in_use: Vec<u64> = self
            .post_handshake
            .iter()
            .chain(self.flight.iter())
            .flat_map(|flight| flight.messages.iter().map(|message| message.epoch))
            .collect();
        self.write.retain(|write| {
            write.epoch == current
                || write.epoch < EPOCH_APPLICATION
                || in_use.contains(&write.epoch)
        });
    }

    pub(crate) fn forget_secrets(&mut self) {
        if let Some(schedule) = &mut self.schedule {
            schedule.forget();
        }
        self.exporter_secret = None;
        self.local_traffic_secret = None;
        self.remote_traffic_secret = None;
        self.cookie_secret = None;
        self.offer = None;
    }

    // ------------------------------------------------------------------------------------
    // Writing records.
    // ------------------------------------------------------------------------------------

    /// How many bytes a record of `epoch` adds to its content.
    fn record_overhead(&self, epoch: u64) -> usize {
        if epoch == 0 {
            PLAINTEXT_HEADER_LEN
        } else {
            let tag_len = self.suite.map_or(16, |suite| suite.tag_len());
            HeaderForm::FULL.header_len(self.remote_connection_id.len()) + 1 + tag_len
        }
    }

    /// Writes one record of `epoch` and queues it. Returns its record number.
    fn write_record(
        &mut self,
        epoch: u64,
        content_type: u8,
        content: &[u8],
    ) -> Result<RecordNumber> {
        if epoch == 0 {
            let sequence = self.plaintext_send_sequence;
            // RFC 9147 section 4: a plaintext record's sequence number stays within 48 bits.
            if sequence > MAX_SEQUENCE_NUMBER {
                return Err(Error::ErrSequenceNumberOverflow);
            }
            self.plaintext_send_sequence += 1;
            self.pending_records
                .push(plaintext_record(content_type, sequence, content));
            return Ok(RecordNumber { epoch, sequence });
        }
        let limit = self
            .confidentiality_limit
            .or(self.suite.map(|suite| suite.confidentiality_limit()))
            .unwrap_or(u64::MAX)
            .min(MAX_SEQUENCE_NUMBER);
        let connection_id = self.remote_connection_id.clone();
        let write = self
            .write
            .iter_mut()
            .find(|write| write.epoch == epoch)
            .ok_or(Error::ErrCipherSuiteUnset)?;
        // RFC 9147 sections 4.2.1 and 4.5.3: no more records under one key than its AEAD
        // allows, and never a sequence number that wraps.
        if write.next_sequence >= limit {
            return Err(Error::ErrSequenceNumberOverflow);
        }
        let number = RecordNumber {
            epoch,
            sequence: write.next_sequence,
        };
        write.next_sequence += 1;
        let record = write.keys.seal(
            number,
            &connection_id,
            HeaderForm::FULL,
            content_type,
            content,
            0,
        )?;
        self.pending_records.push(record);
        Ok(number)
    }

    /// One record of `content_type` holding `content`, protected under this side's current
    /// keys and not queued: for a fuzz harness to hand to the peer.
    #[cfg(any(fuzzing, test))]
    pub(crate) fn seal_for_fuzzing(&mut self, content_type: u8, content: &[u8]) -> Option<Vec<u8>> {
        let epoch = self.send_epoch();
        if epoch == 0 {
            return None;
        }
        self.write_record(epoch, content_type, content).ok()?;
        self.pending_records.pop()
    }

    /// Packs the queued records into datagrams no larger than the MTU, in order.
    fn flush(&mut self) {
        let mtu = self.cfg.maximum_transmission_unit;
        let mut datagram = BytesMut::new();
        for record in self.pending_records.drain(..) {
            if !datagram.is_empty() && datagram.len() + record.len() > mtu {
                self.datagrams.push_back(std::mem::take(&mut datagram));
            }
            datagram.extend_from_slice(&record);
        }
        if !datagram.is_empty() {
            self.datagrams.push_back(datagram);
        }
    }

    pub(crate) fn poll_datagram(&mut self) -> Option<BytesMut> {
        self.flush();
        self.datagrams.pop_front()
    }

    pub(crate) fn poll_application_data(&mut self) -> Option<BytesMut> {
        if self.established {
            self.incoming.pop_front()
        } else {
            None
        }
    }

    /// Queues application data: one record, in the current epoch, once the handshake is
    /// complete.
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.closed || self.failed {
            return Err(Error::ErrConnClosed);
        }
        if data.len() > MAX_PLAINTEXT {
            return Err(Error::ErrRecordOverflow);
        }
        if !self.established {
            self.queued_writes.push_back(data.to_vec());
            return Ok(());
        }
        self.write_application_data(data)
    }

    fn write_application_data(&mut self, data: &[u8]) -> Result<()> {
        let epoch = self.send_epoch();
        self.write_record(epoch, CONTENT_TYPE_APPLICATION_DATA, data)?;
        self.rekey_before_the_limit();
        Ok(())
    }

    /// RFC 9147 section 4.5.3: a key update is started before the keys reach the number of
    /// records their AEAD allows.
    fn rekey_before_the_limit(&mut self) {
        let Some(suite) = self.suite else { return };
        let limit = self
            .confidentiality_limit
            .unwrap_or(suite.confidentiality_limit());
        let epoch = self.send_epoch();
        let used = self
            .write
            .iter()
            .find(|write| write.epoch == epoch)
            .map_or(0, |write| write.next_sequence);
        if used >= limit - limit / 8 && !self.key_update_outstanding() {
            let _ = self.send_key_update(false);
        }
    }

    // ------------------------------------------------------------------------------------
    // Flights: sending, retransmitting, acknowledging (RFC 9147 sections 5.8 and 7).
    // ------------------------------------------------------------------------------------

    /// The pieces of `flight` still to be acknowledged, each small enough for one record of
    /// a datagram of the handshake MTU: (message, offset, length).
    fn unacknowledged_pieces(&self, flight: &Flight) -> Vec<(usize, usize, usize)> {
        let mut pieces = vec![];
        for (index, message) in flight.messages.iter().enumerate() {
            let room = self
                .handshake_mtu
                .saturating_sub(self.record_overhead(message.epoch) + HANDSHAKE_HEADER_LEN)
                .max(1);
            if message.body.is_empty() && !message.acknowledged.covers(1) {
                pieces.push((index, 0, 0));
            }
            for (mut start, end) in message.acknowledged.gaps(message.body.len()) {
                while start < end {
                    let length = room.min(end - start);
                    pieces.push((index, start, length));
                    start += length;
                }
            }
        }
        pieces
    }

    /// Sends what `flight` still has unacknowledged, at most ten records of it (RFC 9147
    /// section 5.8.3): a later transmission goes on where this one stopped.
    fn transmit(&mut self, flight: &mut Flight) -> Result<()> {
        let pieces = self.unacknowledged_pieces(flight);
        if pieces.is_empty() {
            return Ok(());
        }
        let start = if pieces.len() > MAX_RECORDS_PER_TRANSMISSION {
            flight.cursor % pieces.len()
        } else {
            0
        };
        let count = pieces.len().min(MAX_RECORDS_PER_TRANSMISSION);
        for step in 0..count {
            let (index, offset, length) = pieces[(start + step) % pieces.len()];
            let message = &flight.messages[index];
            let fragment = handshake_fragment(
                message.handshake_type,
                message.body.len(),
                message.message_seq,
                offset,
                &message.body[offset..offset + length],
            );
            let number = self.write_record(message.epoch, CONTENT_TYPE_HANDSHAKE, &fragment)?;
            flight.sent.push_back((number, index, offset, length));
            if flight.sent.len() > MAX_SENT_RECORDS {
                flight.sent.pop_front();
            }
        }
        flight.cursor = if pieces.len() > MAX_RECORDS_PER_TRANSMISSION {
            (start + count) % pieces.len()
        } else {
            0
        };
        flight.arm = true;
        Ok(())
    }

    /// Sends a new flight of the handshake, which replaces the one before it.
    pub(crate) fn send_flight(&mut self, mut flight: Flight) -> Result<()> {
        self.transmit(&mut flight)?;
        self.flight = Some(flight);
        // RFC 9147 section 7: what was received of the peer's flight is answered by this
        // one, and the list of records to acknowledge starts again.
        self.received_records.clear();
        self.ack_now = false;
        self.ack_delayed = false;
        self.ack_timer = None;
        Ok(())
    }

    /// The flight the peer was waiting on has been answered by its next one, which
    /// acknowledges all of it (RFC 9147 section 7.2).
    pub(crate) fn flight_answered(&mut self) {
        if let Some(flight) = &self.flight
            && flight.kind == FlightKind::Handshake
        {
            self.answered = Some(flight.first_sent);
            self.flight = None;
        }
    }

    fn retransmit_handshake_flight(&mut self) -> Result<()> {
        let Some(mut flight) = self.flight.take() else {
            return Ok(());
        };
        flight.retransmissions += 1;
        flight.first_sent = None;
        let result = self.transmit(&mut flight);
        self.flight = Some(flight);
        result
    }

    /// Takes an ACK: the bytes that went out in the records it names are acknowledged and
    /// are not sent again (RFC 9147 section 7.2). `ack_epoch` is the epoch of the record
    /// that carried it, which bounds what it can acknowledge (section 7).
    fn handle_ack(&mut self, ack_epoch: u64, content: &[u8]) -> std::result::Result<(), Refusal> {
        let numbers = match decode_ack(content) {
            Ok(numbers) => numbers,
            Err(err) if ack_epoch == 0 => {
                debug!("discarded malformed plaintext ACK: {err}");
                return Ok(());
            }
            Err(err) => return Err(decode_error(err)),
        };
        // RFC 9147 section 7: during the handshake an ACK travels in an epoch no lower than
        // the records it names, so a plaintext one cannot acknowledge protected records.
        // After it the epochs of the two directions move apart, and there is no such order.
        let numbers: Vec<RecordNumber> = numbers
            .into_iter()
            .filter(|number| number.epoch <= ack_epoch || ack_epoch >= EPOCH_APPLICATION)
            .collect();

        if let Some(mut flight) = self.flight.take() {
            let progressed = Self::acknowledge(&mut flight, &numbers);
            if flight.acknowledged() {
                self.answered = Some(flight.first_sent);
                self.on_flight_acknowledged(flight.kind);
            } else {
                // A partial ACK, or an empty one (the peer could read nothing of what
                // arrived): what is still missing goes out again at once (section 5.8.1),
                // out of the flight's budget of retransmissions.
                let asks = progressed || numbers.is_empty();
                if asks && flight.retransmissions < self.cfg.maximum_retransmit_number {
                    flight.retransmissions += 1;
                    flight.first_sent = None;
                    let _ = self.transmit(&mut flight);
                }
                self.flight = Some(flight);
            }
        }

        let mut finished = vec![];
        let mut flights = std::mem::take(&mut self.post_handshake);
        for flight in &mut flights {
            let progressed = Self::acknowledge(flight, &numbers);
            if flight.acknowledged() {
                finished.push(flight.kind);
            } else if progressed && flight.retransmissions < self.cfg.maximum_retransmit_number {
                flight.retransmissions += 1;
                let _ = self.transmit(flight);
            }
        }
        flights.retain(|flight| !flight.acknowledged());
        self.post_handshake = flights;
        for kind in finished {
            self.on_flight_acknowledged(kind);
        }
        Ok(())
    }

    /// Marks what `numbers` acknowledge in `flight`. Whether anything new was.
    fn acknowledge(flight: &mut Flight, numbers: &[RecordNumber]) -> bool {
        let mut progressed = false;
        for (number, index, offset, length) in &flight.sent {
            if !numbers.contains(number) {
                continue;
            }
            let message = &mut flight.messages[*index];
            let end = if message.body.is_empty() {
                1
            } else {
                offset + length
            };
            if !message.acknowledged.contains(*offset, end) {
                message.acknowledged.add(*offset, end);
                progressed = true;
            }
        }
        progressed
    }

    fn on_flight_acknowledged(&mut self, kind: FlightKind) {
        self.flight_activity = true;
        match kind {
            FlightKind::Handshake => {}
            FlightKind::ClientFinal => {
                debug!("client: final flight acknowledged");
                self.confirm();
                // Nothing of the handshake epoch is sent or expected any more.
                self.drop_write_epoch(EPOCH_HANDSHAKE);
                self.drop_read_epoch(EPOCH_HANDSHAKE);
            }
            FlightKind::KeyUpdate => {
                // RFC 9147 section 8: the new keys are used once the KeyUpdate is
                // acknowledged, and not before.
                if let Err(err) = self.advance_write_keys() {
                    warn!("key update failed: {err}");
                }
                if std::mem::take(&mut self.key_update_requested_by_peer) {
                    let _ = self.send_key_update(false);
                }
            }
            FlightKind::NewConnectionId | FlightKind::RequestConnectionId => {}
        }
        self.prune_write_epochs();
    }

    /// Queues an ACK of the records in `received_records` (RFC 9147 section 7), in the
    /// highest epoch this side can send in.
    fn send_ack(&mut self) {
        self.ack_now = false;
        self.ack_delayed = false;
        self.ack_timer = None;
        let epoch = self.send_epoch();
        self.received_records.sort_unstable();
        self.received_records.dedup();
        // RFC 9147 section 7: an ACK travels in an epoch no lower than the records it names.
        let room = self
            .cfg
            .maximum_transmission_unit
            .saturating_sub(self.record_overhead(epoch) + 2)
            / 16;
        let mut numbers: Vec<RecordNumber> = self
            .received_records
            .iter()
            .filter(|number| number.epoch <= epoch || epoch >= EPOCH_APPLICATION)
            .copied()
            .collect();
        // The most recent ones, if they do not all fit.
        let most = room.clamp(1, MAX_ACK_RECORD_NUMBERS);
        if numbers.len() > most {
            numbers.drain(..numbers.len() - most);
        }
        if let Err(err) = self.write_record(epoch, CONTENT_TYPE_ACK, &encode_ack(&numbers)) {
            debug!("could not send an ACK: {err}");
        }
        if self.established {
            // After the handshake each record is acknowledged once (section 7). A server
            // keeps the records of the client's last flight, to acknowledge them again
            // when the client repeats it (section 5.8.1).
            let keep_handshake = !self.is_client;
            self.received_records
                .retain(|number| keep_handshake && number.epoch == EPOCH_HANDSHAKE);
        }
    }

    /// An ACK goes out with the next `drive`.
    pub(crate) fn acknowledge_now(&mut self) {
        self.ack_now = true;
    }

    fn note_received_record(&mut self, number: RecordNumber) {
        if !self.received_records.contains(&number) {
            self.received_records.push(number);
            if self.received_records.len() > MAX_ACK_RECORDS {
                self.received_records.remove(0);
            }
        }
    }

    // ------------------------------------------------------------------------------------
    // Timers. The association reads no clock: `drive` is given the time after anything
    // that may have armed a timer, and `handle_timeout` when one is due.
    // ------------------------------------------------------------------------------------

    /// Sets the timers that what happened since the last call armed, and sends what is due
    /// at once.
    pub(crate) fn drive(&mut self, now: Instant) -> Result<()> {
        if self.failed {
            return Err(Error::ErrConnClosed);
        }
        self.handshake_started.get_or_insert(now);

        // RFC 9147 section 5.8.2: when a flight got through without being sent again, the
        // timer becomes one and a half times the round trip measured for it; otherwise it
        // keeps its backed-off value.
        if let Some(Some(first_sent)) = self.answered.take() {
            let measured = now.saturating_duration_since(first_sent);
            self.retransmit_interval = (measured + measured / 2)
                .max(MINIMUM_MEASURED_RETRANSMIT_INTERVAL)
                .min(self.cfg.maximum_retransmit_interval);
        }

        if std::mem::take(&mut self.peer_retransmitted)
            && self
                .flight
                .as_ref()
                .is_some_and(|flight| flight.retransmissions < self.cfg.maximum_retransmit_number)
        {
            // RFC 9147 section 5.8.1: the peer sent its flight again, so ours was lost.
            self.retransmit_handshake_flight()?;
        }

        if self.established && self.established_at.is_none() {
            self.established_at = Some(now);
            // A server keeps the handshake keys to read, and acknowledge again, a client's
            // last flight that is sent again (RFC 9147 section 5.8.1). A client keeps them
            // while its own last flight is unacknowledged.
            if !self.is_client {
                self.handshake_keys_deadline = Some(now + HANDSHAKE_KEYS_LINGER);
            }
        }

        // RFC 9147 section 5.8.2: after a quiet period of ten times the timer's value, the
        // backed-off timer goes back to where it starts.
        let idle = self
            .flight
            .iter()
            .chain(self.post_handshake.iter())
            .all(|flight| flight.timer.is_none() && flight.retransmissions == 0);
        if idle
            && !self.flight_activity
            && self.last_flight_activity.is_some_and(|last| {
                now.saturating_duration_since(last)
                    >= self.retransmit_interval * IDLE_TIMER_RESET_FACTOR
            })
        {
            self.retransmit_interval = self.cfg.retransmit_interval;
        }
        if std::mem::take(&mut self.flight_activity)
            || self.flight.is_some()
            || !self.post_handshake.is_empty()
        {
            self.last_flight_activity = Some(now);
        }

        let interval = self.retransmit_interval;
        for flight in self.flight.iter_mut().chain(self.post_handshake.iter_mut()) {
            if std::mem::take(&mut flight.arm) {
                flight.timer = Some(now + interval);
                if flight.retransmissions == 0 && flight.first_sent.is_none() {
                    flight.first_sent = Some(now);
                }
            }
        }

        if self.ack_now {
            self.send_ack();
        } else if self.ack_delayed && self.ack_timer.is_none() {
            // RFC 9147 section 7.1: part of a flight arrived; if the rest does not follow,
            // say so after a quarter of the retransmission timer.
            self.ack_timer = Some(now + interval / 4);
        }
        Ok(())
    }

    fn handshake_deadline(&self) -> Option<Instant> {
        if self.established || self.failed {
            return None;
        }
        Some(self.handshake_started? + self.cfg.handshake_timeout?)
    }

    pub(crate) fn next_timeout(&self) -> Option<Instant> {
        if self.failed {
            return None;
        }
        self.flight
            .iter()
            .chain(self.post_handshake.iter())
            .filter_map(|flight| flight.timer)
            .chain(self.ack_timer)
            .chain(self.handshake_deadline())
            .chain(self.handshake_keys_deadline)
            .min()
    }

    /// Advances the association to `now`: gives a handshake up at its deadline, sends again
    /// what has waited a whole timer for its answer (RFC 9147 section 5.8.1), sends a
    /// delayed ACK, and lets go of the handshake keys.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.failed {
            return Err(Error::ErrConnClosed);
        }
        if self
            .handshake_deadline()
            .is_some_and(|deadline| now >= deadline)
        {
            warn!("dtls 1.3 handshake did not complete in time");
            self.fail();
            return Err(Error::ErrHandshakeTimeout);
        }
        if self.handshake_keys_deadline.is_some_and(|at| now >= at) {
            self.handshake_keys_deadline = None;
            self.drop_read_epoch(EPOCH_HANDSHAKE);
            if !self.is_client {
                self.received_records.clear();
            }
        }
        if self.ack_timer.is_some_and(|at| now >= at) {
            self.send_ack();
        }

        let maximum = self.cfg.maximum_retransmit_interval;
        let floor = self.cfg.retransmit_interval;
        let mut expired = false;
        if let Some(mut flight) = self.flight.take() {
            if flight.timer.is_some_and(|at| now >= at) {
                expired = true;
                flight.timer = None;
                flight.retransmissions += 1;
                flight.first_sent = None;
                // RFC 9147 section 4.4: unanswered retransmissions may mean the records are
                // too large for the path, so they are cut smaller.
                if flight.retransmissions > RETRANSMITS_BEFORE_MTU_BACKOFF {
                    self.handshake_mtu = (self.handshake_mtu / 2)
                        .max(FALLBACK_HANDSHAKE_MTU)
                        .min(self.handshake_mtu);
                }
                self.transmit(&mut flight)?;
            }
            if flight.kind == FlightKind::ClientFinal
                && self.state == HandshakeState::Established
                && flight.retransmissions > self.cfg.maximum_retransmit_number
            {
                // The handshake is complete for this client and nothing has acknowledged
                // its last flight: it is not sent for ever. The server either has it or
                // will fail its own handshake.
                self.on_flight_acknowledged(FlightKind::ClientFinal);
            } else {
                self.flight = Some(flight);
            }
        }
        let mut flights = std::mem::take(&mut self.post_handshake);
        for flight in &mut flights {
            if flight.timer.is_some_and(|at| now >= at) {
                flight.timer = None;
                // A post-handshake message is sent again as often as a flight would be and
                // then left: the association goes on without what it asked for.
                if flight.retransmissions < self.cfg.maximum_retransmit_number {
                    expired = true;
                    flight.retransmissions += 1;
                    self.transmit(flight)?;
                }
            }
        }
        self.post_handshake = flights;
        if expired {
            // RFC 9147 section 5.8.2: the timer doubles at each retransmission.
            self.retransmit_interval = (self.retransmit_interval * 2).min(maximum).max(floor);
        }
        self.drive(now)
    }

    // ------------------------------------------------------------------------------------
    // Reading records.
    // ------------------------------------------------------------------------------------

    /// Processes one datagram.
    ///
    /// # Errors
    ///
    /// `ErrAlertFatalOrClose` when the datagram ended the association (a fatal alert, sent
    /// or received, or the peer's close_notify), `ErrConnClosed` when it was over already.
    pub(crate) fn read(&mut self, datagram: &[u8]) -> Result<()> {
        if self.failed {
            self.repeat_fatal_alert(datagram);
            return Err(Error::ErrConnClosed);
        }
        if self.closed_by_peer {
            // RFC 9147 section 5.10: nothing after the peer's closure alert counts.
            return Err(Error::ErrConnClosed);
        }
        self.newest_record_read = false;
        let mut rest = datagram;
        while !rest.is_empty() {
            let (record, taken) = match next_record(rest, self.local_connection_id.len()) {
                Ok(next) => next,
                Err(err) => {
                    // RFC 9147 sections 4.1 and 4.5.2: an invalid record is discarded, and
                    // with it what follows, which cannot be delimited.
                    debug!("discarded {} bytes of a datagram: {err}", rest.len());
                    self.note_invalid_record();
                    break;
                }
            };
            let outcome = match record {
                DatagramRecord::Plaintext {
                    content_type,
                    sequence,
                    fragment,
                } => self.read_plaintext(content_type, sequence, fragment),
                DatagramRecord::Ciphertext { header, record } => {
                    // RFC 9147 section 4: a record for another connection id ends the
                    // datagram.
                    let connection_id = &record[header.connection_id.clone()];
                    if connection_id != &self.local_connection_id[..]
                        && !self
                            .accepted_connection_ids
                            .iter()
                            .any(|accepted| accepted == connection_id)
                    {
                        debug!("discarded a record with another connection id");
                        break;
                    }
                    self.read_ciphertext(&header, record)
                }
            };
            if let Err(refusal) = outcome {
                return Err(self.refuse(refusal));
            }
            if self.failed || self.closed_by_peer {
                return Err(Error::ErrAlertFatalOrClose);
            }
            rest = &rest[taken..];
        }
        Ok(())
    }

    fn read_plaintext(
        &mut self,
        content_type: u8,
        sequence: u64,
        fragment: &[u8],
    ) -> std::result::Result<(), Refusal> {
        // Anti-replay for the unprotected epoch: the window moves only for a record that
        // delivered something, since anyone can send one (RFC 9147 section 4.5.1).
        if !self.plaintext_replay.check(sequence) {
            return Ok(());
        }
        let number = RecordNumber { epoch: 0, sequence };
        match content_type {
            CONTENT_TYPE_HANDSHAKE => {
                // Unprotected handshake messages are the hellos, and they come first.
                if self.peer_uses_keys && self.established {
                    return Ok(());
                }
                match self.read_handshake_record(number, fragment, false) {
                    Ok(outcome) => {
                        if outcome.kept || outcome.repeated {
                            self.plaintext_replay.accept();
                        }
                        if outcome.kept {
                            self.note_received_record(number);
                        }
                        if outcome.repeated {
                            // The peer sent its hello again: our answer was lost.
                            self.peer_retransmitted = true;
                        }
                        Ok(())
                    }
                    Err(refusal) => Err(refusal),
                }
            }
            CONTENT_TYPE_ALERT => {
                // An unprotected alert is the peer's word only until it has shown that it
                // holds the handshake keys: from then on anyone else's.
                if self.peer_uses_keys || self.established {
                    return Ok(());
                }
                if let [_level, description] = fragment
                    && *description != alert::CLOSE_NOTIFY
                    && *description != alert::USER_CANCELED
                {
                    self.plaintext_replay.accept();
                    debug!("<- plaintext alert {description}");
                    self.fail();
                }
                Ok(())
            }
            CONTENT_TYPE_ACK => {
                if self.peer_uses_keys {
                    return Ok(());
                }
                self.handle_ack(0, fragment)
            }
            _ => Ok(()),
        }
    }

    fn read_ciphertext(
        &mut self,
        header: &UnifiedHeader,
        record: &[u8],
    ) -> std::result::Result<(), Refusal> {
        // RFC 9147 section 4.2.2: the keys are those of the most recent epoch whose low
        // bits are the record's.
        let Some(index) = self
            .read
            .iter()
            .enumerate()
            .filter(|(_, read)| (read.epoch & 3) as u8 == header.epoch_bits)
            .max_by_key(|(_, read)| read.epoch)
            .map(|(index, _)| index)
        else {
            // No keys for it (yet): a record that arrived ahead of the message that makes
            // them is held, a few of them, and tried again.
            if !self.established && self.early_records.len() < MAX_EARLY_RECORDS {
                self.early_records.push_back(record.to_vec());
                // RFC 9147 section 7.1: say that nothing of it could be read.
                if self.is_client && self.state == HandshakeState::ClientWaitServerHello {
                    self.ack_delayed = true;
                }
            }
            return Ok(());
        };
        let integrity_limit = self
            .integrity_limit
            .or(self.suite.map(|suite| suite.integrity_limit()))
            .unwrap_or(u64::MAX);
        let read = &mut self.read[index];
        let epoch = read.epoch;
        let (sequence, content_type, content) =
            match read.keys.open(header, record, read.next_expected) {
                Ok(opened) => opened,
                Err(Error::ErrInvalidMac) => {
                    // RFC 9147 section 4.5.3: failures are counted per key, and at the
                    // AEAD's limit the association is closed.
                    read.failures += 1;
                    let failures = read.failures;
                    self.note_invalid_record();
                    if self.failed {
                        return Ok(());
                    }
                    if failures >= integrity_limit {
                        warn!("too many records failed authentication in epoch {epoch}");
                        self.fail();
                    } else if failures == integrity_limit / 2
                        && self.established
                        && !self.key_update_outstanding()
                    {
                        let _ = self.send_key_update(true);
                    }
                    return Ok(());
                }
                // Authenticated, and malformed inside (RFC 8446 section 5.4).
                Err(Error::ErrRecordOverflow) => {
                    return Err(refuse(alert::RECORD_OVERFLOW, Error::ErrRecordOverflow));
                }
                Err(Error::ErrInvalidContentType) => {
                    return Err(refuse(
                        alert::UNEXPECTED_MESSAGE,
                        Error::ErrInvalidContentType,
                    ));
                }
                Err(_) => return Ok(()),
            };
        // RFC 9147 section 4.5.1: the window is consulted, and moved, only for a record
        // that has been deprotected.
        if !read.replay.check(sequence) {
            return Ok(());
        }
        read.replay.accept();
        let newest_epoch = self.read.iter().map(|read| read.epoch).max() == Some(epoch);
        let read = &mut self.read[index];
        if sequence >= read.next_expected && newest_epoch {
            self.newest_record_read = true;
        }
        read.next_expected = read.next_expected.max(sequence + 1);
        self.authenticated_records += 1;
        self.peer_uses_keys = true;
        if epoch >= EPOCH_APPLICATION {
            // A server protects nothing under its application keys before it has taken the
            // client's Finished.
            self.confirm();
        }
        if epoch > EPOCH_APPLICATION {
            // RFC 9147 section 8: the keys before an update are kept until a record under
            // the new ones has been read.
            self.read
                .retain(|read| read.epoch < EPOCH_APPLICATION || read.epoch >= epoch);
        }

        let number = RecordNumber { epoch, sequence };
        match content_type {
            CONTENT_TYPE_HANDSHAKE => {
                let outcome = self.read_handshake_record(number, &content, true)?;
                if outcome.kept || (outcome.repeated && self.established) {
                    self.note_received_record(number);
                }
                if self.failed {
                    return Ok(());
                }
                if outcome.repeated {
                    if self.established && !self.is_client && epoch == EPOCH_HANDSHAKE {
                        // RFC 9147 section 5.8.1: the client sent its last flight again; it
                        // has not seen the ACK.
                        self.ack_now = true;
                    } else if self.established && epoch >= EPOCH_APPLICATION {
                        // Section 7: a post-handshake message is acknowledged each time.
                        self.ack_now = true;
                    } else {
                        self.peer_retransmitted = true;
                    }
                }
                if outcome.out_of_order && !self.received_records.is_empty() {
                    // Section 7.1: a sign of disruption in the peer's flight.
                    self.ack_now = true;
                }
                Ok(())
            }
            CONTENT_TYPE_ALERT => self.read_alert(&content),
            CONTENT_TYPE_ACK => self.handle_ack(epoch, &content),
            CONTENT_TYPE_APPLICATION_DATA => {
                // RFC 8446 section 5: application data is never protected under the
                // handshake keys.
                if epoch < EPOCH_APPLICATION {
                    return Err(refuse(
                        alert::UNEXPECTED_MESSAGE,
                        Error::ErrApplicationDataEpochZero,
                    ));
                }
                if self.established {
                    self.incoming.push_back(BytesMut::from(&content[..]));
                } else {
                    // RFC 9147 section 5.8.1: held until the peer's Finished has arrived.
                    // The peer is past its Finished, so that was lost or is late: our
                    // flight goes out again at once, which draws it again.
                    if !std::mem::replace(&mut self.early_data_seen, true) {
                        self.peer_retransmitted = true;
                    }
                    let held: usize = self.held_application_data.iter().map(BytesMut::len).sum();
                    if self.held_application_data.len() < MAX_PRE_HANDSHAKE_APPLICATION_DATA_PACKETS
                        && held + content.len() <= MAX_PRE_HANDSHAKE_APPLICATION_DATA_BYTES
                    {
                        self.held_application_data
                            .push_back(BytesMut::from(&content[..]));
                    }
                }
                Ok(())
            }
            _ => Err(refuse(
                alert::UNEXPECTED_MESSAGE,
                Error::ErrInvalidContentType,
            )),
        }
    }

    /// RFC 9147 section 5.10: a peer that keeps sending records that are not valid is
    /// given up on, where the configuration sets a limit
    /// ([`ConfigBuilder::with_invalid_record_limit`](crate::config::ConfigBuilder::with_invalid_record_limit)).
    /// The local state goes without an alert: whoever sends such records is not known to be
    /// the peer.
    fn note_invalid_record(&mut self) {
        self.invalid_records += 1;
        if self
            .cfg
            .invalid_record_limit
            .is_some_and(|limit| self.invalid_records > limit)
        {
            warn!(
                "dtls 1.3: {} invalid records, over the configured limit",
                self.invalid_records
            );
            self.fail();
        }
    }

    /// Tries the records that arrived before their keys again.
    pub(crate) fn replay_early_records(&mut self) -> std::result::Result<(), Refusal> {
        let records: Vec<Vec<u8>> = self.early_records.drain(..).collect();
        for record in records {
            if self.failed {
                break;
            }
            if let Ok(header) = UnifiedHeader::parse(&record, self.local_connection_id.len()) {
                self.read_ciphertext(&header, &record[..header.record_len])?;
            }
        }
        Ok(())
    }

    fn read_alert(&mut self, content: &[u8]) -> std::result::Result<(), Refusal> {
        let [_level, description] = content else {
            return Err(decode_error(Error::ErrBufferTooSmall));
        };
        debug!("<- alert {description}");
        match *description {
            alert::CLOSE_NOTIFY => {
                // The peer has closed; the answer is this side's own close_notify.
                self.closed_by_peer = true;
                self.closed = true;
                self.send_alert(alert::CLOSE_NOTIFY);
                Ok(())
            }
            // RFC 8446 section 6.1: user_canceled is followed by a close_notify.
            alert::USER_CANCELED => Ok(()),
            // Section 6.2: every other alert is an error alert, whatever its level says.
            _ => {
                self.fail();
                Ok(())
            }
        }
    }

    // ------------------------------------------------------------------------------------
    // Handshake messages: fragments, order, reassembly (RFC 9147 sections 5.2 and 5.5).
    // ------------------------------------------------------------------------------------

    fn read_handshake_record(
        &mut self,
        number: RecordNumber,
        content: &[u8],
        authenticated: bool,
    ) -> std::result::Result<RecordOutcome, Refusal> {
        let mut outcome = RecordOutcome::default();
        let fragments = match HandshakeFragment::parse_all(content) {
            Ok(fragments) => fragments,
            Err(err) if authenticated => return Err(decode_error(err)),
            Err(_) => return Ok(outcome),
        };
        for fragment in fragments {
            let limit = if authenticated {
                MAX_MESSAGE
            } else {
                MAX_PLAINTEXT_MESSAGE
            };
            if fragment.length > limit {
                if authenticated {
                    return Err(decode_error(Error::ErrLengthMismatch));
                }
                continue;
            }
            // RFC 9147 section 5.2: an older message is discarded, a later one queued.
            if fragment.message_seq < self.next_receive_seq {
                outcome.repeated = true;
                continue;
            }
            if fragment.message_seq - self.next_receive_seq > MESSAGE_SEQ_WINDOW {
                continue;
            }
            if fragment.message_seq != self.next_receive_seq {
                outcome.out_of_order = true;
            }
            let buffered: usize = self.reassembly.values().map(|r| r.data.len()).sum();
            let entry = match self.reassembly.get_mut(&fragment.message_seq) {
                Some(entry) => entry,
                None => {
                    if buffered + fragment.length > MAX_REASSEMBLY_BYTES {
                        continue;
                    }
                    self.reassembly
                        .entry(fragment.message_seq)
                        .or_insert(Reassembly {
                            handshake_type: fragment.handshake_type,
                            data: vec![0; fragment.length],
                            received: Ranges::default(),
                        })
                }
            };
            if entry.handshake_type != fragment.handshake_type
                || entry.data.len() != fragment.length
            {
                // Not a fragment of the message the others are of.
                if authenticated {
                    return Err(refuse(alert::ILLEGAL_PARAMETER, Error::ErrLengthMismatch));
                }
                continue;
            }
            let start = fragment.fragment_offset;
            let end = start + fragment.fragment.len();
            // RFC 9147 section 5.5: overlapping fragments are taken, and a byte that
            // changes between two of them is an illegal_parameter.
            let conflict = entry.received.0.iter().any(|(have_start, have_end)| {
                let from = start.max(*have_start);
                let to = end.min(*have_end);
                from < to && entry.data[from..to] != fragment.fragment[from - start..to - start]
            });
            if conflict {
                if authenticated {
                    return Err(refuse(alert::ILLEGAL_PARAMETER, Error::ErrLengthMismatch));
                }
                continue;
            }
            if start != 0 && !entry.received.contains(0, start) {
                outcome.out_of_order = true;
            }
            entry.data[start..end].copy_from_slice(fragment.fragment);
            entry.received.add(start, end);
            outcome.kept = true;
            let epoch = number.epoch;

            // Process every message that is now complete and next in order.
            while let Some(entry) = self.reassembly.get(&self.next_receive_seq) {
                if !entry.received.covers(entry.data.len()) {
                    break;
                }
                let Some(message) = self.reassembly.remove(&self.next_receive_seq) else {
                    break;
                };
                let message_seq = self.next_receive_seq;
                self.next_receive_seq = self.next_receive_seq.wrapping_add(1);
                debug!(
                    "<- handshake type {} (seq {message_seq}, epoch {epoch})",
                    message.handshake_type
                );
                match self.on_handshake_message(message.handshake_type, &message.data, epoch) {
                    Ok(()) => {}
                    // An unprotected message that does not hold up is anyone's: it is
                    // dropped and its place kept for the genuine one, unless this side has
                    // nothing to go back to.
                    Err(refusal) if !authenticated && self.forgives_plaintext(&refusal) => {
                        debug!(
                            "discarded an unprotected handshake message: {}",
                            refusal.error
                        );
                        self.next_receive_seq = message_seq;
                        outcome.kept = false;
                        return Ok(outcome);
                    }
                    Err(refusal) => return Err(refusal),
                }
                if self.failed {
                    return Ok(outcome);
                }
            }
            if !self.reassembly.is_empty() && self.state != HandshakeState::Established {
                // Part of a flight is here and the rest is not (section 7.1).
                self.ack_delayed = true;
            }
        }
        let _ = number;
        Ok(outcome)
    }

    /// Whether a refusal of an unprotected message is better not acted on: a message that
    /// does not parse can be a forgery, and answering it with a fatal alert would let anyone
    /// end the handshake. A message that parses and is refused for what it says is answered.
    fn forgives_plaintext(&self, refusal: &Refusal) -> bool {
        refusal.alert == alert::DECODE_ERROR
    }

    // ------------------------------------------------------------------------------------
    // Alerts and the end of the association.
    // ------------------------------------------------------------------------------------

    fn send_alert(&mut self, description: u8) {
        // RFC 8446 section 6: close_notify and user_canceled are warnings, the rest fatal.
        let level = if description == alert::CLOSE_NOTIFY || description == alert::USER_CANCELED {
            1
        } else {
            2
        };
        let epoch = self.send_epoch();
        if let Err(err) = self.write_record(epoch, CONTENT_TYPE_ALERT, &[level, description]) {
            debug!("could not send alert {description}: {err}");
        }
    }

    /// Ends the association over `refusal`: the alert goes out and the error comes back.
    pub(crate) fn refuse(&mut self, refusal: Refusal) -> Error {
        warn!(
            "dtls 1.3 {}: alert {} ({})",
            if self.is_client { "client" } else { "server" },
            refusal.alert,
            refusal.error
        );
        self.send_alert(refusal.alert);
        self.fatal_alert_sent = Some((refusal.alert, self.cfg.maximum_retransmit_number));
        self.fail();
        refusal.error
    }

    /// The association is over: nothing more is read, written or retransmitted, and its
    /// secrets are forgotten (RFC 8446 section 6.2).
    pub(crate) fn fail(&mut self) {
        self.failed = true;
        self.closed = true;
        self.flight = None;
        self.post_handshake.clear();
        self.ack_timer = None;
        self.handshake_keys_deadline = None;
        self.forget_secrets();
    }

    /// RFC 9147 section 5.10: an alert is not retransmitted, but the offending record
    /// arriving again (the peer has not seen the alert) draws a new one, a bounded number
    /// of times.
    fn repeat_fatal_alert(&mut self, datagram: &[u8]) {
        let Some((description, remaining)) = self.fatal_alert_sent else {
            return;
        };
        let carries_handshake = datagram.first() == Some(&CONTENT_TYPE_HANDSHAKE)
            || datagram
                .first()
                .is_some_and(|first| is_unified_header(*first));
        if remaining == 0 || !carries_handshake {
            return;
        }
        self.fatal_alert_sent = Some((description, remaining - 1));
        self.send_alert(description);
    }

    /// Begins an orderly shutdown: a close_notify.
    pub(crate) fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.send_alert(alert::CLOSE_NOTIFY);
        }
    }

    /// A client that authenticated itself learns that the server accepted it: only now is
    /// its handshake complete. Until the server has verified the client's certificate it
    /// can still refuse it, and a client that reported completion at its own Finished would
    /// report a connection the server never had.
    fn confirm(&mut self) {
        if self.state == HandshakeState::ClientWaitConfirmation
            && let Err(err) = self.establish()
        {
            warn!("dtls 1.3 client: {err}");
        }
    }

    /// The handshake is complete: what was held is released.
    pub(crate) fn establish(&mut self) -> Result<()> {
        self.established = true;
        self.state = HandshakeState::Established;
        self.incoming.extend(self.held_application_data.drain(..));
        while let Some(data) = self.queued_writes.pop_front() {
            self.write_application_data(&data)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------------------------
    // After the handshake: key updates and connection ids (RFC 9147 sections 8 and 9).
    // ------------------------------------------------------------------------------------

    /// How many post-handshake messages of this side wait for their acknowledgement.
    pub(crate) fn unacknowledged_post_handshake_messages(&self) -> usize {
        self.post_handshake.len()
    }

    fn key_update_outstanding(&self) -> bool {
        self.post_handshake
            .iter()
            .any(|flight| flight.kind == FlightKind::KeyUpdate)
    }

    pub(crate) fn send_post_handshake(
        &mut self,
        kind: FlightKind,
        handshake_type: u8,
        body: Vec<u8>,
    ) -> Result<()> {
        let mut flight = Flight::new(kind);
        flight.push(self.next_send_seq, self.send_epoch(), handshake_type, body);
        self.next_send_seq = self.next_send_seq.wrapping_add(1);
        self.transmit(&mut flight)?;
        self.post_handshake.push(flight);
        Ok(())
    }

    /// Sends a KeyUpdate: this side moves to new sending keys once the peer acknowledges
    /// it. `request_update` asks the peer to update its own as well.
    ///
    /// # Errors
    ///
    /// Before the handshake is complete, while an earlier KeyUpdate is unacknowledged (RFC
    /// 9147 section 8), and when the epoch would pass 2^48-1.
    pub(crate) fn send_key_update(&mut self, request_update: bool) -> Result<()> {
        if !self.established || self.closed {
            return Err(Error::ErrConnClosed);
        }
        if self.key_update_outstanding() {
            return Err(Error::Other(
                "a KeyUpdate is waiting for its acknowledgement".to_owned(),
            ));
        }
        if self.send_epoch() >= MAX_SEND_EPOCH {
            return Err(Error::ErrSequenceNumberOverflow);
        }
        self.send_post_handshake(
            FlightKind::KeyUpdate,
            KEY_UPDATE,
            key_update(request_update),
        )
    }

    /// The peer acknowledged this side's KeyUpdate: the next sending keys take over.
    fn advance_write_keys(&mut self) -> Result<()> {
        let schedule = self.schedule.as_ref().ok_or(Error::ErrCipherSuiteUnset)?;
        let current = self
            .local_traffic_secret
            .as_ref()
            .ok_or(Error::ErrCipherSuiteUnset)?;
        let next =
            schedule.next_application_traffic_secret(self.provider.crypto(), current.as_ref())?;
        let epoch = self.send_epoch() + 1;
        self.install_write_epoch(epoch, next.as_ref())?;
        self.local_traffic_secret = Some(next);
        Ok(())
    }

    /// The peer sent a KeyUpdate: its next records are under its next keys.
    fn advance_read_keys(&mut self) -> Result<()> {
        let schedule = self.schedule.as_ref().ok_or(Error::ErrCipherSuiteUnset)?;
        let current = self
            .remote_traffic_secret
            .as_ref()
            .ok_or(Error::ErrCipherSuiteUnset)?;
        let next =
            schedule.next_application_traffic_secret(self.provider.crypto(), current.as_ref())?;
        let epoch = self
            .read
            .iter()
            .map(|read| read.epoch)
            .max()
            .unwrap_or(EPOCH_APPLICATION)
            + 1;
        self.install_read_epoch(epoch, next.as_ref())?;
        self.remote_traffic_secret = Some(next);
        Ok(())
    }

    /// Sends a NewConnectionId with `connection_ids` for the peer to use in records to this
    /// side (RFC 9147 section 9). With `immediate` the peer switches to one of them at
    /// once, and this side expects it from then on.
    pub(crate) fn send_new_connection_id(
        &mut self,
        connection_ids: Vec<Vec<u8>>,
        immediate: bool,
    ) -> Result<()> {
        if !self.established || self.closed {
            return Err(Error::ErrConnClosed);
        }
        // RFC 9147 section 9: not without a negotiated, non-empty connection id, and one
        // NewConnectionId at a time.
        if !self.connection_ids_negotiated || self.local_connection_id.is_empty() {
            return Err(Error::Other("no connection id was negotiated".to_owned()));
        }
        if self
            .post_handshake
            .iter()
            .any(|flight| flight.kind == FlightKind::NewConnectionId)
        {
            return Err(Error::Other(
                "a NewConnectionId is waiting for its acknowledgement".to_owned(),
            ));
        }
        // The length of a connection id is not in a record, so every id this side hands out
        // has the length of the first.
        if connection_ids
            .iter()
            .any(|id| id.len() != self.local_connection_id.len())
        {
            return Err(Error::Other(
                "connection ids of one association have one length".to_owned(),
            ));
        }
        let usage = if immediate { CID_IMMEDIATE } else { CID_SPARE };
        let body = new_connection_id(&connection_ids, usage);
        // Records under the ids handed out so far are still taken: the peer goes on using
        // the old one until this message reaches it.
        if self.accepted_connection_ids.is_empty() {
            self.accepted_connection_ids
                .push_back(self.local_connection_id.clone());
        }
        for connection_id in &connection_ids {
            self.accepted_connection_ids
                .push_back(connection_id.clone());
            if self.accepted_connection_ids.len() > 2 * MAX_SPARE_CONNECTION_IDS {
                self.accepted_connection_ids.pop_front();
            }
        }
        self.send_post_handshake(FlightKind::NewConnectionId, NEW_CONNECTION_ID, body)
    }

    /// Asks the peer for `count` more connection ids (RFC 9147 section 9).
    pub(crate) fn send_request_connection_id(&mut self, count: u8) -> Result<()> {
        if !self.established || self.closed {
            return Err(Error::ErrConnClosed);
        }
        // Not when this side sends an empty connection id, and one request at a time.
        if !self.connection_ids_negotiated || self.remote_connection_id.is_empty() {
            return Err(Error::Other("no connection id was negotiated".to_owned()));
        }
        if self.connection_id_request_outstanding {
            return Err(Error::Other(
                "a RequestConnectionId is still unfulfilled".to_owned(),
            ));
        }
        self.connection_id_request_outstanding = true;
        self.send_post_handshake(
            FlightKind::RequestConnectionId,
            REQUEST_CONNECTION_ID,
            request_connection_id(count),
        )
    }

    /// Whether `datagram` starts with a protected record under a connection id of this
    /// association: how an endpoint finds the association of a datagram from an address it
    /// does not know (RFC 9146 section 6).
    pub(crate) fn owns_connection_id(&self, datagram: &[u8]) -> bool {
        let length = self.local_connection_id.len();
        let Some(connection_id) = datagram.get(1..1 + length) else {
            return false;
        };
        length > 0
            && datagram[0] & 0xf0 == 0x30
            && (connection_id == &self.local_connection_id[..]
                || self
                    .accepted_connection_ids
                    .iter()
                    .any(|accepted| accepted == connection_id))
    }

    /// Switches to the next spare connection id the peer provided, as an endpoint does when
    /// it sends on a new path (RFC 9147 section 9). `false` when there is none.
    pub(crate) fn use_next_connection_id(&mut self) -> bool {
        match self.spare_connection_ids.pop_front() {
            Some(connection_id) => {
                self.remote_connection_id = connection_id;
                true
            }
            None => false,
        }
    }

    /// A handshake message after the handshake (RFC 9147 section 5.8.4).
    pub(crate) fn on_post_handshake_message(
        &mut self,
        handshake_type: u8,
        body: &[u8],
    ) -> std::result::Result<(), Refusal> {
        let unexpected = || refuse(alert::UNEXPECTED_MESSAGE, Error::ErrUnhandledContextType);
        match handshake_type {
            NEW_SESSION_TICKET if self.is_client => {
                // Tickets are not used: this stack does not resume. Acknowledged, so that
                // the server stops sending it.
                parse_new_session_ticket(body)?;
            }
            KEY_UPDATE => {
                let update_requested = parse_key_update(body)?;
                self.advance_read_keys()
                    .map_err(|err| refuse(alert::INTERNAL_ERROR, err))?;
                if update_requested {
                    // RFC 9147 section 8: answered with a KeyUpdate of our own, unless one
                    // is on its way already or the epoch has no room.
                    if self.key_update_outstanding() {
                        self.key_update_requested_by_peer = false;
                    } else if self.send_epoch() < MAX_SEND_EPOCH {
                        let _ = self.send_key_update(false);
                    }
                }
            }
            NEW_CONNECTION_ID => {
                // RFC 9147 section 9: only when connection ids were negotiated and the
                // peer is not being sent an empty one.
                if !self.connection_ids_negotiated || self.remote_connection_id.is_empty() {
                    return Err(unexpected());
                }
                let (connection_ids, usage) = parse_new_connection_id(body)?;
                self.connection_id_request_outstanding = false;
                let mut connection_ids: VecDeque<Vec<u8>> = connection_ids.into();
                if usage == CID_IMMEDIATE {
                    // One of the new ones is used for every record from now on.
                    match connection_ids.pop_front() {
                        Some(connection_id) => self.remote_connection_id = connection_id,
                        None => {
                            return Err(refuse(
                                alert::ILLEGAL_PARAMETER,
                                Error::Other("cid_immediate without a connection id".to_owned()),
                            ));
                        }
                    }
                }
                // Spare ones are used in the order given; more than are wanted are dropped.
                for connection_id in connection_ids {
                    if self.spare_connection_ids.len() < MAX_SPARE_CONNECTION_IDS {
                        self.spare_connection_ids.push_back(connection_id);
                    }
                }
            }
            REQUEST_CONNECTION_ID => {
                if !self.connection_ids_negotiated || self.local_connection_id.is_empty() {
                    return Err(unexpected());
                }
                let count = parse_request_connection_id(body)?;
                // RFC 9147 section 9: an excessive number of requests may be answered with
                // too_many_cids_requested.
                self.connection_id_requests_received += 1;
                if self.connection_id_requests_received > MAX_CONNECTION_ID_REQUESTS {
                    return Err(refuse(
                        alert::TOO_MANY_CIDS_REQUESTED,
                        Error::Other("too many RequestConnectionId messages".to_owned()),
                    ));
                }
                // As many as asked for, up to what this side cares to track; none when a
                // NewConnectionId of ours is still unacknowledged.
                let count = usize::from(count).min(MAX_SPARE_CONNECTION_IDS);
                let mut connection_ids = vec![];
                for _ in 0..count {
                    let mut connection_id = vec![0u8; self.local_connection_id.len()];
                    self.provider
                        .random()
                        .fill(&mut connection_id)
                        .map_err(|err| {
                            refuse(alert::INTERNAL_ERROR, Error::Crypto(err.to_string()))
                        })?;
                    connection_ids.push(connection_id);
                }
                let _ = self.send_new_connection_id(connection_ids, false);
            }
            // RFC 8446 section 4.6.2: post-handshake authentication was not offered, so a
            // CertificateRequest now is an unexpected_message; so is anything else.
            _ => return Err(unexpected()),
        }
        self.ack_now = true;
        Ok(())
    }
}
