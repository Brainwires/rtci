//! A receiver that stopped reading and starts again reopens the window by itself.
//!
//! Back-pressure works by leaving messages in SCTP's receive buffer (see
//! `data_channel_backpressure_rtc2rtc.rs`): the advertised window falls to zero and the peer
//! stops sending. When the application reads again, the space has to be announced: RFC 9260
//! section 6.2, a receiver sends a SACK "to update the offered window as the receiving
//! application consumes new data". A stopped peer sends nothing that could trigger it, except
//! its zero window probe, a retransmission timeout later (and that timeout doubles).
//!
//! These tests drive two peer connections in memory on a virtual clock the way an event loop
//! drives them: write what is pending, deliver, handle events, read, then sleep until the
//! earliest `poll_timeout` when nothing is in flight. The receiver's application stops
//! reading, the sender fills the window, the application reads again at a moment when no
//! datagram is in flight, and the window update has to leave the receiver at that instant,
//! before any datagram reaches it; then every message arrives, in order.

mod dc_common;

use anyhow::{Result, ensure};
use bytes::BytesMut;
use dc_common::Pair;
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::transport::RTCDtlsRole;
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::time::{Duration, Instant};

/// The receiver's SCTP receive buffer: small, so that the window closes after a few dozen
/// messages beyond the pipeline's own bound.
const RECEIVE_BUFFER: u32 = 64 * 1024;

const MESSAGE_SIZE: usize = 1024;

/// Well past what the pipeline (256 messages) and the receive buffer hold together.
const MESSAGES: u32 = 1_000;

/// How long the application does not read once the channel is open: long enough for the
/// window to close and for the sender to be left probing it.
const STALL: Duration = Duration::from_secs(5);

/// How the receiving application takes its messages.
#[derive(Clone, Copy, Debug)]
enum Reader {
    /// `poll_read`, which walks the pipeline and resumes the parked stream itself.
    PollRead,
    /// `poll_data_read`, which only takes what the pipeline already holds: the parked stream
    /// resumes from the deadline `poll_timeout` reports for it.
    PollDataRead,
}

/// A datagram `from` wrote, as it reaches its destination.
fn arriving(datagram: TaggedBytesMut, now: Instant) -> TaggedBytesMut {
    TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: datagram.transport.peer_addr,
            peer_addr: datagram.transport.local_addr,
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: datagram.message,
    }
}

fn index_of(data: &[u8]) -> u32 {
    u32::from_be_bytes(data[..4].try_into().expect("an index"))
}

fn drain_events(pc: &mut RTCPeerConnection) {
    while pc.poll_event().is_some() {}
}

/// What the run saw around the moment the application read again.
struct Resumed {
    read_at: Instant,
    /// When the receiver next wrote a datagram, and its first byte.
    next_write: Option<(Instant, u8)>,
    /// Whether a datagram reached the receiver before that.
    inbound_before_write: bool,
    /// Messages the application had when it read again.
    received_at_resume: usize,
}

fn run(reader: Reader) -> Result<()> {
    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:50010",
        SettingEngineBuilder::new().with_answering_dtls_role(RTCDtlsRole::Server),
        "127.0.0.1:50011",
        SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Client)
            .with_sctp_max_receive_buffer_size(RECEIVE_BUFFER),
    )?;
    let channel = pair.open_channel("flow")?;
    let opened_at = pair.now;
    let mut now = pair.now;
    let offerer = &mut pair.offerer.pc;
    let answerer = &mut pair.answerer.pc;

    let mut sent = 0u32;
    let mut received: Vec<u32> = Vec::new();
    let mut reading = false;
    let mut resumed: Option<Resumed> = None;
    let deadline = now + Duration::from_secs(120);

    while received.len() < MESSAGES as usize {
        ensure!(
            now < deadline,
            "{reader:?}: {} of {MESSAGES} messages arrived ({sent} sent)",
            received.len()
        );
        // Write what is pending.
        let to_answerer: Vec<_> = std::iter::from_fn(|| offerer.poll_write()).collect();
        let to_offerer: Vec<_> = std::iter::from_fn(|| answerer.poll_write()).collect();
        let quiet = to_answerer.is_empty() && to_offerer.is_empty();
        if let Some(r) = resumed.as_mut()
            && r.next_write.is_none()
            && let Some(first) = to_offerer.first()
        {
            r.next_write = Some((now, first.message.first().copied().unwrap_or(0)));
        }
        // Deliver.
        for datagram in to_answerer {
            if let Some(r) = resumed.as_mut()
                && r.next_write.is_none()
            {
                r.inbound_before_write = true;
            }
            answerer.handle_read(arriving(datagram, now))?;
        }
        for datagram in to_offerer {
            offerer.handle_read(arriving(datagram, now))?;
        }
        drain_events(offerer);
        drain_events(answerer);
        while offerer.poll_read().is_some() {}

        // The application reads again at a quiet moment once the stall is over: nothing is
        // in flight, so only the receiver itself can tell the sender of the space.
        if !reading && quiet && now >= opened_at + STALL {
            reading = true;
            resumed = Some(Resumed {
                read_at: now,
                next_write: None,
                inbound_before_write: false,
                received_at_resume: 0,
            });
        }
        if reading {
            loop {
                let message = match reader {
                    Reader::PollRead => answerer.poll_read(),
                    Reader::PollDataRead => answerer.poll_data_read(),
                };
                let Some(message) = message else { break };
                if let RTCMessage::DataChannelMessage(_, message) = message.message {
                    received.push(index_of(&message.data));
                }
            }
            if let Some(r) = resumed.as_mut()
                && r.received_at_resume == 0
            {
                r.received_at_resume = received.len();
            }
        }

        // The sender keeps the channel full.
        while sent < MESSAGES {
            let mut payload = sent.to_be_bytes().to_vec();
            payload.resize(MESSAGE_SIZE, 0xab);
            let Some(mut dc) = offerer.data_channel(channel) else {
                break;
            };
            if dc.send(now, BytesMut::from(&payload[..])).is_err() {
                break;
            }
            sent += 1;
        }

        // Sleep until the earliest deadline when nothing is in flight.
        if quiet {
            let next = [offerer.poll_timeout(), answerer.poll_timeout()]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(now + Duration::from_secs(1));
            now = now.max(next);
            offerer.handle_timeout(now)?;
            answerer.handle_timeout(now)?;
        }
    }

    let resumed = resumed.expect("the application read again");
    ensure!(
        resumed.received_at_resume < MESSAGES as usize - 100,
        "{reader:?}: the application had {} of {MESSAGES} messages when it read again, so the \
         window never closed and this test proved nothing",
        resumed.received_at_resume
    );
    let (written_at, first_byte) = resumed
        .next_write
        .expect("the receiver wrote nothing after it read again");
    ensure!(
        !resumed.inbound_before_write,
        "{reader:?}: a datagram reached the receiver before it announced the space: the \
         window was reopened by the sender's probe, not by the receiver"
    );
    ensure!(
        written_at == resumed.read_at,
        "{reader:?}: the window update left {:?} after the application read again",
        written_at - resumed.read_at
    );
    // RFC 7983 section 7: DTLS, not a STUN keepalive that happened to be due.
    ensure!(
        (20..=63).contains(&first_byte),
        "{reader:?}: the first datagram after the read was not DTLS (first byte {first_byte})"
    );
    let expected: Vec<u32> = (0..MESSAGES).collect();
    ensure!(
        received == expected,
        "{reader:?}: not every message in order"
    );
    Ok(())
}

#[test]
fn a_receiver_that_reads_again_reopens_the_window_without_an_inbound_datagram() -> Result<()> {
    run(Reader::PollRead)
}

#[test]
fn a_parked_stream_resumes_from_its_deadline_when_the_pipeline_is_drained_directly() -> Result<()> {
    run(Reader::PollDataRead)
}
