//! Two peer connections over loopback TCP, through the reference driver (`rtci-stream-driver`),
//! with a data channel: the smallest complete program that runs the engine's stream half.
//!
//! What is the engine's and what is the driver's:
//!
//! - **Engine** (`rtci`): decides everything. It gathers the ICE-TCP candidates (RFC 6544) for
//!   the UDP host address the application gives it, asks for listeners and connections by id
//!   (`poll_stream_command`), frames every packet with RFC 4571 (`poll_stream_transmit`),
//!   runs ICE, DTLS, SCTP and the data channel over them and closes what ICE no longer needs.
//! - **Driver** (`rtci_stream_driver::StreamDriver`, tokio): owns the sockets and nothing else.
//!   It binds, connects, accepts, reads and writes when told and reports what happened
//!   (`DriverInput`), which the loop hands back to the engine.
//! - **Application** (this file): signalling (here, passing descriptions and candidates
//!   between the two connections in one process) and the event loop.
//!
//! UDP is "blocked" here: nothing written for it leaves, so the connection can only come up
//! over the engine's TCP candidates. Run with `cargo run --example stream-driver-loopback`; it
//! exits 0 once 50 messages crossed the data channel in order, 1 after 30 s without.

use bytes::BytesMut;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::RTCIceCandidateInit;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use std::time::{Duration, Instant};
use stream_driver::{DriverInput, StreamDriver};

/// One side: the engine, the driver that owns its sockets, and what it has seen.
struct Peer {
    name: &'static str,
    pc: RTCPeerConnection,
    driver: StreamDriver,
    connected: bool,
    /// Candidates to trickle to the other side.
    outbox: Vec<RTCIceCandidateInit>,
    received: Vec<Vec<u8>>,
    open: Option<rtci::data_channel::RTCDataChannelId>,
}

impl Peer {
    fn new(name: &'static str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            name,
            pc: RTCPeerConnectionBuilder::new().build(Instant::now())?,
            driver: StreamDriver::default(),
            connected: false,
            outbox: vec![],
            received: vec![],
            open: None,
        })
    }

    /// The UDP host address the engine gathers its TCP candidates for. Its port is never
    /// used: UDP is blocked in this example.
    fn add_host(&mut self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        self.pc.add_local_candidate(RTCIceCandidateInit {
            candidate: format!("candidate:1 1 udp 2130706431 127.0.0.1 {port} typ host"),
            ..Default::default()
        })?;
        Ok(())
    }

    /// The engine's half of the loop: its commands and transmits to the driver, its events
    /// and reads to the application.
    fn run_engine(&mut self) {
        while let Some(command) = self.pc.poll_stream_command() {
            self.driver.execute(command);
        }
        while let Some(transmit) = self.pc.poll_stream_transmit() {
            self.driver.write(transmit);
        }
        // UDP is blocked: datagrams for it are dropped.
        while self.pc.poll_write().is_some() {}
        while let Some(event) = self.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                    if let Some(c) = ev.candidate.filter(|c| !c.end_of_candidates)
                        && let Ok(init) = c.to_json()
                    {
                        self.outbox.push(init);
                    }
                }
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => {
                    println!("{}: connected", self.name);
                    self.connected = true;
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    self.open = Some(id);
                }
                _ => {}
            }
        }
        while let Some(message) = self.pc.poll_read() {
            if let RTCMessage::DataChannelMessage(_, m) = message.message {
                self.received.push(m.data.to_vec());
            }
        }
    }

    /// The driver's half: what the sockets did, back to the engine.
    fn run_driver(&mut self) {
        while let Some(input) = self.driver.try_next() {
            let now = Instant::now();
            match input {
                DriverInput::Event(event) => {
                    let _ = self.pc.handle_stream_event(now, event);
                }
                DriverInput::Read { id, data } => {
                    let _ = self.pc.handle_stream_read(now, id, &data);
                }
                DriverInput::Accepted(accepted) => {
                    match self.pc.handle_stream_accepted(
                        now,
                        accepted.listener,
                        accepted.local,
                        accepted.remote,
                    ) {
                        Some(id) => self.driver.adopt(id, accepted),
                        // Refused by the engine: dropping it closes the socket.
                        None => drop(accepted),
                    }
                }
            }
        }
        let now = Instant::now();
        if self.pc.poll_timeout().is_some_and(|t| t <= now) {
            let _ = self.pc.handle_timeout(now);
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut offerer = Peer::new("offerer")?;
    let mut answerer = Peer::new("answerer")?;

    // Signalling, in-process.
    let channel = offerer.pc.create_data_channel("loopback", None)?.id();
    let offer = offerer.pc.create_offer(None)?;
    offerer
        .pc
        .set_local_description(Instant::now(), offer.clone())?;
    answerer.pc.set_remote_description(Instant::now(), offer)?;
    let answer = answerer.pc.create_answer(None)?;
    answerer
        .pc
        .set_local_description(Instant::now(), answer.clone())?;
    offerer.pc.set_remote_description(Instant::now(), answer)?;
    offerer.add_host(40000)?;
    answerer.add_host(40001)?;

    let messages: Vec<Vec<u8>> = (0..50u8).map(|i| vec![i; 100 + 37 * i as usize]).collect();
    let mut sent = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        for peer in [&mut offerer, &mut answerer] {
            peer.run_engine();
        }
        for c in std::mem::take(&mut offerer.outbox) {
            let _ = answerer.pc.add_remote_candidate(c);
        }
        for c in std::mem::take(&mut answerer.outbox) {
            let _ = offerer.pc.add_remote_candidate(c);
        }
        if !sent && offerer.open == Some(channel) {
            let mut dc = offerer.pc.data_channel(channel).ok_or("no channel")?;
            for m in &messages {
                dc.send(Instant::now(), BytesMut::from(&m[..]))?;
            }
            sent = true;
        }
        if answerer.received.len() >= messages.len() {
            assert_eq!(answerer.received, messages, "every message, in order");
            println!(
                "{} messages over a TCP candidate pair through the driver",
                messages.len()
            );
            return Ok(());
        }
        // Let the driver's tasks run, then take what the sockets did.
        tokio::time::sleep(Duration::from_millis(1)).await;
        for peer in [&mut offerer, &mut answerer] {
            peer.run_driver();
        }
    }
    eprintln!(
        "timed out: connected {}/{}, received {} of {}",
        offerer.connected,
        answerer.connected,
        answerer.received.len(),
        messages.len()
    );
    std::process::exit(1);
}
