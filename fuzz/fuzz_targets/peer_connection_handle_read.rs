#![no_main]
//! Stateful target: a whole peer connection's `handle_read` after a canned handshake.
//!
//! Two peers, built the way an application builds them, exchange an offer and an answer (audio,
//! video and a negotiated data channel) and then talk over an in-memory network on a virtual clock
//! until ICE, DTLS, SRTP and SCTP are up. The input chooses how far the handshake gets before it
//! starts (so it also lands mid-handshake), then a sequence of ops: datagrams to the answerer from
//! the offerer's address, from a stray address, or STUN-shaped; datagrams to the offerer; the
//! peers' own traffic delivered; data-channel sends; and clock steps. Every datagram goes through
//! the demultiplexer into STUN / ICE, DTLS, SRTP / SRTCP, the interceptors and SCTP, exactly as
//! one from the network does.

#[path = "common.rs"]
mod common;

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rtci::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::transport::RTCDtlsRole;
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci::sansio::Protocol;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const NEGOTIATED_ID: u16 = 1;

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

/// Splits the next op argument off `data`: a two-byte length, then that many bytes.
fn take_arg<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    if data.len() < 2 {
        *data = &[];
        return &[];
    }
    let len = usize::from(u16::from_be_bytes([data[0], data[1]])).min(data.len() - 2);
    let (arg, rest) = data[2..].split_at(len);
    *data = rest;
    arg
}

struct Peer {
    pc: RTCPeerConnection,
    addr: SocketAddr,
    channel: RTCDataChannelId,
    open: bool,
}

struct Pair {
    offerer: Peer,
    answerer: Peer,
    now: Instant,
}

impl Pair {
    fn new(config: u8) -> Option<Self> {
        let role = if config & 0x01 == 0 {
            RTCDtlsRole::Client
        } else {
            RTCDtlsRole::Server
        };
        let mut offerer = common::peer(0, 1, role)?;
        let mut answerer = common::peer(1, 2, role)?;
        let offerer_addr: SocketAddr = "192.0.2.1:5000".parse().ok()?;
        let answerer_addr: SocketAddr = "192.0.2.2:6000".parse().ok()?;
        common::add_host_candidate(&mut offerer, offerer_addr)?;
        common::add_host_candidate(&mut answerer, answerer_addr)?;

        let init = RTCDataChannelInit {
            ordered: config & 0x02 == 0,
            negotiated: Some(NEGOTIATED_ID),
            ..Default::default()
        };
        let offerer_channel = offerer
            .create_data_channel("fuzz", Some(init.clone()))
            .ok()?
            .id();
        let answerer_channel = answerer.create_data_channel("fuzz", Some(init)).ok()?.id();
        let _ = offerer.add_transceiver_from_kind(RtpCodecKind::Audio, None);
        if config & 0x04 != 0 {
            let _ = offerer.add_transceiver_from_kind(RtpCodecKind::Video, None);
        }

        let now = common::start();
        let offer = offerer.create_offer(None).ok()?;
        offerer.set_local_description(now, offer.clone()).ok()?;
        answerer.set_remote_description(now, offer).ok()?;
        let answer = answerer.create_answer(None).ok()?;
        answerer.set_local_description(now, answer.clone()).ok()?;
        offerer.set_remote_description(now, answer).ok()?;

        Some(Self {
            offerer: Peer {
                pc: offerer,
                addr: offerer_addr,
                channel: offerer_channel,
                open: false,
            },
            answerer: Peer {
                pc: answerer,
                addr: answerer_addr,
                channel: answerer_channel,
                open: false,
            },
            now,
        })
    }

    /// Delivers what each peer has sent to the other, until both are quiet (or a budget runs
    /// out), and drains both peers' events and reads.
    fn exchange(&mut self) {
        for _ in 0..64 {
            let mut moved = false;
            while let Some(msg) = self.offerer.pc.poll_write() {
                moved = true;
                if msg.transport.peer_addr == self.answerer.addr {
                    common::deliver(
                        &mut self.answerer.pc,
                        self.now,
                        self.offerer.addr,
                        self.answerer.addr,
                        &msg.message,
                    );
                }
            }
            while let Some(msg) = self.answerer.pc.poll_write() {
                moved = true;
                if msg.transport.peer_addr == self.offerer.addr {
                    common::deliver(
                        &mut self.offerer.pc,
                        self.now,
                        self.answerer.addr,
                        self.offerer.addr,
                        &msg.message,
                    );
                }
            }
            self.drain();
            if !moved {
                break;
            }
        }
    }

    fn drain(&mut self) {
        for peer in [&mut self.offerer, &mut self.answerer] {
            let channel = peer.channel;
            let mut opened = false;
            common::drain(&mut peer.pc, |event| {
                if let RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) =
                    event
                    && *id == channel
                {
                    opened = true;
                }
            });
            peer.open |= opened;
        }
    }

    /// Moves the clock to the next timer either peer asked for (at least 1 ms, at most `max`).
    fn tick(&mut self, max: Duration) {
        let floor = self.now + Duration::from_millis(1);
        let ceiling = self.now + max;
        let next = [
            self.offerer.pc.poll_timeout(),
            self.answerer.pc.poll_timeout(),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(ceiling)
        .clamp(floor, ceiling);
        self.now = next;
        let _ = self.offerer.pc.handle_timeout(self.now);
        let _ = self.answerer.pc.handle_timeout(self.now);
    }

    fn send(&mut self, from_answerer: bool, text: bool, arg: &[u8]) {
        let now = self.now;
        let peer = if from_answerer {
            &mut self.answerer
        } else {
            &mut self.offerer
        };
        let channel = peer.channel;
        if let Some(mut dc) = peer.pc.data_channel(channel) {
            if text {
                let _ = dc.send_text(now, String::from_utf8_lossy(arg).into_owned());
            } else {
                let _ = dc.send(now, BytesMut::from(arg));
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    if data.len() < 2 {
        return;
    }
    let config = data[0];
    // How many handshake steps run before the ops: 0 starts at once, 255 runs to completion.
    let steps = data[1];
    data = &data[2..];

    let Some(mut pair) = Pair::new(config) else {
        return;
    };
    let max_steps = if steps == 255 {
        2000
    } else {
        usize::from(steps) * 4
    };
    for _ in 0..max_steps {
        pair.exchange();
        if pair.offerer.open && pair.answerer.open {
            break;
        }
        pair.tick(Duration::from_millis(50));
    }

    let stray: SocketAddr = "198.51.100.7:7000".parse().unwrap();
    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        let (from, to) = (pair.offerer.addr, pair.answerer.addr);
        match op % 8 {
            // A datagram to the answerer from the offerer's address: the selected pair.
            0 | 1 => common::deliver(&mut pair.answerer.pc, pair.now, from, to, arg),
            // From an address that is not part of the connection.
            2 => common::deliver(&mut pair.answerer.pc, pair.now, stray, to, arg),
            // STUN-shaped: a Binding request header (fuzzed type bits), the magic cookie and a
            // transaction id, then the input as attributes.
            3 => {
                let mut message = vec![byte(arg, 0) & 0x3f, byte(arg, 1)];
                let attributes = arg.get(2..).unwrap_or(&[]);
                message.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
                message.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
                message.extend_from_slice(&[0x5a; 12]);
                message.extend_from_slice(attributes);
                let source = if op & 0x80 == 0 { from } else { stray };
                common::deliver(&mut pair.answerer.pc, pair.now, source, to, &message);
            }
            // A datagram to the offerer from the answerer's address.
            4 => common::deliver(&mut pair.offerer.pc, pair.now, to, from, arg),
            5 => pair.exchange(),
            6 => pair.send(op & 0x80 != 0, op & 0x40 != 0, arg),
            _ => pair.tick(Duration::from_millis(u64::from(byte(arg, 0)) * 20 + 1)),
        }
        pair.drain();
    }
    pair.exchange();
});
