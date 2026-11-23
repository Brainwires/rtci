use super::*;

/// A small deterministic generator, so every segmentation a test uses is reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// 1 ..= max
    fn size(&mut self, max: usize) -> usize {
        1 + (self.next() as usize) % max
    }
}

/// Cuts `bytes` into pieces of random sizes up to `max`.
fn segment(bytes: &[u8], rng: &mut XorShift, max: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let n = rng.size(max).min(rest.len());
        out.push(rest[..n].to_vec());
        rest = &rest[n..];
    }
    out
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A connection the table asked for and the driver established.
fn connected(table: &mut StreamTable, framing: Framing) -> StreamId {
    let id = table
        .connect(
            addr("10.0.0.1:0"),
            addr("10.0.0.2:5000"),
            framing,
            7,
            false,
            None,
        )
        .unwrap();
    table
        .handle_event(StreamEvent::Connected {
            id,
            local: addr("10.0.0.1:40001"),
        })
        .unwrap();
    while table.poll_command().is_some() {}
    while table.poll_notice().is_some() {}
    id
}

/// Everything the table hands out, reported written at once.
fn drain_transmits(table: &mut StreamTable) -> Vec<StreamTransmit> {
    let mut out = Vec::new();
    while let Some(t) = table.poll_transmit() {
        table
            .handle_event(StreamEvent::Written {
                id: t.id,
                bytes: t.data.len(),
            })
            .unwrap();
        out.push(t);
    }
    out
}

/// Messages of every interesting size: empty, one byte, a DTLS-record size and the largest
/// RFC 4571 frame.
fn sample_messages(rng: &mut XorShift) -> Vec<Vec<u8>> {
    let mut messages = vec![vec![], vec![0x42], vec![0x17; 1200], vec![0x99; 65535]];
    for _ in 0..200 {
        let len = rng.size(3000);
        messages.push((0..len).map(|i| (i as u8) ^ (len as u8)).collect());
    }
    messages
}

#[test]
fn rfc4571_messages_survive_any_segmentation() {
    let mut rng = XorShift(0x1234_5678_9abc_def0);
    let messages = sample_messages(&mut rng);
    let mut wire = Vec::new();
    for m in &messages {
        wire.extend(Framing::Rfc4571.encode(m).unwrap());
    }
    for max_piece in [1, 2, 3, 7, 100, 1500, 70_000, 300_000] {
        let mut table = StreamTable::default();
        let id = connected(&mut table, Framing::Rfc4571);
        let mut received = Vec::new();
        for piece in segment(&wire, &mut rng, max_piece) {
            received.extend(table.read(id, &piece).unwrap());
        }
        assert_eq!(received, messages, "pieces of up to {max_piece} bytes");
        assert_eq!(
            table.info(id).unwrap().messages_received,
            messages.len() as u64
        );
    }
}

#[test]
fn a_read_of_many_frames_at_once_is_not_refused() {
    // Far more than the decoder's two-frame bound in one read.
    let mut table = StreamTable::default();
    let id = connected(&mut table, Framing::Rfc4571);
    let mut wire = Vec::new();
    for _ in 0..40 {
        wire.extend(Framing::Rfc4571.encode(&[5u8; 65535]).unwrap());
    }
    assert_eq!(table.read(id, &wire).unwrap().len(), 40);
}

#[test]
fn sent_messages_come_out_framed_in_order_and_decode_back() {
    let mut rng = XorShift(99);
    let messages = sample_messages(&mut rng);
    let mut table = StreamTable::default();
    let id = connected(&mut table, Framing::Rfc4571);
    let mut wire = Vec::new();
    for m in &messages {
        assert!(table.send(id, m).unwrap());
        // The driver takes transmits as they come.
        for t in drain_transmits(&mut table) {
            assert_eq!(t.id, id);
            wire.extend(t.data);
        }
    }
    let mut decoder = StreamDecoder::new(Framing::Rfc4571);
    let mut decoded = Vec::new();
    for piece in segment(&wire, &mut rng, 4096) {
        decoded.extend(decoder.decode(&piece).unwrap());
    }
    assert_eq!(decoded, messages);
}

#[test]
fn a_message_over_65535_bytes_is_refused_for_rfc4571() {
    let mut table = StreamTable::default();
    let id = connected(&mut table, Framing::Rfc4571);
    assert_eq!(
        table.send(id, &vec![0; 65536]),
        Err(Error::ErrStreamMessageTooLong)
    );
    assert!(table.poll_transmit().is_none());
}

/// A STUN message header with `length` bytes of attributes.
fn stun(length: u16, fill: u8) -> Vec<u8> {
    let mut m = vec![0x01, 0x01];
    m.extend_from_slice(&length.to_be_bytes());
    m.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    m.extend_from_slice(&[fill; 12]);
    m.extend(std::iter::repeat_n(fill, length as usize));
    m
}

/// A ChannelData message, padded to a multiple of four.
fn channel_data(data: &[u8]) -> Vec<u8> {
    let mut m = vec![0x40, 0x01];
    m.extend_from_slice(&(data.len() as u16).to_be_bytes());
    m.extend_from_slice(data);
    while m.len() % 4 != 0 {
        m.push(0);
    }
    m
}

#[test]
fn turn_messages_survive_any_segmentation() {
    let mut rng = XorShift(7);
    let mut messages = Vec::new();
    for i in 0..300u16 {
        if i % 3 == 0 {
            messages.push(stun((i % 40) * 4, i as u8));
        } else {
            let len = rng.size(1500);
            messages.push(channel_data(&vec![i as u8; len]));
        }
    }
    let wire: Vec<u8> = messages.concat();
    for max_piece in [1, 3, 5, 64, 2000, 1_000_000] {
        let mut table = StreamTable::default();
        let id = connected(&mut table, Framing::Turn);
        let mut received = Vec::new();
        for piece in segment(&wire, &mut rng, max_piece) {
            received.extend(table.read(id, &piece).unwrap());
        }
        assert_eq!(received, messages, "pieces of up to {max_piece} bytes");
    }
}

#[test]
fn bytes_that_are_not_turn_reset_the_connection() {
    let mut table = StreamTable::default();
    let id = connected(&mut table, Framing::Turn);
    assert!(table.read(id, &[0xc0, 0, 0, 4, 1, 2, 3, 4]).is_err());
    assert_eq!(table.poll_command(), Some(StreamCommand::Reset { id }));
    assert!(matches!(
        table.poll_notice(),
        Some(StreamNotice::Closed { id: closed, reset: true, .. }) if closed == id
    ));
    assert!(table.info(id).is_none());
    assert_eq!(table.send(id, b"x"), Err(Error::ErrUnknownStream));
}

#[test]
fn nothing_is_handed_out_before_the_connection_is_established() {
    let mut table = StreamTable::default();
    let id = table
        .connect(
            addr("10.0.0.1:0"),
            addr("10.0.0.2:5000"),
            Framing::Rfc4571,
            1,
            false,
            None,
        )
        .unwrap();
    assert!(table.send(id, b"early").unwrap());
    assert!(table.poll_transmit().is_none());
    assert_eq!(table.info(id).unwrap().state, StreamState::Connecting);
    table
        .handle_event(StreamEvent::Connected {
            id,
            local: addr("10.0.0.1:40000"),
        })
        .unwrap();
    assert!(matches!(
        table.poll_notice(),
        Some(StreamNotice::Connected { tag: 1, .. })
    ));
    assert_eq!(table.info(id).unwrap().local, addr("10.0.0.1:40000"));
    assert_eq!(table.poll_transmit().unwrap().data, b"\x00\x05early");
}

#[test]
fn a_failed_connection_is_reported_with_its_requested_addresses_and_forgotten() {
    let mut table = StreamTable::default();
    let id = table
        .connect(
            addr("10.0.0.1:0"),
            addr("10.0.0.2:5000"),
            Framing::Rfc4571,
            3,
            false,
            None,
        )
        .unwrap();
    table.send(id, b"lost").unwrap();
    table
        .handle_event(StreamEvent::ConnectFailed { id })
        .unwrap();
    assert_eq!(
        table.poll_notice(),
        Some(StreamNotice::ConnectFailed {
            id,
            tag: 3,
            local: addr("10.0.0.1:0"),
            remote: addr("10.0.0.2:5000"),
        })
    );
    assert!(table.info(id).is_none());
    assert!(table.poll_transmit().is_none());
}

#[test]
fn the_window_bounds_what_the_driver_holds_and_written_reopens_it() {
    let config = StreamConfig {
        window: 3000,
        max_queued: 1 << 20,
        ..StreamConfig::default()
    };
    let mut table = StreamTable::new(config);
    let id = connected(&mut table, Framing::Rfc4571);
    for _ in 0..10 {
        assert!(table.send(id, &[1u8; 998]).unwrap()); // 1000 bytes framed
    }
    // Three frames fit in the window, coalesced into one transmit.
    let first = table.poll_transmit().unwrap();
    assert_eq!(first.data.len(), 3000);
    assert!(table.poll_transmit().is_none(), "the window is full");
    assert_eq!(table.info(id).unwrap().in_flight, 3000);
    // Part of it written: one more frame fits.
    table
        .handle_event(StreamEvent::Written { id, bytes: 1000 })
        .unwrap();
    assert_eq!(table.poll_transmit().unwrap().data.len(), 1000);
    assert!(table.poll_transmit().is_none());
    table
        .handle_event(StreamEvent::Written { id, bytes: 3000 })
        .unwrap();
    let rest: usize = drain_transmits(&mut table)
        .iter()
        .map(|t| t.data.len())
        .sum();
    assert_eq!(rest, 6000);
}

#[test]
fn one_transmit_is_allowed_even_when_a_frame_exceeds_the_window() {
    let config = StreamConfig {
        window: 10,
        ..StreamConfig::default()
    };
    let mut table = StreamTable::new(config);
    let id = connected(&mut table, Framing::Rfc4571);
    table.send(id, &[0u8; 100]).unwrap();
    table.send(id, &[0u8; 100]).unwrap();
    assert_eq!(table.poll_transmit().unwrap().data.len(), 102);
    assert!(table.poll_transmit().is_none());
}

#[test]
fn a_full_queue_drops_whole_messages_and_keeps_the_framing_intact() {
    let config = StreamConfig {
        window: 1000,
        max_queued: 5000,
        ..StreamConfig::default()
    };
    let mut table = StreamTable::new(config);
    let id = connected(&mut table, Framing::Rfc4571);
    let mut accepted = Vec::new();
    for i in 0..20u8 {
        let message = vec![i; 998];
        if table.send(id, &message).unwrap() {
            accepted.push(message);
        }
    }
    // The driver is stalled: nothing was taken, so five frames fit.
    assert_eq!(accepted.len(), 5);
    assert_eq!(table.info(id).unwrap().messages_dropped, 15);
    // Draining makes room again.
    let mut wire: Vec<u8> = drain_transmits(&mut table)
        .into_iter()
        .flat_map(|t| t.data)
        .collect();
    assert!(table.send(id, &[99u8; 998]).unwrap());
    accepted.push(vec![99u8; 998]);
    wire.extend(drain_transmits(&mut table).into_iter().flat_map(|t| t.data));
    let decoded = StreamDecoder::new(Framing::Rfc4571).decode(&wire).unwrap();
    assert_eq!(decoded, accepted, "only whole frames on the wire");
}

#[test]
fn close_comes_after_the_last_transmit() {
    let config = StreamConfig {
        window: 1000,
        ..StreamConfig::default()
    };
    let mut table = StreamTable::new(config);
    let id = connected(&mut table, Framing::Rfc4571);
    for _ in 0..3 {
        table.send(id, &[0u8; 998]).unwrap();
    }
    table.close(id);
    assert_eq!(
        table.send(id, b"late"),
        Err(Error::ErrStreamConnectionClosed)
    );
    let mut order = Vec::new();
    loop {
        if let Some(t) = table.poll_transmit() {
            order.push(format!("data {}", t.data.len()));
            table
                .handle_event(StreamEvent::Written {
                    id,
                    bytes: t.data.len(),
                })
                .unwrap();
            continue;
        }
        match table.poll_command() {
            Some(StreamCommand::Close { id: closed }) if closed == id => order.push("close".into()),
            Some(other) => panic!("unexpected {other:?}"),
            None => break,
        }
    }
    assert_eq!(order, ["data 1000", "data 1000", "data 1000", "close"]);
    // The driver reports the close done.
    table.handle_event(StreamEvent::Closed { id }).unwrap();
    assert!(table.info(id).is_none());
}

#[test]
fn closing_a_connection_that_is_still_connecting_resets_it() {
    let mut table = StreamTable::default();
    let id = table
        .connect(
            addr("10.0.0.1:0"),
            addr("10.0.0.2:1"),
            Framing::Rfc4571,
            0,
            false,
            None,
        )
        .unwrap();
    assert!(matches!(
        table.poll_command(),
        Some(StreamCommand::Connect { .. })
    ));
    table.close(id);
    assert_eq!(table.poll_command(), Some(StreamCommand::Reset { id }));
    assert!(table.info(id).is_none());
}

#[test]
fn a_peer_reset_is_reported_and_the_id_forgotten() {
    let mut table = StreamTable::default();
    let id = connected(&mut table, Framing::Rfc4571);
    table.send(id, b"pending").unwrap();
    table.handle_event(StreamEvent::Reset { id }).unwrap();
    assert!(matches!(
        table.poll_notice(),
        Some(StreamNotice::Closed {
            reset: true,
            tag: 7,
            ..
        })
    ));
    assert!(table.poll_transmit().is_none());
    assert_eq!(table.read(id, b"x"), Err(Error::ErrUnknownStream));
    // The driver's own Reset for it, crossing ours, is ignored.
    table.handle_event(StreamEvent::Reset { id }).unwrap();
    assert!(table.poll_notice().is_none());
}

#[test]
fn a_peer_close_is_reported_as_closed_not_reset() {
    let mut table = StreamTable::default();
    let id = connected(&mut table, Framing::Rfc4571);
    table.handle_event(StreamEvent::Closed { id }).unwrap();
    assert!(matches!(
        table.poll_notice(),
        Some(StreamNotice::Closed { reset: false, .. })
    ));
    assert!(table.poll_command().is_none(), "nothing to tell the driver");
}

#[test]
fn listeners_report_their_bound_address_and_accept_with_their_framing_and_tag() {
    let mut table = StreamTable::default();
    let listener = table.listen(addr("10.0.0.2:0"), Framing::Rfc4571, 9, false);
    assert_eq!(
        table.poll_command(),
        Some(StreamCommand::Listen {
            listener,
            local: addr("10.0.0.2:0"),
            reuse_address: false
        })
    );
    assert_eq!(table.listener_address(listener), None);
    table
        .handle_event(StreamEvent::Listening {
            listener,
            local: addr("10.0.0.2:5000"),
        })
        .unwrap();
    assert_eq!(
        table.poll_notice(),
        Some(StreamNotice::Listening {
            listener,
            tag: 9,
            local: addr("10.0.0.2:5000")
        })
    );
    let id = table
        .accept(listener, addr("10.0.0.2:5000"), addr("10.0.0.1:40001"))
        .unwrap();
    let info = table.info(id).unwrap();
    assert_eq!(
        (info.tag, info.origin, info.state, info.framing),
        (
            9,
            StreamOrigin::Accepted(listener),
            StreamState::Open,
            Framing::Rfc4571
        )
    );
    // An accepted connection can send at once.
    table.send(id, b"hi").unwrap();
    assert_eq!(table.poll_transmit().unwrap().data, b"\x00\x02hi");
    // Stopping the listener keeps its connections.
    table.stop_listening(listener);
    assert_eq!(
        table.poll_command(),
        Some(StreamCommand::StopListening { listener })
    );
    assert!(table.info(id).is_some());
    assert!(
        table
            .accept(listener, addr("10.0.0.2:5000"), addr("10.0.0.1:40002"))
            .is_none(),
        "no accept on a stopped listener"
    );
}

#[test]
fn a_listener_that_fails_is_reported_and_forgotten() {
    let mut table = StreamTable::default();
    let listener = table.listen(addr("10.0.0.2:0"), Framing::Rfc4571, 4, false);
    table
        .handle_event(StreamEvent::ListenFailed { listener })
        .unwrap();
    assert_eq!(
        table.poll_notice(),
        Some(StreamNotice::ListenFailed {
            listener,
            tag: 4,
            requested: addr("10.0.0.2:0")
        })
    );
    assert_eq!(table.listeners().count(), 0);
}

#[test]
fn accepts_beyond_the_connection_limit_are_refused() {
    let config = StreamConfig {
        max_connections: 2,
        ..StreamConfig::default()
    };
    let mut table = StreamTable::new(config);
    let listener = table.listen(addr("10.0.0.2:5000"), Framing::Rfc4571, 0, false);
    let local = addr("10.0.0.2:5000");
    assert!(table.accept(listener, local, addr("10.0.0.9:1")).is_some());
    assert!(table.accept(listener, local, addr("10.0.0.9:2")).is_some());
    assert!(table.accept(listener, local, addr("10.0.0.9:3")).is_none());
    assert_eq!(
        table.connect(
            addr("10.0.0.2:0"),
            addr("10.0.0.9:4"),
            Framing::Rfc4571,
            0,
            false,
            None
        ),
        Err(Error::ErrBufferFull)
    );
}

#[test]
fn find_matches_an_active_candidate_by_ip_and_prefers_established_connections() {
    let mut table = StreamTable::default();
    let remote = addr("10.0.0.2:5000");
    let connecting = table
        .connect(addr("10.0.0.1:0"), remote, Framing::Rfc4571, 1, false, None)
        .unwrap();
    let open = table
        .connect(addr("10.0.0.1:0"), remote, Framing::Rfc4571, 1, false, None)
        .unwrap();
    table
        .handle_event(StreamEvent::Connected {
            id: open,
            local: addr("10.0.0.1:40007"),
        })
        .unwrap();
    // RFC 6544 active candidates signal port 9: any port on the IP matches.
    assert_eq!(table.find(1, addr("10.0.0.1:9"), remote, true), Some(open));
    // Exactly, only the bound address (or a connecting one's requested address) matches.
    assert_eq!(
        table.find(1, addr("10.0.0.1:40007"), remote, false),
        Some(open)
    );
    assert_eq!(
        table.find(1, addr("10.0.0.1:0"), remote, false),
        Some(connecting)
    );
    assert_eq!(table.find(1, addr("10.0.0.1:9"), remote, false), None);
    // Another owner's tag, or a closing connection, is not found.
    assert_eq!(table.find(2, addr("10.0.0.1:9"), remote, true), None);
    table.close(open);
    assert_eq!(
        table.find(1, addr("10.0.0.1:9"), remote, true),
        Some(connecting)
    );
}

#[test]
fn connections_take_turns_transmitting() {
    let config = StreamConfig {
        window: 100,
        ..StreamConfig::default()
    };
    let mut table = StreamTable::new(config);
    let a = connected(&mut table, Framing::Rfc4571);
    let b = connected(&mut table, Framing::Rfc4571);
    for _ in 0..3 {
        table.send(a, &[0; 98]).unwrap();
        table.send(b, &[0; 98]).unwrap();
    }
    let order: Vec<StreamId> = drain_transmits(&mut table).iter().map(|t| t.id).collect();
    assert_eq!(order, [a, b, a, b, a, b]);
}

/// A stand-in for TLS: a one-byte handshake each way (0x16 out, 0x16 back), then every byte
/// XOR 0x5a, and 0x15 as `close_notify`.
struct ToyLayer {
    hello_sent: bool,
    established: bool,
    peer_closed: bool,
    plaintext: Vec<u8>,
    wire: Vec<u8>,
}

impl ToyLayer {
    fn new() -> Self {
        Self {
            hello_sent: false,
            established: false,
            peer_closed: false,
            plaintext: Vec::new(),
            wire: Vec::new(),
        }
    }
}

impl StreamLayer for ToyLayer {
    fn receive(&mut self, data: &[u8]) -> Result<()> {
        for &byte in data {
            if !self.established {
                if byte != 0x16 {
                    return Err(Error::Other("bad handshake".into()));
                }
                self.established = true;
            } else if byte == 0x15 ^ 0x5a {
                self.peer_closed = true;
            } else {
                self.plaintext.push(byte ^ 0x5a);
            }
        }
        Ok(())
    }
    fn read_plaintext(&mut self, out: &mut Vec<u8>) -> Result<()> {
        out.append(&mut self.plaintext);
        Ok(())
    }
    fn is_established(&self) -> bool {
        self.established
    }
    fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        assert!(self.established, "plaintext before the handshake");
        self.wire.extend(plaintext.iter().map(|b| b ^ 0x5a));
        Ok(())
    }
    fn write_wire(&mut self, out: &mut Vec<u8>) -> Result<()> {
        if !self.hello_sent {
            self.hello_sent = true;
            out.push(0x16);
        }
        out.append(&mut self.wire);
        Ok(())
    }
    fn close(&mut self) {
        self.wire.push(0x15 ^ 0x5a);
    }
    fn peer_closed(&self) -> bool {
        self.peer_closed
    }
}

#[test]
fn a_layer_sends_its_handshake_first_and_messages_wait_for_it() {
    let mut table = StreamTable::default();
    let id = table
        .connect(
            addr("10.0.0.1:0"),
            addr("203.0.113.10:5349"),
            Framing::Turn,
            2,
            false,
            Some(Box::new(ToyLayer::new())),
        )
        .unwrap();
    assert!(matches!(
        table.poll_command(),
        Some(StreamCommand::Connect { .. })
    ));
    let message = channel_data(b"relayed");
    assert!(table.send(id, &message).unwrap());
    table
        .handle_event(StreamEvent::Connected {
            id,
            local: addr("10.0.0.1:40000"),
        })
        .unwrap();
    // Only the hello: the message waits for the handshake.
    assert_eq!(drain_transmits(&mut table).concat_data(), vec![0x16]);
    // The server's handshake arrives, then a message of its own, byte by byte.
    let mut received = Vec::new();
    received.extend(table.read(id, &[0x16]).unwrap());
    let reply = channel_data(b"back");
    for byte in &reply {
        received.extend(table.read(id, &[byte ^ 0x5a]).unwrap());
    }
    assert_eq!(received, vec![reply]);
    // The waiting message went out encrypted.
    let wire = drain_transmits(&mut table).concat_data();
    let plain: Vec<u8> = wire.iter().map(|b| b ^ 0x5a).collect();
    assert_eq!(plain, message);
    // The peer's close_notify closes the connection in order.
    table.read(id, &[0x15 ^ 0x5a]).unwrap();
    let wire = drain_transmits(&mut table).concat_data();
    assert_eq!(wire, vec![0x15 ^ 0x5a], "our close_notify");
    assert_eq!(table.poll_command(), Some(StreamCommand::Close { id }));
}

#[test]
fn a_layer_error_resets_the_connection() {
    let mut table = StreamTable::default();
    let id = table
        .connect(
            addr("10.0.0.1:0"),
            addr("203.0.113.10:5349"),
            Framing::Turn,
            2,
            false,
            Some(Box::new(ToyLayer::new())),
        )
        .unwrap();
    table
        .handle_event(StreamEvent::Connected {
            id,
            local: addr("10.0.0.1:40000"),
        })
        .unwrap();
    while table.poll_command().is_some() {}
    assert!(table.read(id, &[0x00]).is_err());
    assert_eq!(table.poll_command(), Some(StreamCommand::Reset { id }));
}

trait ConcatData {
    fn concat_data(self) -> Vec<u8>;
}

impl ConcatData for Vec<StreamTransmit> {
    fn concat_data(self) -> Vec<u8> {
        self.into_iter().flat_map(|t| t.data).collect()
    }
}

#[test]
fn events_for_unknown_ids_are_ignored() {
    let mut table = StreamTable::default();
    for event in [
        StreamEvent::Connected {
            id: StreamId(42),
            local: addr("10.0.0.1:1"),
        },
        StreamEvent::ConnectFailed { id: StreamId(42) },
        StreamEvent::Written {
            id: StreamId(42),
            bytes: 10,
        },
        StreamEvent::Closed { id: StreamId(42) },
        StreamEvent::Reset { id: StreamId(42) },
        StreamEvent::Listening {
            listener: ListenerId(42),
            local: addr("10.0.0.1:1"),
        },
        StreamEvent::ListenFailed {
            listener: ListenerId(42),
        },
    ] {
        table.handle_event(event).unwrap();
    }
    assert!(table.poll_notice().is_none());
    assert!(table.poll_command().is_none());
}

#[test]
fn ids_are_never_reused() {
    let mut table = StreamTable::default();
    let a = connected(&mut table, Framing::Rfc4571);
    table.reset(a);
    let b = connected(&mut table, Framing::Rfc4571);
    assert_ne!(a, b);
}
