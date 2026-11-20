//! Data channels over two real SCTP associations joined by an in-memory wire: the tests that
//! upstream (webrtc-rs/webrtc v0.17.1 `data/src/data_channel/data_channel_test.rs`) ran over a
//! tokio bridge, sans-I/O. Each side's wire holds the datagrams it sent and the other has not
//! received yet, so a test can drop or reorder them as upstream's bridge did, and time is
//! virtual. The glue between a `DataChannel` and its SCTP stream is what `rtc`'s SCTP handler
//! does: DCEP messages that configure the stream stay local, everything else is written.

use super::*;
use bytes::Bytes;
use sansio::Protocol;
use sctp::{
    Association, AssociationHandle, ClientConfig, DatagramEvent, Endpoint, EndpointConfig, Event,
    Payload, ServerConfig, StreamEvent, TransportConfig,
};
use shared::TransportProtocol;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Side {
    endpoint: Endpoint,
    addr: SocketAddr,
    conn: Option<(AssociationHandle, Association)>,
    connected: bool,
    channels: HashMap<u16, DataChannel>,
    /// Datagrams this side sent that the other has not received yet.
    wire: Vec<Bytes>,
    /// User messages delivered to this side's channels, in order.
    received: Vec<DataChannelMessage>,
    buffered_amount_low_events: usize,
}

impl Side {
    fn new(addr: SocketAddr, server: bool) -> Self {
        Side {
            endpoint: Endpoint::new(
                addr,
                TransportProtocol::UDP,
                Arc::new(EndpointConfig::default()),
                server.then(|| Arc::new(ServerConfig::new(TransportConfig::default()))),
            ),
            addr,
            conn: None,
            connected: false,
            channels: HashMap::new(),
            wire: vec![],
            received: vec![],
            buffered_amount_low_events: 0,
        }
    }

    fn handle(&self) -> usize {
        self.conn.as_ref().expect("association").0.0
    }

    fn conn(&mut self) -> &mut Association {
        &mut self.conn.as_mut().expect("association").1
    }

    fn receive(&mut self, now: Instant, from: SocketAddr, datagram: Bytes) {
        match self.endpoint.handle(now, from, None, datagram) {
            Some((ch, DatagramEvent::NewAssociation(conn))) => {
                if self.conn.is_none() {
                    self.conn = Some((ch, conn));
                }
            }
            Some((ch, DatagramEvent::AssociationEvent(event))) => {
                if let Some((own, conn)) = self.conn.as_mut()
                    && *own == ch
                {
                    conn.handle_event(event);
                }
            }
            _ => {}
        }
    }

    /// Applies one message a channel wrote to its SCTP stream.
    fn apply(&mut self, now: Instant, msg: DataChannelMessage) -> Result<()> {
        let id = msg.stream_id;
        let conn = self.conn();
        if conn.stream(id).is_err() {
            conn.open_stream(id, msg.ppi)?;
        }
        if msg.ppi == PayloadProtocolIdentifier::Dcep {
            match Message::unmarshal(&mut &msg.payload[..])? {
                Message::DataChannelOpen(open) => {
                    let (unordered, reliability) =
                        DataChannel::get_reliability_params(open.channel_type);
                    conn.stream(id)?.set_reliability_params(
                        unordered,
                        reliability,
                        open.reliability_parameter,
                    )?;
                    if msg.negotiated {
                        return Ok(());
                    }
                }
                Message::DataChannelThreshold(DataChannelThreshold::Low(threshold)) => {
                    return conn
                        .stream(id)?
                        .set_buffered_amount_low_threshold(threshold as usize);
                }
                Message::DataChannelThreshold(DataChannelThreshold::High(threshold)) => {
                    return conn
                        .stream(id)?
                        .set_buffered_amount_high_threshold(threshold as usize);
                }
                Message::DataChannelClose(_) => return conn.stream(id)?.close(now),
                _ => {}
            }
        }
        conn.stream(id)?
            .write_sctp(now, &msg.payload.freeze(), msg.ppi)?;
        Ok(())
    }

    /// Hands everything `stream_id`'s channel wrote to SCTP.
    fn flush_channel(&mut self, now: Instant, stream_id: u16) -> Result<()> {
        let mut out = vec![];
        if let Some(dc) = self.channels.get_mut(&stream_id) {
            while let Some(msg) = dc.poll_write() {
                out.push(msg);
            }
        }
        for msg in out {
            self.apply(now, msg)?;
        }
        Ok(())
    }

    /// A message read from SCTP: the peer's OPEN accepts a channel, the rest go to it.
    fn dispatch(
        &mut self,
        now: Instant,
        id: u16,
        ppi: PayloadProtocolIdentifier,
        payload: BytesMut,
    ) -> Result<()> {
        let handle = self.handle();
        if !self.channels.contains_key(&id) {
            let dc = DataChannel::accept(DataChannelConfig::default(), handle, id, ppi, &payload)?;
            // RFC 8832 5.1: the OPEN configures both directions of the channel.
            let (unordered, reliability) =
                DataChannel::get_reliability_params(dc.config.channel_type);
            let parameter = dc.config.reliability_parameter;
            self.conn()
                .stream(id)?
                .set_reliability_params(unordered, reliability, parameter)?;
            self.channels.insert(id, dc);
        } else if let Some(dc) = self.channels.get_mut(&id) {
            dc.handle_read(DataChannelMessage {
                association_handle: handle,
                stream_id: id,
                ppi,
                payload,
                negotiated: false,
            })?;
            while let Some(msg) = dc.poll_read() {
                self.received.push(msg);
            }
        }
        self.flush_channel(now, id)
    }

    /// Runs due timers, delivers readable messages, and puts what SCTP sends on the wire.
    fn service(&mut self, now: Instant) -> Result<()> {
        let mut inbound = vec![];
        let Some((_, conn)) = self.conn.as_mut() else {
            return Ok(());
        };
        if conn.poll_timeout().is_some_and(|at| at <= now) {
            conn.handle_timeout(now);
        }
        while let Some(event) = conn.poll() {
            match event {
                Event::Connected => self.connected = true,
                Event::Stream(StreamEvent::Readable { id }) => {
                    let mut stream = conn.stream(id)?;
                    while let Some(chunks) = stream.read_sctp()? {
                        inbound.push((id, chunks.ppi, chunks.to_payload(usize::MAX)?));
                    }
                }
                Event::Stream(StreamEvent::BufferedAmountLow { .. }) => {
                    self.buffered_amount_low_events += 1
                }
                _ => {}
            }
        }
        while conn.poll_endpoint_event().is_some() {}
        for (id, ppi, payload) in inbound {
            self.dispatch(now, id, ppi, payload)?;
        }
        let mut sent = Vec::new();
        let conn = self.conn();
        while let Some(transmit) = conn.poll_transmit(now) {
            if let Payload::RawEncode(datagrams) = transmit.message {
                sent.extend(datagrams);
            }
        }
        self.wire.extend(sent);
        Ok(())
    }

    fn next_timeout(&self) -> Option<Instant> {
        self.conn.as_ref().and_then(|(_, c)| c.poll_timeout())
    }
}

/// `a` dials (the SCTP client), `b` accepts.
struct Pair {
    a: Side,
    b: Side,
    now: Instant,
}

impl Pair {
    fn new() -> Result<Self> {
        let mut pair = Pair {
            a: Side::new(SocketAddr::from(([10, 0, 0, 1], 5000)), false),
            b: Side::new(SocketAddr::from(([10, 0, 0, 2], 5000)), true),
            now: Instant::now(),
        };
        let (ch, conn) = pair
            .a
            .endpoint
            .connect(
                pair.now,
                ClientConfig::new(TransportConfig::default()),
                pair.b.addr,
            )
            .map_err(|e| Error::Other(e.to_string()))?;
        pair.a.conn = Some((ch, conn));
        pair.settle()?;
        assert!(pair.a.connected && pair.b.connected, "SCTP handshake");
        Ok(pair)
    }

    /// Lets both sides put what they have to send on their wires, without delivering it.
    fn flush(&mut self) -> Result<()> {
        self.a.service(self.now)?;
        self.b.service(self.now)
    }

    /// Delivers what is on the wires and lets both sides answer, until nothing moves.
    fn settle(&mut self) -> Result<()> {
        for _ in 0..10_000 {
            self.flush()?;
            if self.a.wire.is_empty() && self.b.wire.is_empty() {
                return Ok(());
            }
            let (now, a_addr, b_addr) = (self.now, self.a.addr, self.b.addr);
            for d in std::mem::take(&mut self.a.wire) {
                self.b.receive(now, a_addr, d);
            }
            for d in std::mem::take(&mut self.b.wire) {
                self.a.receive(now, b_addr, d);
            }
        }
        panic!("the pair never settled");
    }

    /// Settles, then lets virtual time run to `duration` from now, firing timers as it goes.
    fn run_for(&mut self, duration: Duration) -> Result<()> {
        let deadline = self.now + duration;
        loop {
            self.settle()?;
            let next = match (self.a.next_timeout(), self.b.next_timeout()) {
                (Some(x), Some(y)) => Some(x.min(y)),
                (x, y) => x.or(y),
            };
            match next {
                Some(at) if at <= deadline => self.now = self.now.max(at),
                _ => break,
            }
        }
        self.now = deadline;
        Ok(())
    }

    fn dial(&mut self, config: DataChannelConfig, stream_id: u16) -> Result<()> {
        let dc = DataChannel::dial(config, self.a.handle(), stream_id)?;
        self.a.channels.insert(stream_id, dc);
        self.a.flush_channel(self.now, stream_id)?;
        // Long enough for the delayed SACKs, so nothing of the handshake stays buffered.
        self.run_for(Duration::from_millis(500))
    }

    /// Writes one user message on `a`'s channel and hands it to SCTP (not to the wire).
    fn write(&mut self, stream_id: u16, data: &[u8], is_string: bool) -> Result<()> {
        let dc = self.a.channels.get_mut(&stream_id).expect("channel");
        dc.handle_write(DataChannel::get_data_channel_message(
            is_string,
            BytesMut::from(data),
        ))?;
        self.a.flush_channel(self.now, stream_id)
    }

    fn a_buffered_amount(&mut self, stream_id: u16) -> Result<usize> {
        self.a.conn().stream(stream_id)?.buffered_amount()
    }
}

fn numbered(i: u32) -> Vec<u8> {
    let mut sbuf = vec![0u8; 1000];
    sbuf[..4].copy_from_slice(&i.to_be_bytes());
    sbuf
}

fn numbers(received: &[DataChannelMessage]) -> Vec<u32> {
    received
        .iter()
        .map(|m| {
            assert_eq!(1000, m.payload.len(), "data length should match");
            u32::from_be_bytes([m.payload[0], m.payload[1], m.payload[2], m.payload[3]])
        })
        .collect()
}

fn config(channel_type: ChannelType, reliability_parameter: u32) -> DataChannelConfig {
    DataChannelConfig {
        channel_type,
        reliability_parameter,
        label: "data".to_string(),
        ..Default::default()
    }
}

/// Upstream's `pr_ordered_unordered_test`: the first message is lost on the wire and, being
/// partially reliable with no retransmission (or no lifetime), abandoned and skipped by FORWARD
/// TSN (RFC 3758). Unordered, the other two are reordered on the wire and arrive in that order.
fn pr_ordered_unordered_test(channel_type: ChannelType, is_ordered: bool) -> Result<()> {
    let mut pair = Pair::new()?;
    let cfg = config(channel_type, 0);
    pair.dial(cfg.clone(), 100)?;
    assert_eq!(
        cfg, pair.a.channels[&100].config,
        "local config should match"
    );
    assert_eq!(
        cfg, pair.b.channels[&100].config,
        "remote config should match"
    );

    let count = if is_ordered { 2 } else { 3 };
    for i in 1..=count {
        pair.write(100, &numbered(i), true)?;
    }
    pair.flush()?;
    assert_eq!(
        count as usize,
        pair.a.wire.len(),
        "one message per datagram"
    );
    pair.a.wire.remove(0); // drop the first packet on the wire
    if !is_ordered {
        pair.a.wire.reverse(); // reorder the rest
    }
    // Abandonment waits for T3-rtx (RTO 1 s): there are too few SACKs for fast retransmit.
    pair.run_for(Duration::from_secs(5))?;

    let expected = if is_ordered { vec![2] } else { vec![3, 2] };
    assert_eq!(expected, numbers(&pair.b.received));
    assert!(
        pair.b
            .received
            .iter()
            .all(|m| m.ppi == PayloadProtocolIdentifier::String),
        "should return isString being true"
    );
    Ok(())
}

#[test]
fn test_data_channel_channel_type_reliable_unordered() -> Result<()> {
    let mut pair = Pair::new()?;
    let cfg = config(ChannelType::ReliableUnordered, 123);
    pair.dial(cfg.clone(), 100)?;
    assert_eq!(
        cfg, pair.a.channels[&100].config,
        "local config should match"
    );
    assert_eq!(
        cfg, pair.b.channels[&100].config,
        "remote config should match"
    );

    pair.write(100, &numbered(1), true)?;
    pair.write(100, &numbered(2), true)?;
    pair.flush()?;
    assert_eq!(2, pair.a.wire.len());
    pair.a.wire.reverse(); // reordering on the wire
    pair.settle()?;

    assert_eq!(vec![2, 1], numbers(&pair.b.received));
    Ok(())
}

#[test]
fn test_data_channel_channel_type_partial_reliable_rexmit() -> Result<()> {
    pr_ordered_unordered_test(ChannelType::PartialReliableRexmit, true)
}

#[test]
fn test_data_channel_channel_type_partial_reliable_rexmit_unordered() -> Result<()> {
    pr_ordered_unordered_test(ChannelType::PartialReliableRexmitUnordered, false)
}

#[test]
fn test_data_channel_channel_type_partial_reliable_timed() -> Result<()> {
    pr_ordered_unordered_test(ChannelType::PartialReliableTimed, true)
}

#[test]
fn test_data_channel_channel_type_partial_reliable_timed_unordered() -> Result<()> {
    pr_ordered_unordered_test(ChannelType::PartialReliableTimedUnordered, false)
}

#[test]
fn test_data_channel_buffered_amount() -> Result<()> {
    let mut pair = Pair::new()?;
    pair.dial(config(ChannelType::Reliable, 0), 100)?;
    assert_eq!(0, pair.a_buffered_amount(100)?);

    // An empty message is one placeholder byte on the wire (RFC 8831 6.6).
    pair.write(100, &[], false)?;
    assert_eq!(1, pair.a_buffered_amount(100)?, "incorrect bufferedAmount");
    pair.write(100, &[0], false)?;
    assert_eq!(2, pair.a_buffered_amount(100)?, "incorrect bufferedAmount");
    pair.run_for(Duration::from_millis(500))?;
    assert_eq!(2, pair.b.received.len());
    assert_eq!(
        PayloadProtocolIdentifier::BinaryEmpty,
        pair.b.received[0].ppi
    );
    assert_eq!(&[0][..], &pair.b.received[1].payload[..]);
    assert_eq!(0, pair.a_buffered_amount(100)?, "acknowledged");

    pair.a
        .channels
        .get_mut(&100)
        .unwrap()
        .set_buffered_amount_low_threshold(1500)?;
    pair.a.flush_channel(pair.now, 100)?;
    assert_eq!(
        1500,
        pair.a.conn().stream(100)?.buffered_amount_low_threshold()?,
        "incorrect bufferedAmountLowThreshold"
    );

    // Write 10 1000-byte messages (10,000 bytes in all).
    for i in 0..10 {
        pair.write(100, &[0u8; 1000], false)?;
        assert_eq!(1000 * (i + 1), pair.a_buffered_amount(100)?);
    }
    pair.run_for(Duration::from_millis(500))?;

    assert_eq!(12, pair.b.received.len());
    assert_eq!(0, pair.a_buffered_amount(100)?);
    assert!(
        pair.a.buffered_amount_low_events > 0,
        "should make at least one callback"
    );
    Ok(())
}

#[test]
fn test_stats() -> Result<()> {
    let mut pair = Pair::new()?;
    pair.dial(config(ChannelType::Reliable, 123), 100)?;
    let sbuf = vec![0u8; 1000];

    let mut bytes_sent = 0;
    for (i, data) in [&sbuf[..], &sbuf[..], &[0][..], &[][..]]
        .into_iter()
        .enumerate()
    {
        pair.write(100, data, false)?;
        bytes_sent += data.len();
        let dc0 = &pair.a.channels[&100];
        assert_eq!(bytes_sent, dc0.bytes_sent());
        assert_eq!(i + 1, dc0.messages_sent());
    }
    pair.settle()?;

    let dc1 = &pair.b.channels[&100];
    assert_eq!(bytes_sent, dc1.bytes_received());
    assert_eq!(4, dc1.messages_received());
    Ok(())
}

/// Upstream's `PollDataChannel` is the async adapter; a channel's own `handle_write` and
/// `poll_read` are the same calls here.
#[test]
fn test_poll_data_channel() -> Result<()> {
    let mut pair = Pair::new()?;
    pair.dial(config(ChannelType::Reliable, 123), 100)?;

    pair.write(100, &numbered(1), false)?;
    pair.settle()?;
    assert_eq!(vec![1], numbers(&pair.b.received));
    Ok(())
}
