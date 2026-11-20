//! RFC 3550 6.1: every compound RTCP packet carries an SDES CNAME after its leading report.

use super::*;
use interceptor::{AttributedPacket, StreamInfo};
use rtcp::reception_report::ReceptionReport;
use sansio::Protocol;
use shared::TransportContext;

/// Hands out on `poll_write` whatever it was given on `handle_write`.
#[derive(Default)]
struct QueueChain {
    writes: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for QueueChain {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, _: TaggedPacket) -> Result<()> {
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        None
    }
    fn handle_write(&mut self, msg: TaggedPacket) -> Result<()> {
        self.writes.push_back(msg);
        Ok(())
    }
    fn poll_write(&mut self) -> Option<TaggedPacket> {
        self.writes.pop_front()
    }
    fn handle_event(&mut self, _: ()) -> Result<()> {
        Ok(())
    }
    fn poll_event(&mut self) -> Option<()> {
        None
    }
    fn handle_timeout(&mut self, _: Instant) -> Result<()> {
        Ok(())
    }
    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Interceptor for QueueChain {
    fn bind_local_stream(&mut self, _: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _: &StreamInfo) {}
}

fn rtcp(packets: Vec<Box<dyn rtcp::Packet>>) -> TaggedPacket {
    TaggedPacket {
        now: Instant::now(),
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(packets)),
    }
}

fn receiver_report(ssrc: u32) -> Box<dyn rtcp::Packet> {
    Box::new(ReceiverReport {
        ssrc,
        reports: vec![ReceptionReport {
            ssrc: 99,
            ..Default::default()
        }],
        ..Default::default()
    })
}

/// Run `packets` out through an interceptor handler past the handshake.
fn written(packets: Vec<TaggedPacket>) -> Vec<Vec<Box<dyn rtcp::Packet>>> {
    let mut ctx = InterceptorHandlerContext {
        is_dtls_handshake_complete: true,
        ..Default::default()
    };
    let mut chain = QueueChain::default();
    for packet in packets {
        chain.handle_write(packet).unwrap();
    }
    let mut transceivers = vec![];
    let media_engine = MediaEngine::default();
    let mut stats = RTCStatsAccumulator::default();
    let mut handler = InterceptorHandler::new(
        &mut ctx,
        &mut transceivers,
        &media_engine,
        &mut chain,
        &mut stats,
    );

    std::iter::from_fn(|| handler.poll_write())
        .map(|message| match message.message {
            RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(packets))) => packets,
            _ => panic!("expected RTCP"),
        })
        .collect()
}

fn cname_of(packets: &[Box<dyn rtcp::Packet>]) -> Option<(u32, String)> {
    let sdes = packets[1].as_any().downcast_ref::<SourceDescription>()?;
    let chunk = sdes.chunks.first()?;
    let item = chunk.items.first()?;
    assert_eq!(SdesType::SdesCname, item.sdes_type);
    Some((
        chunk.source,
        String::from_utf8(item.text.to_vec()).expect("utf-8"),
    ))
}

#[test]
fn a_receiver_report_carries_a_cname_right_after_it() {
    let out = written(vec![rtcp(vec![receiver_report(0x1111)])]);

    assert_eq!(1, out.len());
    assert_eq!(2, out[0].len());
    let (source, cname) = cname_of(&out[0]).expect("an SDES CNAME second");
    assert_eq!(0x1111, source);
    assert!(!cname.is_empty());
}

#[test]
fn every_report_of_a_connection_names_the_same_cname() {
    let out = written(vec![
        rtcp(vec![receiver_report(0x1111)]),
        rtcp(vec![receiver_report(0x2222)]),
    ]);

    let first = cname_of(&out[0]).expect("a CNAME").1;
    let second = cname_of(&out[1]).expect("a CNAME").1;
    assert_eq!(first, second);
}

#[test]
fn rtcp_without_a_leading_report_is_left_alone() {
    let pli: Box<dyn rtcp::Packet> = Box::new(PictureLossIndication {
        sender_ssrc: 1,
        media_ssrc: 2,
    });
    let out = written(vec![rtcp(vec![pli])]);

    assert_eq!(1, out[0].len());
}
