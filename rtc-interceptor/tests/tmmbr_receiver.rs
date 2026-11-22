//! The media receiver's side of TMMBR (RFC 5104 section 4.2.1.2), between two congestion
//! control chains: the receiver asks a limit with `TmmbrControl`, the sender obeys it and
//! answers with a TMMBN, and the receiver goes quiet once acknowledged.

use rtc_interceptor::{
    CongestionControlBuilder, CongestionControlHandle, ConstantBitrate, Interceptor, Packet,
    RTCPFeedback, Registry, Slot, StreamInfo, TMMBR_REPEAT_INTERVAL, TaggedPacket, TmmbrControl,
};
use rtcp::transport_feedbacks::tmmb::{
    TemporaryMaximumBitrateNotification, TemporaryMaximumBitrateRequest,
};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const MEDIA: u32 = 0x1111_2222;

fn stream(tmmbr: bool) -> StreamInfo {
    StreamInfo {
        ssrc: MEDIA,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        payload_type: 96,
        rtcp_feedback: if tmmbr {
            vec![RTCPFeedback {
                typ: "ccm".to_owned(),
                parameter: "tmmbr".to_owned(),
            }]
        } else {
            vec![]
        },
        ..Default::default()
    }
}

fn chain() -> (Box<dyn Interceptor>, CongestionControlHandle) {
    let (cc, handle) =
        CongestionControlBuilder::new(ConstantBitrate::new(2_000_000.0)).build_with_handle();
    (
        Box::new(Registry::new().with(Slot::CongestionControl, cc).build()),
        handle,
    )
}

/// The RTCP packets a chain wrote.
fn written(chain: &mut Box<dyn Interceptor>) -> Vec<TaggedPacket> {
    let mut out = vec![];
    while let Some(packet) = chain.poll_write() {
        if matches!(&packet.message.packet, Packet::Rtcp(p) if !p.is_empty()) {
            out.push(packet);
        }
    }
    out
}

fn requests(packets: &[TaggedPacket]) -> Vec<TemporaryMaximumBitrateRequest> {
    packets
        .iter()
        .filter_map(|p| match &p.message.packet {
            Packet::Rtcp(rtcp) => rtcp
                .iter()
                .find_map(|r| r.as_any().downcast_ref::<TemporaryMaximumBitrateRequest>())
                .cloned(),
            _ => None,
        })
        .collect()
}

fn notifications(packets: &[TaggedPacket]) -> Vec<TemporaryMaximumBitrateNotification> {
    packets
        .iter()
        .filter_map(|p| match &p.message.packet {
            Packet::Rtcp(rtcp) => rtcp
                .iter()
                .find_map(|r| {
                    r.as_any()
                        .downcast_ref::<TemporaryMaximumBitrateNotification>()
                })
                .cloned(),
            _ => None,
        })
        .collect()
}

/// RTP packets of the remote stream, 20 octets of RTP header (a 12-octet header and one
/// 8-octet extension block), so the receiver has an overhead to report.
fn receive_media(receiver: &mut Box<dyn Interceptor>, now: Instant, count: u16) {
    for seq in 0..count {
        let mut header = rtp::header::Header {
            version: 2,
            payload_type: 96,
            sequence_number: seq,
            ssrc: MEDIA,
            ..Default::default()
        };
        header
            .set_extension_upgrading(1, bytes::Bytes::from_static(&[1, 2, 3]))
            .unwrap();
        receiver
            .handle_read(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: rtc_interceptor::AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header,
                    payload: vec![0u8; 1000].into(),
                })),
            })
            .unwrap();
        while receiver.poll_read().is_some() {}
    }
}

/// RFC 5104 section 4.2.1.2: a receiver whose stream negotiated `ccm tmmbr` asks the sender
/// for a limit; the first TMMBR goes at once (section 4.2.1.3), names the media sender and
/// carries the overhead measured on the stream (IPv4, UDP and the RTP header, 48 octets); the
/// sender is bounded by it and answers with a TMMBN naming the receiver as owner; after that
/// the receiver sends nothing more for an unchanged limit, and lifting the limit is reported.
#[test]
fn a_receiver_limits_the_remote_sender_with_tmmbr_until_a_tmmbn_acknowledges_it() {
    let now = Instant::now();
    let (mut receiver, _) = chain();
    let (mut sender, sender_handle) = chain();
    receiver.bind_remote_stream(&stream(true));
    sender.bind_local_stream(&stream(true));
    receive_media(&mut receiver, now, 50);
    written(&mut receiver);

    receiver
        .handle_write(
            TmmbrControl::Limit {
                media_ssrc: MEDIA,
                bitrate: 400_000,
            }
            .into_packet(now),
        )
        .unwrap();
    let out = written(&mut receiver);
    let tmmbr = requests(&out);
    assert_eq!(tmmbr.len(), 1, "sent at once");
    assert_eq!(tmmbr[0].entries.len(), 1);
    assert_eq!(tmmbr[0].entries[0].ssrc, MEDIA, "names the media sender");
    assert_eq!(tmmbr[0].entries[0].bitrate(), 400_000);
    assert_eq!(tmmbr[0].entries[0].measured_overhead, 20 + 8 + 20);
    assert_ne!(tmmbr[0].sender_ssrc, 0);

    for packet in out {
        sender.handle_read(packet).unwrap();
    }
    while sender.poll_read().is_some() {}
    assert_eq!(
        sender_handle.tmmbr_limit(),
        Some(400_000.0),
        "the sender obeys"
    );
    let answer = written(&mut sender);
    let tmmbn = notifications(&answer);
    assert_eq!(tmmbn.len(), 1);
    assert_eq!(
        tmmbn[0].entries[0].ssrc, tmmbr[0].sender_ssrc,
        "the receiver owns it"
    );

    for packet in answer {
        receiver.handle_read(packet).unwrap();
    }
    while receiver.poll_read().is_some() {}
    receiver
        .handle_timeout(now + TMMBR_REPEAT_INTERVAL * 3)
        .unwrap();
    assert!(
        requests(&written(&mut receiver)).is_empty(),
        "acknowledged: not repeated"
    );

    // The same limit again changes nothing; lifting it is reported.
    receiver
        .handle_write(
            TmmbrControl::Limit {
                media_ssrc: MEDIA,
                bitrate: 400_000,
            }
            .into_packet(now + TMMBR_REPEAT_INTERVAL * 3),
        )
        .unwrap();
    assert!(requests(&written(&mut receiver)).is_empty());
    receiver
        .handle_write(
            TmmbrControl::NegotiatedMaximum(Some(1_500_000))
                .into_packet(now + TMMBR_REPEAT_INTERVAL * 3),
        )
        .unwrap();
    written(&mut receiver);
    receiver
        .handle_write(
            TmmbrControl::Clear { media_ssrc: MEDIA }.into_packet(now + TMMBR_REPEAT_INTERVAL * 3),
        )
        .unwrap();
    let lifted = requests(&written(&mut receiver));
    assert_eq!(lifted.len(), 1);
    assert_eq!(
        lifted[0].entries[0].bitrate(),
        1_500_000,
        "lifted to the negotiated maximum, never above it"
    );
}

/// RFC 5104 section 4.2.1.2: "A TMMBR FCI entry MAY be repeated [...] if no [TMMBN] has been
/// received", in regular RTCP rhythm rather than at once (section 4.2.1.3).
#[test]
fn an_unacknowledged_tmmbr_is_repeated_once_a_reporting_interval() {
    let now = Instant::now();
    let (mut receiver, _) = chain();
    receiver.bind_remote_stream(&stream(true));
    receiver
        .handle_write(
            TmmbrControl::Limit {
                media_ssrc: MEDIA,
                bitrate: 250_000,
            }
            .into_packet(now),
        )
        .unwrap();
    assert_eq!(requests(&written(&mut receiver)).len(), 1);
    assert_eq!(receiver.poll_timeout(), Some(now + TMMBR_REPEAT_INTERVAL));
    receiver
        .handle_timeout(now + TMMBR_REPEAT_INTERVAL / 2)
        .unwrap();
    assert!(requests(&written(&mut receiver)).is_empty(), "not early");
    receiver
        .handle_timeout(now + TMMBR_REPEAT_INTERVAL)
        .unwrap();
    assert_eq!(requests(&written(&mut receiver)).len(), 1, "repeated");
}

/// RFC 5104 section 7.2: no CCM is used that both sides did not indicate. A remote stream
/// without `ccm tmmbr` is never sent a TMMBR.
#[test]
fn a_remote_stream_without_ccm_tmmbr_is_never_sent_a_tmmbr() {
    let now = Instant::now();
    let (mut receiver, _) = chain();
    receiver.bind_remote_stream(&stream(false));
    receiver
        .handle_write(
            TmmbrControl::Limit {
                media_ssrc: MEDIA,
                bitrate: 250_000,
            }
            .into_packet(now),
        )
        .unwrap();
    receiver
        .handle_timeout(now + Duration::from_secs(5))
        .unwrap();
    assert!(requests(&written(&mut receiver)).is_empty());
}
