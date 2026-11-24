//! Media that arrives before the answer (RFC 3264 section 5.1; RFC 9429 sections 4.1.11, 5.9
//! and 5.11), between two `rtci` peers on an in-memory network and a virtual clock.
//!
//! The offerer "MUST be prepared to receive media for any recvonly streams described by that
//! offer" and for sendrecv ones "Once the offerer has sent the offer": the answerer sends as
//! soon as it has applied its answer, and here that answer reaches the offerer half a second
//! of media later (or is preceded by a provisional answer, or never arrives). Every packet
//! must reach the track of the receiver the offer described, none may be discarded, and the
//! answer, a rollback or a glare must leave the receiver in the state the specifications
//! give it.

mod dtls_sdp_common;

use anyhow::Result;
use bytes::Bytes;
use dtls_sdp_common::{Peer, World};
use rtci::interceptor::Registry;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::RTCPeerConnectionBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::state::RTCSignalingState;
use rtci::rtp_transceiver::rtp_receiver::RTCEncodedFrameMetadataKind;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use rtci::rtp_transceiver::{
    RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverId, RTCRtpTransceiverInit,
};
use rtci::statistics::StatsSelector;
use rtci::statistics::report::RTCStatsReportEntry;
use std::time::{Duration, Instant};

const SSRC: u32 = 0x00ea_7101;

/// A peer with the default codecs, interceptors and header extensions (MID, RtpStreamId and
/// RepairedRtpStreamId among them).
fn peer(addr: &str) -> Result<Peer> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build(Instant::now())?;
    Peer::from_connection(addr, pc)
}

fn world() -> Result<World> {
    Ok(World::new(peer("10.0.0.1:5000")?, peer("10.0.0.2:5000")?))
}

/// A video track with one encoding per `(rid, ssrc)`.
fn video_track(layers: &[(&str, u32)]) -> MediaStreamTrack {
    MediaStreamTrack::new(
        "early-stream".to_owned(),
        "early".to_owned(),
        "early".to_owned(),
        RtpCodecKind::Video,
        layers
            .iter()
            .map(|(rid, ssrc)| RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: (*rid).to_owned(),
                    ssrc: Some(*ssrc),
                    ..Default::default()
                },
                active: true,
                ..Default::default()
            })
            .collect(),
    )
}

/// The payload type of the first `a=rtpmap` of `encoding` (e.g. `VP8/90000`) in `sdp`.
fn payload_type(sdp: &str, encoding: &str) -> u8 {
    sdp.lines()
        .find_map(|l| {
            let rest = l.strip_prefix("a=rtpmap:")?;
            let (pt, name) = rest.split_once(' ')?;
            name.eq_ignore_ascii_case(encoding)
                .then(|| pt.parse().ok())?
        })
        .unwrap_or_else(|| panic!("no {encoding} in {sdp}"))
}

/// `sdp` without the format `pt` and the RTX formats that repair it: the m= line, rtpmap,
/// fmtp and rtcp-fb lines.
fn without_format(sdp: &str, pt: u8) -> String {
    let mut gone = vec![pt.to_string()];
    for line in sdp.lines() {
        if let Some(rest) = line.strip_prefix("a=fmtp:")
            && let Some((rtx, params)) = rest.split_once(' ')
            && params.split(';').any(|p| p.trim() == format!("apt={pt}"))
        {
            gone.push(rtx.to_owned());
        }
    }
    let mut out = String::new();
    for line in sdp.split("\r\n").filter(|l| !l.is_empty()) {
        if line.starts_with("m=video") {
            let kept: Vec<&str> = line
                .split(' ')
                .enumerate()
                .filter(|(i, f)| *i < 3 || !gone.iter().any(|g| g == f))
                .map(|(_, f)| f)
                .collect();
            out += &kept.join(" ");
        } else if ["a=rtpmap:", "a=fmtp:", "a=rtcp-fb:"].iter().any(|prefix| {
            line.strip_prefix(prefix)
                .is_some_and(|rest| gone.iter().any(|g| rest.starts_with(&format!("{g} "))))
        }) {
            continue;
        } else {
            out += line;
        }
        out += "\r\n";
    }
    out
}

/// `sdp` without every format named `encoding` (e.g. `VP9/90000`), and their RTX formats.
fn without_encoding(sdp: &str, encoding: &str) -> String {
    let mut out = sdp.to_owned();
    while let Some(pt) = out.lines().find_map(|l| {
        let (pt, name) = l.strip_prefix("a=rtpmap:")?.split_once(' ')?;
        name.eq_ignore_ascii_case(encoding)
            .then(|| pt.parse::<u8>().ok())?
    }) {
        out = without_format(&out, pt);
    }
    out
}

/// Peer `from` writes `count` packets on `ssrc`, 20 ms apart, with sequence numbers from
/// `first` (they may wrap), then the network settles.
fn send(
    world: &mut World,
    from: usize,
    sender: RTCRtpSenderId,
    payload_type: u8,
    ssrc: u32,
    first: u16,
    count: u16,
) -> Result<()> {
    for n in 0..count {
        let now = world.now;
        let sequence_number = first.wrapping_add(n);
        world.peers[from]
            .pc
            .rtp_sender(sender)
            .expect("the sender")
            .write_rtp(
                now,
                rtci::rtp::Packet {
                    header: rtci::rtp::header::Header {
                        version: 2,
                        payload_type,
                        sequence_number,
                        timestamp: u32::from(n) * 3000,
                        ssrc,
                        marker: true,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; 100]),
                },
            )?;
        world.run_for(Duration::from_millis(20), |_| false);
    }
    world.run_for(Duration::from_millis(100), |_| false);
    Ok(())
}

/// The sequence numbers peer `at` delivered for `ssrc`, with the track each went to.
fn delivered(world: &World, at: usize, ssrc: u32) -> Vec<(String, u8, u16)> {
    world.peers[at]
        .packets
        .iter()
        .filter(|(_, header)| header.ssrc == ssrc)
        .map(|(track, header)| (track.clone(), header.payload_type, header.sequence_number))
        .collect()
}

fn sequence(first: u16, count: u16) -> Vec<u16> {
    (0..count).map(|n| first.wrapping_add(n)).collect()
}

/// How many events of peer `at` have `needle` in their `Debug` form.
fn events(world: &World, at: usize, needle: &str) -> usize {
    world.peers[at]
        .events
        .iter()
        .filter(|event| event.contains(needle))
        .count()
}

/// The id of the track of the receiver of transceiver `id`: the one the application has
/// from `addTransceiver` on.
fn receiver_track(world: &mut World, at: usize, id: RTCRtpTransceiverId) -> String {
    world.peers[at]
        .pc
        .rtp_receiver(RTCRtpReceiverId::from(id))
        .expect("the receiver")
        .track()
        .track_id()
        .clone()
}

/// The codec name the receiver of transceiver `id` has established for its first stream.
fn established_codec(world: &mut World, at: usize, id: RTCRtpTransceiverId) -> Vec<String> {
    world.peers[at]
        .pc
        .rtp_receiver(RTCRtpReceiverId::from(id))
        .expect("the receiver")
        .track()
        .codings()
        .iter()
        .map(|coding| coding.codec.mime_type.to_ascii_lowercase())
        .collect()
}

/// `packetsReceived` of the inbound-rtp statistics of `ssrc` at peer `at`, if it has any.
/// It counts every arrival on the SSRC (RFC 3550 section 6.4.1), the sender's padding probes
/// included, so it is at least the number of media packets delivered.
fn packets_received(world: &mut World, at: usize, ssrc: u32) -> Option<u64> {
    let now = world.now;
    let report = world.peers[at].pc.get_stats(now, StatsSelector::None);
    report.iter().find_map(|entry| match entry {
        RTCStatsReportEntry::InboundRtp(stats) => {
            let json = serde_json::to_value(stats).expect("json");
            (json["ssrc"].as_u64() == Some(u64::from(ssrc)))
                .then(|| json["packetsReceived"].as_u64())
                .flatten()
        }
        _ => None,
    })
}

/// Peer 0's offer, applied by both peers, and peer 1's answer, applied by peer 1 only: the
/// answer is still on its way to peer 0. `prepare` runs on peer 1 between its two steps.
fn offer_and_hold_the_answer<T>(
    world: &mut World,
    prepare: impl FnOnce(&mut Peer) -> Result<T>,
) -> Result<(String, String, T)> {
    let now = world.now;
    let offer = world.peers[0].pc.create_offer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, offer.clone())?;
    world.peers[1]
        .pc
        .set_remote_description(now, RTCSessionDescription::offer(offer.sdp.clone())?)?;
    let prepared = prepare(&mut world.peers[1])?;
    let answer = world.peers[1].pc.create_answer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, answer.clone())?;
    Ok((offer.sdp, answer.sdp, prepared))
}

/// A connected pair (a data channel), then an offer from peer 0 that adds a recvonly video
/// section, which peer 1 answers with a sender on [`SSRC`]. The answer is held back.
/// Returns the world, the offerer's transceiver, the answerer's sender, the offer and the
/// answer.
fn a_later_offer_adds_a_recvonly_section()
-> Result<(World, RTCRtpTransceiverId, RTCRtpSenderId, String, String)> {
    let mut world = world()?;
    world.connect()?;
    let id = world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let (offer, answer, sender) = offer_and_hold_the_answer(&mut world, |peer| {
        Ok(peer.pc.add_track(video_track(&[("", SSRC)]))?)
    })?;
    Ok((world, id, sender, offer, answer))
}

/// RFC 3264 section 5.1, RFC 9429 section 5.9 ("If the direction attribute is of type
/// 'sendrecv' or 'recvonly', enable receipt and decoding of media"): a later offer adds a
/// recvonly section, the peer sends as soon as it has applied its answer, and the answer
/// takes 500 ms to reach the offerer. Every packet is delivered, to the track of the receiver
/// the offer described (W3C webrtc-pc: `[[Receptive]]` is true from the local offer on, and
/// arriving data unmutes the track), none is discarded; the `track` event waits for the
/// remote description. The stream then goes on across the answer under the same SSRC, track
/// and statistics. The sequence numbers wrap before the answer, so the SRTP rollover counter
/// of the stream is one the offerer worked out before it had the answer.
#[test]
fn media_for_a_section_a_later_offer_adds_is_delivered_before_the_answer() -> Result<()> {
    let (mut world, id, sender, offer, answer) = a_later_offer_adds_a_recvonly_section()?;
    let vp8 = payload_type(&offer, "VP8/90000");
    let track = receiver_track(&mut world, 0, id);

    // 25 packets, 20 ms apart: the half second the answer is under way.
    send(&mut world, 1, sender, vp8, SSRC, 65_520, 25)?;
    assert_eq!(
        world.peers[0].pc.signaling_state(),
        RTCSignalingState::HaveLocalOffer
    );
    let early = delivered(&world, 0, SSRC);
    assert_eq!(
        early.iter().map(|(_, _, seq)| *seq).collect::<Vec<_>>(),
        sequence(65_520, 25),
        "every packet sent before the answer arrived is delivered"
    );
    assert!(
        early.iter().all(|(to, pt, _)| *to == track && *pt == vp8),
        "to the track of the receiver the offer described: {early:?}"
    );
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);
    assert_eq!(events(&world, 0, "OnUnassociatedRtpDiscarded"), 0);
    assert_eq!(events(&world, 0, "OnUnmute"), 1, "data unmutes the track");
    assert_eq!(
        events(&world, 0, "OnRemoteTrack"),
        0,
        "the track event is the remote description's"
    );
    let counted_early = packets_received(&mut world, 0, SSRC).expect("inbound-rtp statistics");
    assert!(counted_early >= 25, "{counted_early}");

    let now = world.now;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(answer)?)?;
    world.run_for(Duration::from_millis(20), |_| false);
    assert_eq!(events(&world, 0, "OnRemoteTrack"), 1);
    assert_eq!(receiver_track(&mut world, 0, id), track);

    send(
        &mut world,
        1,
        sender,
        vp8,
        SSRC,
        65_520u16.wrapping_add(25),
        5,
    )?;
    let all = delivered(&world, 0, SSRC);
    assert_eq!(
        all.iter().map(|(_, _, seq)| *seq).collect::<Vec<_>>(),
        sequence(65_520, 30)
    );
    assert!(all.iter().all(|(to, _, _)| *to == track));
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);
    assert_eq!(
        events(&world, 0, "OnTrack(OnOpen"),
        1,
        "the stream that arrived early stays bound: it is not opened again"
    );
    let counted = packets_received(&mut world, 0, SSRC).expect("inbound-rtp statistics");
    assert!(
        counted >= counted_early + 5,
        "the statistics of the early stream go on: {counted_early} then {counted}"
    );
    assert_eq!(established_codec(&mut world, 0, id), vec!["video/vp8"]);
    Ok(())
}

/// RFC 3264 section 5.1: the offerer "MUST be prepared to send and receive media for any
/// sendrecv streams in the offer ... (of course, it cannot actually send until the peer
/// provides an answer ...)". A later offer adds a sendrecv section; the peer's media for it
/// is delivered before the answer, and once the answer is applied the offerer's own media
/// for the section reaches the peer.
#[test]
fn a_sendrecv_section_receives_before_the_answer_and_sends_once_it_has_it() -> Result<()> {
    const OFFERERS: u32 = 0x00ea_7401;
    let mut world = world()?;
    world.connect()?;
    let own_sender = world.peers[0]
        .pc
        .add_track(video_track(&[("", OFFERERS)]))?;
    let id = RTCRtpTransceiverId::from(own_sender);
    let track = receiver_track(&mut world, 0, id);
    let (offer, answer, sender) = offer_and_hold_the_answer(&mut world, |peer| {
        Ok(peer.pc.add_track(video_track(&[("", SSRC)]))?)
    })?;
    assert!(offer.contains("a=sendrecv"), "{offer}");
    let vp8 = payload_type(&offer, "VP8/90000");

    send(&mut world, 1, sender, vp8, SSRC, 1, 25)?;
    let early = delivered(&world, 0, SSRC);
    assert_eq!(
        early.iter().map(|(_, _, seq)| *seq).collect::<Vec<_>>(),
        sequence(1, 25)
    );
    assert!(early.iter().all(|(to, _, _)| *to == track));
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);

    let now = world.now;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(answer)?)?;
    send(&mut world, 0, own_sender, vp8, OFFERERS, 1, 10)?;
    assert_eq!(
        delivered(&world, 1, OFFERERS)
            .iter()
            .map(|(_, _, seq)| *seq)
            .collect::<Vec<_>>(),
        sequence(1, 10)
    );
    send(&mut world, 1, sender, vp8, SSRC, 26, 5)?;
    assert_eq!(delivered(&world, 0, SSRC).len(), 30);
    Ok(())
}

/// The codecs of the registered video formats named in `names` (and RTX), as codec
/// preferences.
fn preferences(world: &mut World, at: usize, names: &[&str]) -> Vec<RTCRtpCodecParameters> {
    let id = world.peers[at]
        .pc
        .get_receivers()
        .next()
        .expect("a receiver");
    world.peers[at]
        .pc
        .rtp_receiver(id)
        .expect("the receiver")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video capabilities")
        .codecs
        .into_iter()
        .filter(|codec| {
            names
                .iter()
                .chain(&["video/rtx"])
                .any(|name| codec.mime_type.eq_ignore_ascii_case(name))
        })
        .map(|rtp_codec| RTCRtpCodecParameters {
            rtp_codec,
            payload_type: 0,
        })
        .collect()
}

/// RFC 9429 section 4.1.11: "the PeerConnection MUST be able to simultaneously support use
/// of both the current and pending local descriptions (e.g., support the codecs that exist
/// in either description)". A section negotiated with VP8 only is offered again with VP9
/// added; the peer, which had sent nothing yet, starts in VP9 before its answer arrives. The
/// stream is established as VP9 (its codec, its statistics), not just let through.
#[test]
fn a_format_a_later_offer_adds_is_received_as_that_format_before_the_answer() -> Result<()> {
    let mut world = world()?;
    let id = world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let vp8_only = preferences(&mut world, 0, &["video/VP8"]);
    world.peers[0]
        .pc
        .rtp_transceiver(id)
        .expect("the transceiver")
        .set_codec_preferences(vp8_only)?;
    let sender = world.peers[1].pc.add_track(video_track(&[("", SSRC)]))?;
    let (first_offer, first_answer) = world.connect()?;
    assert!(!first_offer.contains("VP9/90000"), "{first_offer}");
    let _ = first_answer;

    let both = preferences(&mut world, 0, &["video/VP8", "video/VP9"]);
    world.peers[0]
        .pc
        .rtp_transceiver(id)
        .expect("the transceiver")
        .set_codec_preferences(both)?;
    let (offer, answer, ()) = offer_and_hold_the_answer(&mut world, |_| Ok(()))?;
    let vp9 = payload_type(&offer, "VP9/90000");
    assert!(answer.contains("VP9/90000"), "{answer}");
    let track = receiver_track(&mut world, 0, id);

    send(&mut world, 1, sender, vp9, SSRC, 100, 25)?;
    let early = delivered(&world, 0, SSRC);
    assert_eq!(
        early.iter().map(|(_, _, seq)| *seq).collect::<Vec<_>>(),
        sequence(100, 25)
    );
    assert!(early.iter().all(|(to, pt, _)| *to == track && *pt == vp9));
    assert_eq!(
        established_codec(&mut world, 0, id),
        vec!["video/vp9"],
        "the stream is established in the format only the pending offer lists"
    );
    let counted_early = packets_received(&mut world, 0, SSRC).expect("inbound-rtp statistics");
    assert!(counted_early >= 25, "{counted_early}");
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);
    // webrtc-encoded-transform 4: the metadata of a frame that arrived early names the
    // format the pending offer gives its payload type, and when it was received.
    let header = world.peers[0].packets[0].1.clone();
    let metadata = world.peers[0]
        .pc
        .rtp_receiver(RTCRtpReceiverId::from(id))
        .expect("the receiver")
        .encoded_frame_metadata(&[rtci::rtp::Packet {
            header,
            payload: Bytes::from(vec![0x10u8; 100]),
        }])?;
    let RTCEncodedFrameMetadataKind::Video(metadata) = metadata else {
        panic!("a video frame: {metadata:?}");
    };
    assert_eq!(metadata.frame.payload_type, vp9);
    assert!(
        metadata.frame.mime_type.eq_ignore_ascii_case("video/VP9"),
        "{:?}",
        metadata.frame
    );
    assert!(metadata.frame.receive_time.is_some());

    let now = world.now;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(answer)?)?;
    send(&mut world, 1, sender, vp9, SSRC, 125, 5)?;
    assert_eq!(delivered(&world, 0, SSRC).len(), 30);
    assert!(packets_received(&mut world, 0, SSRC) >= Some(counted_early + 5));
    assert_eq!(established_codec(&mut world, 0, id), vec!["video/vp9"]);
    assert_eq!(events(&world, 0, "OnTrack(OnOpen"), 1);
    Ok(())
}

/// RFC 9429 section 4.1.10.1: a provisional answer warms the transport up, and media flows
/// while the offer is still open; section 4.1.11: the dual processing "continues until
/// setRemoteDescription is called with either (1) a final answer ... or (2) a rollback". An
/// initial offer is answered provisionally with VP8 only; the peer sends VP9, which the
/// final answer will name. The provisional answer narrows nothing: the VP9 stream is
/// delivered and established, and goes on across the final answer.
#[test]
fn an_initial_offer_receives_what_it_lists_while_a_provisional_answer_is_in_force() -> Result<()> {
    let mut world = world()?;
    let id = world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let track = receiver_track(&mut world, 0, id);
    let (offer, answer, sender) = offer_and_hold_the_answer(&mut world, |peer| {
        Ok(peer.pc.add_track(video_track(&[("", SSRC)]))?)
    })?;
    let vp8 = payload_type(&offer, "VP8/90000");
    let vp9 = payload_type(&offer, "VP9/90000");
    assert!(answer.contains("VP9/90000"), "{answer}");

    // Nothing reaches the offerer before a remote description: its transports take the
    // remote credentials and fingerprint from one (RFC 8842 section 5.2).
    let provisional = without_encoding(&answer, "VP9/90000");
    assert!(provisional.contains(&format!("a=rtpmap:{vp8} VP8")));
    assert!(!provisional.contains("VP9/90000"));
    let now = world.now;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::pranswer(provisional)?)?;
    assert_eq!(
        world.peers[0].pc.signaling_state(),
        RTCSignalingState::HaveRemotePranswer
    );
    world.trickle()?;
    world.run("the transport the provisional answer starts", |peers| {
        peers.iter().all(|p| p.connected())
    })?;

    send(&mut world, 1, sender, vp9, SSRC, 500, 25)?;
    let early = delivered(&world, 0, SSRC);
    assert_eq!(
        early.iter().map(|(_, _, seq)| *seq).collect::<Vec<_>>(),
        sequence(500, 25),
        "a format of the offer that the provisional answer does not name is still received"
    );
    assert!(early.iter().all(|(to, pt, _)| *to == track && *pt == vp9));
    assert_eq!(established_codec(&mut world, 0, id), vec!["video/vp9"]);
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);

    let now = world.now;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(answer)?)?;
    send(&mut world, 1, sender, vp9, SSRC, 525, 5)?;
    assert_eq!(delivered(&world, 0, SSRC).len(), 30);
    assert!(packets_received(&mut world, 0, SSRC) >= Some(30));
    assert_eq!(events(&world, 0, "OnTrack(OnOpen"), 1);
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);
    Ok(())
}

/// RFC 9429 section 5.7: after a rollback "the state of the session is restored to the
/// state it was in before the offer". The early stream is unbound and its statistics are
/// gone, the track its media unmuted is muted again, the transceiver has no mid; what the
/// peer still sends is unassociated media, discarded and reported (RFC 8830 section 3.1).
/// A new offer then negotiates the section as if the first had never been made.
#[test]
fn a_rollback_takes_back_what_the_offer_prepared() -> Result<()> {
    let (mut world, id, sender, offer, _answer) = a_later_offer_adds_a_recvonly_section()?;
    let vp8 = payload_type(&offer, "VP8/90000");
    let track = receiver_track(&mut world, 0, id);

    send(&mut world, 1, sender, vp8, SSRC, 1, 10)?;
    assert_eq!(delivered(&world, 0, SSRC).len(), 10);
    let counted_early = packets_received(&mut world, 0, SSRC).expect("inbound-rtp statistics");
    assert!(counted_early >= 10);

    let now = world.now;
    world.peers[0]
        .pc
        .set_local_description(now, RTCSessionDescription::rollback(None)?)?;
    world.run_for(Duration::from_millis(20), |_| false);
    assert_eq!(
        world.peers[0].pc.signaling_state(),
        RTCSignalingState::Stable
    );
    assert_eq!(packets_received(&mut world, 0, SSRC), None);
    assert_eq!(established_codec(&mut world, 0, id), Vec::<String>::new());
    assert_eq!(events(&world, 0, "OnMute"), 1);
    assert_eq!(
        world.peers[0]
            .pc
            .rtp_transceiver(id)
            .expect("the transceiver stays")
            .mid()
            .clone(),
        None
    );

    // The peer, which has not heard of the rollback, goes on sending.
    send(&mut world, 1, sender, vp8, SSRC, 11, 10)?;
    assert_eq!(
        delivered(&world, 0, SSRC).len(),
        10,
        "nothing of the rolled back section is delivered"
    );
    let discarded = world.peers[0].pc.discarded_rtp_packets();
    assert!(discarded >= 10, "{discarded}");
    assert_eq!(events(&world, 0, "OnUnassociatedRtpDiscarded"), 1);

    // The peer, stable since its answer, makes the next offer: the section is negotiated
    // from the state the rollback restored, and its media is delivered to the same receiver's
    // track.
    world.exchange(1)?;
    send(&mut world, 1, sender, vp8, SSRC, 21, 10)?;
    let all = delivered(&world, 0, SSRC);
    assert_eq!(
        all.iter().map(|(_, _, seq)| *seq).collect::<Vec<_>>(),
        sequence(1, 10)
            .into_iter()
            .chain(sequence(21, 10))
            .collect::<Vec<_>>()
    );
    assert!(all.iter().all(|(to, _, _)| *to == track));
    assert!(packets_received(&mut world, 0, SSRC) >= Some(10));
    Ok(())
}

/// A glare: the peer's own offer overtakes its answer, and the offerer, which has a local
/// offer pending, rolls that back implicitly to take it (W3C webrtc-pc `setRemoteDescription`;
/// RFC 9429 section 5.7). What the rolled back offer prepared is gone with it, exactly as
/// with an explicit rollback: the early stream's statistics and binding, and the unmuted
/// state of the track. The offerer's answer to the peer's offer then negotiates the section,
/// and the media reaches the same track again.
#[test]
fn a_glare_rolls_back_what_the_offer_prepared() -> Result<()> {
    let (mut world, id, sender, offer, _lost_answer) = a_later_offer_adds_a_recvonly_section()?;
    let vp8 = payload_type(&offer, "VP8/90000");
    let track = receiver_track(&mut world, 0, id);

    send(&mut world, 1, sender, vp8, SSRC, 1, 10)?;
    assert_eq!(delivered(&world, 0, SSRC).len(), 10);
    assert!(packets_received(&mut world, 0, SSRC) >= Some(10));

    // The peer, stable since its answer, makes an offer of its own, which arrives first.
    let now = world.now;
    let peers_offer = world.peers[1].pc.create_offer(None)?;
    world.peers[1]
        .pc
        .set_local_description(now, peers_offer.clone())?;
    world.peers[0].pc.set_remote_description(now, peers_offer)?;
    world.run_for(Duration::from_millis(20), |_| false);
    assert_eq!(
        world.peers[0].pc.signaling_state(),
        RTCSignalingState::HaveRemoteOffer
    );
    assert_eq!(
        packets_received(&mut world, 0, SSRC),
        None,
        "the early stream went with the offer that was rolled back"
    );
    assert_eq!(established_codec(&mut world, 0, id), Vec::<String>::new());
    assert_eq!(events(&world, 0, "OnMute"), 1);

    let now = world.now;
    let answer = world.peers[0].pc.create_answer(None)?;
    world.peers[0]
        .pc
        .set_local_description(now, answer.clone())?;
    world.peers[1].pc.set_remote_description(now, answer)?;
    send(&mut world, 1, sender, vp8, SSRC, 11, 10)?;
    let all = delivered(&world, 0, SSRC);
    assert_eq!(
        all.iter().map(|(_, _, seq)| *seq).collect::<Vec<_>>(),
        sequence(1, 20)
    );
    assert!(all.iter().all(|(to, _, _)| *to == track));
    assert!(packets_received(&mut world, 0, SSRC) >= Some(10));
    Ok(())
}

/// RFC 3264 section 8.3.2: "if the offered stream is rejected, the offer can cease being
/// prepared to receive using any new formats as soon as the rejection is received". The
/// peer's early media is VP9; the answer that then arrives does not list VP9. From the
/// answer on VP9 is no longer received, and the same stream in VP8, which the answer does
/// list, is established anew on the same SSRC and track.
#[test]
fn a_format_the_answer_leaves_out_stops_being_received_with_the_answer() -> Result<()> {
    let (mut world, id, sender, offer, answer) = a_later_offer_adds_a_recvonly_section()?;
    let vp8 = payload_type(&offer, "VP8/90000");
    let vp9 = payload_type(&offer, "VP9/90000");
    let track = receiver_track(&mut world, 0, id);

    send(&mut world, 1, sender, vp9, SSRC, 1, 10)?;
    assert_eq!(delivered(&world, 0, SSRC).len(), 10);
    assert_eq!(established_codec(&mut world, 0, id), vec!["video/vp9"]);

    let now = world.now;
    world.peers[0].pc.set_remote_description(
        now,
        RTCSessionDescription::answer(without_encoding(&answer, "VP9/90000"))?,
    )?;
    assert_eq!(
        established_codec(&mut world, 0, id),
        vec![""],
        "the stream is no longer established in the format the answer left out"
    );
    send(&mut world, 1, sender, vp9, SSRC, 11, 5)?;
    assert_eq!(
        delivered(&world, 0, SSRC).len(),
        10,
        "a format the answer left out is not received after the answer"
    );

    send(&mut world, 1, sender, vp8, SSRC, 16, 5)?;
    let all = delivered(&world, 0, SSRC);
    assert_eq!(all.len(), 15, "{all:?}");
    assert!(
        all[10..]
            .iter()
            .all(|(to, pt, _)| *to == track && *pt == vp8)
    );
    assert_eq!(established_codec(&mut world, 0, id), vec!["video/vp8"]);
    Ok(())
}

/// RFC 8853 section 5.3.1: an offerer that lists streams to receive is ready for any of
/// them. The offer asks for two simulcast streams by rid; the peer sends both before its
/// answer arrives. Each is placed by the MID and RtpStreamId header extensions, read with
/// the ids of the offer (this session had negotiated none), and stays bound to its SSRC
/// across the answer.
#[test]
fn simulcast_streams_an_offer_asks_for_are_received_before_the_answer() -> Result<()> {
    const HIGH: u32 = 0x00ea_7201;
    const LOW: u32 = 0x00ea_7202;
    let mut world = world()?;
    world.connect()?;
    let id = world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    world.peers[0]
        .pc
        .rtp_transceiver(id)
        .expect("the transceiver")
        .set_receive_simulcast(vec!["h".to_owned(), "l".to_owned()])?;
    let track = receiver_track(&mut world, 0, id);
    let (offer, answer, sender) = offer_and_hold_the_answer(&mut world, |peer| {
        Ok(peer.pc.add_track(video_track(&[("h", HIGH), ("l", LOW)]))?)
    })?;
    assert!(offer.contains("a=simulcast:recv h;l"), "{offer}");
    assert!(answer.contains("a=simulcast:send h;l"), "{answer}");
    let vp8 = payload_type(&offer, "VP8/90000");

    for round in 0..5u16 {
        send(&mut world, 1, sender, vp8, HIGH, 1 + round * 5, 5)?;
        send(&mut world, 1, sender, vp8, LOW, 1001 + round * 5, 5)?;
    }
    for (ssrc, first) in [(HIGH, 1), (LOW, 1001)] {
        let early = delivered(&world, 0, ssrc);
        assert_eq!(
            early.iter().map(|(_, _, seq)| *seq).collect::<Vec<_>>(),
            sequence(first, 25)
        );
        assert!(early.iter().all(|(to, _, _)| *to == track));
        assert!(packets_received(&mut world, 0, ssrc) >= Some(25));
    }
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);
    assert_eq!(events(&world, 0, "OnTrack(OnOpen"), 2);

    let now = world.now;
    world.peers[0]
        .pc
        .set_remote_description(now, RTCSessionDescription::answer(answer)?)?;
    send(&mut world, 1, sender, vp8, HIGH, 26, 5)?;
    send(&mut world, 1, sender, vp8, LOW, 1026, 5)?;
    for ssrc in [HIGH, LOW] {
        assert_eq!(delivered(&world, 0, ssrc).len(), 30);
        assert!(packets_received(&mut world, 0, ssrc) >= Some(30));
    }
    assert_eq!(
        events(&world, 0, "OnTrack(OnOpen"),
        2,
        "the layers stay bound to the SSRCs they arrived on"
    );
    assert_eq!(world.peers[0].pc.discarded_rtp_packets(), 0);
    let layers: Vec<(String, Option<u32>)> = world.peers[0]
        .pc
        .rtp_receiver(RTCRtpReceiverId::from(id))
        .expect("the receiver")
        .track()
        .codings()
        .iter()
        .map(|c| {
            (
                c.rtp_coding_parameters.rid.clone(),
                c.rtp_coding_parameters.ssrc,
            )
        })
        .collect();
    assert_eq!(
        layers,
        vec![("h".to_owned(), Some(HIGH)), ("l".to_owned(), Some(LOW))]
    );
    Ok(())
}
