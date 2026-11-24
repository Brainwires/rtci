//! Rows of the sweep (jsep12) that need media between two connected `rtci` peers in virtual
//! time: what the sender puts on the wire follows the negotiated formats of its own section
//! (RFC 3264 sections 8.3.2, 8.3.4; RFC 9143 section 9.1).

mod dtls_sdp_common;

use anyhow::Result;
use bytes::Bytes;
use dtls_sdp_common::{Peer, World, keep};
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MIME_TYPE_VP9};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use std::time::Duration;

const SSRC: u32 = 0x5e20_0101;

fn video_track() -> MediaStreamTrack {
    video_track_with(RTCRtpCodec::default())
}

/// A video track whose one encoding names `codec` (W3C `RTCRtpEncodingParameters.codec`;
/// the default names none, and the sender sends with what negotiation picks).
fn video_track_with(codec: RTCRtpCodec) -> MediaStreamTrack {
    MediaStreamTrack::new(
        "s".to_owned(),
        "v".to_owned(),
        "v".to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(SSRC),
                ..Default::default()
            },
            codec,
            ..Default::default()
        }],
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

/// Writes `packets` RTP packets with sequence numbers from `first` (SRTP's replay window
/// drops a number it has seen).
fn write(
    world: &mut World,
    sender: RTCRtpSenderId,
    payload_type: u8,
    first: u16,
    packets: u16,
) -> Result<()> {
    for n in 0..packets {
        let now = world.now;
        let mut s = world.peers[0].pc.rtp_sender(sender).expect("the sender");
        s.write_rtp(
            now,
            rtci::rtp::Packet {
                header: rtci::rtp::header::Header {
                    version: 2,
                    payload_type,
                    sequence_number: first + n,
                    timestamp: u32::from(first + n) * 3000,
                    ssrc: SSRC,
                    marker: true,
                    ..Default::default()
                },
                payload: Bytes::from(vec![0x10u8; 100]),
            },
        )?;
        world.run_for(Duration::from_millis(20), |_| false);
    }
    world.run_for(Duration::from_millis(200), |_| false);
    Ok(())
}

/// The payload types of the packets peer 1 received on [`SSRC`].
fn received_payload_types(world: &World) -> Vec<u8> {
    world.peers[1]
        .rtp
        .iter()
        .filter(|(_, ssrc)| *ssrc == SSRC)
        .map(|(pt, _)| *pt)
        .collect()
}

/// RFC 9143 section 9.1: an SSRC "MUST NOT" be used with payload types of another bundled
/// section: a packet the application writes on the video sender with the audio section's
/// payload type goes out with the video one.
#[test]
fn a_packet_with_another_sections_payload_type_goes_out_with_the_senders_own() -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let sender = world.peers[0].pc.add_track(video_track())?;
    let (offer, _) = world.connect()?;
    let vp8 = payload_type(&offer, "VP8/90000");
    let opus = payload_type(&offer, "opus/48000/2");

    write(&mut world, sender, vp8, 100, 5)?;
    write(&mut world, sender, opus, 200, 5)?;
    let received = received_payload_types(&world);
    assert!(received.len() >= 8, "{received:?}");
    assert!(received.iter().all(|pt| *pt == vp8), "{received:?}");
    Ok(())
}

/// RFC 3264 sections 8.3.2 and 8.3.4: once a later answer no longer lists the format the
/// sender used, the sender switches to one the new answer lists, as soon as that answer is
/// applied; the old one is not sent. The application keeps writing with the old payload type
/// (it is the engine that follows the answer). With `codec` set, the encoding names the
/// dropped codec: W3C webrtc-pc 4.4.1.6 removes `encoding.codec` when the answer does not
/// negotiate it for sending, so that encoding switches too instead of failing.
fn the_sender_follows_a_new_answer(codec: RTCRtpCodec) -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    let named = !codec.mime_type.is_empty();
    let sender = world.peers[0].pc.add_track(video_track_with(codec))?;
    if named {
        // An encoding that names a codec makes it the transceiver's preference; the
        // application lists VP9 too, so that an answer without VP8 still has a format.
        let codecs: Vec<rtci::rtp_transceiver::rtp_sender::RTCRtpCodecParameters> = world.peers[0]
            .pc
            .rtp_sender(sender)
            .expect("the sender")
            .get_capabilities(RtpCodecKind::Video)
            .expect("video capabilities")
            .codecs
            .into_iter()
            .filter(|c| {
                [MIME_TYPE_VP8, MIME_TYPE_VP9, "video/rtx"]
                    .iter()
                    .any(|m| c.mime_type.eq_ignore_ascii_case(m))
            })
            .map(
                |rtp_codec| rtci::rtp_transceiver::rtp_sender::RTCRtpCodecParameters {
                    rtp_codec,
                    payload_type: 0,
                },
            )
            .collect();
        world.peers[0]
            .pc
            .rtp_transceiver(rtci::rtp_transceiver::RTCRtpTransceiverId::from(sender))
            .expect("the transceiver")
            .set_codec_preferences(codecs)?;
    }
    let (offer, _) = world.connect()?;
    if named {
        payload_type(&offer, "VP9/90000");
    }
    let vp8 = payload_type(&offer, "VP8/90000");

    write(&mut world, sender, vp8, 100, 5)?;
    let received = received_payload_types(&world);
    assert!(received.len() >= 4, "{received:?}");
    assert!(received.iter().all(|pt| *pt == vp8), "{received:?}");

    // A later answer without VP8.
    let (_, answer) = world.exchange_with(
        0,
        |offer| offer.to_owned(),
        |answer| without_format(answer, vp8),
    )?;
    assert!(
        answer.contains(&format!("a=rtpmap:{vp8} VP8")),
        "the answerer's own still has it"
    );
    let encoding_codec = world.peers[0]
        .pc
        .rtp_sender(sender)
        .expect("the sender")
        .get_parameters()
        .encodings[0]
        .codec
        .clone();
    assert!(
        encoding_codec.mime_type.is_empty(),
        "the encoding still names {encoding_codec:?} (named: {named})"
    );
    world.peers[1].rtp.clear();
    write(&mut world, sender, vp8, 300, 5)?;
    let received = received_payload_types(&world);
    let listed = without_format(&answer, vp8);
    assert!(
        received.len() >= 4,
        "sent after the new answer: {received:?}"
    );
    for pt in &received {
        assert_ne!(*pt, vp8, "{received:?}");
        assert!(
            listed.contains(&format!("a=rtpmap:{pt} ")),
            "{pt} is not in {listed}"
        );
    }
    Ok(())
}

#[test]
fn the_sender_follows_a_new_answer_that_drops_its_format() -> Result<()> {
    the_sender_follows_a_new_answer(RTCRtpCodec::default())
}

#[test]
fn an_encoding_that_names_a_dropped_codec_switches_with_the_new_answer() -> Result<()> {
    the_sender_follows_a_new_answer(RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        ..Default::default()
    })
}

/// The SRTP / SRTCP datagrams `peer` wrote from index `from` on that name `ssrc`: RTP (RFC
/// 7983 first byte 128 to 191, RFC 5761 section 4 second byte outside 192 to 223) with that
/// SSRC in its clear header, and RTCP whose first packet's sender SSRC (clear in SRTCP, RFC
/// 3711 section 3.4) is it.
fn datagrams_naming(peer: &Peer, from: usize, ssrc: u32) -> (usize, usize) {
    let (mut rtp, mut rtcp) = (0, 0);
    for d in &peer.written[from..] {
        if d.len() < 12 || !(128..=191).contains(&d[0]) {
            continue;
        }
        let is_rtcp = (192..=223).contains(&d[1]);
        let named = if is_rtcp {
            u32::from_be_bytes([d[4], d[5], d[6], d[7]])
        } else {
            u32::from_be_bytes([d[8], d[9], d[10], d[11]])
        };
        if named == ssrc {
            if is_rtcp {
                rtcp += 1;
            } else {
                rtp += 1;
            }
        }
    }
    (rtp, rtcp)
}

/// `answer` with its video section rejected: port zero, and its mid out of the BUNDLE group
/// (RFC 9143 section 7.3.3: a rejected section is not in the answer's group).
fn reject_video(answer: &str) -> String {
    let video = answer
        .split("\r\nm=")
        .find(|s| s.starts_with("video "))
        .expect("video");
    let mid = video
        .lines()
        .find_map(|l| l.strip_prefix("a=mid:"))
        .expect("a mid")
        .to_owned();
    // The port is whatever the answer's default destination is (9 only while it has no
    // candidate): it becomes zero.
    answer
        .lines()
        .map(|l| match l.strip_prefix("m=video ") {
            Some(rest) => format!(
                "m=video 0 {}",
                rest.split_once(' ').map_or("", |(_, protos)| protos)
            ),
            None => l.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\r\n")
        .lines()
        .map(|l| match l.strip_prefix("a=group:BUNDLE ") {
            Some(mids) => {
                let kept: Vec<&str> = mids.split(' ').filter(|m| *m != mid).collect();
                format!("a=group:BUNDLE {}\r\n", kept.join(" "))
            }
            None => format!("{l}\r\n"),
        })
        .collect()
}

/// RFC 3264 section 6: "the offerer MUST NOT generate media (or RTCP packets) for that media
/// stream" when the answer rejects it (port zero). The video sender sends RTP and sender
/// reports while its section is accepted; after a later answer that rejects the section,
/// nothing that names its SSRC goes out, RTP or RTCP, however long the application writes.
#[test]
fn a_rejected_stream_gets_neither_media_nor_rtcp() -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    // Audio first: the video section is not the BUNDLE tag.
    world.peers[0]
        .pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let sender = world.peers[0].pc.add_track(video_track())?;
    let (offer, _) = world.connect()?;
    let vp8 = payload_type(&offer, "VP8/90000");

    let start = world.peers[0].written.len();
    write(&mut world, sender, vp8, 100, 5)?;
    world.run_for(Duration::from_secs(6), |_| false);
    let (rtp, rtcp) = datagrams_naming(&world.peers[0], start, SSRC);
    assert!(rtp >= 4 && rtcp >= 1, "accepted: {rtp} RTP, {rtcp} RTCP");

    // The answer rejects the video section. What holds the media back is that the
    // transceiver is stopped (W3C webrtc-pc 4.4.1.6, "set a session description": a rejected
    // m= section stops its transceiver; its sender's streams are unbound and say BYE); the
    // section having no transport any more is a second, unstated barrier.
    world.exchange_with(0, |offer| offer.to_owned(), reject_video)?;
    world.run_for(Duration::from_millis(500), |_| false);
    // Stopped, and then gone with the answer (W3C 4.4.1.6): the audio one alone is live.
    let ids: Vec<_> = world.peers[0].pc.get_transceivers().collect();
    let states: Vec<(bool, bool)> = ids
        .into_iter()
        .filter_map(|id| {
            world.peers[0]
                .pc
                .rtp_transceiver(id)
                .map(|t| (t.stopped(), t.is_stopped()))
        })
        .collect();
    let live = states.iter().filter(|(stopping, _)| !stopping).count();
    assert_eq!(
        live, 1,
        "the rejected section's transceiver is not stopped: (stopping, stopped) {states:?}"
    );
    let start = world.peers[0].written.len();
    for n in 0..5u16 {
        let now = world.now;
        if let Some(mut s) = world.peers[0].pc.rtp_sender(sender) {
            let _ = s.write_rtp(
                now,
                rtci::rtp::Packet {
                    header: rtci::rtp::header::Header {
                        version: 2,
                        payload_type: vp8,
                        sequence_number: 300 + n,
                        timestamp: u32::from(300 + n) * 3000,
                        ssrc: SSRC,
                        marker: true,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; 100]),
                },
            );
        }
        world.run_for(Duration::from_millis(20), |_| false);
    }
    world.run_for(Duration::from_secs(10), |_| false);
    assert_eq!(
        datagrams_naming(&world.peers[0], start, SSRC),
        (0, 0),
        "rejected: RTP and RTCP datagrams naming the SSRC"
    );
    Ok(())
}

/// The RTCP datagrams `peer` wrote from index `from` on (RFC 5761 section 4: second byte 192
/// to 223 once RTP and RTCP share a port).
fn rtcp_datagrams(peer: &Peer, from: usize) -> usize {
    peer.written[from..]
        .iter()
        .filter(|d| d.len() >= 8 && (128..=191).contains(&d[0]) && (192..=223).contains(&d[1]))
        .count()
}

/// RFC 8866 sections 6.7.1 and 6.7.4 (RFC 3264 section 5.1): a `recvonly` endpoint, and an
/// `inactive` one, still send RTCP. The answerer has no track, so its section is recvonly; it
/// sends receiver reports for the video it gets. After a later exchange makes the section
/// inactive both ways, RTCP keeps going out from both peers.
#[test]
fn recvonly_and_inactive_endpoints_still_send_rtcp() -> Result<()> {
    use rtci::rtp_transceiver::RTCRtpTransceiverDirection;
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    let sender = world.peers[0].pc.add_track(video_track())?;
    let (offer, answer) = world.connect()?;
    assert!(answer.contains("\r\na=recvonly\r\n"), "{answer}");
    let vp8 = payload_type(&offer, "VP8/90000");
    let start = world.peers[1].written.len();
    write(&mut world, sender, vp8, 100, 5)?;
    world.run_for(Duration::from_secs(8), |_| false);
    assert!(
        rtcp_datagrams(&world.peers[1], start) >= 1,
        "the recvonly endpoint sent no RTCP"
    );

    let transceiver = world.peers[0]
        .pc
        .get_transceivers()
        .next()
        .expect("the transceiver");
    world.peers[0]
        .pc
        .rtp_transceiver(transceiver)
        .expect("the transceiver")
        .set_direction(RTCRtpTransceiverDirection::Inactive)?;
    let (_, answer) = world.exchange(0)?;
    assert!(answer.contains("\r\na=inactive\r\n"), "{answer}");
    world.run_for(Duration::from_millis(500), |_| false);
    let starts = [world.peers[0].written.len(), world.peers[1].written.len()];
    world.run_for(Duration::from_secs(12), |_| false);
    for i in 0..2 {
        assert!(
            rtcp_datagrams(&world.peers[i], starts[i]) >= 1,
            "inactive: peer {i} sent no RTCP"
        );
    }
    Ok(())
}

/// RFC 8830 section 3.1: an RTP stream arriving in a section whose description signals no
/// msid at all "creates a track" of the section's media type, associated by MID (RFC 9143
/// section 9.2), in no MediaStream. The offer reaches the answerer without its `a=msid` and
/// `a=ssrc` lines; the video the offerer sends is still delivered.
#[test]
fn a_section_without_msid_still_gets_its_media() -> Result<()> {
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    let sender = world.peers[0].pc.add_track(video_track())?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let strip = |offer: &str| {
        offer
            .split("\r\n")
            .filter(|l| {
                !l.starts_with("a=msid")
                    && !l.starts_with("a=ssrc:")
                    && !l.starts_with("a=ssrc-group:")
            })
            .map(|l| format!("{l}\r\n"))
            .collect::<String>()
            .trim_end_matches("\r\n")
            .to_owned()
            + "\r\n"
    };
    let (offer, _) = world.exchange_with(0, strip, keep)?;
    assert!(!strip(&offer).contains("msid"), "{}", strip(&offer));
    world.trickle()?;
    world.run("connected", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    let vp8 = payload_type(&offer, "VP8/90000");
    write(&mut world, sender, vp8, 100, 5)?;
    let received = received_payload_types(&world);
    assert!(received.len() >= 4, "{received:?}");
    Ok(())
}

/// RFC 8853 section 5.3.3: the offerer "MUST NOT send RTP streams for rid-ids that the answer
/// removed". The offerer sends three simulcast layers; the answer receives only `a` and `b`.
/// Afterwards what the application writes for `c` goes nowhere: no datagram names its SSRC,
/// while `a` flows.
#[test]
fn no_rtp_goes_out_for_a_simulcast_layer_the_answer_removed() -> Result<()> {
    let ssrc = |i: u32| 0x5e30_0100 + i;
    let encodings = ["a", "b", "c"]
        .iter()
        .enumerate()
        .map(|(i, rid)| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: (*rid).to_owned(),
                ssrc: Some(ssrc(i as u32)),
                ..Default::default()
            },
            active: true,
            ..Default::default()
        })
        .collect();
    let track = MediaStreamTrack::new(
        "s".to_owned(),
        "v".to_owned(),
        "v".to_owned(),
        RtpCodecKind::Video,
        encodings,
    );
    let mut world = World::new(
        Peer::new("10.0.0.1:5000", SettingEngineBuilder::new().build())?,
        Peer::new("10.0.0.2:5000", SettingEngineBuilder::new().build())?,
    );
    let sender = world.peers[0].pc.add_track(track)?;
    world.peers[0].pc.create_data_channel("data", None)?;
    let without_c = |answer: &str| -> String {
        answer
            .split("\r\n")
            .filter(|l| !l.is_empty() && !l.starts_with("a=rid:c "))
            .map(|l| match l.strip_prefix("a=simulcast:") {
                Some(rest) => {
                    let (dir, rids) = rest.split_once(' ').unwrap_or((rest, ""));
                    let kept: Vec<&str> = rids.split(';').filter(|r| *r != "c").collect();
                    format!("a=simulcast:{dir} {}\r\n", kept.join(";"))
                }
                None => format!("{l}\r\n"),
            })
            .collect()
    };
    let (offer, answer) = world.exchange_with(0, keep, without_c)?;
    assert!(offer.contains("a=rid:c send"), "{offer}");
    assert!(answer.contains("a=rid:c recv"), "{answer}");
    world.trickle()?;
    world.run("connected", |peers| {
        peers.iter().all(|p| p.connected() && p.channel.is_some())
    })?;
    let vp8 = payload_type(&offer, "VP8/90000");
    let start = world.peers[0].written.len();
    for n in 0..5u16 {
        for i in [0u32, 2] {
            let now = world.now;
            let mut s = world.peers[0].pc.rtp_sender(sender).expect("the sender");
            let _ = s.write_rtp(
                now,
                rtci::rtp::Packet {
                    header: rtci::rtp::header::Header {
                        version: 2,
                        payload_type: vp8,
                        sequence_number: 100 + n,
                        timestamp: u32::from(100 + n) * 3000,
                        ssrc: ssrc(i),
                        marker: true,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0x10u8; 100]),
                },
            );
        }
        world.run_for(Duration::from_millis(20), |_| false);
    }
    world.run_for(Duration::from_millis(500), |_| false);
    assert!(
        datagrams_naming(&world.peers[0], start, ssrc(0)).0 >= 4,
        "layer a"
    );
    assert_eq!(
        datagrams_naming(&world.peers[0], start, ssrc(2)),
        (0, 0),
        "layer c, which the answer removed"
    );
    Ok(())
}
