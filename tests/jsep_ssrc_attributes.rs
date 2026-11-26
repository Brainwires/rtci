//! RFC 5576 (source-specific media attributes): what a remote description's `a=ssrc` lines
//! do to the receivers, and how SSRCs are chosen.

mod jsep_common;

use std::time::Instant;

use jsep_common::{SESSION, TRANSPORT, TestResult, crlf, default_peer};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::SSRC;

/// A remote offer (session version `version`) of one VP8 section, mid 0, whose source lines
/// are `sources`.
fn video_offer(
    version: u32,
    sources: &str,
) -> Result<RTCSessionDescription, Box<dyn std::error::Error>> {
    let session = SESSION.replace(" 2 IN IP4", &format!(" {version} IN IP4"));
    Ok(RTCSessionDescription::offer(crlf(&format!(
        "{session}a=group:BUNDLE 0\n\
         m=video 9 UDP/TLS/RTP/SAVPF 96\n{TRANSPORT}a=mid:0\na=sendrecv\n\
         a=msid:stream track\na=rtpmap:96 VP8/90000\n{sources}"
    )))?)
}

fn answer(pc: &mut RTCPeerConnection, offer: RTCSessionDescription) -> TestResult {
    let now = Instant::now();
    pc.set_remote_description(now, offer)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer)?;
    Ok(())
}

/// The SSRCs the receiver of the one transceiver expects.
fn receiver_ssrcs(pc: &mut RTCPeerConnection) -> Vec<SSRC> {
    let id = pc.get_receivers().next().expect("a receiver");
    let receiver = pc.rtp_receiver(id).expect("the receiver");
    let mut ssrcs: Vec<SSRC> = receiver.track().ssrcs().collect();
    ssrcs.sort_unstable();
    ssrcs
}

/// RFC 5576 section 5: "the source information signalled in SDP ... may be out of date"; a
/// receiver "MUST" treat it so. Each remote description rebuilds the bindings: the first
/// declares 1111 for the section, the next one 2222 instead, and the receiver then expects
/// 2222 alone; a third with no source lines leaves no declared SSRC behind (the streams are
/// placed by their MID as they arrive).
#[test]
fn source_bindings_are_rebuilt_from_each_remote_description() -> TestResult {
    let mut pc = default_peer()?;
    answer(&mut pc, video_offer(2, "a=ssrc:1111 cname:remote\n")?)?;
    assert_eq!(receiver_ssrcs(&mut pc), vec![1111]);

    answer(&mut pc, video_offer(3, "a=ssrc:2222 cname:remote\n")?)?;
    assert_eq!(receiver_ssrcs(&mut pc), vec![2222]);

    answer(
        &mut pc,
        video_offer(
            4,
            "a=ssrc-group:FID 3333 4444\na=ssrc:3333 cname:remote\na=ssrc:4444 cname:remote\n",
        )?,
    )?;
    assert!(
        !receiver_ssrcs(&mut pc).contains(&2222),
        "{:?}",
        receiver_ssrcs(&mut pc)
    );
    assert!(receiver_ssrcs(&mut pc).contains(&3333));

    answer(&mut pc, video_offer(5, "")?)?;
    assert!(
        receiver_ssrcs(&mut pc).is_empty(),
        "{:?}",
        receiver_ssrcs(&mut pc)
    );
    Ok(())
}

/// RFC 5576 section 4.2: a group "MUST list at least one <ssrc-id> for a group and MAY list
/// any number of additional ones". An `a=ssrc-group:SIM` of three sources is one track with
/// three simulcast streams, each with the RTX flow its `FID` group names and the FEC flow of
/// a `FEC-FR` group of three ids (two sources, one repair flow, RFC 5956 section 4.2); no
/// repair flow is a stream of its own.
#[test]
fn groups_of_three_ids_and_a_sim_group_make_one_track_of_three_streams() -> TestResult {
    let mut pc = default_peer()?;
    answer(
        &mut pc,
        video_offer(
            2,
            "a=ssrc-group:SIM 1001 1002 1003\n\
             a=ssrc-group:FID 1001 2001\n\
             a=ssrc-group:FID 1002 2002\n\
             a=ssrc-group:FID 1003 2003\n\
             a=ssrc-group:FEC-FR 1001 1002 3001\n\
             a=ssrc:1001 cname:remote\na=ssrc:1002 cname:remote\na=ssrc:1003 cname:remote\n\
             a=ssrc:2001 cname:remote\na=ssrc:2002 cname:remote\na=ssrc:2003 cname:remote\n\
             a=ssrc:3001 cname:remote\n",
        )?,
    )?;
    assert_eq!(receiver_ssrcs(&mut pc), vec![1001, 1002, 1003]);
    let id = pc.get_receivers().next().expect("a receiver");
    let receiver = pc.rtp_receiver(id).expect("the receiver");
    let layers: Vec<(Option<SSRC>, Option<SSRC>, Option<SSRC>)> = receiver
        .track()
        .codings()
        .iter()
        .map(|coding| {
            let c = &coding.rtp_coding_parameters;
            (
                c.ssrc,
                c.rtx.as_ref().map(|r| r.ssrc),
                c.fec.as_ref().map(|f| f.ssrc),
            )
        })
        .collect();
    assert_eq!(
        layers,
        vec![
            (Some(1001), Some(2001), Some(3001)),
            (Some(1002), Some(2002), Some(3001)),
            (Some(1003), Some(2003), None),
        ]
    );
    Ok(())
}

/// The number of `a=ssrc:<id> cname:` lines of each SSRC of each media section of `sdp`, for
/// every SSRC that has source attributes at all.
fn cname_lines_per_ssrc(sdp: &str) -> Vec<std::collections::BTreeMap<SSRC, usize>> {
    jsep_common::media_sections(sdp)
        .iter()
        .map(|section| {
            let mut counts = std::collections::BTreeMap::new();
            for line in section {
                let Some((id, attribute)) = line
                    .strip_prefix("a=ssrc:")
                    .and_then(|rest| rest.split_once(' '))
                else {
                    continue;
                };
                let id: SSRC = id.parse().expect("an ssrc-id");
                let count = counts.entry(id).or_insert(0);
                if attribute.starts_with("cname:") {
                    *count += 1;
                }
            }
            counts
        })
        .collect()
}

/// RFC 5576 section 6.1: "The "cname" attribute MUST NOT occur more than once for the same
/// ssrc-id within a given media stream", and it "is REQUIRED to be present if any source
/// attributes are present for a source". In the offer and the answer this endpoint writes,
/// each SSRC with source attributes has exactly one `cname` line: the media, RTX and FlexFEC
/// SSRCs of a sender in two streams, the three simulcast SSRCs of another (source lines
/// written for simulcast, `with_write_ssrc_attributes_for_simulcast`), and the answerer's
/// own sender. The section on the receiver says nothing of a duplicate it receives; a remote
/// description that repeats a `cname` line is applied, its SSRC declared once.
#[test]
fn a_generated_description_gives_each_ssrc_one_cname_line() -> TestResult {
    use rtci::peer_connection::RTCPeerConnectionBuilder;
    use rtci::peer_connection::configuration::media_engine::{
        MIME_TYPE_FLEX_FEC03, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
    };
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use rtci::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
        RtpCodecKind,
    };
    use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};

    let peer = || -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
        let mut media_engine = MediaEngine::default();
        for (mime_type, fmtp, payload_type) in [
            (MIME_TYPE_VP8, "", 96),
            (MIME_TYPE_RTX, "apt=96", 97),
            (MIME_TYPE_FLEX_FEC03, "repair-window=10000000", 49),
        ] {
            media_engine.register_codec(
                RTCRtpCodecParameters {
                    rtp_codec: RTCRtpCodec {
                        mime_type: mime_type.to_owned(),
                        clock_rate: 90000,
                        channels: 0,
                        sdp_fmtp_line: fmtp.to_owned(),
                        rtcp_feedback: vec![],
                    },
                    payload_type,
                },
                RtpCodecKind::Video,
            )?;
        }
        Ok(RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_write_ssrc_attributes_for_simulcast(true)
                    .build(),
            )
            .build(Instant::now())?)
    };
    let mut offerer = peer()?;
    offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec!["first".to_owned(), "second".to_owned()],
            send_encodings: vec![RTCRtpEncodingParameters {
                active: true,
                ..Default::default()
            }],
        }),
    )?;
    offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec!["layers".to_owned()],
            send_encodings: ["q", "h", "f"]
                .into_iter()
                .map(|rid| RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        rid: rid.to_owned(),
                        ..Default::default()
                    },
                    active: true,
                    ..Default::default()
                })
                .collect(),
        }),
    )?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    let counts = cname_lines_per_ssrc(&offer.sdp);
    assert_eq!(2, counts.len(), "{}", offer.sdp);
    // The test reaches the rule: media, RTX and FEC SSRCs in the first section (with its
    // FID and FEC-FR groups), three or more simulcast SSRCs in the second.
    assert!(offer.sdp.contains("a=ssrc-group:FID "), "{}", offer.sdp);
    assert!(offer.sdp.contains("a=ssrc-group:FEC-FR "), "{}", offer.sdp);
    assert!(counts[0].len() >= 3, "{}", offer.sdp);
    assert!(counts[1].len() >= 3, "{}", offer.sdp);
    for (index, section) in counts.iter().enumerate() {
        for (ssrc, cnames) in section {
            assert_eq!(
                1, *cnames,
                "offer section {index}: ssrc {ssrc} has {cnames} cname lines\n{}",
                offer.sdp
            );
        }
    }

    let mut answerer = peer()?;
    answerer.set_remote_description(now, RTCSessionDescription::offer(offer.sdp.clone())?)?;
    answerer.add_track(jsep_common::video_track("back", 0x0B0B_0B0B))?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer.clone())?;
    let counts = cname_lines_per_ssrc(&answer.sdp);
    assert!(
        counts
            .iter()
            .any(|section| section.contains_key(&0x0B0B_0B0B)),
        "the answer describes its sender: {}",
        answer.sdp
    );
    for (index, section) in counts.iter().enumerate() {
        for (ssrc, cnames) in section {
            assert_eq!(
                1, *cnames,
                "answer section {index}: ssrc {ssrc} has {cnames} cname lines\n{}",
                answer.sdp
            );
        }
    }

    // A later offer (nothing changed) writes the same.
    let later = offerer.create_offer(None)?;
    for (index, section) in cname_lines_per_ssrc(&later.sdp).iter().enumerate() {
        for (ssrc, cnames) in section {
            assert_eq!(
                1, *cnames,
                "later offer section {index}: ssrc {ssrc}\n{}",
                later.sdp
            );
        }
    }

    // Received: a description that repeats the cname line is applied.
    let mut receiver = default_peer()?;
    crate::answer(
        &mut receiver,
        video_offer(
            1,
            "a=ssrc:1111 cname:repeated\na=ssrc:1111 cname:repeated\n",
        )?,
    )?;
    assert_eq!(vec![1111], receiver_ssrcs(&mut receiver));
    Ok(())
}
