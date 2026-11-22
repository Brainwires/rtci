//! Browser offers through the strict parser, the serializer, `validate` and the typed
//! accessors.
//!
//! * `safari_offer.sdp`: captured from Safari 26.5.2 (audio, video, a data channel).
//! * `firefox_152_simulcast_offer.sdp`: captured from Firefox 152 (three simulcast layers);
//!   the same file as `tests/testdata/firefox_152_simulcast_offer.sdp`.
//! * `chrome_format_offer.sdp`: NOT a capture. It is written in the form libwebrtc gives an
//!   offer (the lines Chrome writes that the two captures lack: gathered candidates of
//!   every type, `a=ssrc ... msid`, simulcast, the dependency-descriptor extension), with
//!   made-up identifiers and documentation addresses.

use std::io::Cursor;

use shared::error::Result;

use super::session::*;
use crate::attribute::*;
use crate::description::common::BandwidthKind;
use crate::direction::Direction;
use crate::util::ConnectionRole;

const SAFARI: &str = include_str!("testdata/safari_offer.sdp");
const FIREFOX: &str = include_str!("testdata/firefox_152_simulcast_offer.sdp");
const CHROME_FORMAT: &str = include_str!("testdata/chrome_format_offer.sdp");

fn parse(sdp: &str) -> Result<SessionDescription> {
    SessionDescription::unmarshal(&mut Cursor::new(sdp.as_bytes()))
}

/// The text with every line ending in CRLF.
fn crlf(sdp: &str) -> String {
    sdp.replace("\r\n", "\n").replace('\n', "\r\n")
}

#[test]
fn browser_offers_parse_strictly_and_are_written_back_byte_for_byte() -> Result<()> {
    for (name, offer) in [
        ("safari", SAFARI),
        ("firefox", FIREFOX),
        ("chrome format", CHROME_FORMAT),
    ] {
        let parsed = parse(offer).unwrap_or_else(|e| panic!("{name}: {e}"));
        let written = parsed.marshal();
        assert_eq!(written, crlf(offer), "{name}");
        // And what was written parses to the same text again.
        assert_eq!(parse(&written)?.marshal(), written, "{name}");
    }
    Ok(())
}

#[test]
fn browser_offers_validate() -> Result<()> {
    for (name, offer) in [
        ("safari", SAFARI),
        ("firefox", FIREFOX),
        ("chrome format", CHROME_FORMAT),
    ] {
        parse(offer)?
            .validate()
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    Ok(())
}

/// Every typed accessor succeeds on every section, and each typed value that has one
/// canonical form prints back as the line it came from.
#[test]
fn every_attribute_of_a_browser_offer_has_a_typed_reading() -> Result<()> {
    fn same<T: TypedAttribute>(value: &str) {
        let parsed = T::parse(value).unwrap_or_else(|e| panic!("a={}:{value}: {e}", T::NAME));
        assert_eq!(parsed.to_string(), value, "a={}", T::NAME);
    }

    for (name, offer) in [
        ("safari", SAFARI),
        ("firefox", FIREFOX),
        ("chrome format", CHROME_FORMAT),
    ] {
        let parsed = parse(offer)?;
        let levels = std::iter::once(&parsed.attributes)
            .chain(parsed.media_descriptions.iter().map(|m| &m.attributes));
        let mut known = 0usize;
        for attribute in levels.flatten() {
            let Some(value) = attribute.value.as_deref() else {
                continue;
            };
            known += 1;
            match attribute.key.as_str() {
                "group" => same::<Group>(value),
                "mid" => same::<Mid>(value),
                "msid" => same::<Msid>(value),
                "ssrc" => same::<Ssrc>(value),
                "ssrc-group" => same::<SsrcGroup>(value),
                "rid" => same::<Rid>(value),
                "simulcast" => same::<Simulcast>(value),
                "extmap" => same::<crate::extmap::ExtMap>(value),
                "rtcp" => same::<Rtcp>(value),
                "rtcp-fb" => same::<RtcpFb>(value),
                "rtpmap" => same::<RtpMap>(value),
                "fmtp" => same::<Fmtp>(value),
                "candidate" => same::<Candidate>(value),
                "ice-ufrag" => same::<IceUfrag>(value),
                "ice-pwd" => same::<IcePwd>(value),
                "ice-options" => same::<IceOptions>(value),
                "fingerprint" => same::<Fingerprint>(value),
                "setup" => same::<Setup>(value),
                "sctp-port" => same::<SctpPort>(value),
                "max-message-size" => same::<MaxMessageSize>(value),
                "imageattr" => same::<ImageAttr>(value),
                // Chrome writes a space after the colon, which the typed form drops.
                "msid-semantic" => {
                    MsidSemantic::parse(value)?;
                }
                other => panic!("{name}: no typed reading for a={other}"),
            }
        }
        assert!(known > 50, "{name}: {known}");
    }
    Ok(())
}

#[test]
fn the_safari_offer_reads_as_audio_video_and_data() -> Result<()> {
    let offer = parse(SAFARI)?;
    assert_eq!(offer.origin.username, "-");
    assert_eq!(offer.session_name, "-");
    assert_eq!(offer.bundle_groups()?[0].mids, vec!["0", "1", "2"]);
    assert!(offer.extmap_allow_mixed()?);
    assert_eq!(offer.msid_semantic()?.unwrap().semantic, "WMS");
    assert_eq!(offer.direction()?, None);

    let audio = &offer.media_descriptions[0];
    assert_eq!(audio.mid()?.unwrap().as_str(), "0");
    assert_eq!(audio.direction()?, Some(Direction::SendRecv));
    assert_eq!(audio.setup()?.unwrap().0, ConnectionRole::Actpass);
    assert_eq!(audio.ice_ufrag()?.unwrap().as_str(), "A4sp");
    assert_eq!(
        audio.ice_pwd()?.unwrap().as_str(),
        "NtRew5Uit024CmNLovX4++t4"
    );
    assert!(audio.ice_options()?.unwrap().contains("trickle"));
    let fingerprint = &audio.fingerprints()?[0];
    assert_eq!(fingerprint.hash_function, "sha-256");
    assert_eq!(fingerprint.bytes.len(), 32);
    assert_eq!(fingerprint.bytes[0], 0x6E);
    assert!(audio.rtcp_mux()? && audio.rtcp_rsize()?);
    assert!(!audio.rtcp_mux_only()?);
    let rtcp = audio.rtcp()?.unwrap();
    assert_eq!(
        (rtcp.port, rtcp.address.unwrap().address.as_str()),
        (9, "0.0.0.0")
    );
    let opus = &audio.rtpmaps()?[0];
    assert_eq!(
        (opus.payload_type, opus.clock_rate, opus.channels),
        (111, 48000, Some(2))
    );
    assert!(opus.is_encoding("OPUS"));
    let fmtp = &audio.fmtps()?[0];
    assert_eq!(
        fmtp.parameter_list(),
        vec![("minptime", Some("10")), ("useinbandfec", Some("1"))]
    );
    assert_eq!(audio.msids()?[0].id, "-");
    let ssrcs = audio.ssrcs()?;
    assert_eq!(ssrcs[0].id, 4124696349);
    assert_eq!(ssrcs[0].cname(), Some("c5QoiALq+DrR4NJX"));
    assert_eq!(ssrcs[1].msid().unwrap()?.id, "-");
    assert_eq!(audio.extmaps()?.len(), 4);
    assert!(audio.candidates()?.is_empty());
    assert_eq!(audio.bandwidth_of(BandwidthKind::ApplicationSpecific), None);

    let video = &offer.media_descriptions[1];
    assert_eq!(video.ssrc_groups()?[0].semantics, "FID");
    assert_eq!(video.ssrc_groups()?[0].ssrcs, vec![1698465521, 1478334356]);
    let feedback = video.rtcp_fbs()?;
    assert!(feedback.iter().any(|fb| fb.kind() == RtcpFbKind::GoogRemb));
    assert!(
        feedback
            .iter()
            .any(|fb| fb.kind() == RtcpFbKind::TransportCc)
    );
    assert!(feedback.iter().any(|fb| fb.kind() == RtcpFbKind::CcmFir));
    assert!(feedback.iter().any(|fb| fb.kind() == RtcpFbKind::NackPli));
    assert!(feedback.iter().all(|fb| fb.kind() != RtcpFbKind::Other));
    // The codecs keep their fmtp text whole and their feedback in order.
    let codecs = video.codecs();
    assert_eq!(codecs[&96].name, "H264");
    assert_eq!(
        codecs[&96].rtcp_feedback,
        vec!["goog-remb", "transport-cc", "ccm fir", "nack", "nack pli"]
    );
    assert_eq!(
        codecs[&96].fmtp,
        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640c1f"
    );
    assert_eq!(codecs[&97].fmtp, "apt=96");

    let data = &offer.media_descriptions[2];
    assert_eq!(data.media_name.formats, vec!["webrtc-datachannel"]);
    assert_eq!(data.sctp_port()?.unwrap().0, 5000);
    assert!(data.max_message_size()?.is_some());
    assert_eq!(data.direction()?, None);
    Ok(())
}

#[test]
fn the_firefox_offer_reads_as_simulcast_video_and_audio() -> Result<()> {
    let offer = parse(FIREFOX)?;
    assert_eq!(offer.origin.username, "mozilla...THIS_IS_SDPARTA-99.0");
    // Firefox writes these at the session level.
    assert_eq!(offer.direction()?, Some(Direction::SendRecv));
    assert_eq!(offer.fingerprints()?.len(), 1);
    assert!(offer.ice_options()?.unwrap().contains("trickle"));
    assert_eq!(offer.msid_semantic()?.unwrap().ids, vec!["*"]);
    assert_eq!(offer.bundle_groups()?[0].mids, vec!["0", "1"]);

    let video = &offer.media_descriptions[0];
    let extmaps = video.extmaps()?;
    let rid_extension = extmaps
        .iter()
        .find(|e| {
            e.uri
                .as_ref()
                .is_some_and(|u| u.as_str() == crate::extmap::SDES_RTP_STREAM_ID_URI)
        })
        .unwrap();
    assert_eq!(rid_extension.direction, Direction::SendOnly);
    assert!(video.extmap_allow_mixed()?);
    let rids = video.rids()?;
    assert_eq!(
        rids.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        vec!["h", "m", "l"]
    );
    assert!(
        rids.iter()
            .all(|r| r.direction == RidDirection::Send && r.formats.is_empty())
    );
    let simulcast = video.simulcast()?.unwrap();
    assert_eq!(simulcast.rids().collect::<Vec<_>>(), vec!["h", "m", "l"]);
    assert!(simulcast.recv.is_empty());
    assert_eq!(video.ssrc_groups()?.len(), 3);
    assert_eq!(video.ssrcs()?.len(), 6);
    let msid = &video.msids()?[0];
    assert_eq!(msid.id, "-");
    assert_eq!(
        msid.appdata.as_deref(),
        Some("{aea1c6e2-84b9-4fa0-b786-abff665a9575}")
    );
    assert_eq!(video.fmtps()?[0].parameter("max-fs"), Some("12288"));
    assert_eq!(video.fmtps()?[0].parameter("MAX-FR"), Some("60"));
    assert_eq!(
        video.ice_pwd()?.unwrap().as_str(),
        "a5e919b107fc0ee2dbcf909c6b552dc6"
    );

    let audio = &offer.media_descriptions[1];
    assert_eq!(audio.mid()?.unwrap().as_str(), "1");
    // RFC 4733 events: a parameter without a name.
    let events = audio
        .fmtps()?
        .into_iter()
        .find(|f| f.format == "101")
        .unwrap();
    assert_eq!(events.parameter_list(), vec![("0-15", None)]);
    assert_eq!(audio.rtpmaps()?[1].channels, Some(1));
    Ok(())
}

#[test]
fn the_chrome_format_offer_reads_candidates_and_simulcast() -> Result<()> {
    let offer = parse(CHROME_FORMAT)?;
    assert_eq!(
        offer.msid_semantic()?.unwrap().ids,
        vec!["7c1f0a52-6b1e-4e0c-9b55-0c2d2a1f6e11"]
    );

    let audio = &offer.media_descriptions[0];
    let candidates = audio.candidates()?;
    assert_eq!(
        candidates
            .iter()
            .map(|c| c.typ.as_str())
            .collect::<Vec<_>>(),
        vec!["host", "host", "srflx", "host", "host", "relay"]
    );
    assert_eq!(candidates[1].address, "2001:db8:1::10");
    assert_eq!(candidates[2].related_address.as_deref(), Some("192.0.2.10"));
    assert_eq!(candidates[2].related_port, Some(51472));
    assert_eq!(candidates[3].transport, "tcp");
    assert_eq!(candidates[3].extension("tcptype"), Some("active"));
    assert!(candidates[4].address.ends_with(".local"));
    assert_eq!(candidates[4].extension("network-cost"), Some("999"));
    assert_eq!(candidates[5].extension("network-id"), Some("1"));
    assert!(!audio.end_of_candidates()?);
    assert_eq!(
        audio.ssrcs()?[1].msid().unwrap()?.appdata.as_deref(),
        Some("1a9e2d57-3c0f-4c38-9d8e-5b6a7c8d9e0f")
    );

    let video = &offer.media_descriptions[1];
    let h264 = video
        .fmtps()?
        .into_iter()
        .find(|f| f.format == "100")
        .unwrap();
    assert_eq!(h264.parameter("profile-level-id"), Some("42e01f"));
    assert_eq!(h264.parameter("packetization-mode"), Some("1"));
    assert_eq!(video.rids()?.len(), 3);
    assert_eq!(video.simulcast()?.unwrap().send.len(), 3);
    assert!(video.extmaps()?.iter().all(|e| e.is_element_id()));

    let data = &offer.media_descriptions[2];
    assert_eq!(data.max_message_size()?.unwrap().0, 262144);
    Ok(())
}

/// A small deterministic generator (xorshift64*), so that the mutations below are the same
/// on every run.
struct Mutator(u64);

impl Mutator {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    /// One edit of `lines`: drop, repeat, move or cut a line, or change one of its bytes.
    fn mutate(&mut self, lines: &mut Vec<String>) {
        if lines.is_empty() {
            return;
        }
        let at = self.below(lines.len());
        match self.below(7) {
            0 => {
                lines.remove(at);
            }
            1 => lines.insert(at, lines[at].clone()),
            2 => {
                let to = self.below(lines.len());
                lines.swap(at, to);
            }
            3 => {
                let line = lines[at].as_bytes();
                let cut = self.below(line.len() + 1);
                lines[at] = String::from_utf8_lossy(&line[..cut]).into_owned();
            }
            4 => {
                let mut line = lines[at].clone().into_bytes();
                if !line.is_empty() {
                    let i = self.below(line.len());
                    const REPLACEMENTS: &[u8] = b" :;,=/-~*0a\t[]\0\r";
                    line[i] = REPLACEMENTS[self.below(REPLACEMENTS.len())];
                }
                lines[at] = String::from_utf8_lossy(&line).into_owned();
            }
            5 => {
                let mut line = lines[at].clone().into_bytes();
                let i = self.below(line.len() + 1);
                line.insert(i, b" 9:a/"[self.below(5)]);
                lines[at] = String::from_utf8_lossy(&line).into_owned();
            }
            _ => lines.insert(at, String::new()),
        }
    }
}

/// What the fuzz target `description_roundtrip` checks, run here on a few thousand mutations
/// of the browser offers: nothing panics, what the strict parser accepts is written as text
/// it accepts again, that text is a fixed point, and the same holds for the lenient parser.
#[test]
fn mutated_browser_offers_never_break_the_parse_and_marshal_fixed_point() {
    let lenient = ParseOptions::lenient();
    let mut mutator = Mutator(0x9E37_79B9_7F4A_7C15);
    let (mut accepted, mut refused) = (0usize, 0usize);

    for offer in [SAFARI, FIREFOX, CHROME_FORMAT] {
        let original: Vec<String> = offer.lines().map(str::to_owned).collect();
        for _ in 0..1500 {
            let mut lines = original.clone();
            for _ in 0..=mutator.below(3) {
                mutator.mutate(&mut lines);
            }
            let text = lines.join("\r\n");

            match parse(&text) {
                Ok(parsed) => {
                    accepted += 1;
                    let written = parsed.marshal();
                    let again = parse(&written)
                        .unwrap_or_else(|e| panic!("strict output refused ({e}):\n{written}"));
                    assert_eq!(again.marshal(), written);
                    // Reading every attribute never panics, whatever it holds.
                    let _ = parsed.validate();
                    for media in &parsed.media_descriptions {
                        let _ = media.codecs();
                        let _ = media.candidates();
                        let _ = media.rids();
                        let _ = media.simulcast();
                        let _ = media.imageattrs();
                    }
                }
                Err(_) => refused += 1,
            }
            if let Ok(parsed) = SessionDescription::parse_with_options(&text, &lenient) {
                let written = parsed.marshal();
                let again = SessionDescription::parse_with_options(&written, &lenient)
                    .unwrap_or_else(|e| panic!("lenient output refused ({e}):\n{written}"));
                assert_eq!(again.marshal(), written);
            }
        }
    }
    // The mutations reach both sides of the parser.
    assert!(accepted > 500, "{accepted} accepted");
    assert!(refused > 500, "{refused} refused");
}
