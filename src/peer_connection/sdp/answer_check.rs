//! The checks a remote answer has to pass against the offer it answers, before any of it is
//! applied (RFC 9429 section 5.8.3: "If the session description is of type 'pranswer' or
//! 'answer', the following additional checks are applied").
//!
//! Nothing here changes state: `set_remote_description` runs it while the connection is still
//! exactly as it was, so a refused answer leaves the offer pending and can be followed by a
//! correct one.

use super::{ATTR_KEY_BUNDLE_ONLY, get_mid_value, is_rejected_media};
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use sdp::description::media::MediaDescription;
use sdp::description::session::{ATTR_KEY_GROUP, SessionDescription};
use shared::error::{Error, Result};
use std::collections::HashSet;

const ATTR_KEY_RTCP_FB: &str = "rtcp-fb";
const ATTR_KEY_RTPMAP: &str = "rtpmap";
/// `a=group` semantics of RFC 9143.
const GROUP_SEMANTICS_BUNDLE: &str = "BUNDLE";

fn mismatch(index: usize, what: impl AsRef<str>) -> Error {
    Error::ErrAnswerDoesNotMatchOffer(format!("m= section {index}: {}", what.as_ref()))
}

/// Every `a=group:BUNDLE` line of a description, each as its identification-tags in order
/// (RFC 9143 section 5: a description may carry several BUNDLE groups).
pub(crate) fn bundle_groups(desc: &SessionDescription) -> Vec<Vec<&str>> {
    desc.attributes
        .iter()
        .filter(|a| a.key == ATTR_KEY_GROUP)
        .filter_map(|a| a.value.as_deref())
        .filter_map(|value| {
            let mut tokens = value.split_whitespace();
            (tokens.next() == Some(GROUP_SEMANTICS_BUNDLE)).then(|| tokens.collect())
        })
        .collect()
}

/// The direction a media section states: its own attribute, else the session's, else
/// `sendrecv` (RFC 8866 section 6.7: "If none of the attributes ... is present, 'sendrecv'
/// SHOULD be assumed as the default").
pub(crate) fn effective_direction(
    desc: &SessionDescription,
    media: &MediaDescription,
) -> RTCRtpTransceiverDirection {
    let from_attributes = |attributes: &[sdp::description::common::Attribute]| {
        attributes
            .iter()
            .map(|a| RTCRtpTransceiverDirection::from(a.key.as_str()))
            .find(|d| *d != RTCRtpTransceiverDirection::Unspecified)
    };
    from_attributes(&media.attributes)
        .or_else(|| from_attributes(&desc.attributes))
        .unwrap_or(RTCRtpTransceiverDirection::Sendrecv)
}

/// Whether `answered` is a direction RFC 3264 section 6.1 allows in answer to `offered`: a
/// sendonly stream is answered recvonly or inactive, a recvonly one sendonly or inactive, an
/// inactive one inactive, and a sendrecv one with any of the four.
fn direction_answers(
    offered: RTCRtpTransceiverDirection,
    answered: RTCRtpTransceiverDirection,
) -> bool {
    use RTCRtpTransceiverDirection::*;
    match offered {
        Sendonly => matches!(answered, Recvonly | Inactive),
        Recvonly => matches!(answered, Sendonly | Inactive),
        Inactive => answered == Inactive,
        _ => true,
    }
}

/// One `a=rtcp-fb` line: the payload type it is for (`None` for the `*` wildcard of RFC 4585
/// section 4.2) and its feedback value, lower-cased with single spaces.
struct Feedback {
    payload_type: Option<String>,
    value: String,
}

fn feedback_lines(media: &MediaDescription) -> Vec<Feedback> {
    media
        .attributes
        .iter()
        .filter(|a| a.key == ATTR_KEY_RTCP_FB)
        .filter_map(|a| a.value.as_deref())
        .filter_map(|value| {
            let mut tokens = value.split_whitespace();
            let payload_type = tokens.next()?;
            let value = tokens.collect::<Vec<_>>().join(" ").to_ascii_lowercase();
            if value.is_empty() {
                return None;
            }
            Some(Feedback {
                payload_type: (payload_type != "*").then(|| payload_type.to_owned()),
                value,
            })
        })
        .collect()
}

/// The encoding name and clock rate (`<name>/<rate>`, lower-cased, channels left out) each
/// payload type of a section is mapped to by `a=rtpmap`.
fn rtpmap_names(media: &MediaDescription) -> Vec<(String, String)> {
    media
        .attributes
        .iter()
        .filter(|a| a.key == ATTR_KEY_RTPMAP)
        .filter_map(|a| a.value.as_deref())
        .filter_map(|value| {
            let (payload_type, encoding) = value.split_once(' ')?;
            let mut parts = encoding.trim().split('/');
            let name = parts.next()?.to_ascii_lowercase();
            let rate = parts.next().unwrap_or_default();
            Some((payload_type.to_owned(), format!("{name}/{rate}")))
        })
        .collect()
}

/// RFC 4585 section 4.2: "The answerer MUST NOT add feedback parameters to a media section or
/// alter values of such parameters"; RFC 9429 section 5.11: "If the answer contains any
/// 'a=rtcp-fb' attributes ... that were not present in the offer, this indicates an error."
///
/// A feedback line of the answer is one the offer had when the offer carries the same value
/// for the wildcard, for the same payload type, or for a payload type the offer maps to the
/// same encoding (an answerer may number a format differently, RFC 3264 section 6.1). An
/// answered wildcard is one the offer had as a wildcard or for every format the answer lists.
/// `trr-int` is each side's own minimum interval (RFC 4585 section 4.2: declarative), so its
/// number is not compared.
fn check_feedback(index: usize, offer: &MediaDescription, answer: &MediaDescription) -> Result<()> {
    let answered = feedback_lines(answer);
    if answered.is_empty() {
        return Ok(());
    }
    let offered = feedback_lines(offer);
    let kind = |value: &str| -> String {
        if value.starts_with("trr-int") {
            "trr-int".to_owned()
        } else {
            value.to_owned()
        }
    };
    let offered_for = |payload_type: Option<&str>, value: &str| -> bool {
        offered.iter().any(|f| {
            kind(&f.value) == kind(value)
                && (f.payload_type.is_none() || f.payload_type.as_deref() == payload_type)
        })
    };
    let offer_names = rtpmap_names(offer);
    let answer_names = rtpmap_names(answer);
    let name_of = |names: &[(String, String)], payload_type: &str| -> Option<String> {
        names
            .iter()
            .find(|(pt, _)| pt == payload_type)
            .map(|(_, name)| name.clone())
    };
    // The offer's payload types an answered payload type may stand for: the same number when
    // the offer lists it, else every offered number of the same encoding.
    let offered_payload_types = |payload_type: &str| -> Vec<String> {
        if offer.media_name.formats.iter().any(|f| f == payload_type) {
            return vec![payload_type.to_owned()];
        }
        let Some(name) = name_of(&answer_names, payload_type) else {
            return vec![];
        };
        offer_names
            .iter()
            .filter(|(_, offered_name)| *offered_name == name)
            .map(|(pt, _)| pt.clone())
            .collect()
    };

    for feedback in &answered {
        let allowed = match &feedback.payload_type {
            Some(payload_type) => {
                offered_for(None, &feedback.value)
                    || offered_payload_types(payload_type)
                        .iter()
                        .any(|pt| offered_for(Some(pt), &feedback.value))
            }
            None => {
                offered_for(None, &feedback.value)
                    || (!answer.media_name.formats.is_empty()
                        && answer.media_name.formats.iter().all(|format| {
                            offered_payload_types(format)
                                .iter()
                                .any(|pt| offered_for(Some(pt), &feedback.value))
                        }))
            }
        };
        if !allowed {
            return Err(mismatch(
                index,
                format!(
                    "a=rtcp-fb:{} {} was not in the offer",
                    feedback.payload_type.as_deref().unwrap_or("*"),
                    feedback.value
                ),
            ));
        }
    }
    Ok(())
}

/// Checks a remote answer (or provisional answer) against the local offer it answers.
///
/// - RFC 3264 section 6: "the answer MUST contain exactly the same number of 'm=' lines as the
///   offer", in the offer's order, each with the offer's media type; RFC 9429 section 5.8.3
///   adds the `<proto>` of each m= line.
/// - RFC 5888 section 9.1: the identification-tag of each m= line is the offer's.
/// - RFC 3264 section 6: a stream offered with port zero stays rejected; section 6.1: the
///   answered direction is one the offered direction allows.
/// - RFC 9143 section 7.4: "the offerer MUST check that any bundled 'm=' section in the answer
///   was indicated as bundled in the corresponding offer"; section 7.3: a group only if the
///   offer had one, no section moved between groups, no rejected section in a group
///   (section 7.3.3).
/// - RFC 4585 section 4.2 and RFC 9429 section 5.11: no `a=rtcp-fb` the offer did not have.
///
/// The first difference is returned as [`Error::ErrAnswerDoesNotMatchOffer`].
pub(crate) fn check_answer_against_offer(
    offer: &SessionDescription,
    answer: &SessionDescription,
) -> Result<()> {
    if offer.media_descriptions.len() != answer.media_descriptions.len() {
        return Err(Error::ErrAnswerDoesNotMatchOffer(format!(
            "the offer has {} m= sections, the answer {}",
            offer.media_descriptions.len(),
            answer.media_descriptions.len()
        )));
    }

    for (index, (offered, answered)) in offer
        .media_descriptions
        .iter()
        .zip(&answer.media_descriptions)
        .enumerate()
    {
        if offered.media_name.media != answered.media_name.media {
            return Err(mismatch(
                index,
                format!(
                    "media type {} answered with {}",
                    offered.media_name.media, answered.media_name.media
                ),
            ));
        }
        if offered.media_name.protos != answered.media_name.protos {
            return Err(mismatch(
                index,
                format!(
                    "proto {} answered with {}",
                    offered.media_name.protos.join("/"),
                    answered.media_name.protos.join("/")
                ),
            ));
        }
        let (offered_mid, answered_mid) = (get_mid_value(offered), get_mid_value(answered));
        if offered_mid != answered_mid {
            return Err(mismatch(
                index,
                format!(
                    "mid {} answered with {}",
                    offered_mid.map_or("(none)", String::as_str),
                    answered_mid.map_or("(none)", String::as_str)
                ),
            ));
        }

        if is_rejected_media(answered) {
            continue;
        }
        if is_rejected_media(offered) {
            return Err(mismatch(index, "offered with port zero, answered accepted"));
        }
        // RFC 9143 section 7.3.3 leaves bundle-only to offers: an answered section with port
        // zero is rejected, which `is_rejected_media` reads as kept when the attribute is there.
        if answered.media_name.port.value == 0 && answered.has_attribute(ATTR_KEY_BUNDLE_ONLY) {
            return Err(mismatch(index, "a=bundle-only with port zero in an answer"));
        }

        let offered_direction = effective_direction(offer, offered);
        let answered_direction = effective_direction(answer, answered);
        if !direction_answers(offered_direction, answered_direction) {
            return Err(mismatch(
                index,
                format!("{offered_direction} answered with {answered_direction}"),
            ));
        }

        check_feedback(index, offered, answered)?;
    }

    // BUNDLE groups: each of the answer's is a subset of one of the offer's, and holds no
    // rejected section.
    let offered_groups: Vec<HashSet<&str>> = bundle_groups(offer)
        .into_iter()
        .map(|group| group.into_iter().collect())
        .collect();
    for group in bundle_groups(answer) {
        let fits = offered_groups
            .iter()
            .any(|offered| group.iter().all(|mid| offered.contains(mid)));
        if !fits {
            return Err(Error::ErrAnswerDoesNotMatchOffer(format!(
                "a=group:BUNDLE {} bundles a section the offer did not bundle with the others",
                group.join(" ")
            )));
        }
        for mid in group {
            let rejected = answer
                .media_descriptions
                .iter()
                .find(|m| get_mid_value(m).is_some_and(|v| v == mid))
                .is_none_or(is_rejected_media);
            if rejected {
                return Err(Error::ErrAnswerDoesNotMatchOffer(format!(
                    "a=group:BUNDLE names {mid}, which the answer rejects or does not have"
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(sdp: &str) -> SessionDescription {
        let mut reader = std::io::Cursor::new(sdp.as_bytes());
        SessionDescription::unmarshal(&mut reader).expect("test SDP parses")
    }

    const HEAD: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";

    fn video(mid: &str, extra: &str) -> String {
        format!(
            "m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\nc=IN IP4 0.0.0.0\r\na=mid:{mid}\r\n\
a=rtpmap:96 VP8/90000\r\na=rtpmap:97 H264/90000\r\n{extra}"
        )
    }

    fn check(offer: &str, answer: &str) -> Result<()> {
        check_answer_against_offer(&parse(offer), &parse(answer))
    }

    #[test]
    fn feedback_of_the_answer_is_a_subset_of_the_offers() {
        let offer = format!(
            "{HEAD}{}",
            video(
                "0",
                "a=rtcp-fb:96 nack\r\na=rtcp-fb:96 nack pli\r\na=rtcp-fb:* transport-cc\r\n"
            )
        );
        // A subset, the wildcard used for one payload type, and case and spacing differences.
        let subset = format!(
            "{HEAD}{}",
            video(
                "0",
                "a=rtcp-fb:96 NACK  PLI\r\na=rtcp-fb:97 transport-cc\r\n"
            )
        );
        assert!(check(&offer, &subset).is_ok());

        // The offer had `nack` for 96 only.
        let other_format = format!("{HEAD}{}", video("0", "a=rtcp-fb:97 nack\r\n"));
        assert!(matches!(
            check(&offer, &other_format),
            Err(Error::ErrAnswerDoesNotMatchOffer(_))
        ));
        // A wildcard in the answer needs the value for every answered format.
        let wildcard = format!("{HEAD}{}", video("0", "a=rtcp-fb:* nack\r\n"));
        assert!(check(&offer, &wildcard).is_err());
        let offered_wildcard = format!("{HEAD}{}", video("0", "a=rtcp-fb:* transport-cc\r\n"));
        assert!(check(&offer, &offered_wildcard).is_ok());
        // A value the offer never had.
        let added = format!("{HEAD}{}", video("0", "a=rtcp-fb:96 ccm fir\r\n"));
        assert!(check(&offer, &added).is_err());
    }

    #[test]
    fn feedback_follows_a_format_the_answer_renumbers() {
        let offer = format!("{HEAD}{}", video("0", "a=rtcp-fb:96 nack\r\n"));
        // The answerer calls VP8 payload type 100.
        let answer = format!(
            "{HEAD}m=video 9 UDP/TLS/RTP/SAVPF 100\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n\
a=rtpmap:100 VP8/90000\r\na=rtcp-fb:100 nack\r\n"
        );
        assert!(check(&offer, &answer).is_ok());
        let h264 = format!(
            "{HEAD}m=video 9 UDP/TLS/RTP/SAVPF 100\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n\
a=rtpmap:100 H264/90000\r\na=rtcp-fb:100 nack\r\n"
        );
        assert!(check(&offer, &h264).is_err());
    }

    #[test]
    fn a_trr_int_of_the_answer_needs_one_in_the_offer_not_the_same_number() {
        let offer = format!("{HEAD}{}", video("0", "a=rtcp-fb:* trr-int 100\r\n"));
        let answer = format!("{HEAD}{}", video("0", "a=rtcp-fb:* trr-int 500\r\n"));
        assert!(check(&offer, &answer).is_ok());
        let bare = format!("{HEAD}{}", video("0", ""));
        assert!(check(&bare, &answer).is_err());
    }

    #[test]
    fn a_section_without_a_direction_attribute_is_sendrecv() {
        let offer = format!("{HEAD}{}", video("0", "a=sendonly\r\n"));
        let unstated = format!("{HEAD}{}", video("0", ""));
        // sendonly answered sendrecv (no attribute) is refused; the reverse is fine.
        assert!(check(&offer, &unstated).is_err());
        assert!(check(&unstated, &offer).is_ok());
        // A session-level direction is the section's when it has none.
        let session_recvonly = format!("{HEAD}a=recvonly\r\n{}", video("0", ""));
        assert!(check(&offer, &session_recvonly).is_ok());
    }

    #[test]
    fn several_bundle_groups_are_each_checked_against_the_offers() {
        let sections = format!("{}{}{}", video("a", ""), video("b", ""), video("c", ""));
        let offer =
            format!("{HEAD}a=group:LS a b\r\na=group:BUNDLE a b\r\na=group:BUNDLE c\r\n{sections}");
        let same = format!("{HEAD}a=group:BUNDLE a b\r\na=group:BUNDLE c\r\n{sections}");
        assert!(check(&offer, &same).is_ok());
        let subset = format!("{HEAD}a=group:BUNDLE a\r\n{sections}");
        assert!(check(&offer, &subset).is_ok());
        // `c` was bundled, but not with `a`.
        let merged = format!("{HEAD}a=group:BUNDLE a c\r\n{sections}");
        assert!(check(&offer, &merged).is_err());
        assert_eq!(
            bundle_groups(&parse(&offer)),
            vec![vec!["a", "b"], vec!["c"]]
        );
    }
}
