//! RTP header extension control (webrtc-extensions section 4): a transceiver's
//! `[[HeaderExtensionsToNegotiate]]` with a direction per extension, the validation of
//! `setHeaderExtensionsToNegotiate`, and `[[NegotiatedHeaderExtensions]]` as an answer sets
//! them.

use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_sender::{RTCRtpHeaderExtensionToNegotiate, RtpCodecKind};
use sdp::MediaDescription;
use shared::error::{Error, Result};

/// Extensions the engine cannot do without when they are negotiated at all: the BUNDLE
/// media identification (RFC 8843 section 9.2: "MUST ... use the SDES item"). An application
/// may not make it anything but "sendrecv" (webrtc-extensions 4.2: "mandatory-to-use").
const MANDATORY_TO_USE: &[&str] = &[rtp::extension::SDES_MID_URI];

/// Extensions WebRTC endpoints must implement (RFC 8834 section 5.2: the mid, and for audio
/// the client-to-mixer audio level of RFC 6464): an application may restrict their direction
/// but not stop them (webrtc-extensions 4.2).
const MANDATORY_TO_IMPLEMENT: &[&str] = &[
    rtp::extension::SDES_MID_URI,
    rtp::extension::AUDIO_LEVEL_URI,
];

/// W3C webrtc-pc 5.2 / 5.3 `getParameters().headerExtensions`: keeps the extensions
/// `negotiated` (a transceiver's `[[NegotiatedHeaderExtensions]]`) lists in a direction that
/// sends (`sending`) or receives; nothing before an answer was applied.
pub(crate) fn retain_negotiated(
    extensions: &mut Vec<crate::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionParameters>,
    negotiated: &[RTCRtpHeaderExtensionToNegotiate],
    sending: bool,
) {
    extensions.retain(|extension| {
        negotiated.iter().any(|n| {
            n.uri == extension.uri
                && if sending {
                    n.direction.has_send()
                } else {
                    n.direction.has_recv()
                }
        })
    });
}

/// The initial `[[HeaderExtensionsToNegotiate]]` of a transceiver of `kind` that has no
/// other non-stopping transceiver of its kind to copy from (webrtc-extensions 4.1): every
/// extension the media engine registered for the kind, once each, in registration order,
/// with the direction it was registered for ("sendrecv" when it was registered for any).
/// The engine offers every registered extension, so none starts "stopped".
pub(crate) fn default_to_negotiate(
    media_engine: &MediaEngine,
    kind: RtpCodecKind,
) -> Vec<RTCRtpHeaderExtensionToNegotiate> {
    let mut list: Vec<RTCRtpHeaderExtensionToNegotiate> = vec![];
    for extension in &media_engine.header_extensions {
        let of_kind = match kind {
            RtpCodecKind::Audio => extension.is_audio,
            RtpCodecKind::Video => extension.is_video,
            _ => false,
        };
        if !of_kind || list.iter().any(|e| e.uri == extension.uri) {
            continue;
        }
        list.push(RTCRtpHeaderExtensionToNegotiate {
            uri: extension.uri.clone(),
            direction: match extension.allowed_direction {
                Some(
                    direction @ (RTCRtpTransceiverDirection::Sendonly
                    | RTCRtpTransceiverDirection::Recvonly
                    | RTCRtpTransceiverDirection::Inactive),
                ) => direction,
                _ => RTCRtpTransceiverDirection::Sendrecv,
            },
        });
    }
    list
}

/// webrtc-extensions 4.2 `setHeaderExtensionsToNegotiate(extensions)`: the checks, each an
/// InvalidModificationError. The list must have the current one's size and, index by index,
/// its URIs; a mandatory-to-use extension must stay "sendrecv"; a mandatory-to-implement one
/// must not be "stopped". A direction outside the five a header extension can have is a
/// TypeError (WebIDL: the enum has no "unspecified").
pub(crate) fn validate(
    current: &[RTCRtpHeaderExtensionToNegotiate],
    extensions: &[RTCRtpHeaderExtensionToNegotiate],
) -> Result<()> {
    if extensions.len() != current.len() {
        return Err(Error::InvalidModificationError);
    }
    for (extension, existing) in extensions.iter().zip(current) {
        if extension.direction == RTCRtpTransceiverDirection::Unspecified {
            return Err(Error::TypeError(format!(
                "{}: a header extension's direction is one of sendrecv, sendonly, recvonly, \
                 inactive and stopped",
                extension.uri
            )));
        }
        if extension.uri != existing.uri {
            return Err(Error::InvalidModificationError);
        }
        if MANDATORY_TO_USE.contains(&extension.uri.as_str())
            && extension.direction != RTCRtpTransceiverDirection::Sendrecv
        {
            return Err(Error::InvalidModificationError);
        }
        if MANDATORY_TO_IMPLEMENT.contains(&extension.uri.as_str())
            && extension.direction == RTCRtpTransceiverDirection::Stopped
        {
            return Err(Error::InvalidModificationError);
        }
    }
    Ok(())
}

/// webrtc-extensions 4.2 `setHeaderExtensionsToNegotiate`: "If necessary, restrict
/// extension.direction as to not exceed the user agent's capabilities for this extension."
/// The engine's capability for an extension is the direction the media engine registered it
/// with for the transceiver's kind (`register_header_extension`'s `allowed_direction`; none
/// is "sendrecv"): a requested direction keeps only the halves that one allows ("sendrecv"
/// asked of a receive-only extension is "recvonly"). "stopped" stays "stopped".
pub(crate) fn restrict_to_capabilities(
    media_engine: &MediaEngine,
    kind: RtpCodecKind,
    extensions: &mut [RTCRtpHeaderExtensionToNegotiate],
) {
    for extension in extensions.iter_mut() {
        if extension.direction == RTCRtpTransceiverDirection::Stopped {
            continue;
        }
        let capability = media_engine.header_extensions.iter().find(|registered| {
            registered.uri == extension.uri
                && match kind {
                    RtpCodecKind::Audio => registered.is_audio,
                    RtpCodecKind::Video => registered.is_video,
                    _ => false,
                }
        });
        if let Some(
            allowed @ (RTCRtpTransceiverDirection::Sendonly
            | RTCRtpTransceiverDirection::Recvonly
            | RTCRtpTransceiverDirection::Inactive),
        ) = capability.and_then(|c| c.allowed_direction)
        {
            extension.direction = extension.direction.intersect(allowed);
        }
    }
}

/// webrtc-extensions 4.1, applying an answer: each extension of `to_negotiate` takes the
/// direction of the answer's `a=extmap` for its URI, reversed to this side's point of view
/// when the answer is the remote one (`remote_answer`), or "stopped" when the answer has
/// none. The result is both `[[NegotiatedHeaderExtensions]]` and the new
/// `[[HeaderExtensionsToNegotiate]]`.
pub(crate) fn negotiated_from_answer(
    to_negotiate: &[RTCRtpHeaderExtensionToNegotiate],
    answer_section: &MediaDescription,
    remote_answer: bool,
) -> Vec<RTCRtpHeaderExtensionToNegotiate> {
    use sdp::direction::Direction;
    let answered: Vec<(String, Direction)> = answer_section
        .attributes
        .iter()
        .filter(|a| a.key == "extmap")
        .filter_map(|a| {
            let line = format!("extmap:{}", a.value.as_deref()?);
            let extmap = sdp::extmap::ExtMap::unmarshal(&mut line.as_bytes()).ok()?;
            // RFC 6904: an encrypted extension names its URI in the attribute.
            let uri = match &extmap.ext_attr {
                Some(inner)
                    if extmap.uri.as_ref().map(|u| u.as_str())
                        == Some("urn:ietf:params:rtp-hdrext:encrypt") =>
                {
                    inner.split_whitespace().next()?.to_owned()
                }
                _ => extmap.uri.as_ref()?.to_string(),
            };
            Some((uri, extmap.direction))
        })
        .collect();
    // The media section's negotiated direction from this side's point of view: an extension
    // whose direction it leaves no use for (a send-only extension on a section that only
    // receives, and the reverse) "cannot be used because of other options negotiated in the
    // answer" and is stopped (webrtc-extensions 4.1). A held (inactive) or rejected section
    // stops nothing: the list is what the next offers negotiate, and the extensions are
    // wanted again when the media resumes.
    let section = if answer_section.media_name.port.value == 0 {
        RTCRtpTransceiverDirection::Sendrecv
    } else {
        let answered = ["sendrecv", "sendonly", "recvonly", "inactive"]
            .into_iter()
            .find(|d| answer_section.attributes.iter().any(|a| a.key == *d))
            .map_or(
                RTCRtpTransceiverDirection::Sendrecv,
                RTCRtpTransceiverDirection::from,
            );
        if remote_answer {
            answered.reverse()
        } else {
            answered
        }
    };
    let usable = |direction: RTCRtpTransceiverDirection| {
        section == RTCRtpTransceiverDirection::Inactive
            || (direction.has_send() && section.has_send())
            || (direction.has_recv() && section.has_recv())
    };
    to_negotiate
        .iter()
        .map(|extension| {
            let direction = answered
                .iter()
                .filter(|(uri, _)| *uri == extension.uri)
                .map(|(_, direction)| direction.clone())
                // An inactive clear form beside an encrypted one (RFC 6904 4.1) is not the
                // answer's choice.
                .find(|d| !matches!(d, Direction::Inactive))
                .or_else(|| {
                    answered
                        .iter()
                        .find(|(uri, _)| *uri == extension.uri)
                        .map(|(_, d)| d.clone())
                });
            let direction = match direction {
                None => RTCRtpTransceiverDirection::Stopped,
                Some(Direction::Unspecified | Direction::SendRecv) => {
                    RTCRtpTransceiverDirection::Sendrecv
                }
                Some(Direction::Inactive) => RTCRtpTransceiverDirection::Inactive,
                Some(Direction::SendOnly) if remote_answer => RTCRtpTransceiverDirection::Recvonly,
                Some(Direction::SendOnly) => RTCRtpTransceiverDirection::Sendonly,
                Some(Direction::RecvOnly) if remote_answer => RTCRtpTransceiverDirection::Sendonly,
                Some(Direction::RecvOnly) => RTCRtpTransceiverDirection::Recvonly,
            };
            let direction = if direction != RTCRtpTransceiverDirection::Stopped
                && direction != RTCRtpTransceiverDirection::Inactive
                && !usable(direction)
            {
                RTCRtpTransceiverDirection::Stopped
            } else {
                direction
            };
            RTCRtpHeaderExtensionToNegotiate {
                uri: extension.uri.clone(),
                direction,
            }
        })
        .collect()
}
