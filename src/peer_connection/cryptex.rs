//! Cryptex ([RFC 9335]) signalling: `rtpHeaderEncryptionPolicy` (webrtc-extensions), the
//! `a=cryptex` attribute in offers and answers, and the SRTP contexts' use of it once both
//! sides have signalled it.
//!
//! [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335

use sdp::description::media::MediaDescription;
use sdp::description::session::SessionDescription;
use srtp::cryptex::Cryptex;

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::sdp::RTCSessionDescription;
use shared::error::{Error, Result};

/// `a=cryptex` (RFC 9335 section 4), a property attribute.
pub(crate) const ATTR_KEY_CRYPTEX: &str = "cryptex";

/// `RTCRtpHeaderEncryptionPolicy` (webrtc-extensions): whether a connection negotiates the
/// encryption of RTP header extensions and CSRCs (Cryptex, RFC 9335).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RTCRtpHeaderEncryptionPolicy {
    /// No `a=cryptex` in offers or answers; packets are protected as RFC 3711 has it.
    Disable,
    /// Offer Cryptex, answer it when offered, and use it once both sides signalled it. The
    /// default, as W3C webrtc-extensions 10.2 has it.
    #[default]
    Negotiate,
    /// As `Negotiate`, and refuse received packets whose CSRCs or header extensions are
    /// not protected with Cryptex once it is negotiated (RFC 9335 section 5.2).
    Require,
}

/// Whether Cryptex applies to every RTP `m=` section of a description: `a=cryptex` at the
/// session level, or on each audio / video section that isn't rejected. A description with
/// no RTP section doesn't have it.
pub(crate) fn description_has_cryptex(d: &SessionDescription) -> bool {
    let rtp: Vec<&MediaDescription> = d
        .media_descriptions
        .iter()
        .filter(|m| is_live_rtp_section(m))
        .collect();
    if rtp.is_empty() {
        return false;
    }
    d.has_attribute(ATTR_KEY_CRYPTEX) || rtp.iter().all(|m| m.has_attribute(ATTR_KEY_CRYPTEX))
}

fn is_live_rtp_section(m: &MediaDescription) -> bool {
    let kind = m.media_name.media.to_ascii_lowercase();
    (kind == "audio" || kind == "video") && m.media_name.port.value != 0
}

fn parsed_has_cryptex(description: Option<&RTCSessionDescription>) -> bool {
    description
        .and_then(|d| d.parsed.as_ref())
        .is_some_and(description_has_cryptex)
}

impl RTCPeerConnection {
    /// Sets the `RTCRtpHeaderEncryptionPolicy` (webrtc-extensions). It applies to the next
    /// offer or answer, and to the SRTP contexts at once.
    pub fn set_rtp_header_encryption_policy(
        &mut self,
        policy: RTCRtpHeaderEncryptionPolicy,
    ) -> Result<()> {
        // webrtc-extensions 10.2: the W3C member is `RTCConfiguration`'s and cannot change
        // after construction; this engine setting may until a description has been set.
        if policy != self.rtp_header_encryption_policy() && self.a_description_was_set() {
            return Err(Error::InvalidModificationError);
        }
        // The policy is the connection's: every transport's SRTP contexts follow it.
        for transport in self.pipeline_context.transports.iter_mut() {
            transport.srtp_handler_context.rtp_header_encryption_policy = policy;
        }
        self.configuration.rtp_header_encryption_policy = policy;
        self.update_cryptex();
        Ok(())
    }

    /// Whether a local or remote description has been set (a rollback included).
    pub(crate) fn a_description_was_set(&self) -> bool {
        self.local_description_was_set
            || self.current_remote_description.is_some()
            || self.pending_remote_description.is_some()
            || self.current_local_description.is_some()
    }

    /// The `RTCRtpHeaderEncryptionPolicy` in force.
    pub fn rtp_header_encryption_policy(&self) -> RTCRtpHeaderEncryptionPolicy {
        self.pipeline_context
            .transports
            .default()
            .srtp_handler_context
            .rtp_header_encryption_policy
    }

    /// Whether the negotiated session uses Cryptex: the current local and remote
    /// descriptions both signal it for every RTP section, and the policy allows it.
    pub fn cryptex_negotiated(&self) -> bool {
        self.rtp_header_encryption_policy() != RTCRtpHeaderEncryptionPolicy::Disable
            && parsed_has_cryptex(self.current_local_description.as_ref())
            && parsed_has_cryptex(self.current_remote_description.as_ref())
    }

    /// Adds a session-level `a=cryptex` to an offer or answer being generated when the
    /// policy says so: an offer with an RTP section carries it unless the policy is
    /// `Disable`; an answer carries it when the offer did as well (RFC 9335 section 4).
    pub(crate) fn add_cryptex_attribute(
        &self,
        d: SessionDescription,
        is_offer: bool,
    ) -> SessionDescription {
        if self.rtp_header_encryption_policy() == RTCRtpHeaderEncryptionPolicy::Disable
            || !d.media_descriptions.iter().any(is_live_rtp_section)
        {
            return d;
        }
        if !is_offer && !parsed_has_cryptex(self.remote_description()) {
            return d;
        }
        d.with_property_attribute(ATTR_KEY_CRYPTEX.to_owned())
    }

    /// Under the `Require` policy, refuses a remote description that has a live RTP section
    /// without Cryptex for every RTP section. Otherwise the session would negotiate media with
    /// the header extensions and CSRCs in the clear and no error at all (`require` would only
    /// apply once Cryptex was negotiated, which it never is). Checked before anything of the
    /// description is applied.
    pub(crate) fn check_required_cryptex(&self, remote: &SessionDescription) -> Result<()> {
        if self.rtp_header_encryption_policy() == RTCRtpHeaderEncryptionPolicy::Require
            && remote.media_descriptions.iter().any(is_live_rtp_section)
            && !description_has_cryptex(remote)
        {
            return Err(Error::ErrSessionDescriptionMissingCryptex);
        }
        Ok(())
    }

    /// Hands the SRTP contexts what the current session and policy say: send with Cryptex
    /// once it is negotiated, and with `Require`, refuse packets without it.
    pub(crate) fn update_cryptex(&mut self) {
        let negotiated = self.cryptex_negotiated();
        let require = negotiated
            && self.rtp_header_encryption_policy() == RTCRtpHeaderEncryptionPolicy::Require;
        for transport in self.pipeline_context.transports.iter_mut() {
            transport.srtp_handler_context.set_cryptex(Cryptex {
                send: negotiated,
                require,
            });
        }
    }
}

impl RTCPeerConnection {
    /// Hands the SRTP contexts the ids of the header extensions negotiated in their encrypted
    /// form (RFC 6904 section 4): their payload is encrypted when sending and decrypted when
    /// receiving. A packet protected with Cryptex is not processed this way (RFC 9335 section
    /// 5, in the SRTP context).
    pub(crate) fn update_encrypted_header_extensions(&mut self) {
        let ids: Vec<u8> = self
            .media_engine
            .negotiated_header_extensions
            .iter()
            .filter(|(_, e)| e.encrypted)
            .filter_map(|(id, _)| u8::try_from(*id).ok())
            .collect();
        let set = srtp::header_extension::EncryptedHeaderExtensions::new(&ids).unwrap_or_default();
        for transport in self.pipeline_context.transports.iter_mut() {
            transport
                .srtp_handler_context
                .set_encrypted_header_extensions(set);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(sdp: &str) -> SessionDescription {
        let mut reader = std::io::Cursor::new(sdp.as_bytes());
        SessionDescription::unmarshal(&mut reader).expect("test SDP parses")
    }

    const HEAD: &str = "v=0\r\no=- 0 3 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";

    #[test]
    fn cryptex_at_the_session_or_on_every_rtp_section() {
        let audio = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
        let video = "m=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\na=mid:1\r\n";
        let data =
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:2\r\n";

        let session = parse(&format!("{HEAD}a=cryptex\r\n{audio}{video}{data}"));
        assert!(description_has_cryptex(&session));

        let media = parse(&format!(
            "{HEAD}{audio}a=cryptex\r\n{video}a=cryptex\r\n{data}"
        ));
        assert!(description_has_cryptex(&media));

        let partial = parse(&format!("{HEAD}{audio}a=cryptex\r\n{video}{data}"));
        assert!(!description_has_cryptex(&partial));

        let none = parse(&format!("{HEAD}{audio}{video}"));
        assert!(!description_has_cryptex(&none));

        let data_only = parse(&format!("{HEAD}a=cryptex\r\n{data}"));
        assert!(!description_has_cryptex(&data_only));
    }
}
