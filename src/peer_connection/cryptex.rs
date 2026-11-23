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
/// session level, or for each audio / video section that isn't rejected. A description with no
/// RTP section doesn't have it.
///
/// For a section in a BUNDLE group the reading depends on `strict`:
/// - `false` (the default): the attribute is of the TRANSPORT category under BUNDLE (RFC 9335
///   section 4, RFC 8859 section 4.5), so the group's BUNDLE-tagged section decides for every
///   section of the group (see [`group_has_cryptex`]); RFC 9143 section 7.1.3 has answers and
///   later offers carry such attributes there only.
/// - `true` ([`SettingEngineBuilder::with_cryptex_required_on_every_bundled_section`]): every
///   RTP section must carry it itself, as RFC 9335 section 4 asks of the writer.
///
/// A section outside any BUNDLE group decides by its own attribute either way.
///
/// [`SettingEngineBuilder::with_cryptex_required_on_every_bundled_section`]: crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_cryptex_required_on_every_bundled_section
pub(crate) fn description_has_cryptex(d: &SessionDescription, strict: bool) -> bool {
    let rtp: Vec<&MediaDescription> = d
        .media_descriptions
        .iter()
        .filter(|m| is_live_rtp_section(m))
        .collect();
    if rtp.is_empty() {
        return false;
    }
    if d.has_attribute(ATTR_KEY_CRYPTEX) {
        return true;
    }
    if strict {
        return rtp.iter().all(|m| m.has_attribute(ATTR_KEY_CRYPTEX));
    }
    rtp.iter().all(|m| match bundle_group_of(d, m) {
        Some(tags) => group_has_cryptex(d, &tags),
        None => m.has_attribute(ATTR_KEY_CRYPTEX),
    })
}

fn mid_of(m: &MediaDescription) -> Option<&str> {
    m.attribute("mid").flatten()
}

fn section_by_mid<'a>(d: &'a SessionDescription, mid: &str) -> Option<&'a MediaDescription> {
    d.media_descriptions.iter().find(|s| mid_of(s) == Some(mid))
}

/// The identification-tags of the BUNDLE group the section `m` is in, if any.
fn bundle_group_of<'a>(d: &'a SessionDescription, m: &MediaDescription) -> Option<Vec<&'a str>> {
    let mid = mid_of(m)?;
    d.attributes
        .iter()
        .filter(|a| a.key == "group")
        .filter_map(|a| a.value.as_deref()?.strip_prefix("BUNDLE "))
        .map(|tags| tags.split_whitespace().collect::<Vec<_>>())
        .find(|tags| tags.contains(&mid))
}

/// Whether a BUNDLE group has Cryptex, read from its BUNDLE-tagged section: the first
/// identification-tag whose m= section has a port other than zero (RFC 9143 section 7.3.1: a
/// zero-port section, rejected or bundle-only, is never the tagged one, so a rejected tagged
/// section moves the tag to the next). `a=cryptex` there applies to the whole group; on other
/// sections of the group without it there, it does not. When the tagged section is not
/// RTP-based (a data section), a group whose every live RTP section carries `a=cryptex` has it
/// too: that is the form RFC 9335 section 4 itself asks for.
fn group_has_cryptex(d: &SessionDescription, tags: &[&str]) -> bool {
    let sections: Vec<&MediaDescription> = tags
        .iter()
        .filter_map(|tag| section_by_mid(d, tag))
        .collect();
    let tagged = sections.iter().find(|m| m.media_name.port.value != 0);
    if tagged.is_some_and(|t| t.has_attribute(ATTR_KEY_CRYPTEX)) {
        return true;
    }
    if tagged.is_some_and(|t| is_live_rtp_section(t)) {
        return false;
    }
    let mut rtp = sections
        .iter()
        .filter(|m| is_live_rtp_section(m))
        .peekable();
    rtp.peek().is_some() && rtp.all(|m| m.has_attribute(ATTR_KEY_CRYPTEX))
}

fn is_live_rtp_section(m: &MediaDescription) -> bool {
    let kind = m.media_name.media.to_ascii_lowercase();
    (kind == "audio" || kind == "video") && m.media_name.port.value != 0
}

impl RTCPeerConnection {
    /// [`description_has_cryptex`], read as the setting engine says.
    fn has_cryptex(&self, d: &SessionDescription) -> bool {
        description_has_cryptex(
            d,
            self.setting_engine
                .cryptex_required_on_every_bundled_section,
        )
    }

    fn parsed_has_cryptex(&self, description: Option<&RTCSessionDescription>) -> bool {
        description
            .and_then(|d| d.parsed.as_ref())
            .is_some_and(|d| self.has_cryptex(d))
    }
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
            && self.parsed_has_cryptex(self.current_local_description.as_ref())
            && self.parsed_has_cryptex(self.current_remote_description.as_ref())
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
        if !is_offer && !self.parsed_has_cryptex(self.remote_description()) {
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
            && !self.has_cryptex(remote)
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

        for strict in [false, true] {
            let session = parse(&format!("{HEAD}a=cryptex\r\n{audio}{video}{data}"));
            assert!(description_has_cryptex(&session, strict));

            let media = parse(&format!(
                "{HEAD}{audio}a=cryptex\r\n{video}a=cryptex\r\n{data}"
            ));
            assert!(description_has_cryptex(&media, strict));

            // No BUNDLE group: each section decides by its own attribute.
            let partial = parse(&format!("{HEAD}{audio}a=cryptex\r\n{video}{data}"));
            assert!(!description_has_cryptex(&partial, strict));

            let none = parse(&format!("{HEAD}{audio}{video}"));
            assert!(!description_has_cryptex(&none, strict));

            let data_only = parse(&format!("{HEAD}a=cryptex\r\n{data}"));
            assert!(!description_has_cryptex(&data_only, strict));
        }
    }

    /// Under BUNDLE the tagged section (the first tag with a port) decides for its group, each
    /// group by its own, unless the strict reading is asked for.
    #[test]
    fn under_bundle_the_tagged_section_decides_for_its_group() {
        let section = |kind: &str, port: u16, mid: &str, cryptex: bool| {
            let fmt = if kind == "application" {
                "UDP/DTLS/SCTP webrtc-datachannel".to_owned()
            } else {
                "UDP/TLS/RTP/SAVPF 96".to_owned()
            };
            let attr = if cryptex { "a=cryptex\r\n" } else { "" };
            format!("m={kind} {port} {fmt}\r\nc=IN IP4 0.0.0.0\r\na=mid:{mid}\r\n{attr}")
        };
        let cases: [(&str, Vec<String>, bool, bool); 7] = [
            // (group lines, sections, default reading, strict reading)
            (
                "a=group:BUNDLE 0 1\r\n",
                vec![
                    section("audio", 9, "0", true),
                    section("video", 9, "1", false),
                ],
                true,
                false,
            ),
            (
                "a=group:BUNDLE 0 1\r\n",
                vec![
                    section("audio", 9, "0", false),
                    section("video", 9, "1", true),
                ],
                false,
                false,
            ),
            // The tag is the first identification-tag with a port: "1" here, not "0".
            (
                "a=group:BUNDLE 1 0\r\n",
                vec![
                    section("audio", 9, "0", false),
                    section("video", 9, "1", true),
                ],
                true,
                false,
            ),
            // A rejected (zero-port) section is never the tagged one: the tag moves to "1".
            (
                "a=group:BUNDLE 0 1 2\r\n",
                vec![
                    section("audio", 0, "0", false),
                    section("video", 9, "1", true),
                    section("video", 9, "2", false),
                ],
                true,
                false,
            ),
            // Two groups, each read from its own tagged section.
            (
                "a=group:BUNDLE 0 1\r\na=group:BUNDLE 2 3\r\n",
                vec![
                    section("audio", 9, "0", true),
                    section("audio", 9, "1", false),
                    section("video", 9, "2", true),
                    section("video", 9, "3", false),
                ],
                true,
                false,
            ),
            (
                "a=group:BUNDLE 0 1\r\na=group:BUNDLE 2 3\r\n",
                vec![
                    section("audio", 9, "0", true),
                    section("audio", 9, "1", false),
                    section("video", 9, "2", false),
                    section("video", 9, "3", true),
                ],
                false,
                false,
            ),
            // A data section as the tag without it: every RTP section carrying it is enough.
            (
                "a=group:BUNDLE 0 1 2\r\n",
                vec![
                    section("application", 9, "0", false),
                    section("audio", 9, "1", true),
                    section("video", 9, "2", true),
                ],
                true,
                true,
            ),
        ];
        for (groups, sections, default, strict) in cases {
            let sdp = format!("{HEAD}{groups}{}", sections.concat());
            let d = parse(&sdp);
            assert_eq!(description_has_cryptex(&d, false), default, "{sdp}");
            assert_eq!(description_has_cryptex(&d, true), strict, "{sdp}");
        }
    }
}
