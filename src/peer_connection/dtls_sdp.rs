//! The session-description attributes that identify the DTLS association and its owner, on
//! top of `a=setup` and `a=fingerprint`: `a=tls-id` (RFC 8842 section 4) and `a=identity`
//! (RFC 8827 section 5).

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::sdp::{
    ATTR_KEY_TLS_ID, extract_tls_id, has_rtp_media, is_rejected_media,
};
use sdp::description::common::Attribute;
use sdp::description::session::{ATTR_KEY_IDENTITY, SessionDescription};
use shared::error::{Error, Result};

/// RFC 8827 section 5:
///
/// ```text
/// identity-assertion       = identity-assertion-value *(SP identity-extension)
/// identity-assertion-value = base64
/// identity-extension       = extension-name [ "=" extension-value ]
/// extension-name           = token
/// extension-value          = 1*(%x01-09 / %x0b-0c / %x0e-3a / %x3c-ff)
/// ```
fn is_valid_identity_assertion(assertion: &str) -> bool {
    let mut parts = assertion.split(' ');
    let is_base64 = |value: &str| {
        let body = value.trim_end_matches('=');
        !body.is_empty()
            && value.len() - body.len() <= 2
            && value.len().is_multiple_of(4)
            && body
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    };
    let is_token = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`{|}~".contains(&b))
    };
    let is_extension = |extension: &str| match extension.split_once('=') {
        None => is_token(extension),
        Some((name, value)) => {
            is_token(name)
                && !value.is_empty()
                && value
                    .bytes()
                    .all(|b| !matches!(b, 0x00 | 0x0a | 0x0d | 0x3b))
        }
    };
    parts.next().is_some_and(is_base64) && parts.all(is_extension)
}

impl RTCPeerConnection {
    /// Sets, or with `None` clears, the identity assertion this endpoint sends: the value of
    /// the session-level `a=identity` attribute (RFC 8827 section 5) of every offer and answer
    /// created from now on.
    ///
    /// The engine carries the assertion; it does not make or verify one. The application
    /// obtains it from its identity provider, bound to the fingerprints of this connection's
    /// certificates ([`RTCCertificate::get_fingerprints`](crate::peer_connection::certificate::RTCCertificate::get_fingerprints)):
    /// RFC 8827 section 5.1.1 requires the assertion to cover every `a=fingerprint` of the
    /// description, and the certificates of a connection never change, so one assertion holds
    /// for its whole life (section 5.1.4). At most one attribute is written (section 5).
    ///
    /// # Errors
    ///
    /// [`Error::ErrInvalidIdentityAssertion`] if the value is not a base64 string, optionally
    /// followed by space-separated extensions, as the attribute's syntax requires.
    pub fn set_identity_assertion(&mut self, assertion: Option<String>) -> Result<()> {
        if assertion
            .as_deref()
            .is_some_and(|assertion| !is_valid_identity_assertion(assertion))
        {
            return Err(Error::ErrInvalidIdentityAssertion);
        }
        self.identity_assertion = assertion;
        Ok(())
    }

    /// The identity assertion of the remote description: the value of its first session-level
    /// `a=identity` attribute (RFC 8827 section 5; a relying party may ignore all but the
    /// first), or `None`.
    ///
    /// Verifying it is the application's (it needs the identity provider): an application
    /// that requires an identity checks the assertion of a description before it applies it,
    /// and does not apply one whose verification fails (section 5.1.3).
    pub fn remote_identity_assertion(&self) -> Option<&str> {
        self.remote_description()?
            .parsed
            .as_ref()?
            .attributes
            .iter()
            .find(|attribute| attribute.key == ATTR_KEY_IDENTITY)?
            .value
            .as_deref()
    }

    /// Adds `a=identity` and `a=tls-id` to an offer or answer being generated.
    ///
    /// `a=tls-id` (RFC 8842): an offer carries the association's value, or a new one when it
    /// asks for a new association (sections 5.2 and 5.5); an answer carries one only when the
    /// offer did (section 5.3), the association's, which `set_remote_description` replaced if
    /// the offer led to a new association. Its multiplexing category is IDENTICAL, so it is
    /// written once, on the first m-section that is not rejected: the BUNDLE tag (section 4).
    pub(crate) fn add_dtls_association_attributes(
        &mut self,
        mut d: SessionDescription,
        is_offer: bool,
    ) -> Result<SessionDescription> {
        if let Some(assertion) = &self.identity_assertion {
            d.attributes.push(Attribute::new(
                ATTR_KEY_IDENTITY.to_owned(),
                Some(assertion.clone()),
            ));
        }

        if self.setting_engine.disable_sdp_tls_id {
            return Ok(d);
        }
        let tls_id = if is_offer {
            // The offer asks for a new association when it sets a closed transport up again,
            // and when it has a media section on an association that cannot key SRTP (one
            // set up for data channels only, RFC 5764 section 4.1).
            let new_association = self.transport_closed
                || (has_rtp_media(&d)
                    && self.dtls_transport().is_started()
                    && !self.dtls_transport().can_key_srtp());
            self.dtls_transport_mut().offer_tls_id(new_association)?
        } else {
            let offered = self
                .remote_description()
                .and_then(|remote| remote.parsed.as_ref())
                .and_then(|parsed| extract_tls_id(parsed).ok().flatten());
            if offered.is_none() {
                return Ok(d);
            }
            // The new association the offer asks for has the `tls-id` staged for it
            // (`defer_remote_transport`).
            match &self.dtls_transport().staged_local_tls_id {
                Some(staged)
                    if self
                        .pending_remote_transport
                        .as_ref()
                        .is_some_and(|pending| pending.new_dtls_role.is_some()) =>
                {
                    staged.clone()
                }
                _ => self.dtls_transport().local_tls_id.clone(),
            }
        };
        if let Some(tagged) = d
            .media_descriptions
            .iter_mut()
            .find(|m| !is_rejected_media(m))
        {
            tagged
                .attributes
                .push(Attribute::new(ATTR_KEY_TLS_ID.to_owned(), Some(tls_id)));
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8827 section 5: a base64 value, then optional extensions.
    #[test]
    fn identity_assertion_syntax() {
        for valid in [
            "eyJpZHAiOnsiZG9tYWluIjoiZXhhbXBsZS5vcmciLCJwcm90b2NvbCI6ImJvZ3VzIn19",
            "YWJj",
            "YWI=",
            "YQ==",
            "YWJj ext",
            "YWJj ext=value other=a=b",
        ] {
            assert!(is_valid_identity_assertion(valid), "{valid:?}");
        }
        for invalid in [
            "",
            " ",
            "YWJ",
            "YQ===",
            "====",
            "YW Jj!",
            "YWJj\r\na=setup:active",
            "YWJj ext=",
            "YWJj =value",
            "YWJj  ext",
            "YWJj ext=a;b",
            "not base64",
        ] {
            assert!(!is_valid_identity_assertion(invalid), "{invalid:?}");
        }
    }
}
