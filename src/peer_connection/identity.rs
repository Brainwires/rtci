//! The peer's identity (RFC 8827 sections 5.1.4 and 7.4).
//!
//! The engine carries identity assertions (`dtls_sdp`); verifying one is the application's,
//! with the identity provider the assertion names (asynchronous, and outside a sans-I/O
//! engine). What the engine keeps is the binding the RFC asks for: an identity the
//! application established is the peer's only while it covers every fingerprint of the
//! remote description and the certificate the DTLS association authenticated, for the
//! associations made with those fingerprints, and it is discarded when the remote
//! description's fingerprints change.

use super::RTCPeerConnection;
use crate::peer_connection::sdp::extract_fingerprints;
use crate::peer_connection::transport::dtls::fingerprint::{
    RTCDtlsFingerprint, fingerprint_hash, format_fingerprint,
};
use shared::error::{Error, Result};

/// What an identity provider's verification of the peer's assertion established (RFC 8827
/// section 7.4): the identity it attests, and the fingerprints the assertion was bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RTCPeerIdentity {
    /// The asserted identity, `user@domain`.
    pub identity: String,
    /// The fingerprints the assertion covers, as the identity provider returned them.
    pub fingerprints: Vec<RTCDtlsFingerprint>,
}

/// An identity the application established, and the remote description fingerprints it was
/// established for.
#[derive(Debug, Clone)]
pub(crate) struct EstablishedIdentity {
    identity: RTCPeerIdentity,
    description_fingerprints: Vec<RTCDtlsFingerprint>,
}

fn same_fingerprint(a: &RTCDtlsFingerprint, b: &RTCDtlsFingerprint) -> bool {
    a.algorithm.eq_ignore_ascii_case(&b.algorithm) && a.value.eq_ignore_ascii_case(&b.value)
}

fn same_set(a: &[RTCDtlsFingerprint], b: &[RTCDtlsFingerprint]) -> bool {
    a.iter().all(|x| b.iter().any(|y| same_fingerprint(x, y)))
        && b.iter().all(|y| a.iter().any(|x| same_fingerprint(x, y)))
}

impl RTCPeerConnection {
    /// Establishes the peer's identity from the application's verification of the identity
    /// assertion of the current remote description
    /// ([`remote_identity_assertion`](Self::remote_identity_assertion)) with its identity
    /// provider. Replaces an identity established before: a newly received identity applies
    /// to every existing association (RFC 8827 section 5.1.4).
    ///
    /// # Errors
    ///
    /// - [`Error::ErrNoRemoteIdentityAssertion`] without a remote description, or with one that
    ///   carries no `a=identity`;
    /// - [`Error::ErrIdentityFingerprintsNotCovered`] when `verified` does not cover every
    ///   fingerprint of the remote description (section 7.4: "The identity attribute MUST
    ///   include all fingerprint values");
    /// - [`Error::ErrIdentityCertificateNotCovered`] when a DTLS association has authenticated
    ///   a certificate that is not among `verified`'s fingerprints (section 7.4: "the in-use
    ///   certificate for a DTLS connection is in the set of fingerprints returned from the
    ///   IdP").
    pub fn set_peer_identity(&mut self, verified: RTCPeerIdentity) -> Result<()> {
        if self.remote_identity_assertion().is_none() {
            return Err(Error::ErrNoRemoteIdentityAssertion);
        }
        let parsed = self
            .remote_description()
            .and_then(|description| description.parsed.as_ref())
            .ok_or(Error::ErrNoRemoteIdentityAssertion)?;
        let described = extract_fingerprints(parsed)?;
        if !described.iter().all(|fingerprint| {
            verified
                .fingerprints
                .iter()
                .any(|covered| same_fingerprint(covered, fingerprint))
        }) {
            return Err(Error::ErrIdentityFingerprintsNotCovered);
        }
        if !self.certificate_in_use_is_among(&verified.fingerprints) {
            return Err(Error::ErrIdentityCertificateNotCovered);
        }
        self.peer_identity = Some(EstablishedIdentity {
            identity: verified,
            description_fingerprints: described,
        });
        Ok(())
    }

    /// The peer's identity, once [`set_peer_identity`](Self::set_peer_identity) has
    /// established it: for the DTLS associations made with the fingerprints it was established
    /// for, existing and new (RFC 8827 section 5.1.4), and only while the certificate the
    /// current association authenticated is among them (section 7.4). `None` before, after
    /// the remote description's fingerprints changed, and for an association whose
    /// certificate the identity does not cover.
    pub fn peer_identity(&self) -> Option<&str> {
        let established = self.peer_identity.as_ref()?;
        self.certificate_in_use_is_among(&established.identity.fingerprints)
            .then_some(established.identity.identity.as_str())
    }

    /// Whether the certificate the current DTLS association authenticated, if it has one yet,
    /// matches one of `fingerprints`.
    fn certificate_in_use_is_among(&self, fingerprints: &[RTCDtlsFingerprint]) -> bool {
        let transport = self.dtls_transport();
        let Some(certificate) = transport.get_remote_certificates().first() else {
            return true;
        };
        let crypto = transport.crypto_provider.crypto();
        fingerprints.iter().any(|fingerprint| {
            fingerprint_hash(&fingerprint.algorithm.to_ascii_lowercase()).is_some_and(
                |(algorithm, _)| {
                    crypto.hash(algorithm, certificate).is_ok_and(|digest| {
                        format_fingerprint(&digest).eq_ignore_ascii_case(&fingerprint.value)
                    })
                },
            )
        })
    }

    /// RFC 8827 section 5.1.4: when the fingerprints of the remote description change, "the
    /// receiver MUST discard all previously established identities". Run after every remote
    /// description that is applied.
    pub(crate) fn discard_peer_identity_if_fingerprints_changed(&mut self) {
        let Some(established) = &self.peer_identity else {
            return;
        };
        let current = self
            .remote_description()
            .and_then(|description| description.parsed.as_ref())
            .and_then(|parsed| extract_fingerprints(parsed).ok());
        if !current.is_some_and(|current| same_set(&current, &established.description_fingerprints))
        {
            self.peer_identity = None;
        }
    }
}
