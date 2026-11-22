use crypto::{ActiveKeyExchange, KeyExchangeAlgorithm, RTCCrypto};
use shared::error::*;

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
/// The named elliptic curves this crate can perform ECDHE over.
#[non_exhaustive]
pub enum NamedCurve {
    /// `UNSUPPORTED` (`0x0000`).
    Unsupported = 0x0000,
    /// `P256` (`0x0017`).
    P256 = 0x0017,
    /// `P384` (`0x0018`).
    P384 = 0x0018,
    /// `X25519` (`0x001d`).
    X25519 = 0x001d,
    /// `X25519MLKEM768` (`0x11ec`, draft-ietf-tls-ecdhe-mlkem): the hybrid of ML-KEM-768
    /// and X25519. A group of DTLS 1.3 only, and only with a provider that has ML-KEM.
    X25519MlKem768 = 0x11ec,
}

impl From<u16> for NamedCurve {
    fn from(val: u16) -> Self {
        match val {
            0x0017 => NamedCurve::P256,
            0x0018 => NamedCurve::P384,
            0x001d => NamedCurve::X25519,
            0x11ec => NamedCurve::X25519MlKem768,
            _ => NamedCurve::Unsupported,
        }
    }
}

/// An ephemeral ECDHE key pair, with the curve it belongs to.
pub struct NamedCurveKeypair {
    pub(crate) curve: NamedCurve,
    pub(crate) public_key: Vec<u8>,
    active: Option<Box<dyn ActiveKeyExchange>>,
}

impl NamedCurveKeypair {
    pub(crate) fn complete(&mut self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        let active = self
            .active
            .take()
            .ok_or(Error::ErrNamedCurveAndPrivateKeyMismatch)?;
        active
            .complete(peer_public_key)
            .map(|secret| secret.into_bytes())
            .map_err(|error| Error::Crypto(error.to_string()))
    }
}

impl NamedCurve {
    pub(crate) const fn crypto_algorithm(self) -> Result<KeyExchangeAlgorithm> {
        match self {
            Self::P256 => Ok(KeyExchangeAlgorithm::P256),
            Self::P384 => Ok(KeyExchangeAlgorithm::P384),
            Self::X25519 => Ok(KeyExchangeAlgorithm::X25519),
            Self::X25519MlKem768 => Ok(KeyExchangeAlgorithm::X25519MlKem768),
            Self::Unsupported => Err(Error::ErrInvalidNamedCurve),
        }
    }

    /// Whether the group is one of TLS 1.3 only: not an elliptic curve a DTLS 1.2 ECDHE
    /// exchange can use.
    pub(crate) const fn is_tls13_only(self) -> bool {
        matches!(self, Self::X25519MlKem768)
    }

    /// The responder's side of a key exchange over this group: its share for the peer's,
    /// and the shared secret.
    pub(crate) fn respond_with_crypto(
        self,
        crypto: &dyn RTCCrypto,
        peer_share: &[u8],
    ) -> Result<(Vec<u8>, crypto::SecretVec)> {
        crypto
            .key_exchange_respond(self.crypto_algorithm()?, peer_share)
            .map_err(|error| Error::Crypto(error.to_string()))
    }

    pub(crate) fn generate_keypair_with_crypto(
        self,
        crypto: &dyn RTCCrypto,
    ) -> Result<NamedCurveKeypair> {
        let active = crypto
            .start_key_exchange(self.crypto_algorithm()?)
            .map_err(|error| Error::Crypto(error.to_string()))?;
        let public_key = active.public_key().to_vec();
        Ok(NamedCurveKeypair {
            curve: self,
            public_key,
            active: Some(active),
        })
    }
}
