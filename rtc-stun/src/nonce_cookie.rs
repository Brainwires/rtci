//! The nonce cookie and the STUN Security Features it carries (RFC 8489 sections 9.2, 9.2.1
//! and 18.1).
//!
//! A server that implements RFC 8489 starts every NONCE with `obMatJos2` followed by the
//! base64 encoding of 24 feature bits. The NONCE is covered by the message integrity of the
//! client's next request, so an attacker on the path cannot strip a feature (drop
//! PASSWORD-ALGORITHMS to force MD5, say) without the client seeing that the cookie promised
//! it: that is the bid-down protection, applied by
//! [`LongTermCredentials`](crate::long_term::LongTermCredentials).

use base64::prelude::*;

/// What a nonce that carries the cookie starts with.
pub const NONCE_COOKIE_PREFIX: &str = "obMatJos2";
/// The length of the nonce cookie: the prefix and four base64 characters.
pub const NONCE_COOKIE_LEN: usize = 13;

/// The 24 STUN Security Feature bits of a nonce cookie.
///
/// The three bytes are one 24-bit number in network order, and the features are numbered
/// from its least significant end: RFC 8489 section 18.1 as corrected by its verified erratum
/// 6290 ("Bit 0 is the rightmost bit"). The nonce of the RFC's own test vector (appendix
/// B.1), `obMatJos2AAAC...`, is `0x000002`: bit 1, username anonymity, and the vector duly
/// carries USERHASH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct SecurityFeatures(u32);

impl SecurityFeatures {
    /// No feature.
    pub const NONE: Self = Self(0);
    /// Bit 0, "Password algorithms": the server sends PASSWORD-ALGORITHMS.
    pub const PASSWORD_ALGORITHMS: Self = Self(1);
    /// Bit 1, "Username anonymity": the client sends USERHASH in place of USERNAME.
    pub const USERNAME_ANONYMITY: Self = Self(1 << 1);

    /// The features of the cookie `nonce` starts with, or `None` when it does not start with a
    /// nonce cookie (a server that predates RFC 8489).
    #[must_use]
    pub fn from_nonce(nonce: &str) -> Option<Self> {
        let encoded = nonce
            .strip_prefix(NONCE_COOKIE_PREFIX)?
            .as_bytes()
            .get(..NONCE_COOKIE_LEN - NONCE_COOKIE_PREFIX.len())?;
        let bits = BASE64_STANDARD.decode(encoded).ok()?;
        let bits: [u8; 3] = bits.try_into().ok()?;
        Some(Self(u32::from_be_bytes([0, bits[0], bits[1], bits[2]])))
    }

    /// These features and those of `other`.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every feature of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether the "Password algorithms" bit is set.
    #[must_use]
    pub const fn password_algorithms(self) -> bool {
        self.contains(Self::PASSWORD_ALGORITHMS)
    }

    /// Whether the "Username anonymity" bit is set.
    #[must_use]
    pub const fn username_anonymity(self) -> bool {
        self.contains(Self::USERNAME_ANONYMITY)
    }

    /// The 24 bits as a number: feature bit N of the registry is `1 << N`.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The nonce cookie for these features: what a server puts ahead of its own nonce value.
    #[must_use]
    pub fn cookie(self) -> String {
        let bytes = self.0.to_be_bytes();
        format!(
            "{NONCE_COOKIE_PREFIX}{}",
            BASE64_STANDARD.encode(&bytes[1..])
        )
    }
}

#[cfg(test)]
mod nonce_cookie_test {
    use super::*;

    /// RFC 8489 section 9.2: the cookie is "obMatJos2" and the base64 of the three feature
    /// bytes; section 18.1 with erratum 6290: password algorithms is bit 0, username anonymity
    /// bit 1, counted from the least significant end.
    #[test]
    fn test_security_features_are_read_from_the_nonce_cookie() {
        // 0x00 0x00 0x01 is "AAAB", 0x00 0x00 0x02 is "AAAC", 0x00 0x00 0x03 is "AAAD".
        let password = SecurityFeatures::from_nonce("obMatJos2AAABserver-part").unwrap();
        assert!(password.password_algorithms() && !password.username_anonymity());
        // The nonce of RFC 8489 appendix B.1, whose request carries USERHASH.
        let anonymity =
            SecurityFeatures::from_nonce("obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA").unwrap();
        assert!(!anonymity.password_algorithms() && anonymity.username_anonymity());
        let both = SecurityFeatures::from_nonce("obMatJos2AAAD").unwrap();
        assert!(both.password_algorithms() && both.username_anonymity());
        // An unassigned bit is neither.
        let other = SecurityFeatures::from_nonce("obMatJos2gAAAserver-part").unwrap();
        assert!(!other.password_algorithms() && !other.username_anonymity());
        assert_eq!(other.bits(), 0x80_0000);
        let none = SecurityFeatures::from_nonce("obMatJos2AAAAf//499k954d6OL34oL9FSTvy64sA");
        assert_eq!(none, Some(SecurityFeatures::NONE));

        assert_eq!(
            SecurityFeatures::PASSWORD_ALGORITHMS.cookie(),
            "obMatJos2AAAB"
        );
        assert_eq!(
            SecurityFeatures::PASSWORD_ALGORITHMS
                .with(SecurityFeatures::USERNAME_ANONYMITY)
                .cookie(),
            "obMatJos2AAAD"
        );
        assert_eq!(SecurityFeatures::NONE.cookie().len(), NONCE_COOKIE_LEN);
    }

    /// A nonce of a server that predates RFC 8489 has no cookie, whatever it looks like.
    #[test]
    fn test_a_nonce_without_the_cookie_has_no_security_features() {
        for nonce in [
            "",
            "f//499k954d6OL34oL9FSTvy64sA",
            "obMatJos2",
            "obMatJos2AAA",
            "obMatJos2A*ABxyz",
            "xobMatJos2AAAB",
        ] {
            assert_eq!(SecurityFeatures::from_nonce(nonce), None, "{nonce:?}");
        }
    }
}
