use crypto::{CryptoAlgorithm, HashAlgorithm, RTCCrypto};
use serde::{Deserialize, Serialize};
use shared::error::{Error, Result};

/// DTLS certificate fingerprint for authentication.
///
/// `RTCDtlsFingerprint` contains a cryptographic hash of a certificate that is
/// used to verify the identity of the remote peer during the DTLS handshake.
/// The fingerprint is exchanged in the SDP and must match the actual certificate
/// presented during the DTLS handshake.
///
/// # Security
///
/// The fingerprint allows WebRTC to verify that the DTLS certificate received
/// during the handshake matches the certificate that was signaled out-of-band
/// via SDP. This prevents man-in-the-middle attacks even if the signaling channel
/// is not encrypted.
///
/// # Common Hash Algorithms
///
/// - `sha-256` - Most commonly used, recommended
/// - `sha-384` - Higher security
/// - `sha-512` - Maximum security
/// - `sha-1` - Deprecated, should not be used
///
/// # Format
///
/// The fingerprint value is a colon-separated sequence of lowercase hexadecimal
/// bytes, for example: `"AB:CD:EF:01:23:45:67:89:..."`
///
/// # Examples
///
/// ## Creating a Fingerprint
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsFingerprint;
///
/// let fingerprint = RTCDtlsFingerprint {
///     algorithm: "sha-256".to_string(),
///     value: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89".to_string(),
/// };
///
/// println!("Fingerprint: {} {}", fingerprint.algorithm, fingerprint.value);
/// ```
///
/// ## Serialization for SDP
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsFingerprint;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let fingerprint = RTCDtlsFingerprint {
///     algorithm: "sha-256".to_string(),
///     value: "12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF".to_string(),
/// };
///
/// // Serialize to JSON for signaling
/// let json = serde_json::to_string(&fingerprint)?;
/// println!("Fingerprint JSON: {}", json);
/// # Ok(())
/// # }
/// ```
///
/// ## Verifying Algorithm Support
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsFingerprint;
///
/// fn is_secure_algorithm(fingerprint: &RTCDtlsFingerprint) -> bool {
///     matches!(
///         fingerprint.algorithm.as_str(),
///         "sha-256" | "sha-384" | "sha-512"
///     )
/// }
///
/// let fp = RTCDtlsFingerprint {
///     algorithm: "sha-256".to_string(),
///     value: "AB:CD:EF:01:...".to_string(),
/// };
///
/// assert!(is_secure_algorithm(&fp));
/// ```
///
/// # Specification
///
/// - [RFC 4572] - Connection-Oriented Media Transport over TLS
/// - [RFC 8122] - Updates to RFC 4572
/// - [W3C RTCDtlsFingerprint]
///
/// [RFC 4572]: https://datatracker.ietf.org/doc/html/rfc4572
/// [RFC 8122]: https://datatracker.ietf.org/doc/html/rfc8122
/// [W3C RTCDtlsFingerprint]: https://www.w3.org/TR/webrtc/#rtcdtlsfingerprint
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RTCDtlsFingerprint {
    /// Hash function algorithm name.
    ///
    /// Specifies one of the hash function algorithms defined in the
    /// 'Hash function Textual Names' registry, such as:
    ///
    /// - `"sha-256"` - Recommended
    /// - `"sha-384"` - Higher security
    /// - `"sha-512"` - Maximum security
    /// - `"sha-1"` - Deprecated, should not be used
    ///
    /// The algorithm name is case-insensitive but typically lowercase.
    pub algorithm: String,

    /// Certificate fingerprint value.
    ///
    /// The value of the certificate fingerprint as a lowercase hex string
    /// using the syntax specified in [RFC 4572 Section 5]. Each byte is
    /// represented as two hexadecimal digits, with bytes separated by colons.
    ///
    /// Example: `"AB:CD:EF:01:23:45:67:89:..."`
    ///
    /// The length depends on the hash algorithm:
    /// - SHA-256: 32 bytes (95 characters with colons)
    /// - SHA-384: 48 bytes (143 characters with colons)
    /// - SHA-512: 64 bytes (191 characters with colons)
    ///
    /// [RFC 4572 Section 5]: https://datatracker.ietf.org/doc/html/rfc4572#section-5
    pub value: String,
}

impl TryFrom<&str> for RTCDtlsFingerprint {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let fields: Vec<&str> = value.split_whitespace().collect();
        if fields.len() == 2 {
            Ok(Self {
                algorithm: fields[0].to_string(),
                value: fields[1].to_string(),
            })
        } else {
            Err(Error::Other("invalid fingerprint".to_string()))
        }
    }
}

/// The hash functions a certificate fingerprint may use (RFC 8122 section 5), with their digest
/// length in bytes, in the order this endpoint prefers them when it verifies a peer: SHA-256
/// first (the function RFC 8122 calls preferred and the one every WebRTC endpoint sends), then
/// the stronger ones, then the weaker ones. SHA-1 is last: RFC 8122 still defines it and
/// browsers still accept it, so a peer that offers nothing else is verified with it, but it is
/// never produced here. MD5 and MD2 are not in the list: RFC 8122 section 5 forbids computing
/// or verifying a fingerprint with them.
pub(crate) const FINGERPRINT_HASHES: [(&str, HashAlgorithm, usize); 5] = [
    ("sha-256", HashAlgorithm::Sha256, 32),
    ("sha-512", HashAlgorithm::Sha512, 64),
    ("sha-384", HashAlgorithm::Sha384, 48),
    ("sha-224", HashAlgorithm::Sha224, 28),
    ("sha-1", HashAlgorithm::Sha1, 20),
];

/// The digest length of the hash functions RFC 8122 lists only so that they are recognised.
const FORBIDDEN_FINGERPRINT_HASHES: [(&str, usize); 2] = [("md5", 16), ("md2", 16)];

/// The hash function a fingerprint's `hash-func` token names, if it is one a fingerprint may be
/// verified with (case-insensitive, as SDP tokens of this registry are).
pub(crate) fn fingerprint_hash(name: &str) -> Option<(HashAlgorithm, usize)> {
    FINGERPRINT_HASHES
        .iter()
        .find(|(known, _, _)| known.eq_ignore_ascii_case(name))
        .map(|&(_, algorithm, len)| (algorithm, len))
}

/// A digest as a fingerprint value: two hex digits per byte, colon-separated, lower case (the
/// SDP writers upper-case it, RFC 8122 section 5).
pub(crate) fn format_fingerprint(digest: &[u8]) -> String {
    let values: Vec<String> = digest.iter().map(|x| format!("{x:02x}")).collect();
    values.join(":")
}

/// Parses the value of an `a=fingerprint` attribute (RFC 8122 section 5):
/// `hash-func SP 2UHEX *(":" 2UHEX)`.
///
/// The value must be colon-separated bytes of two hex digits each, and for a hash function
/// RFC 8122 defines, as many bytes as its digest has. The hex digits are upper-case (`UHEX`);
/// `accept_lowercase` also reads lower-case ones, as browsers do
/// (`SettingEngineBuilder::with_lowercase_fingerprints_accepted`). A fingerprint of a hash
/// function this endpoint does not know is kept, syntax-checked, and never matches a
/// certificate.
pub(crate) fn parse_fingerprint_attribute(
    value: &str,
    accept_lowercase: bool,
) -> Result<RTCDtlsFingerprint> {
    let mut parts = value.split(' ');
    let (Some(algorithm), Some(fingerprint), None) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::ErrSessionDescriptionInvalidFingerprint);
    };
    let is_token = !algorithm.is_empty()
        && algorithm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`{|}~".contains(&b));
    if !is_token {
        return Err(Error::ErrSessionDescriptionInvalidFingerprint);
    }
    let mut bytes = 0;
    for byte in fingerprint.split(':') {
        let is_hex = |b: u8| {
            b.is_ascii_digit()
                || (b'A'..=b'F').contains(&b)
                || (accept_lowercase && (b'a'..=b'f').contains(&b))
        };
        if byte.len() != 2 || !byte.bytes().all(is_hex) {
            return Err(Error::ErrSessionDescriptionInvalidFingerprint);
        }
        bytes += 1;
    }
    let expected = fingerprint_hash(algorithm).map(|(_, len)| len).or_else(|| {
        FORBIDDEN_FINGERPRINT_HASHES
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(algorithm))
            .map(|&(_, len)| len)
    });
    if expected.is_some_and(|expected| expected != bytes) {
        return Err(Error::ErrSessionDescriptionInvalidFingerprint);
    }
    Ok(RTCDtlsFingerprint {
        algorithm: algorithm.to_owned(),
        value: fingerprint.to_owned(),
    })
}

/// The peer's fingerprints this endpoint verifies a certificate against (RFC 8122 section 5.1):
/// those of the most preferred hash function, among the ones the peer offered, that the crypto
/// provider can compute. `None` when the peer offered no such function (only MD5, MD2, unknown
/// ones, or ones the provider lacks).
pub(crate) fn preferred_fingerprints<'a>(
    fingerprints: &'a [RTCDtlsFingerprint],
    crypto: &dyn RTCCrypto,
) -> Option<(HashAlgorithm, Vec<&'a RTCDtlsFingerprint>)> {
    FINGERPRINT_HASHES.iter().find_map(|&(name, algorithm, _)| {
        if !crypto.supports(CryptoAlgorithm::Hash(algorithm)) {
            return None;
        }
        let set: Vec<&RTCDtlsFingerprint> = fingerprints
            .iter()
            .filter(|fp| fp.algorithm.eq_ignore_ascii_case(name))
            .collect();
        (!set.is_empty()).then_some((algorithm, set))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256: &str = "19:E2:1C:3B:4B:9F:81:E6:B8:5C:F4:A5:A8:D8:73:04:\
                          BB:05:2F:70:9F:04:A9:0E:05:E9:26:33:E8:70:88:A2";

    fn hex(bytes: usize) -> String {
        vec!["AB"; bytes].join(":")
    }

    /// RFC 8122 section 5, Figure 2: a hash function token, one space, colon-separated hex
    /// bytes, as many as the function's digest has.
    #[test]
    fn a_fingerprint_attribute_is_parsed_by_its_abnf() {
        let parsed = parse_fingerprint_attribute(&format!("sha-256 {SHA256}"), false).unwrap();
        assert_eq!(parsed.algorithm, "sha-256");
        assert_eq!(parsed.value, SHA256);
        for (name, _, len) in FINGERPRINT_HASHES {
            assert!(
                parse_fingerprint_attribute(&format!("{name} {}", hex(len)), false).is_ok(),
                "{name}"
            );
            for wrong in [len - 1, len + 1] {
                assert_eq!(
                    parse_fingerprint_attribute(&format!("{name} {}", hex(wrong)), false),
                    Err(Error::ErrSessionDescriptionInvalidFingerprint),
                    "{name} with {wrong} bytes"
                );
            }
        }
        // The name is case-insensitive, lower-case hex is read only on request, and an
        // unknown function's fingerprint is kept (it is never matched).
        let lowercase = format!("SHA-256 {}", SHA256.to_lowercase());
        assert_eq!(
            parse_fingerprint_attribute(&lowercase, false),
            Err(Error::ErrSessionDescriptionInvalidFingerprint),
            "UHEX is upper-case"
        );
        assert!(parse_fingerprint_attribute(&lowercase, true).is_ok());
        assert!(parse_fingerprint_attribute("sha3-256 AB:CD", false).is_ok());
        assert!(parse_fingerprint_attribute(&format!("md5 {}", hex(16)), false).is_ok());
    }

    #[test]
    fn a_malformed_fingerprint_attribute_is_refused() {
        for value in [
            "",
            "sha-256",
            "sha-256 ",
            "sha-256 zz",
            &format!("sha-256  {SHA256}"),
            &format!("sha-256 {SHA256} extra"),
            &format!("sha-256 {}", SHA256.replace(':', "")),
            &format!("sha-256 {}", SHA256.replace(':', "-")),
            &format!("sha-256 {SHA256}:"),
            &format!("sha-256 :{SHA256}"),
            &format!("sha-256 {}", SHA256.replacen("19", "1", 1)),
            &format!("sha-256 {}", SHA256.replacen("19", "1G", 1)),
            &format!("sha 256 {SHA256}"),
            &format!("sha/256 {}", hex(4)),
            &format!("md5 {}", hex(20)),
            "sha3-256 ",
        ] {
            assert_eq!(
                parse_fingerprint_attribute(value, true),
                Err(Error::ErrSessionDescriptionInvalidFingerprint),
                "{value:?}"
            );
        }
    }

    /// RFC 8122 section 5.1: the set of the most preferred hash function among those offered;
    /// MD5 and MD2 are never used to verify.
    #[test]
    fn the_most_preferred_offered_hash_function_is_selected() {
        let provider = crypto::default_provider().unwrap();
        let fp = |algorithm: &str| RTCDtlsFingerprint {
            algorithm: algorithm.to_owned(),
            value: String::new(),
        };
        let selected = |offered: &[&str]| {
            let offered: Vec<_> = offered.iter().map(|a| fp(a)).collect();
            preferred_fingerprints(&offered, provider.crypto())
                .map(|(algorithm, set)| (algorithm, set.len()))
        };
        assert_eq!(
            selected(&["sha-1", "sha-512", "sha-256", "SHA-256", "md5"]),
            Some((HashAlgorithm::Sha256, 2))
        );
        assert_eq!(
            selected(&["sha-1", "sha-384", "sha-512"]),
            Some((HashAlgorithm::Sha512, 1))
        );
        assert_eq!(
            selected(&["sha-1", "sha-224", "sha-384"]),
            Some((HashAlgorithm::Sha384, 1))
        );
        assert_eq!(
            selected(&["sha-1", "sha-224"]),
            Some((HashAlgorithm::Sha224, 1))
        );
        assert_eq!(selected(&["md2", "sha-1"]), Some((HashAlgorithm::Sha1, 1)));
        assert_eq!(selected(&["md5", "md2", "sha3-256"]), None);
        assert_eq!(selected(&[]), None);
    }
}
