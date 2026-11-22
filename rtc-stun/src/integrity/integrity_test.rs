use super::*;
use crate::attributes::ATTR_SOFTWARE;
use crate::fingerprint::FINGERPRINT;
use crate::message::TransactionId;
use crate::textattrs::TextAttribute;
use crypto::{
    CryptoAlgorithm, CryptoError, HashAlgorithm, HmacAlgorithm, RTCCrypto, RTCCryptoProvider,
    RTCRandom, constant_time_eq,
};
use std::sync::Arc;

struct TestProvider {
    crypto: TestCrypto,
    random: TestRandom,
}

struct TestCrypto;

struct TestRandom;

impl RTCCryptoProvider for TestProvider {
    fn name(&self) -> &'static str {
        "test"
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        &self.crypto
    }

    fn random(&self) -> &dyn RTCRandom {
        &self.random
    }
}

impl RTCRandom for TestRandom {
    fn fill(&self, output: &mut [u8]) -> std::result::Result<(), CryptoError> {
        output.fill(0x42);
        Ok(())
    }
}

impl RTCCrypto for TestCrypto {
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
        matches!(
            algorithm,
            CryptoAlgorithm::Hash(HashAlgorithm::Md5) | CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1)
        )
    }

    fn hash(
        &self,
        algorithm: HashAlgorithm,
        data: &[u8],
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        if algorithm != HashAlgorithm::Md5 {
            return Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hash(
                algorithm,
            )));
        }
        let mut output = vec![0_u8; 16];
        let output_len = output.len();
        for (index, byte) in data.iter().enumerate() {
            output[index % output_len] ^= byte;
        }
        Ok(output)
    }

    fn new_hmac(
        &self,
        algorithm: HmacAlgorithm,
        key: &[u8],
    ) -> std::result::Result<Box<dyn crypto::Mac>, CryptoError> {
        if algorithm != HmacAlgorithm::Sha1 {
            return Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hmac(
                algorithm,
            )));
        }
        Ok(Box::new(TestMac {
            key: key.to_vec(),
            output_len: algorithm.output_len(),
        }))
    }
}

/// A deliberately fake MAC: an XOR fold, not HMAC-SHA1. It exists to prove the custom-provider
/// path is honoured, so tests asserting RFC 5389 vectors must use `builtin_provider()` instead.
struct TestMac {
    key: Vec<u8>,
    output_len: usize,
}

impl crypto::Mac for TestMac {
    fn output_len(&self) -> usize {
        self.output_len
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> std::result::Result<(), CryptoError> {
        if output.len() != self.output_len {
            return Err(CryptoError::InvalidTagLength {
                expected: self.output_len,
                actual: output.len(),
            });
        }
        output.fill(0);
        for (index, byte) in self
            .key
            .iter()
            .chain(input.iter().flat_map(|part| part.iter()))
            .enumerate()
        {
            output[index % self.output_len] ^= byte;
        }
        Ok(())
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> std::result::Result<(), CryptoError> {
        if expected.len() != self.output_len {
            return Err(CryptoError::InvalidTagLength {
                expected: self.output_len,
                actual: expected.len(),
            });
        }
        let mut actual = vec![0_u8; self.output_len];
        self.sign(input, &mut actual)?;
        if constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

fn test_provider() -> Arc<dyn RTCCryptoProvider> {
    Arc::new(TestProvider {
        crypto: TestCrypto,
        random: TestRandom,
    })
}

/// A real built-in provider. Tests asserting RFC 5389 key/tag vectors need genuine MD5 and
/// HMAC-SHA1, not the `TestProvider` stand-in above.
fn builtin_provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

#[test]
fn explicit_custom_provider_round_trip_and_truncated_tag_rejection() -> Result<()> {
    let provider = test_provider();
    let integrity = MessageIntegrity::new_long_term_integrity_with_provider(
        "user".to_owned(),
        "realm".to_owned(),
        "password".to_owned(),
        provider.crypto(),
    )?;
    let mut message = Message::new();
    message.write_header();
    integrity.add_to(&mut message)?;
    MessageIntegrity::check(&mut message, integrity.key.as_ref(), provider.crypto())?;

    let attribute = message
        .attributes
        .0
        .iter_mut()
        .find(|attribute| attribute.typ == ATTR_MESSAGE_INTEGRITY)
        .expect("MESSAGE-INTEGRITY attribute");
    attribute.value.pop();
    attribute.length -= 1;
    assert_eq!(
        MessageIntegrity::check(&mut message, integrity.key.as_ref(), provider.crypto()),
        Err(Error::ErrIntegrityMismatch)
    );

    Ok(())
}

#[test]
fn test_message_integrity_add_to_simple() -> Result<()> {
    {
        let provider = builtin_provider();
        let i = MessageIntegrity::new_long_term_integrity_with_provider(
            "user".to_owned(),
            "realm".to_owned(),
            "passsss".to_owned(),
            provider.crypto(),
        )?;
        let expected = vec![
            104, 228, 91, 113, 61, 154, 222, 34, 101, 61, 181, 146, 177, 90, 4, 29,
        ];
        assert_eq!(i.key.as_ref(), expected, "{}", Error::ErrIntegrityMismatch);
    }

    let provider = builtin_provider();
    let i = MessageIntegrity::new_long_term_integrity_with_provider(
        "user".to_owned(),
        "realm".to_owned(),
        "pass".to_owned(),
        provider.crypto(),
    )?;
    let expected = vec![
        0x84, 0x93, 0xfb, 0xc5, 0x3b, 0xa5, 0x82, 0xfb, 0x4c, 0x04, 0x4c, 0x45, 0x6b, 0xdc, 0x40,
        0xeb,
    ];
    assert_eq!(i.key.as_ref(), expected, "{}", Error::ErrIntegrityMismatch);

    //"Check"
    {
        let mut m = Message::new();
        m.write_header();
        i.add_to(&mut m)?;
        let a = TextAttribute {
            attr: ATTR_SOFTWARE,
            text: "software".to_owned(),
        };
        a.add_to(&mut m)?;
        m.write_header();

        let mut d_m = Message::new();
        d_m.raw = m.raw.clone();
        d_m.decode()?;
        MessageIntegrity::check(&mut d_m, i.key.as_ref(), provider.crypto())?;

        d_m.raw[24] += 12; // HMAC now invalid
        d_m.decode()?;
        let result = MessageIntegrity::check(&mut d_m, i.key.as_ref(), provider.crypto());
        assert!(result.is_err(), "should be invalid");
    }

    Ok(())
}

#[test]
fn test_message_integrity_with_fingerprint() -> Result<()> {
    let mut m = Message::new();
    m.transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0]);
    m.write_header();
    let a = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: "software".to_owned(),
    };
    a.add_to(&mut m)?;

    let provider = builtin_provider();
    let i = MessageIntegrity::new_short_term_integrity_with_provider(
        "pwd".to_owned(),
        provider.crypto(),
    );
    assert_eq!(
        i.to_string(),
        "MESSAGE-INTEGRITY key: [REDACTED; 3 bytes]",
        "bad string {i}"
    );
    let result = MessageIntegrity::check(&mut m, i.key.as_ref(), provider.crypto());
    assert!(result.is_err(), "should error");

    i.add_to(&mut m)?;
    FINGERPRINT.add_to(&mut m)?;
    MessageIntegrity::check(&mut m, i.key.as_ref(), provider.crypto())?;
    m.raw[24] = 33;
    m.decode()?;
    let result = MessageIntegrity::check(&mut m, i.key.as_ref(), provider.crypto());
    assert!(result.is_err(), "mismatch expected");

    Ok(())
}

#[test]
fn test_message_integrity() -> Result<()> {
    let mut m = Message::new();
    let provider = builtin_provider();
    let i = MessageIntegrity::new_short_term_integrity_with_provider(
        "password".to_owned(),
        provider.crypto(),
    );
    m.write_header();
    i.add_to(&mut m)?;
    m.get(ATTR_MESSAGE_INTEGRITY)?;
    Ok(())
}

#[test]
fn test_message_integrity_before_fingerprint() -> Result<()> {
    let mut m = Message::new();
    m.write_header();
    FINGERPRINT.add_to(&mut m)?;
    let provider = builtin_provider();
    let i = MessageIntegrity::new_short_term_integrity_with_provider(
        "password".to_owned(),
        provider.crypto(),
    );
    let result = i.add_to(&mut m);
    assert!(result.is_err(), "should error");

    Ok(())
}

/// The sample messages of RFC 5769 section 2, byte for byte. Their attribute padding is
/// spaces, not zeros, which a receiver has to ignore (RFC 8489 section 14).
mod rfc5769 {
    #[rustfmt::skip]
    pub(super) const REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42,
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        // SOFTWARE "STUN test client"
        0x80, 0x22, 0x00, 0x10,
        0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e,
        0x74,
        // PRIORITY
        0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff,
        // ICE-CONTROLLED
        0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36,
        // USERNAME "evtj:h6vY", three bytes of padding
        0x00, 0x06, 0x00, 0x09,
        0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20, 0x20,
        // MESSAGE-INTEGRITY
        0x00, 0x08, 0x00, 0x14,
        0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2,
        0x49, 0xc1, 0xb5, 0x71, 0xa2,
        // FINGERPRINT
        0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
    ];

    #[rustfmt::skip]
    pub(super) const IPV4_RESPONSE: &[u8] = &[
        0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42,
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        // SOFTWARE "test vector", one byte of padding
        0x80, 0x22, 0x00, 0x0b,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
        // XOR-MAPPED-ADDRESS 192.0.2.1:32853
        0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
        // MESSAGE-INTEGRITY
        0x00, 0x08, 0x00, 0x14,
        0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba,
        0x53, 0xf0, 0x6b, 0xe7, 0xd7,
        // FINGERPRINT
        0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
    ];

    #[rustfmt::skip]
    pub(super) const IPV6_RESPONSE: &[u8] = &[
        0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42,
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        // SOFTWARE "test vector", one byte of padding
        0x80, 0x22, 0x00, 0x0b,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
        // XOR-MAPPED-ADDRESS [2001:db8:1234:5678:11:2233:4455:6677]:32853
        0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47,
        0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25, 0xf4, 0xb5, 0xbe, 0xd2, 0xb9,
        0xd9,
        // MESSAGE-INTEGRITY
        0x00, 0x08, 0x00, 0x14,
        0xa3, 0x82, 0x95, 0x4e, 0x4b, 0xe6, 0x7b, 0xf1, 0x17, 0x84, 0xc9, 0x7c, 0x82, 0x92, 0xc2,
        0x75, 0xbf, 0xe3, 0xed, 0x41,
        // FINGERPRINT
        0x80, 0x28, 0x00, 0x04, 0xc8, 0xfb, 0x0b, 0x4c,
    ];

    #[rustfmt::skip]
    pub(super) const LONG_TERM_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x60, 0x21, 0x12, 0xa4, 0x42,
        0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
        // USERNAME, 18 bytes of UTF-8 and two of padding
        0x00, 0x06, 0x00, 0x12,
        0xe3, 0x83, 0x9e, 0xe3, 0x83, 0x88, 0xe3, 0x83, 0xaa, 0xe3, 0x83, 0x83, 0xe3, 0x82, 0xaf,
        0xe3, 0x82, 0xb9, 0x00, 0x00,
        // NONCE "f//499k954d6OL34oL9FSTvy64sA"
        0x00, 0x15, 0x00, 0x1c,
        0x66, 0x2f, 0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36, 0x4f, 0x4c, 0x33,
        0x34, 0x6f, 0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73, 0x41,
        // REALM "example.org", one byte of padding
        0x00, 0x14, 0x00, 0x0b,
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00,
        // MESSAGE-INTEGRITY
        0x00, 0x08, 0x00, 0x14,
        0xf6, 0x70, 0x24, 0x65, 0x6d, 0xd6, 0x4a, 0x3e, 0x02, 0xb8, 0xe0, 0x71, 0x2e, 0x85, 0xc9,
        0xa2, 0x8c, 0xa8, 0x96, 0x66,
    ];
}

/// RFC 5769 sections 2.1 to 2.3 (short-term credentials, password
/// "VOkJxbRl1RmTxUk/WvJxBt"): the MESSAGE-INTEGRITY and FINGERPRINT of the sample request and
/// of both sample responses verify, and the attributes read back as the RFC gives them.
#[test]
fn test_rfc5769_short_term_sample_messages_verify() -> Result<()> {
    use crate::validated::Validator;
    use crate::xoraddr::XorMappedAddress;

    let provider = builtin_provider();
    let crypto = provider.crypto();
    let key = MessageIntegrity::short_term("VOkJxbRl1RmTxUk/WvJxBt", crypto)?;
    let validator = Validator::new().require_fingerprint();

    let mut request = Message::new();
    request.unmarshal_binary(rfc5769::REQUEST)?;
    MessageIntegrity::check(&mut request, key.key.as_ref(), crypto)?;
    FINGERPRINT.check(&request)?;
    let valid = validator
        .authenticate(&request, key.key.as_ref(), crypto)
        .expect("the sample request validates");
    assert_eq!(valid.typ, BINDING_REQUEST);
    assert_eq!(
        TextAttribute::get_from_as(&valid, ATTR_USERNAME)?.text,
        "evtj:h6vY"
    );
    assert_eq!(
        TextAttribute::get_from_as(&valid, ATTR_SOFTWARE)?.text,
        "STUN test client"
    );
    assert_eq!(valid.get(ATTR_PRIORITY)?, [0x6e, 0x00, 0x01, 0xff]);

    for (raw, expected) in [
        (rfc5769::IPV4_RESPONSE, "192.0.2.1:32853"),
        (
            rfc5769::IPV6_RESPONSE,
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853",
        ),
    ] {
        let mut response = Message::new();
        response.unmarshal_binary(raw)?;
        let valid = validator
            .authenticate(&response, key.key.as_ref(), crypto)
            .expect("the sample response validates");
        let mut mapped = XorMappedAddress::default();
        mapped.get_from(&valid)?;
        assert_eq!(mapped.to_string(), expected);
        // The padding byte (a space) is not part of the value.
        assert_eq!(
            TextAttribute::get_from_as(&valid, ATTR_SOFTWARE)?.text,
            "test vector"
        );
    }

    // The HMAC this implementation computes for the request is the RFC's.
    let mut built = Message::new();
    built.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(request.transaction_id),
        Box::new(TextAttribute::new(
            ATTR_SOFTWARE,
            "STUN test client".to_owned(),
        )),
        Box::new(crate::attributes::RawAttribute {
            typ: ATTR_PRIORITY,
            length: 0,
            value: vec![0x6e, 0x00, 0x01, 0xff],
        }),
        Box::new(crate::attributes::RawAttribute {
            typ: ATTR_ICE_CONTROLLED,
            length: 0,
            value: vec![0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36],
        }),
        Box::new(TextAttribute::new(ATTR_USERNAME, "evtj:h6vY".to_owned())),
    ])?;
    // The RFC pads USERNAME with spaces; the HMAC covers the padding.
    let padding = built.raw.len() - 3;
    built.raw[padding..].copy_from_slice(b"   ");
    key.add_to(&mut built)?;
    assert_eq!(
        built.get(ATTR_MESSAGE_INTEGRITY)?,
        request.get(ATTR_MESSAGE_INTEGRITY)?
    );
    FINGERPRINT.add_to(&mut built)?;
    assert_eq!(built.raw, rfc5769::REQUEST);
    Ok(())
}

/// RFC 5769 section 2.4 (long-term credentials: the user name of six katakana, password
/// "TheMatrIX", realm "example.org"): the MESSAGE-INTEGRITY verifies under the key of RFC
/// 8489 section 9.2.2.
#[test]
fn test_rfc5769_long_term_sample_request_verifies() -> Result<()> {
    let provider = builtin_provider();
    let crypto = provider.crypto();
    let mut request = Message::new();
    request.unmarshal_binary(rfc5769::LONG_TERM_REQUEST)?;

    let username = TextAttribute::get_from_as(&request, ATTR_USERNAME)?.text;
    assert_eq!(username, "\u{30de}\u{30c8}\u{30ea}\u{30c3}\u{30af}\u{30b9}");
    let realm = TextAttribute::get_from_as(&request, ATTR_REALM)?.text;
    assert_eq!(realm, "example.org");
    let key =
        MessageIntegrity::long_term_integrity_key(username, realm, "TheMatrIX".to_owned(), crypto)?;
    MessageIntegrity::check(&mut request, &key, crypto)?;
    assert_eq!(
        MessageIntegrity::check(&mut request, b"0123456789abcdef", crypto),
        Err(Error::ErrIntegrityMismatch)
    );
    Ok(())
}

/// RFC 8489 sections 9.1.1 and 9.2.2: the key is made of OpaqueString-processed parts, so two
/// spellings of one password that the profile maps together give one key, and a password the
/// profile does not allow gives none.
#[test]
fn test_keys_are_made_of_opaque_strings() -> Result<()> {
    let provider = builtin_provider();
    let crypto = provider.crypto();
    // "a" with COMBINING RING ABOVE composes to U+00E5; IDEOGRAPHIC SPACE becomes SPACE.
    let decomposed = "pa\u{30a}ss\u{3000}word";
    let composed = "p\u{e5}ss word";
    assert_eq!(
        MessageIntegrity::short_term(decomposed, crypto)?
            .key
            .as_ref(),
        composed.as_bytes()
    );
    for algorithm in [PASSWORD_ALGORITHM_MD5, PASSWORD_ALGORITHM_SHA256] {
        assert_eq!(
            long_term_key(algorithm, "user", "re\u{3000}alm", decomposed, crypto)?,
            long_term_key(algorithm, "user", "re alm", composed, crypto)?
        );
    }
    assert_eq!(
        long_term_key(PASSWORD_ALGORITHM_SHA256, "user", "realm", "pass", crypto)?.len(),
        32
    );
    assert!(MessageIntegrity::short_term("tab\u{9}", crypto).is_err());
    assert!(long_term_key(PASSWORD_ALGORITHM_MD5, "user", "realm", "nul\u{0}", crypto).is_err());
    assert!(long_term_key(0x7777, "user", "realm", "pass", crypto).is_err());
    Ok(())
}

/// RFC 8489 section 14.5: the HMAC covers the message up to MESSAGE-INTEGRITY with the length
/// field pointing to the end of that attribute, whatever follows it.
#[test]
fn test_message_integrity_checks_with_attributes_after_it() -> Result<()> {
    let provider = builtin_provider();
    let crypto = provider.crypto();
    let key = b"key";
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([1; TRANSACTION_ID_SIZE])),
        Box::new(TextAttribute::new(ATTR_SOFTWARE, "software".to_owned())),
        Box::new(MessageIntegrity::new_raw_integrity_with_provider(
            key.to_vec(),
            crypto,
        )),
        Box::new(MessageIntegritySha256::new_raw(key.to_vec(), crypto)),
        Box::new(FINGERPRINT),
    ])?;
    let raw = m.raw.clone();
    MessageIntegrity::check(&mut m, key, crypto)?;
    MessageIntegritySha256::check(&m, key, crypto)?;
    FINGERPRINT.check(&m)?;
    assert_eq!(m.raw, raw, "checking leaves the message as it was");
    assert_eq!(m.get(ATTR_MESSAGE_INTEGRITY_SHA256)?.len(), 32);

    // No integrity attribute goes after FINGERPRINT (section 14.7).
    let result = MessageIntegritySha256::new_raw(key.to_vec(), crypto).add_to(&mut m);
    assert_eq!(result, Err(Error::ErrFingerprintBeforeIntegrity));
    Ok(())
}
