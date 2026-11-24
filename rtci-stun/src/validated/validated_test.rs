use super::*;
use crate::error_code::ErrorCodeAttribute;
use crate::integrity::{MessageIntegrity, MessageIntegritySha256};
use crate::textattrs::TextAttribute;
use crypto::RTCCryptoProvider;
use std::sync::Arc;

const KEY: &[u8] = b"the short-term password";

fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

/// The attributes ICE adds to STUN's own.
fn ice_known() -> Vec<AttrType> {
    [&STUN_ATTRIBUTES[..], &[ATTR_PRIORITY, ATTR_USE_CANDIDATE]].concat()
}

fn raw_attr(typ: AttrType, value: &[u8]) -> Box<RawAttribute> {
    Box::new(RawAttribute {
        typ,
        length: 0,
        value: value.to_vec(),
    })
}

fn build(setters: &[Box<dyn Setter + '_>]) -> Message {
    let mut m = Message::new();
    m.build(setters).expect("the message builds");
    m
}

/// What the receiver decodes from the bytes of `m`.
fn received(m: &Message) -> Message {
    let mut decoded = Message::new();
    decoded
        .unmarshal_binary(&m.raw)
        .expect("the message decodes");
    decoded
}

/// `m` with one more attribute put after everything it has, the header length fixed up: what
/// anyone on the path can do to a message without knowing its key.
fn with_appended(m: &Message, typ: AttrType, value: &[u8]) -> Message {
    let mut tampered = m.clone();
    tampered.add(typ, value);
    received(&tampered)
}

/// A Binding request from the controlling peer: ICE-CONTROLLING inside the integrity.
fn signed_request(integrity: &[Box<dyn Setter + '_>]) -> Message {
    let mut setters: Vec<Box<dyn Setter + '_>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([3; TRANSACTION_ID_SIZE])),
        Box::new(TextAttribute::new(ATTR_USERNAME, "local:remote".to_owned())),
        raw_attr(ATTR_ICE_CONTROLLING, &[9; 8]),
    ];
    let mut m = Message::new();
    m.build(&setters).unwrap();
    setters.clear();
    for setter in integrity {
        setter.add_to(&mut m).unwrap();
    }
    m
}

/// RFC 8489 section 9: attributes that follow MESSAGE-INTEGRITY are ignored. An
/// ICE-CONTROLLED appended to a genuine request passes the HMAC check and is visible on the
/// message, but not on what the validator returns.
#[test]
fn test_attribute_appended_after_message_integrity_is_not_exposed() {
    let provider = provider();
    let crypto = provider.crypto();
    let genuine = signed_request(
        &[Box::new(MessageIntegrity::new_raw_integrity_with_provider(
            KEY.to_vec(),
            crypto,
        ))],
    );
    let mut tampered = with_appended(&genuine, ATTR_ICE_CONTROLLED, &[0; 8]);

    // The attack: the integrity check alone accepts the message, and the appended attribute
    // is there to be read.
    MessageIntegrity::check(&mut tampered, KEY, crypto).expect("the HMAC still holds");
    assert!(tampered.contains(ATTR_ICE_CONTROLLED));

    let known = ice_known();
    let valid = Validator::new()
        .known_attributes(&known)
        .authenticate(&tampered, KEY, crypto)
        .expect("the genuine part authenticates");
    assert!(!valid.contains(ATTR_ICE_CONTROLLED));
    assert!(valid.get(ATTR_ICE_CONTROLLED).is_err());
    assert!(valid.contains(ATTR_ICE_CONTROLLING));
    assert_eq!(
        TextAttribute::get_from_as(&valid, ATTR_USERNAME)
            .unwrap()
            .text,
        "local:remote"
    );
    assert_eq!(valid.integrity(), Some(IntegrityAlgorithm::Sha1));
    assert_eq!(valid.transaction_id, genuine.transaction_id);
    assert_eq!(valid.typ, BINDING_REQUEST);

    // The view is a well-formed message of its own: it decodes to the same attributes.
    let reparsed = received(valid.message());
    assert_eq!(reparsed.attributes, valid.attributes);
    assert_eq!(valid.into_message().attributes.0.len(), 2);
}

/// RFC 8489 section 9: attributes that follow MESSAGE-INTEGRITY-SHA256 are ignored when
/// there is no MESSAGE-INTEGRITY.
#[test]
fn test_attribute_appended_after_message_integrity_sha256_is_not_exposed() {
    let provider = provider();
    let crypto = provider.crypto();
    let genuine = signed_request(&[Box::new(MessageIntegritySha256::new_raw(
        KEY.to_vec(),
        crypto,
    ))]);
    let tampered = with_appended(&genuine, ATTR_ICE_CONTROLLED, &[0; 8]);
    MessageIntegritySha256::check(&tampered, KEY, crypto).expect("the HMAC still holds");

    let valid = Validator::new()
        .authenticate(&tampered, KEY, crypto)
        .expect("the genuine part authenticates");
    assert!(!valid.contains(ATTR_ICE_CONTROLLED));
    assert!(valid.contains(ATTR_ICE_CONTROLLING));
    assert_eq!(valid.integrity(), Some(IntegrityAlgorithm::Sha256));
}

/// RFC 8489 sections 9 and 9.1.3: with both integrity attributes, MESSAGE-INTEGRITY-SHA256 is
/// the one verified, and whatever follows MESSAGE-INTEGRITY is ignored, the attribute between
/// the two included, although the SHA-256 HMAC covers it.
#[test]
fn test_with_both_integrity_attributes_sha256_is_verified_and_the_first_one_ends_the_message() {
    let provider = provider();
    let crypto = provider.crypto();
    let sha1 = || MessageIntegrity::new_raw_integrity_with_provider(KEY.to_vec(), crypto);
    let sha256 = |key: &[u8]| MessageIntegritySha256::new_raw(key.to_vec(), crypto);

    let both = received(&signed_request(&[Box::new(sha1()), Box::new(sha256(KEY))]));
    let valid = Validator::new().authenticate(&both, KEY, crypto).unwrap();
    assert_eq!(valid.integrity(), Some(IntegrityAlgorithm::Sha256));
    assert_eq!(valid.attributes.0.len(), 2);

    // A wrong SHA-256 HMAC is not rescued by a right SHA-1 one.
    let bad_sha256 = received(&signed_request(&[
        Box::new(sha1()),
        Box::new(sha256(b"another key")),
    ]));
    assert_eq!(
        Validator::new().authenticate(&bad_sha256, KEY, crypto),
        Err(Rejection::IntegrityMismatch)
    );

    let between = received(&signed_request(&[
        Box::new(sha1()),
        raw_attr(ATTR_ICE_CONTROLLED, &[0; 8]),
        Box::new(sha256(KEY)),
    ]));
    let valid = Validator::new()
        .authenticate(&between, KEY, crypto)
        .unwrap();
    assert!(!valid.contains(ATTR_ICE_CONTROLLED));
}

/// RFC 8489 sections 9.1.3 and 9.1.4: a message without the integrity attribute, or with one
/// that does not match, is not authenticated; and when one algorithm is expected, the other
/// does not do.
#[test]
fn test_missing_wrong_or_other_integrity_is_refused() {
    let provider = provider();
    let crypto = provider.crypto();
    let unsigned = received(&signed_request(&[]));
    assert_eq!(
        Validator::new().authenticate(&unsigned, KEY, crypto),
        Err(Rejection::IntegrityMissing)
    );

    let sha1 = received(&signed_request(&[Box::new(
        MessageIntegrity::new_raw_integrity_with_provider(KEY.to_vec(), crypto),
    )]));
    assert_eq!(
        Validator::new().authenticate(&sha1, b"another key", crypto),
        Err(Rejection::IntegrityMismatch)
    );
    assert!(Validator::new().authenticate(&sha1, KEY, crypto).is_ok());
    assert!(
        Validator::new()
            .authenticate_with(&sha1, IntegrityAlgorithm::Sha1, KEY, crypto)
            .is_ok()
    );
    assert_eq!(
        Validator::new().authenticate_with(&sha1, IntegrityAlgorithm::Sha256, KEY, crypto),
        Err(Rejection::IntegrityMissing),
        "the request carried MESSAGE-INTEGRITY-SHA256: a MESSAGE-INTEGRITY response is not it"
    );

    // One changed byte of the covered part.
    let mut flipped = sha1.raw.clone();
    flipped[MESSAGE_HEADER_SIZE + 5] ^= 1;
    let mut m = Message::new();
    m.unmarshal_binary(&flipped).unwrap();
    assert_eq!(
        Validator::new().authenticate(&m, KEY, crypto),
        Err(Rejection::IntegrityMismatch)
    );
}

/// RFC 8489 section 14.6: MESSAGE-INTEGRITY-SHA256 is the whole 32 bytes unless the usage
/// allows truncation; then it is at least 16 bytes (or the usage's own minimum) and a
/// multiple of 4.
#[test]
fn test_truncated_message_integrity_sha256_needs_the_usage_to_allow_it() {
    let provider = provider();
    let crypto = provider.crypto();
    let truncated = |len: usize| {
        received(&signed_request(&[Box::new(
            MessageIntegritySha256::new_raw(KEY.to_vec(), crypto)
                .with_tag_len(len)
                .unwrap(),
        )]))
    };
    let sixteen = truncated(16);
    assert_eq!(
        sixteen.get(ATTR_MESSAGE_INTEGRITY_SHA256).unwrap().len(),
        16
    );
    assert_eq!(
        Validator::new().authenticate(&sixteen, KEY, crypto),
        Err(Rejection::IntegrityMismatch)
    );
    assert!(
        Validator::new()
            .allow_truncated_sha256(16)
            .authenticate(&sixteen, KEY, crypto)
            .is_ok()
    );
    assert_eq!(
        Validator::new()
            .allow_truncated_sha256(20)
            .authenticate(&sixteen, KEY, crypto),
        Err(Rejection::IntegrityMismatch),
        "shorter than the usage's minimum"
    );
    assert!(
        Validator::new()
            .allow_truncated_sha256(20)
            .authenticate(&truncated(24), KEY, crypto)
            .is_ok()
    );
    assert_eq!(
        Validator::new().allow_truncated_sha256(16).authenticate(
            &truncated(16),
            b"another key",
            crypto
        ),
        Err(Rejection::IntegrityMismatch)
    );

    // What the sender refuses to produce, and the receiver to accept even when asked for
    // less than 16.
    let whole = MessageIntegritySha256::new_raw(KEY.to_vec(), crypto);
    for len in [0, 12, 18, 36] {
        assert!(whole.clone().with_tag_len(len).is_err(), "{len} bytes");
    }
    let mut twelve = signed_request(&[Box::new(whole)]);
    let last = twelve.attributes.0.len() - 1;
    twelve.attributes.0[last].value.truncate(12);
    twelve.encode();
    assert_eq!(
        Validator::new()
            .allow_truncated_sha256(4)
            .authenticate(&received(&twelve), KEY, crypto),
        Err(Rejection::IntegrityMismatch)
    );
}

/// RFC 8489 sections 6.3, 7 and 14.7: where FINGERPRINT is used, a message without it is not
/// for the usage; a FINGERPRINT with another value, or one that is not the last attribute,
/// makes the message invalid whether it is required or not.
#[test]
fn test_fingerprint_is_verified_and_must_be_last() {
    let provider = provider();
    let crypto = provider.crypto();
    let integrity = || MessageIntegrity::new_raw_integrity_with_provider(KEY.to_vec(), crypto);
    let with = received(&signed_request(&[
        Box::new(integrity()),
        Box::new(FINGERPRINT),
    ]));
    let without = received(&signed_request(&[Box::new(integrity())]));
    let lenient = Validator::new();
    let strict = Validator::new().require_fingerprint();

    let valid = strict.authenticate(&with, KEY, crypto).unwrap();
    assert!(valid.has_fingerprint());
    assert!(!valid.contains(ATTR_FINGERPRINT), "only covered attributes");
    assert_eq!(
        strict.authenticate(&without, KEY, crypto),
        Err(Rejection::FingerprintMissing)
    );
    let valid = lenient.authenticate(&without, KEY, crypto).unwrap();
    assert!(!valid.has_fingerprint());
    assert_eq!(
        strict.unauthenticated(&without),
        Err(Rejection::FingerprintMissing)
    );

    // A wrong CRC.
    let mut wrong = with.raw.clone();
    let end = wrong.len() - 1;
    wrong[end] ^= 0xff;
    let mut m = Message::new();
    m.unmarshal_binary(&wrong).unwrap();
    for validator in [lenient, strict] {
        assert_eq!(
            validator.authenticate(&m, KEY, crypto),
            Err(Rejection::FingerprintMismatch)
        );
        assert_eq!(
            validator.unauthenticated(&m),
            Err(Rejection::FingerprintMismatch)
        );
    }

    // An attribute after FINGERPRINT: FINGERPRINT is no longer last, and its CRC no longer
    // describes the message.
    let appended = with_appended(&with, ATTR_ICE_CONTROLLED, &[0; 8]);
    assert_eq!(
        lenient.authenticate(&appended, KEY, crypto),
        Err(Rejection::FingerprintMismatch)
    );
    // The same with a FINGERPRINT recomputed by the attacker over the longer message: the
    // message is valid STUN again, and the appended attribute stays out of sight.
    let mut refingerprinted = with_appended(&without, ATTR_ICE_CONTROLLED, &[0; 8]);
    FINGERPRINT.add_to(&mut refingerprinted).unwrap();
    let valid = strict
        .authenticate(&received(&refingerprinted), KEY, crypto)
        .unwrap();
    assert!(!valid.contains(ATTR_ICE_CONTROLLED));
}

/// RFC 8489 section 6.3: unknown comprehension-optional attributes are ignored;
/// unknown comprehension-required ones fail the message and are reported, in order and once
/// each. Attributes after the integrity attribute are ignored, so they are not reported.
#[test]
fn test_unknown_comprehension_required_attributes_are_reported() {
    let provider = provider();
    let crypto = provider.crypto();
    let known = ice_known();
    let validator = Validator::new().known_attributes(&known);
    let base = |extra: Vec<Box<dyn Setter>>| {
        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId([3; TRANSACTION_ID_SIZE])),
            raw_attr(ATTR_PRIORITY, &[0, 0, 1, 0]),
        ];
        setters.extend(extra);
        setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
            KEY.to_vec(),
            crypto,
        )));
        received(&build(&setters))
    };

    // libwebrtc's NETWORK-COST (0xC057) and an attribute nobody has defined, both optional.
    let optional = base(vec![
        raw_attr(ATTR_NETWORK_COST, &[0, 1, 0, 10]),
        raw_attr(AttrType(0xff00), b"whatever"),
    ]);
    let valid = validator.authenticate(&optional, KEY, crypto).unwrap();
    assert!(valid.contains(ATTR_PRIORITY));

    // RFC 5780's CHANGE-REQUEST (0x0003) and PADDING (0x0026) are comprehension-required and
    // ICE does not use them; 0x7f00 is unassigned.
    let required = base(vec![
        raw_attr(AttrType(0x7f00), &[]),
        raw_attr(ATTR_CHANGE_REQUEST, &[0, 0, 0, 6]),
        raw_attr(AttrType(0x7f00), &[1]),
        raw_attr(ATTR_PADDING, &[0; 8]),
    ]);
    assert_eq!(
        validator.authenticate(&required, KEY, crypto),
        Err(Rejection::UnknownAttributes(vec![
            AttrType(0x7f00),
            ATTR_CHANGE_REQUEST,
            ATTR_PADDING
        ]))
    );
    assert_eq!(
        validator.unauthenticated(&required),
        Err(Rejection::UnknownAttributes(vec![
            AttrType(0x7f00),
            ATTR_CHANGE_REQUEST,
            ATTR_PADDING
        ]))
    );
    // A validator that was given no list does not look.
    assert!(
        Validator::new()
            .authenticate(&required, KEY, crypto)
            .is_ok()
    );
    // Authentication comes first: with the wrong key the answer is not a list of attributes.
    assert_eq!(
        validator.authenticate(&required, b"another key", crypto),
        Err(Rejection::IntegrityMismatch)
    );

    let after_integrity = with_appended(&base(vec![]), AttrType(0x7f00), &[]);
    assert!(
        validator
            .authenticate(&after_integrity, KEY, crypto)
            .is_ok()
    );
}

/// RFC 8489 sections 6.3.1, 6.3.1.1 and 14.8: the answer to a request with unknown
/// comprehension-required attributes is an error response of the request's method and
/// transaction id with ERROR-CODE 420 and the attributes in UNKNOWN-ATTRIBUTES.
#[test]
fn test_unknown_attributes_are_answered_420_with_the_list() {
    let provider = provider();
    let crypto = provider.crypto();
    let request = received(&build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([5; TRANSACTION_ID_SIZE])),
        raw_attr(ATTR_CHANGE_REQUEST, &[0, 0, 0, 6]),
        raw_attr(ATTR_PADDING, &[0; 4]),
    ]));
    let unknown = match Validator::new()
        .known_attributes(&STUN_ATTRIBUTES)
        .unauthenticated(&request)
    {
        Err(Rejection::UnknownAttributes(unknown)) => unknown,
        other => panic!("expected unknown attributes, got {other:?}"),
    };

    let response = unknown_attributes_response(
        &request,
        &unknown,
        &[
            Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                KEY.to_vec(),
                crypto,
            )),
            Box::new(FINGERPRINT),
        ],
    )
    .unwrap();
    // On the wire: Binding error response, the request's transaction id, then ERROR-CODE
    // with class 4 and number 20.
    assert_eq!(&response.raw[..2], &[0x01, 0x11]);
    assert_eq!(&response.raw[8..20], &[5; TRANSACTION_ID_SIZE]);
    assert_eq!(
        &response.raw[20..28],
        &[0x00, 0x09, 0x00, 0x15, 0x00, 0x00, 0x04, 20]
    );

    let decoded = received(&response);
    assert_eq!(decoded.typ, BINDING_ERROR);
    let valid = Validator::new()
        .require_fingerprint()
        .authenticate(&decoded, KEY, crypto)
        .expect("the response is signed and fingerprinted");
    let mut code = ErrorCodeAttribute::default();
    code.get_from(&valid).unwrap();
    assert_eq!(code.code, CODE_UNKNOWN_ATTRIBUTE);
    assert_eq!(code.reason, b"Unknown Attribute");
    let mut list = UnknownAttributes(vec![]);
    list.get_from(&valid).unwrap();
    assert_eq!(list.0, vec![ATTR_CHANGE_REQUEST, ATTR_PADDING]);
    assert_eq!(
        valid.get(ATTR_UNKNOWN_ATTRIBUTES).unwrap(),
        [0x00, 0x03, 0x00, 0x26]
    );

    // Only a request is answered: an indication or a response with unknown attributes is
    // dropped (sections 6.3.2 to 6.3.4).
    for class in [
        CLASS_INDICATION,
        CLASS_SUCCESS_RESPONSE,
        CLASS_ERROR_RESPONSE,
    ] {
        let mut other = request.clone();
        other.typ.class = class;
        assert!(unknown_attributes_response(&other, &unknown, &[]).is_err());
    }
}

/// A message that is not authenticated by design still has the attributes after an integrity
/// attribute left out (RFC 8489 section 9 binds every agent), and is not reported as
/// authenticated.
#[test]
fn test_unauthenticated_message_hides_what_follows_an_integrity_attribute() {
    let provider = provider();
    let crypto = provider.crypto();
    let plain = received(&signed_request(&[]));
    let valid = Validator::new().unauthenticated(&plain).unwrap();
    assert!(!valid.is_authenticated());
    assert_eq!(valid.attributes, plain.attributes);
    assert_eq!(valid.raw, plain.raw);

    let signed_by_someone = with_appended(
        &signed_request(
            &[Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                b"unknown key".to_vec(),
                crypto,
            ))],
        ),
        ATTR_ICE_CONTROLLED,
        &[0; 8],
    );
    let valid = Validator::new()
        .unauthenticated(&signed_by_someone)
        .unwrap();
    assert_eq!(valid.integrity(), None);
    assert!(valid.contains(ATTR_ICE_CONTROLLING));
    assert!(!valid.contains(ATTR_ICE_CONTROLLED));
}
