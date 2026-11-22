use super::*;
use crate::error_code::{CODE_BAD_REQUEST, CODE_SERVER_ERROR};
use crate::fingerprint::FINGERPRINT;
use crate::integrity::{MessageIntegrity, MessageIntegritySha256};
use crypto::RTCCryptoProvider;
use std::sync::Arc;

const USER: &str = "user";
const PASS: &str = "pass";
const REALM: &str = "realm";

fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn message(setters: &[Box<dyn Setter + '_>]) -> Message {
    let mut built = Message::new();
    built.build(setters).expect("the message builds");
    // Through the wire, as the other side would see it.
    let mut received = Message::new();
    received
        .unmarshal_binary(&built.raw)
        .expect("the message decodes");
    received
}

/// An Allocate request as the client sends it: its own attribute, then the credentials.
fn request(credentials: &LongTermCredentials, crypto: &dyn RTCCrypto) -> Message {
    message(&[
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
        Box::new(TransactionId::new()),
        Box::new(RawAttribute {
            typ: ATTR_REQUESTED_TRANSPORT,
            length: 0,
            value: vec![17, 0, 0, 0],
        }),
        Box::new(credentials.setter(crypto)),
        Box::new(FINGERPRINT),
    ])
}

fn error(request: &Message, code: ErrorCode, attrs: Vec<Box<dyn Setter + '_>>) -> Message {
    let mut setters: Vec<Box<dyn Setter + '_>> = vec![
        Box::new(MessageType::new(request.typ.method, CLASS_ERROR_RESPONSE)),
        Box::new(request.transaction_id),
        Box::new(code),
    ];
    setters.extend(attrs);
    message(&setters)
}

fn text(attr: AttrType, s: &str) -> Box<TextAttribute> {
    Box::new(TextAttribute::new(attr, s.to_owned()))
}

fn sha256_then_md5() -> PasswordAlgorithms {
    PasswordAlgorithms(vec![
        PasswordAlgorithm::new(PASSWORD_ALGORITHM_SHA256),
        PasswordAlgorithm::new(PASSWORD_ALGORITHM_MD5),
    ])
}

/// The nonce of an RFC 8489 server with the given features.
fn nonce(features: SecurityFeatures) -> String {
    format!("{}f//499k954d6OL34oL9FSTvy64sA", features.cookie())
}

/// RFC 8489 section 9.2.3.1: the first request carries none of USERNAME, USERHASH,
/// MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256, REALM, NONCE, PASSWORD-ALGORITHMS and
/// PASSWORD-ALGORITHM.
#[test]
fn test_first_request_carries_no_credentials() -> Result<()> {
    let provider = provider();
    let credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, provider.crypto());
    for attr in [
        ATTR_USERNAME,
        ATTR_USER_HASH,
        ATTR_MESSAGE_INTEGRITY,
        ATTR_MESSAGE_INTEGRITY_SHA256,
        ATTR_REALM,
        ATTR_NONCE,
        ATTR_PASSWORD_ALGORITHMS,
        ATTR_PASSWORD_ALGORITHM,
    ] {
        assert!(!first.contains(attr), "{attr} in the first request");
    }
    assert!(first.contains(ATTR_REQUESTED_TRANSPORT));
    Ok(())
}

/// RFC 8489 sections 9.2.2 and 9.2.5 against a server of RFC 5389 (no nonce cookie, no
/// PASSWORD-ALGORITHMS): the retry carries USERNAME, the REALM and NONCE of the response and
/// MESSAGE-INTEGRITY under the MD5 key, and nothing RFC 8489 added.
#[test]
fn test_retry_for_an_rfc5389_server_uses_username_and_the_md5_key() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, crypto);
    let challenge = error(
        &first,
        CODE_UNAUTHORIZED,
        vec![text(ATTR_REALM, REALM), text(ATTR_NONCE, "plain-nonce")],
    );
    credentials
        .challenge(&first, &challenge, crypto)
        .expect("a 401 with REALM and NONCE is retried");

    let mut retry = request(&credentials, crypto);
    assert_eq!(
        TextAttribute::get_from_as(&retry, ATTR_USERNAME)?.text,
        USER
    );
    assert_eq!(TextAttribute::get_from_as(&retry, ATTR_REALM)?.text, REALM);
    assert_eq!(
        TextAttribute::get_from_as(&retry, ATTR_NONCE)?.text,
        "plain-nonce"
    );
    for attr in [
        ATTR_USER_HASH,
        ATTR_PASSWORD_ALGORITHMS,
        ATTR_PASSWORD_ALGORITHM,
        ATTR_MESSAGE_INTEGRITY_SHA256,
    ] {
        assert!(!retry.contains(attr), "{attr} sent to an RFC 5389 server");
    }
    // The key of RFC 8489 section 9.2.2 for user:realm:pass.
    let key = [
        0x84, 0x93, 0xfb, 0xc5, 0x3b, 0xa5, 0x82, 0xfb, 0x4c, 0x04, 0x4c, 0x45, 0x6b, 0xdc, 0x40,
        0xeb,
    ];
    MessageIntegrity::check(&mut retry, &key, crypto)?;
    assert_eq!(credentials.integrity(), Some(IntegrityAlgorithm::Sha1));
    Ok(())
}

/// RFC 8489 section 9.2.5 against a server of RFC 8489 that sets both security features: the
/// retry carries USERHASH and no USERNAME, the REALM and NONCE of the response,
/// PASSWORD-ALGORITHMS with the same content, PASSWORD-ALGORITHM with the first supported
/// algorithm, and MESSAGE-INTEGRITY-SHA256 alone under that algorithm's key.
#[test]
fn test_retry_for_an_rfc8489_server_uses_userhash_algorithms_and_sha256() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, crypto);
    let server_nonce =
        nonce(SecurityFeatures::PASSWORD_ALGORITHMS.with(SecurityFeatures::USERNAME_ANONYMITY));
    let challenge = error(
        &first,
        CODE_UNAUTHORIZED,
        vec![
            text(ATTR_REALM, REALM),
            text(ATTR_NONCE, &server_nonce),
            Box::new(sha256_then_md5()),
        ],
    );
    credentials
        .challenge(&first, &challenge, crypto)
        .expect("the challenge is consistent");

    let retry = request(&credentials, crypto);
    assert!(!retry.contains(ATTR_USERNAME), "USERNAME with anonymity on");
    let mut userhash = Userhash::default();
    userhash.get_from(&retry)?;
    assert_eq!(userhash, Userhash::new(USER, REALM, crypto)?);
    assert_eq!(TextAttribute::get_from_as(&retry, ATTR_REALM)?.text, REALM);
    assert_eq!(
        TextAttribute::get_from_as(&retry, ATTR_NONCE)?.text,
        server_nonce
    );
    assert_eq!(
        retry.get(ATTR_PASSWORD_ALGORITHMS)?,
        challenge.get(ATTR_PASSWORD_ALGORITHMS)?,
        "PASSWORD-ALGORITHMS is echoed with the same content"
    );
    let mut algorithm = PasswordAlgorithm::default();
    algorithm.get_from(&retry)?;
    assert_eq!(algorithm.algorithm, PASSWORD_ALGORITHM_SHA256);
    assert!(
        !retry.contains(ATTR_MESSAGE_INTEGRITY),
        "MESSAGE-INTEGRITY-SHA256 only after PASSWORD-ALGORITHMS"
    );
    let key = long_term_key(PASSWORD_ALGORITHM_SHA256, USER, REALM, PASS, crypto)?;
    assert_eq!(key.len(), 32);
    MessageIntegritySha256::check(&retry, &key, crypto)?;
    assert_eq!(credentials.integrity(), Some(IntegrityAlgorithm::Sha256));
    assert!(credentials.uses_userhash());
    Ok(())
}

/// RFC 8489 section 9.2.5: "the first algorithm supported on the list": the server's order
/// decides, and the key is that algorithm's.
#[test]
fn test_password_algorithm_is_the_first_supported_in_the_servers_order() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, crypto);
    let offered = PasswordAlgorithms(vec![
        PasswordAlgorithm::new(0x7777),
        PasswordAlgorithm::new(PASSWORD_ALGORITHM_MD5),
        PasswordAlgorithm::new(PASSWORD_ALGORITHM_SHA256),
    ]);
    let challenge = error(
        &first,
        CODE_UNAUTHORIZED,
        vec![
            text(ATTR_REALM, REALM),
            text(ATTR_NONCE, &nonce(SecurityFeatures::PASSWORD_ALGORITHMS)),
            Box::new(offered),
        ],
    );
    credentials.challenge(&first, &challenge, crypto).unwrap();

    let retry = request(&credentials, crypto);
    let mut algorithm = PasswordAlgorithm::default();
    algorithm.get_from(&retry)?;
    assert_eq!(algorithm.algorithm, PASSWORD_ALGORITHM_MD5);
    assert!(retry.contains(ATTR_USERNAME), "no anonymity bit: USERNAME");
    let key = long_term_key(PASSWORD_ALGORITHM_MD5, USER, REALM, PASS, crypto)?;
    MessageIntegritySha256::check(&retry, &key, crypto)?;
    Ok(())
}

/// RFC 8489 section 9.2.5: a nonce cookie with the "Password algorithms" bit and no
/// PASSWORD-ALGORITHMS attribute means the attribute was stripped: the client does not retry.
/// A PASSWORD-ALGORITHMS placed after an integrity attribute does not count (section 9).
#[test]
fn test_challenge_without_the_promised_password_algorithms_is_not_retried() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, crypto);
    let promised = nonce(SecurityFeatures::PASSWORD_ALGORITHMS);

    for code in [CODE_UNAUTHORIZED, CODE_STALE_NONCE] {
        let stripped = error(
            &first,
            code,
            vec![text(ATTR_REALM, REALM), text(ATTR_NONCE, &promised)],
        );
        assert_eq!(
            credentials.challenge(&first, &stripped, crypto),
            Err(ChallengeError::BidDown)
        );
    }
    let appended = error(
        &first,
        CODE_UNAUTHORIZED,
        vec![
            text(ATTR_REALM, REALM),
            text(ATTR_NONCE, &promised),
            Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                b"some previous key".to_vec(),
                crypto,
            )),
            Box::new(sha256_then_md5()),
        ],
    );
    assert_eq!(
        credentials.challenge(&first, &appended, crypto),
        Err(ChallengeError::BidDown)
    );

    // Nothing was taken from the refused challenges: the next request is still a first one.
    assert_eq!(credentials.realm(), None);
    assert!(!request(&credentials, crypto).contains(ATTR_NONCE));
    Ok(())
}

/// RFC 8489 section 9.2.5: no retry when PASSWORD-ALGORITHMS lists no supported algorithm.
#[test]
fn test_challenge_with_no_supported_algorithm_is_not_retried() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let first = request(&LongTermCredentials::new(USER, PASS)?, crypto);
    let with_list = |list: PasswordAlgorithms| {
        error(
            &first,
            CODE_UNAUTHORIZED,
            vec![
                text(ATTR_REALM, REALM),
                text(ATTR_NONCE, &nonce(SecurityFeatures::PASSWORD_ALGORITHMS)),
                Box::new(list),
            ],
        )
    };

    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let unknown_only = with_list(PasswordAlgorithms(vec![PasswordAlgorithm::new(0x7777)]));
    assert_eq!(
        credentials.challenge(&first, &unknown_only, crypto),
        Err(ChallengeError::NoSupportedAlgorithm)
    );

    // A client that keeps MD5 for no one (section 18.5.1.1) refuses an MD5-only server.
    let mut sha256_only = LongTermCredentials::new(USER, PASS)?
        .with_password_algorithms(&[PASSWORD_ALGORITHM_SHA256]);
    let md5_only = with_list(PasswordAlgorithms(vec![PasswordAlgorithm::new(
        PASSWORD_ALGORITHM_MD5,
    )]));
    assert_eq!(
        sha256_only.challenge(&first, &md5_only, crypto),
        Err(ChallengeError::NoSupportedAlgorithm)
    );
    let legacy = error(
        &first,
        CODE_UNAUTHORIZED,
        vec![text(ATTR_REALM, REALM), text(ATTR_NONCE, "plain-nonce")],
    );
    assert_eq!(
        sha256_only.challenge(&first, &legacy, crypto),
        Err(ChallengeError::NoSupportedAlgorithm)
    );
    assert!(
        sha256_only
            .challenge(&first, &with_list(sha256_then_md5()), crypto)
            .is_ok()
    );
    Ok(())
}

/// RFC 8489 section 9.2.5: no retry of a 401 without changing the user name, the realm or
/// the password; a 401 that names another realm is a new challenge.
#[test]
fn test_a_401_to_the_same_credentials_is_not_retried() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, crypto);
    let challenge = |to: &Message, realm: &str| {
        error(
            to,
            CODE_UNAUTHORIZED,
            vec![text(ATTR_REALM, realm), text(ATTR_NONCE, "nonce-1")],
        )
    };
    credentials
        .challenge(&first, &challenge(&first, REALM), crypto)
        .unwrap();

    let authenticated = request(&credentials, crypto);
    assert_eq!(
        credentials.challenge(&authenticated, &challenge(&authenticated, REALM), crypto),
        Err(ChallengeError::CredentialsRejected)
    );
    assert_eq!(credentials.realm(), Some(REALM));

    credentials
        .challenge(
            &authenticated,
            &challenge(&authenticated, "other.example"),
            crypto,
        )
        .expect("another realm is another credential");
    assert_eq!(credentials.realm(), Some("other.example"));
    Ok(())
}

/// RFC 8489 section 9.2.5: a 438 is retried with its new NONCE, with USERNAME, REALM and the
/// integrity attribute.
#[test]
fn test_stale_nonce_is_retried_with_the_new_nonce() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, crypto);
    let with_nonce = |to: &Message, code: ErrorCode, nonce: &str| {
        error(
            to,
            code,
            vec![text(ATTR_REALM, REALM), text(ATTR_NONCE, nonce)],
        )
    };
    credentials
        .challenge(
            &first,
            &with_nonce(&first, CODE_UNAUTHORIZED, "nonce-1"),
            crypto,
        )
        .unwrap();
    let second = request(&credentials, crypto);
    credentials
        .challenge(
            &second,
            &with_nonce(&second, CODE_STALE_NONCE, "nonce-2"),
            crypto,
        )
        .expect("a 438 is retried");

    let mut third = request(&credentials, crypto);
    assert_eq!(
        TextAttribute::get_from_as(&third, ATTR_NONCE)?.text,
        "nonce-2"
    );
    assert_eq!(
        TextAttribute::get_from_as(&third, ATTR_USERNAME)?.text,
        USER
    );
    assert_eq!(TextAttribute::get_from_as(&third, ATTR_REALM)?.text, REALM);
    let key = long_term_key(PASSWORD_ALGORITHM_MD5, USER, REALM, PASS, crypto)?;
    MessageIntegrity::check(&mut third, &key, crypto)?;
    Ok(())
}

/// Only a 401 or a 438 with REALM and NONCE is a challenge.
#[test]
fn test_other_responses_are_not_challenges() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, crypto);
    let realm_and_nonce =
        || -> Vec<Box<dyn Setter>> { vec![text(ATTR_REALM, REALM), text(ATTR_NONCE, "n")] };

    let try_alternate = error(
        &first,
        crate::error_code::CODE_TRY_ALTERNATE,
        realm_and_nonce(),
    );
    assert_eq!(
        credentials.challenge(&first, &try_alternate, crypto),
        Err(ChallengeError::NotAChallenge)
    );
    let success = message(&[
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE)),
        Box::new(first.transaction_id),
        text(ATTR_REALM, REALM),
        text(ATTR_NONCE, "n"),
    ]);
    assert_eq!(
        credentials.challenge(&first, &success, crypto),
        Err(ChallengeError::NotAChallenge)
    );
    let no_nonce = error(&first, CODE_UNAUTHORIZED, vec![text(ATTR_REALM, REALM)]);
    assert_eq!(
        credentials.challenge(&first, &no_nonce, crypto),
        Err(ChallengeError::Incomplete)
    );
    Ok(())
}

/// RFC 8489 section 9.2.5, receiving a response: authenticated responses are accepted; a 400
/// without an integrity attribute, and any response whose integrity is absent or wrong, is
/// discarded; 401 and 438 are challenges; a response with the "Password algorithms" cookie
/// bit and no PASSWORD-ALGORITHMS is ignored; after PASSWORD-ALGORITHMS only
/// MESSAGE-INTEGRITY-SHA256 authenticates.
#[test]
fn test_responses_are_authenticated_discarded_or_challenges() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut credentials = LongTermCredentials::new(USER, PASS)?;
    let first = request(&credentials, crypto);
    let promised = nonce(SecurityFeatures::PASSWORD_ALGORITHMS);
    let challenge = error(
        &first,
        CODE_UNAUTHORIZED,
        vec![
            text(ATTR_REALM, REALM),
            text(ATTR_NONCE, &promised),
            Box::new(sha256_then_md5()),
        ],
    );
    let validator = Validator::new();

    // Before the challenge there is no key: a challenge is recognised, nothing authenticates.
    assert!(matches!(
        credentials.check_response(&challenge, &validator, crypto),
        Ok(LongTermResponse::Challenge(_))
    ));
    credentials.challenge(&first, &challenge, crypto).unwrap();
    let retry = request(&credentials, crypto);
    let key = long_term_key(PASSWORD_ALGORITHM_SHA256, USER, REALM, PASS, crypto)?;
    let success_type = MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE);

    let signed = message(&[
        Box::new(success_type),
        Box::new(retry.transaction_id),
        Box::new(RawAttribute {
            typ: ATTR_LIFETIME,
            length: 0,
            value: vec![0, 0, 2, 88],
        }),
        Box::new(MessageIntegritySha256::new_raw(key.clone(), crypto)),
    ]);
    match credentials.check_response(&signed, &validator, crypto) {
        Ok(LongTermResponse::Authenticated(valid)) => {
            assert!(valid.contains(ATTR_LIFETIME));
            assert_eq!(valid.integrity(), Some(IntegrityAlgorithm::Sha256));
        }
        other => panic!("expected an authenticated response, got {other:?}"),
    }

    let bad_request = error(&retry, CODE_BAD_REQUEST, vec![]);
    assert_eq!(
        credentials.check_response(&bad_request, &validator, crypto),
        Err(Rejection::IntegrityMissing),
        "a 400 without an integrity attribute is discarded"
    );
    let forged = error(
        &retry,
        CODE_SERVER_ERROR,
        vec![Box::new(MessageIntegritySha256::new_raw(
            b"not the key".to_vec(),
            crypto,
        ))],
    );
    assert_eq!(
        credentials.check_response(&forged, &validator, crypto),
        Err(Rejection::IntegrityMismatch)
    );
    let sha1_only = message(&[
        Box::new(success_type),
        Box::new(retry.transaction_id),
        Box::new(MessageIntegrity::new_raw_integrity_with_provider(
            key.clone(),
            crypto,
        )),
    ]);
    assert_eq!(
        credentials.check_response(&sha1_only, &validator, crypto),
        Err(Rejection::IntegrityMissing),
        "MESSAGE-INTEGRITY does not authenticate once PASSWORD-ALGORITHMS was received"
    );

    let stale = error(
        &retry,
        CODE_STALE_NONCE,
        vec![
            text(ATTR_REALM, REALM),
            text(ATTR_NONCE, &promised),
            Box::new(sha256_then_md5()),
        ],
    );
    assert!(matches!(
        credentials.check_response(&stale, &validator, crypto),
        Ok(LongTermResponse::Challenge(_))
    ));

    // "For all other responses": the cookie promises PASSWORD-ALGORITHMS, the response has
    // none, so it is ignored although its integrity holds.
    let stripped = message(&[
        Box::new(success_type),
        Box::new(retry.transaction_id),
        text(ATTR_NONCE, &promised),
        Box::new(MessageIntegritySha256::new_raw(key.clone(), crypto)),
    ]);
    assert!(
        credentials
            .check_response(&stripped, &validator, crypto)
            .is_err()
    );
    let intact = message(&[
        Box::new(success_type),
        Box::new(retry.transaction_id),
        text(ATTR_NONCE, &promised),
        Box::new(sha256_then_md5()),
        Box::new(MessageIntegritySha256::new_raw(key, crypto)),
    ]);
    assert!(matches!(
        credentials.check_response(&intact, &validator, crypto),
        Ok(LongTermResponse::Authenticated(_))
    ));
    Ok(())
}

/// RFC 8489 appendix B.1 as corrected by its verified erratum 6268 (the message length
/// excludes the header, PASSWORD-ALGORITHM is present, the HMAC is recomputed): the sample
/// request with long-term authentication, MESSAGE-INTEGRITY-SHA256 and USERHASH.
#[test]
fn test_rfc8489_appendix_b1_userhash_and_message_integrity_sha256() -> Result<()> {
    #[rustfmt::skip]
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x90, // Request type and message length
        0x21, 0x12, 0xa4, 0x42, // Magic cookie
        0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e, // Transaction ID
        0x00, 0x1e, 0x00, 0x20, // USERHASH attribute header
        0x4a, 0x3c, 0xf3, 0x8f, 0xef, 0x69, 0x92, 0xbd, 0xa9, 0x52, 0xc6, 0x78, 0x04, 0x17, 0xda,
        0x0f, 0x24, 0x81, 0x94, 0x15, 0x56, 0x9e, 0x60, 0xb2, 0x05, 0xc4, 0x6e, 0x41, 0x40, 0x7f,
        0x17, 0x04,
        0x00, 0x15, 0x00, 0x29, // NONCE attribute header
        0x6f, 0x62, 0x4d, 0x61, 0x74, 0x4a, 0x6f, 0x73, 0x32, 0x41, 0x41, 0x41, 0x43, 0x66, 0x2f,
        0x2f, 0x34, 0x39, 0x39, 0x6b, 0x39, 0x35, 0x34, 0x64, 0x36, 0x4f, 0x4c, 0x33, 0x34, 0x6f,
        0x4c, 0x39, 0x46, 0x53, 0x54, 0x76, 0x79, 0x36, 0x34, 0x73, 0x41, 0x00, 0x00, 0x00,
        0x00, 0x14, 0x00, 0x0b, // REALM attribute header
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x6f, 0x72, 0x67, 0x00,
        0x00, 0x1d, 0x00, 0x04, // PASSWORD-ALGORITHM attribute header
        0x00, 0x02, 0x00, 0x00, // SHA-256, no parameters
        0x00, 0x1c, 0x00, 0x20, // MESSAGE-INTEGRITY-SHA256 attribute header
        0xb5, 0xc7, 0xbf, 0x00, 0x5b, 0x6c, 0x52, 0xa2, 0x1c, 0x51, 0xc5, 0xe8, 0x92, 0xf8, 0x19,
        0x24, 0x13, 0x62, 0x96, 0xcb, 0x92, 0x7c, 0x43, 0x14, 0x93, 0x09, 0x27, 0x8c, 0xc6, 0x51,
        0x8e, 0x65,
    ];
    let username = "\u{30de}\u{30c8}\u{30ea}\u{30c3}\u{30af}\u{30b9}";
    let nonce = "obMatJos2AAACf//499k954d6OL34oL9FSTvy64sA";
    let provider = provider();
    let crypto = provider.crypto();

    let mut m = Message::new();
    m.unmarshal_binary(&raw)?;
    assert_eq!(m.typ, BINDING_REQUEST);

    let mut userhash = Userhash::default();
    userhash.get_from(&m)?;
    assert_eq!(userhash, Userhash::new(username, "example.org", crypto)?);
    assert_eq!(TextAttribute::get_from_as(&m, ATTR_NONCE)?.text, nonce);
    let mut algorithm = PasswordAlgorithm::default();
    algorithm.get_from(&m)?;
    assert_eq!(algorithm, PasswordAlgorithm::new(PASSWORD_ALGORITHM_SHA256));

    let key = long_term_key(
        PASSWORD_ALGORITHM_SHA256,
        username,
        "example.org",
        "TheMatrIX",
        crypto,
    )?;
    MessageIntegritySha256::check(&m, &key, crypto)?;
    let valid = Validator::new()
        .authenticate(&m, &key, crypto)
        .expect("the vector authenticates");
    assert_eq!(valid.integrity(), Some(IntegrityAlgorithm::Sha256));

    // The same bytes come out of the encoder.
    let mut built = Message::new();
    built.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(m.transaction_id),
        Box::new(userhash),
        text(ATTR_NONCE, nonce),
        text(ATTR_REALM, "example.org"),
        Box::new(algorithm),
        Box::new(MessageIntegritySha256::new_raw(key, crypto)),
    ])?;
    assert_eq!(built.raw, raw);
    Ok(())
}
