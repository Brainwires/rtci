#![no_main]
//! Parser target: a STUN message (RFC 8489) and every attribute decoder the ICE agent and the
//! TURN client call on what a peer or server sends: MAPPED-ADDRESS and its aliases,
//! XOR-MAPPED-ADDRESS (IPv4 and IPv6 lengths), the text attributes, ERROR-CODE,
//! UNKNOWN-ATTRIBUTES, FINGERPRINT and MESSAGE-INTEGRITY, and what RFC 8489 added:
//! MESSAGE-INTEGRITY-SHA256, USERHASH, PASSWORD-ALGORITHM(S), ALTERNATE-DOMAIN, the nonce
//! cookie, the validator, the long-term challenge and the 300 (Try Alternate) reader. Decoding
//! happens lazily, attribute by attribute, so parsing the message alone
//! (`message_unmarshal_binary`) never reaches these.

use libfuzzer_sys::fuzz_target;
use rtc_stun::addr::{AlternateServer, MappedAddress, OtherAddress, ResponseOrigin};
use rtc_stun::alternate::TryAlternate;
use rtc_stun::attributes::{
    ATTR_ALTERNATE_DOMAIN, ATTR_ALTERNATE_SERVER, ATTR_NONCE, ATTR_OTHER_ADDRESS, ATTR_REALM,
    ATTR_RESPONSE_ORIGIN, ATTR_SOFTWARE, ATTR_USERNAME, ATTR_XOR_PEER_ADDRESS,
    ATTR_XOR_RELAYED_ADDRESS, STUN_ATTRIBUTES,
};
use rtc_stun::error_code::ErrorCodeAttribute;
use rtc_stun::fingerprint::FingerprintAttr;
use rtc_stun::integrity::{MessageIntegrity, MessageIntegritySha256};
use rtc_stun::long_term::LongTermCredentials;
use rtc_stun::message::{Getter, Message};
use rtc_stun::nonce_cookie::SecurityFeatures;
use rtc_stun::password_algorithm::{PasswordAlgorithm, PasswordAlgorithms};
use rtc_stun::textattrs::TextAttribute;
use rtc_stun::uattrs::UnknownAttributes;
use rtc_stun::userhash::Userhash;
use rtc_stun::validated::Validator;
use rtc_stun::xoraddr::XorMappedAddress;

fuzz_target!(|data: &[u8]| {
    let mut m = Message::new();
    if m.unmarshal_binary(data).is_err() {
        return;
    }

    let _ = XorMappedAddress::default().get_from(&m);
    for t in [ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS] {
        let _ = XorMappedAddress::default().get_from_as(&m, t);
    }
    let _ = MappedAddress::default().get_from(&m);
    for t in [
        ATTR_ALTERNATE_SERVER,
        ATTR_RESPONSE_ORIGIN,
        ATTR_OTHER_ADDRESS,
    ] {
        let _ = MappedAddress::default().get_from_as(&m, t);
    }
    let _ = AlternateServer::default().get_from(&m);
    let _ = ResponseOrigin::default().get_from(&m);
    let _ = OtherAddress::default().get_from(&m);
    for t in [
        ATTR_USERNAME,
        ATTR_REALM,
        ATTR_NONCE,
        ATTR_SOFTWARE,
        ATTR_ALTERNATE_DOMAIN,
    ] {
        let _ = TextAttribute::get_from_as(&m, t);
    }
    if let Ok(nonce) = TextAttribute::get_from_as(&m, ATTR_NONCE) {
        let _ = SecurityFeatures::from_nonce(&nonce.text);
    }
    let _ = PasswordAlgorithm::default().get_from(&m);
    let _ = PasswordAlgorithms::default().get_from(&m);
    let _ = Userhash::default().get_from(&m);
    let _ = m.unknown_required_attributes(&STUN_ATTRIBUTES);
    let _ = ErrorCodeAttribute::default().get_from(&m);
    let _ = UnknownAttributes(Vec::new()).get_from(&m);
    let _ = FingerprintAttr.check(&m);

    if let Ok(provider) = rtc_stun::crypto::default_provider() {
        // A short-term key, as ICE uses; TURN's long-term key is a key of the same kind.
        let crypto = provider.crypto();
        let _ = MessageIntegrity::check(&mut m, b"password", crypto);
        let _ = MessageIntegritySha256::check_truncated(&m, 16, b"password", crypto);

        // The receive path of a usage: every check, then only the covered attributes.
        let validator = Validator::new()
            .known_attributes(&STUN_ATTRIBUTES)
            .allow_truncated_sha256(16);
        let _ = validator.authenticate(&m, b"password", crypto);
        if let Ok(view) = validator.unauthenticated(&m) {
            let _ = TryAlternate::from_response(&view);
        }
        if let Ok(mut credentials) = LongTermCredentials::new("user", "password") {
            let _ = credentials.challenge(&m, &m, crypto);
            let _ = credentials.check_response(&m, &Validator::new(), crypto);
        }
    }
});
