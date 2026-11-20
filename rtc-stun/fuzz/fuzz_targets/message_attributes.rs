#![no_main]
//! Parser target: a STUN message (RFC 8489) and every attribute decoder the ICE agent and the
//! TURN client call on what a peer or server sends: MAPPED-ADDRESS and its aliases,
//! XOR-MAPPED-ADDRESS (IPv4 and IPv6 lengths), the text attributes, ERROR-CODE,
//! UNKNOWN-ATTRIBUTES, FINGERPRINT and MESSAGE-INTEGRITY. Decoding happens lazily, attribute by
//! attribute, so parsing the message alone (`message_unmarshal_binary`) never reaches these.

use libfuzzer_sys::fuzz_target;
use rtc_stun::addr::MappedAddress;
use rtc_stun::attributes::{
    ATTR_ALTERNATE_SERVER, ATTR_NONCE, ATTR_OTHER_ADDRESS, ATTR_REALM, ATTR_RESPONSE_ORIGIN,
    ATTR_SOFTWARE, ATTR_USERNAME, ATTR_XOR_PEER_ADDRESS, ATTR_XOR_RELAYED_ADDRESS,
};
use rtc_stun::error_code::ErrorCodeAttribute;
use rtc_stun::fingerprint::FingerprintAttr;
use rtc_stun::integrity::MessageIntegrity;
use rtc_stun::message::{Getter, Message};
use rtc_stun::textattrs::TextAttribute;
use rtc_stun::uattrs::UnknownAttributes;
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
    for t in [ATTR_USERNAME, ATTR_REALM, ATTR_NONCE, ATTR_SOFTWARE] {
        let _ = TextAttribute::get_from_as(&m, t);
    }
    let _ = ErrorCodeAttribute::default().get_from(&m);
    let _ = UnknownAttributes(Vec::new()).get_from(&m);
    let _ = FingerprintAttr.check(&m);

    if let Ok(provider) = rtc_stun::crypto::default_provider() {
        // A short-term key, as ICE uses; TURN's long-term key is a key of the same kind.
        let _ = MessageIntegrity::check(&mut m, b"password", provider.crypto());
    }
});
