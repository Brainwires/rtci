#![no_main]

use libfuzzer_sys::fuzz_target;
use rtci_stun::attributes::ATTR_SOFTWARE;
use rtci_stun::message::Message;
use rtci_stun::textattrs::TextAttribute;
use rtci_stun::xoraddr::XorMappedAddress;

fuzz_target!(|data: &[u8]| {
    let mut m = Message::new();
    m.build(&[
        Box::new(TextAttribute::new(ATTR_SOFTWARE, "software".to_owned())),
        Box::new(XorMappedAddress {
            ip: "213.1.223.5".parse().unwrap(),
            port: 0,
        }),
    ])
    .unwrap();

    let _ = m.unmarshal_binary(data);
});
