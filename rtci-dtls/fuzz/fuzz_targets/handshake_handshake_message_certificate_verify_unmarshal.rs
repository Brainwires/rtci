#![no_main]
use libfuzzer_sys::fuzz_target;
use rtci_dtls::handshake::handshake_message_certificate_verify::HandshakeMessageCertificateVerify;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = HandshakeMessageCertificateVerify::unmarshal(&mut cursor);
});
