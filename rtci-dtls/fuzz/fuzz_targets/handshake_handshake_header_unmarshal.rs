#![no_main]
use libfuzzer_sys::fuzz_target;
use rtci_dtls::handshake::handshake_header::HandshakeHeader;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = HandshakeHeader::unmarshal(&mut cursor);
});
