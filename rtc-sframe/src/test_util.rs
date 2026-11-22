//! Helpers shared by the tests.

use std::sync::Arc;

use crypto::RTCCryptoProvider;

/// The built-in provider the tests run on.
pub(crate) fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

/// The bytes of a hex string; spaces and line breaks are skipped, as the RFC's vectors have
/// them.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            other => panic!("not a lowercase hex digit: {other:#x}"),
        })
        .collect();
    assert!(digits.len().is_multiple_of(2), "odd number of hex digits");
    let (pairs, _) = digits.as_chunks::<2>();
    pairs.iter().map(|&[high, low]| (high << 4) | low).collect()
}
