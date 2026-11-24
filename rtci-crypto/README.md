# rtci-crypto

`rtci-crypto` provides the provider-neutral cryptographic operations used by every crate of the `rtci` workspace. Applications can use a built-in Ring or AWS-LC-RS provider, or implement the public provider traits without registration or sealing.

The crate owns primitives and opaque keyed state. DTLS, SRTP, STUN, certificate policy, and wire-format composition remain in their protocol crates.

Enable `test-support` to run the reusable provider conformance suite from a downstream provider's tests.

```rust
#[test]
fn provider_conforms() {
    let provider = MyProvider::new();
    rtci_crypto::conformance::assert_provider(&provider);
}
```

Partial providers can invoke the public operation-family helpers that match their advertised capabilities. The feature adds no built-in backend, so a downstream provider can test with `default-features = false, features = ["test-support"]`.

The `crypto-ring` (default) and `crypto-aws-lc-rs` features are additive. The ring provider is the default when enabled, including builds that enable both backends. With neither backend enabled, applications construct their own `Arc<dyn RTCCryptoProvider>` and `default_provider()` returns `CryptoError::NoDefaultProvider`.

`openssl` (and `vendored-openssl`) add an OpenSSL AES-CTR stream cipher for `rtci-srtp`'s `openssl` feature. There is no I/O in the crate: providers are called with the data and keys their callers hold.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
