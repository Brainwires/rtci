#![cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]

use rtc_crypto::{RTCCryptoProvider, SignatureScheme};

#[cfg(feature = "crypto-ring")]
#[test]
fn ring_imports_and_uses_rsa_pkcs8() {
    assert_rsa_import(&rtc_crypto::providers::RingProvider::new());
}

#[cfg(feature = "crypto-aws-lc-rs")]
#[test]
fn aws_lc_rs_imports_and_uses_rsa_pkcs8() {
    assert_rsa_import(&rtc_crypto::providers::AwsLcRsProvider::new());
}

fn assert_rsa_import(provider: &dyn RTCCryptoProvider) {
    let pkcs8 = pem::parse(include_str!("data/rsa-2048.pkcs8.pem"))
        .unwrap()
        .into_contents();
    let key = provider
        .crypto()
        .import_signing_key(SignatureScheme::RsaPkcs1Sha256, &pkcs8)
        .unwrap();
    let message = b"RSA PKCS#8 import conformance";
    let signature = key.sign(SignatureScheme::RsaPkcs1Sha256, message).unwrap();
    provider
        .crypto()
        .verify_signature(
            SignatureScheme::RsaPkcs1Sha256,
            key.public_key(),
            message,
            &signature,
        )
        .unwrap();
    assert_eq!(
        key.to_pkcs8_der().unwrap().unwrap().as_ref(),
        pkcs8.as_slice()
    );

    // The same key signs RSASSA-PSS (the TLS 1.3 rsa_pss_rsae schemes): a PSS signature is
    // randomised, so two differ, and each verifies under its own scheme only.
    for scheme in [
        SignatureScheme::RsaPssSha256,
        SignatureScheme::RsaPssSha384,
        SignatureScheme::RsaPssSha512,
    ] {
        assert!(key.supports(scheme));
        let first = key.sign(scheme, message).unwrap();
        let second = key.sign(scheme, message).unwrap();
        assert_ne!(first, second);
        for signature in [&first, &second] {
            provider
                .crypto()
                .verify_signature(scheme, key.public_key(), message, signature)
                .unwrap();
        }
        assert_eq!(
            provider.crypto().verify_signature(
                SignatureScheme::RsaPkcs1Sha256,
                key.public_key(),
                message,
                &first,
            ),
            Err(rtc_crypto::CryptoError::InvalidSignature)
        );
    }
    assert!(!key.supports(SignatureScheme::EcdsaP256Sha256));
}
