//! The key schedule against the trace of RFC 8448 section 3 (which is TLS 1.3, so with the
//! `"tls13 "` label prefix), and what DTLS 1.3 changes: the prefix and the record-number key.

use super::key_schedule::*;
use super::suite::Suite13;
use crate::cipher_suite::CipherSuiteId;
use shared::error::Result;
use std::sync::Arc;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

pub(crate) fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| (byte as char).to_digit(16).expect("a hex digit") as u8)
        .collect();
    assert!(digits.len().is_multiple_of(2));
    digits
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

const AES128: Suite13 = Suite13 {
    id: CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
};

#[test]
fn the_key_schedule_reproduces_the_rfc_8448_trace() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut schedule = KeySchedule::new(crypto, AES128, TLS13_LABEL_PREFIX)?;

    // "extract secret handshake", "derive secret tls13 c hs traffic / s hs traffic".
    schedule.enter_handshake(
        crypto,
        &hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"),
        &hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
    )?;
    let client_handshake = schedule.client_handshake_traffic.clone().unwrap();
    let server_handshake = schedule.server_handshake_traffic.clone().unwrap();
    assert_eq!(
        client_handshake.as_ref(),
        hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    );
    assert_eq!(
        server_handshake.as_ref(),
        hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    );

    // "derive write traffic keys for handshake data".
    let keys = schedule.traffic_keys(crypto, server_handshake.as_ref())?;
    assert_eq!(keys.key.as_ref(), hex("3fce516009c21727d0f2e4e86ee403bc"));
    assert_eq!(keys.iv.as_ref(), hex("5d313eb2671276ee13000b30"));
    assert_eq!(keys.sequence_number_key.len(), 16);

    // "extract secret master", "derive secret tls13 c ap traffic / s ap traffic / exp master".
    let through_server_finished =
        hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    schedule.enter_application(crypto, &through_server_finished)?;
    assert_eq!(
        schedule
            .client_application_traffic
            .as_ref()
            .unwrap()
            .as_ref(),
        hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
    );
    let server_application = schedule.server_application_traffic.clone().unwrap();
    assert_eq!(
        server_application.as_ref(),
        hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
    );
    assert_eq!(
        schedule.exporter.as_ref().unwrap().as_ref(),
        hex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")
    );
    let keys = schedule.traffic_keys(crypto, server_application.as_ref())?;
    assert_eq!(keys.key.as_ref(), hex("9f02283b6c9c07efc26bb9f2ac92e356"));
    assert_eq!(keys.iv.as_ref(), hex("cf782b88dd83549aadf1e984"));

    // "calculate finished tls13 finished" for the client: over the transcript through the
    // server's Finished, keyed from the client handshake traffic secret.
    assert_eq!(
        schedule.finished_verify_data(
            crypto,
            client_handshake.as_ref(),
            &through_server_finished
        )?,
        hex("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")
    );
    Ok(())
}

#[test]
fn the_dtls_label_prefix_separates_the_keys_from_tls_13() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let shared = [0x42u8; 32];
    let transcript_hash = [0x17u8; 32];
    let secret_of = |prefix| -> Result<Vec<u8>> {
        let mut schedule = KeySchedule::new(crypto, AES128, prefix)?;
        schedule.enter_handshake(crypto, &shared, &transcript_hash)?;
        Ok(schedule
            .client_handshake_traffic
            .as_ref()
            .unwrap()
            .as_ref()
            .to_vec())
    };
    // RFC 9147 section 5.9: "dtls13", six bytes like "tls13 ", and a different key for it.
    assert_eq!(DTLS13_LABEL_PREFIX.len(), TLS13_LABEL_PREFIX.len());
    assert_ne!(
        secret_of(DTLS13_LABEL_PREFIX)?,
        secret_of(TLS13_LABEL_PREFIX)?
    );
    Ok(())
}

#[test]
fn each_suite_derives_keys_of_its_own_lengths() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    for (id, hash_len, key_len, mask_key_len) in [
        (CipherSuiteId::Tls_Aes_128_Gcm_Sha256, 32, 16, 16),
        (CipherSuiteId::Tls_Aes_256_Gcm_Sha384, 48, 32, 32),
        (CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256, 32, 32, 32),
        (CipherSuiteId::Tls_Aes_128_Ccm_Sha256, 32, 16, 16),
        (CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256, 32, 16, 16),
    ] {
        let suite = Suite13::for_id(id).expect("a TLS 1.3 suite");
        let mut schedule = KeySchedule::new(crypto, suite, DTLS13_LABEL_PREFIX)?;
        schedule.enter_handshake(crypto, &[1; 32], &vec![2; hash_len])?;
        let secret = schedule.server_handshake_traffic.clone().unwrap();
        assert_eq!(secret.len(), hash_len, "{id}");
        let keys = schedule.traffic_keys(crypto, secret.as_ref())?;
        assert_eq!(keys.key.len(), key_len, "{id}");
        assert_eq!(keys.iv.len(), 12, "{id}");
        assert_eq!(keys.sequence_number_key.len(), mask_key_len, "{id}");
        // The three are separate keys: none is a prefix of another.
        assert_ne!(
            keys.key.as_ref()[..12],
            keys.iv.as_ref()[..],
            "{id}: key and iv"
        );
        assert_ne!(
            keys.key.as_ref(),
            &keys.sequence_number_key.as_ref()[..key_len.min(mask_key_len)],
            "{id}: key and sn key"
        );
        let verify_data =
            schedule.finished_verify_data(crypto, secret.as_ref(), &vec![3; hash_len])?;
        assert_eq!(verify_data.len(), hash_len, "{id}");

        schedule.enter_application(crypto, &vec![4; hash_len])?;
        let application = schedule.client_application_traffic.clone().unwrap();
        let next = schedule.next_application_traffic_secret(crypto, application.as_ref())?;
        assert_eq!(next.len(), hash_len);
        assert_ne!(
            next.as_ref(),
            application.as_ref(),
            "{id}: a key update changes the secret"
        );
    }
    Ok(())
}

#[test]
fn the_exporter_depends_on_label_context_and_length() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let mut schedule = KeySchedule::new(crypto, AES128, DTLS13_LABEL_PREFIX)?;
    schedule.enter_handshake(crypto, &[1; 32], &[2; 32])?;
    schedule.enter_application(crypto, &[3; 32])?;
    let exporter = schedule.exporter.clone().unwrap();
    let export = |label: &str, context: &[u8], length| {
        schedule
            .export(crypto, exporter.as_ref(), label, context, length)
            .map(|secret| secret.as_ref().to_vec())
    };
    let srtp = export("EXTRACTOR-dtls_srtp", &[], 60)?;
    assert_eq!(srtp.len(), 60);
    assert_eq!(srtp, export("EXTRACTOR-dtls_srtp", &[], 60)?);
    assert_ne!(srtp, export("EXTRACTOR-other", &[], 60)?);
    assert_ne!(srtp, export("EXTRACTOR-dtls_srtp", b"context", 60)?);
    // The length is part of the HkdfLabel, so a shorter output is not a prefix of a longer.
    assert_ne!(srtp[..32], export("EXTRACTOR-dtls_srtp", &[], 32)?[..]);
    Ok(())
}

#[test]
fn a_hello_retry_request_replaces_the_first_client_hello_with_its_hash() -> Result<()> {
    let provider = provider();
    let crypto = provider.crypto();
    let client_hello = [0xabu8; 100];
    let mut transcript = Transcript::default();
    assert!(transcript.is_empty());
    transcript.add(1, &client_hello);
    let hash_of_client_hello = transcript.hash(crypto, AES128)?;

    // RFC 8446 section 4.4.1: message_hash (254), a 24-bit length, Hash(ClientHello1).
    transcript.replace_with_message_hash(crypto, AES128)?;
    let mut expected = vec![254, 0, 0, 32];
    expected.extend_from_slice(&hash_of_client_hello);
    assert_eq!(
        transcript.hash(crypto, AES128)?,
        crypto
            .hash(crypto::HashAlgorithm::Sha256, &expected)
            .unwrap()
    );

    // A server that kept nothing starts from the hash in its cookie and gets the same.
    let mut stateless = Transcript::default();
    stateless.set_message_hash(&hash_of_client_hello);
    assert_eq!(
        stateless.hash(crypto, AES128)?,
        transcript.hash(crypto, AES128)?
    );

    // hash_with is the hash of the transcript with a message appended.
    let mut longer = transcript.clone();
    longer.add(2, b"hello");
    assert_eq!(
        transcript.hash_with(crypto, AES128, &[2, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'])?,
        longer.hash(crypto, AES128)?
    );
    Ok(())
}

#[test]
fn the_certificate_verify_input_is_the_one_rfc_8446_defines() {
    let hash = [0x55u8; 32];
    let server = certificate_verify_input(true, &hash);
    assert_eq!(&server[..64], &[0x20; 64]);
    assert_eq!(&server[64..97], b"TLS 1.3, server CertificateVerify");
    assert_eq!(server[97], 0);
    assert_eq!(&server[98..], &hash);
    let client = certificate_verify_input(false, &hash);
    assert_eq!(&client[64..97], b"TLS 1.3, client CertificateVerify");
    assert_ne!(server, client);
}
