//! The DTLS 1.3 fuzz harnesses: what the fuzz targets of `rtc-dtls/fuzz` run (through
//! `crate::fuzzing`, with deterministic providers), and what `fuzz_corpus_test.rs` runs over
//! a fixed corpus with the default provider.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use shared::TransportProtocol;

use crate::cipher_suite::CipherSuiteId;
use crate::config::{ClientAuthType, ConfigBuilder, HandshakeConfig};
use crate::crypto::Certificate;
use crate::endpoint::Endpoint;

/// Parses `data` as the records of a DTLS 1.3 datagram (the first byte chooses the length of
/// the connection id the receiver expects), and as an ACK.
pub(crate) fn record_parse(data: &[u8]) {
    use crate::dtls13::record::{DatagramRecord, decode_ack, next_record};

    let Some((first, mut rest)) = data.split_first() else {
        return;
    };
    let connection_id_len = usize::from(first % 5);
    let _ = decode_ack(rest);
    while !rest.is_empty() {
        let Ok((record, taken)) = next_record(rest, connection_id_len) else {
            break;
        };
        match record {
            DatagramRecord::Plaintext { fragment, .. } => {
                let _ = crate::dtls13::messages::HandshakeFragment::parse_all(fragment);
            }
            DatagramRecord::Ciphertext { header, record } => {
                assert!(header.header_len <= record.len());
                assert_eq!(header.record_len, record.len());
            }
        }
        assert!(taken > 0 && taken <= rest.len());
        rest = &rest[taken..];
    }
}

/// Parses `data` as each DTLS 1.3 handshake message in turn, and negotiates from it as a
/// ClientHello.
pub(crate) fn handshake_parse(
    data: &[u8],
    provider: Arc<dyn crypto::RTCCryptoProvider>,
    server_certificate: Certificate,
) {
    use crate::dtls13::hello;
    use crate::dtls13::messages::*;

    if let Ok(client_hello) = ClientHello::parse(data) {
        let _ = client_hello.supported_versions();
        for (_, extension) in &client_hello.extensions {
            let _ = parse_u16_list(extension);
            let _ = parse_client_key_shares(extension);
            let _ = parse_use_srtp(extension);
            let _ = parse_connection_id(extension);
            let _ = parse_server_name(extension);
            let _ = hello::parse_cookie(extension);
            let _ = super::psk::parse_psk_key_exchange_modes(extension);
            let _ = super::psk::parse_client_pre_shared_key(extension);
        }
        if let Some(config) = config(provider, Some(server_certificate), false, 0) {
            let _ = hello::negotiate(&config, &client_hello);
        }
        let _ = hello::second_client_hello(
            &client_hello,
            Some((29, &[1; 32])),
            Some(b"cookie"),
            client_hello.extension(EXT_PRE_SHARED_KEY),
        );
    }
    if let Ok(server_hello) = ServerHello::parse(data) {
        let _ = server_hello.is_hello_retry_request();
        let _ = server_hello.selected_version();
    }
    let _ = parse_certificate(data);
    let _ = parse_certificate_verify(data);
    let _ = parse_certificate_request(data);
    let _ = parse_key_update(data);
    let _ = parse_new_connection_id(data);
    let _ = parse_request_connection_id(data);
    let _ = parse_new_session_ticket(data);
    let _ = HandshakeFragment::parse_all(data);
    let _ = hello::whole_client_hello(data);
}

/// The TLS 1.3 suites the fuzzer picks from.
const SUITES: [CipherSuiteId; 4] = [
    CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
    CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
    CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
    CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256,
];

fn config(
    provider: Arc<dyn crypto::RTCCryptoProvider>,
    certificate: Option<Certificate>,
    is_client: bool,
    options: u8,
) -> Option<Arc<HandshakeConfig>> {
    use crate::config::DtlsVersion;

    let suite = SUITES[usize::from(options & 3)];
    let client_auth = options & 4 != 0;
    let mut builder = ConfigBuilder::default()
        .with_crypto_provider(provider.clone())
        .with_cipher_suites(vec![suite])
        .with_protocol_versions(DtlsVersion::Dtls1_3, DtlsVersion::Dtls1_3)
        .with_cookie_exchange(options & 8 != 0)
        .with_connection_id((options & 16 != 0).then_some(3))
        .with_insecure_skip_verify(true);
    if !is_client || client_auth {
        builder = builder.with_certificates(vec![certificate?]);
    }
    if !is_client && client_auth {
        builder = builder.with_client_auth(ClientAuthType::RequireAnyClientCert);
    }
    builder.build(is_client, None).ok().map(Arc::new)
}

/// Runs a DTLS 1.3 handshake between two in-memory endpoints and lets the fuzzer inject
/// datagrams into either at a point it chooses: before, during or after the handshake. A
/// datagram is injected as it is, or protected under the sender's current keys with a
/// content type of the fuzzer's choice, so that it passes record authentication and reaches
/// the handshake reassembly, the state machine, the ACK and the post-handshake code.
///
/// The input: one byte of options (suite, client authentication, cookie exchange, connection
/// ids), one byte saying after how many exchanges of the handshake the injection starts, then
/// operations, each a byte of flags, a byte of length and that many bytes.
pub(crate) fn conn_handle_datagrams(
    data: &[u8],
    start: Instant,
    client: (Arc<dyn crypto::RTCCryptoProvider>, Certificate),
    server: (Arc<dyn crypto::RTCCryptoProvider>, Certificate),
) {
    let [options, rounds, operations @ ..] = data else {
        return;
    };
    let (Some(client_config), Some(server_config)) = (
        config(client.0, Some(client.1), true, *options),
        config(server.0, Some(server.1), false, *options),
    ) else {
        return;
    };
    let client_addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    let server_addr = SocketAddr::from(([127, 0, 0, 1], 5001));
    let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
    let mut server = Endpoint::new(server_addr, TransportProtocol::UDP, Some(server_config));
    if client
        .connect(start, server_addr, client_config, None)
        .is_err()
    {
        return;
    }
    let mut now = start;
    let exchange = |client: &mut Endpoint, server: &mut Endpoint, now: Instant| {
        while let Some(transmit) = client.poll_transmit() {
            let _ = server.read(now, client_addr, None, transmit.message);
        }
        while let Some(transmit) = server.poll_transmit() {
            let _ = client.read(now, server_addr, None, transmit.message);
        }
    };
    for _ in 0..(rounds % 8) {
        exchange(&mut client, &mut server, now);
    }

    let mut rest = operations;
    while let [flags, length, tail @ ..] = rest {
        let length = usize::from(*length).min(tail.len());
        let (payload, tail) = tail.split_at(length);
        rest = tail;
        let to_server = flags & 1 != 0;
        let (sender, receiver, sender_remote, receiver_remote) = if to_server {
            (&mut client, &mut server, server_addr, client_addr)
        } else {
            (&mut server, &mut client, client_addr, server_addr)
        };
        match (flags >> 1) & 7 {
            // The bytes as they are.
            0 | 1 => {
                let _ = receiver.read(now, receiver_remote, None, BytesMut::from(payload));
            }
            // Protected under the sender's keys: content type and content from the input.
            2 | 3 | 4 => {
                let sealed = sender
                    .connection_mut(&sender_remote)
                    .and_then(|conn| conn.v13.as_mut())
                    .and_then(|v13| match payload.split_first() {
                        Some((content_type, content)) => {
                            v13.seal_for_fuzzing(*content_type, content)
                        }
                        None => None,
                    });
                if let Some(record) = sealed {
                    let _ = receiver.read(now, receiver_remote, None, BytesMut::from(&record[..]));
                }
            }
            // Time passes, and timers fire.
            5 => {
                now += Duration::from_millis(length as u64 * 50);
                let _ = client.handle_timeout(server_addr, now);
                let _ = server.handle_timeout(client_addr, now);
            }
            // The application acts.
            6 => {
                let _ = sender.write(now, sender_remote, payload);
                let _ = sender.update_keys(now, sender_remote, flags & 0x80 != 0);
            }
            _ => {
                let _ =
                    sender.new_connection_ids(now, sender_remote, length % 4, flags & 0x80 != 0);
                let _ = sender.request_connection_ids(now, sender_remote, length as u8);
            }
        }
        exchange(&mut client, &mut server, now);
    }
}
