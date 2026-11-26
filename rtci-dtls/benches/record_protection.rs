//! DTLS record-protection benchmarks.
//!
//! Measures the per-record cost of each record cipher after the G3 crypto-provider migration,
//! and separates it from one-time key-schedule setup:
//!
//! * `Setup/*` constructs a cipher, so it covers the provider lookup, key import, and key
//!   schedule. This happens once per DTLS epoch.
//! * `Encrypt/*` and `Decrypt/*` protect and unprotect a single record on an already-keyed
//!   cipher. This is the hot path and the number that matters for throughput.
//! * `Handshake/*` runs a whole mutually authenticated DTLS 1.2 handshake between two in-memory
//!   endpoints (no socket), so a cost added to key agreement or the key schedule shows too.
//!
//! Every DTLS 1.2 record cipher the crate has is here: AES-GCM, AES-CBC, AES-CCM, AES-CCM-8 and
//! ChaCha20-Poly1305. The pull-request job of `.github/workflows/bench.yml` compares each of
//! these with the base branch (`scripts/bench-compare.py`; `docs/performance.md`).
//!
//! The split exists because the provider indirection is deliberately concentrated in setup: a
//! keyed cipher object is obtained once and then used per record with no further provider
//! dispatch. A regression in `Encrypt/*` would mean that property broke.
//!
//! Every cipher runs against each enabled built-in provider under identical inputs, so the two
//! backends are directly comparable.
//!
//! Run with:
//!
//! ```text
//! cargo bench --package rtci-dtls --bench record_protection
//! cargo bench --package rtci-dtls --bench record_protection --no-default-features --features aws-lc-rs
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, criterion_main};

use crypto::RTCCryptoProvider;
use rtci_dtls::config::{ClientAuthType, ConfigBuilder, DtlsVersion};
use rtci_dtls::content::ContentType;
use rtci_dtls::crypto::Certificate;
use rtci_dtls::crypto::crypto_cbc::CryptoCbc;
use rtci_dtls::crypto::crypto_ccm::{CryptoCcm, CryptoCcmTagLen};
use rtci_dtls::crypto::crypto_chacha20::CryptoChaCha20;
use rtci_dtls::crypto::crypto_gcm::CryptoGcm;
use rtci_dtls::endpoint::{Endpoint, EndpointEvent};
use rtci_dtls::record_layer::record_layer_header::{
    PROTOCOL_VERSION1_2, RECORD_LAYER_HEADER_SIZE, RecordLayerHeader,
};
use shared::TransportProtocol;

/// A 1200-byte record, sized to a typical WebRTC MTU-bound payload.
const PAYLOAD_LEN: usize = 1200;

const KEY_128: &[u8] = &[
    0x60, 0xb4, 0x1f, 0x04, 0x77, 0x89, 0x80, 0xfc, 0x4b, 0xc2, 0xfc, 0x2c, 0x3f, 0x38, 0x3d, 0x37,
];
const KEY_256: &[u8] = &[
    0x60, 0xb4, 0x1f, 0x04, 0x77, 0x89, 0x80, 0xfc, 0x4b, 0xc2, 0xfc, 0x2c, 0x3f, 0x38, 0x3d, 0x37,
    0xf7, 0x1a, 0x31, 0x5e, 0x63, 0x1d, 0x4f, 0x5e, 0x05, 0x6f, 0xfc, 0xd8, 0x3e, 0xc3, 0x11, 0x22,
];
const IV_GCM: &[u8] = &[0xf7, 0x1a, 0x31, 0x5e];
/// The ChaCha20-Poly1305 write IV is a full 12-byte nonce mask (RFC 7905 section 2).
const IV_CHACHA: &[u8] = &[
    0xf7, 0x1a, 0x31, 0x5e, 0x63, 0x1d, 0x4f, 0x5e, 0x05, 0x6f, 0xfc, 0xd8,
];
const MAC_SHA1: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14,
];

/// A DTLS 1.2 application-data record: marshalled header followed by the payload.
///
/// The header must be marshalled rather than zero-filled, because `decrypt` re-parses it from
/// the ciphertext buffer.
fn record() -> (RecordLayerHeader, Vec<u8>) {
    let header = RecordLayerHeader {
        content_type: ContentType::ApplicationData,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 1,
        sequence_number: 1,
        content_len: PAYLOAD_LEN as u16,
    };
    let mut raw = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + PAYLOAD_LEN);
    header.marshal(&mut raw).unwrap();
    raw.extend((0..PAYLOAD_LEN).map(|index| index as u8));
    (header, raw)
}

/// The built-in providers compiled into this benchmark.
fn providers() -> Vec<(&'static str, Arc<dyn RTCCryptoProvider>)> {
    let mut providers: Vec<(&'static str, Arc<dyn RTCCryptoProvider>)> = Vec::new();
    #[cfg(feature = "crypto-ring")]
    providers.push(("ring", Arc::new(crypto::providers::RingProvider::default())));
    #[cfg(feature = "crypto-aws-lc-rs")]
    providers.push((
        "aws-lc-rs",
        Arc::new(crypto::providers::AwsLcRsProvider::default()),
    ));
    assert!(
        !providers.is_empty(),
        "enable `ring` or `aws-lc-rs` to run these benchmarks"
    );
    providers
}

fn benchmark_gcm(group: &mut BenchmarkGroup<WallTime>) {
    for (name, provider) in providers() {
        // One-time cost: provider dispatch, key import, key schedule.
        group.bench_function(format!("Setup/AES-128-GCM/{name}"), |b| {
            b.iter(|| {
                CryptoGcm::new(Arc::clone(&provider), KEY_128, IV_GCM, KEY_128, IV_GCM).unwrap()
            });
        });

        let mut cipher =
            CryptoGcm::new(Arc::clone(&provider), KEY_128, IV_GCM, KEY_128, IV_GCM).unwrap();
        let (header, raw) = record();

        group.bench_function(format!("Encrypt/AES-128-GCM/{name}"), |b| {
            b.iter(|| cipher.encrypt(&header, &raw).unwrap());
        });

        let encrypted = cipher.encrypt(&header, &raw).unwrap();
        group.bench_function(format!("Decrypt/AES-128-GCM/{name}"), |b| {
            b.iter(|| cipher.decrypt(&encrypted).unwrap());
        });
    }
}

fn benchmark_cbc(group: &mut BenchmarkGroup<WallTime>) {
    for (name, provider) in providers() {
        group.bench_function(format!("Setup/AES-256-CBC/{name}"), |b| {
            b.iter(|| {
                CryptoCbc::new(Arc::clone(&provider), KEY_256, MAC_SHA1, KEY_256, MAC_SHA1).unwrap()
            });
        });

        let mut cipher =
            CryptoCbc::new(Arc::clone(&provider), KEY_256, MAC_SHA1, KEY_256, MAC_SHA1).unwrap();
        let (header, raw) = record();

        group.bench_function(format!("Encrypt/AES-256-CBC/{name}"), |b| {
            b.iter(|| cipher.encrypt(&header, &raw).unwrap());
        });

        let encrypted = cipher.encrypt(&header, &raw).unwrap();
        group.bench_function(format!("Decrypt/AES-256-CBC/{name}"), |b| {
            b.iter(|| cipher.decrypt(&encrypted).unwrap());
        });
    }
}

fn benchmark_ccm(group: &mut BenchmarkGroup<WallTime>) {
    for (suite, tag_len) in [
        ("AES-128-CCM", CryptoCcmTagLen::CryptoCcmTagLength),
        ("AES-128-CCM-8", CryptoCcmTagLen::CryptoCcm8TagLength),
    ] {
        for (name, provider) in providers() {
            group.bench_function(format!("Setup/{suite}/{name}"), |b| {
                b.iter(|| {
                    CryptoCcm::new(
                        Arc::clone(&provider),
                        &tag_len,
                        KEY_128,
                        IV_GCM,
                        KEY_128,
                        IV_GCM,
                    )
                    .unwrap()
                });
            });

            let mut cipher = CryptoCcm::new(
                Arc::clone(&provider),
                &tag_len,
                KEY_128,
                IV_GCM,
                KEY_128,
                IV_GCM,
            )
            .unwrap();
            let (header, raw) = record();

            group.bench_function(format!("Encrypt/{suite}/{name}"), |b| {
                b.iter(|| cipher.encrypt(&header, &raw).unwrap());
            });

            let encrypted = cipher.encrypt(&header, &raw).unwrap();
            group.bench_function(format!("Decrypt/{suite}/{name}"), |b| {
                b.iter(|| cipher.decrypt(&encrypted).unwrap());
            });
        }
    }
}

fn benchmark_chacha20(group: &mut BenchmarkGroup<WallTime>) {
    for (name, provider) in providers() {
        group.bench_function(format!("Setup/CHACHA20-POLY1305/{name}"), |b| {
            b.iter(|| {
                CryptoChaCha20::new(
                    Arc::clone(&provider),
                    KEY_256,
                    IV_CHACHA,
                    KEY_256,
                    IV_CHACHA,
                )
                .unwrap()
            });
        });

        let mut cipher = CryptoChaCha20::new(
            Arc::clone(&provider),
            KEY_256,
            IV_CHACHA,
            KEY_256,
            IV_CHACHA,
        )
        .unwrap();
        let (header, raw) = record();

        group.bench_function(format!("Encrypt/CHACHA20-POLY1305/{name}"), |b| {
            b.iter(|| cipher.encrypt(&header, &raw).unwrap());
        });

        let encrypted = cipher.encrypt(&header, &raw).unwrap();
        group.bench_function(format!("Decrypt/CHACHA20-POLY1305/{name}"), |b| {
            b.iter(|| cipher.decrypt(&encrypted).unwrap());
        });
    }
}

/// Every datagram `source` has queued, read by `destination`; whether that completed its
/// handshake.
fn transfer(
    source: &mut Endpoint,
    destination: &mut Endpoint,
    source_addr: SocketAddr,
    now: Instant,
) -> bool {
    let mut completed = false;
    while let Some(packet) = source.poll_transmit() {
        completed |= destination
            .read(now, source_addr, packet.transport.ecn, packet.message)
            .unwrap()
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
    }
    completed
}

/// A whole DTLS 1.2 handshake between two in-memory endpoints, mutually authenticated with
/// self-signed certificates made once outside the timed loop: key agreement, signing,
/// verification, the key schedule and both directions' record ciphers. The addresses are only
/// labels; no socket is opened.
fn benchmark_handshake(group: &mut BenchmarkGroup<WallTime>) {
    let client_addr: SocketAddr = "127.0.0.1:44001".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:44002".parse().unwrap();
    for (name, provider) in providers() {
        let certificate =
            Certificate::generate_self_signed(vec!["localhost".into()], provider.crypto()).unwrap();
        let configuration = ConfigBuilder::default()
            .with_crypto_provider(Arc::clone(&provider))
            .with_certificates(vec![certificate])
            .with_insecure_skip_verify(true)
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2);
        let client_config = Arc::new(configuration.clone().build(true, None).unwrap());
        let server_config = Arc::new(configuration.build(false, None).unwrap());

        group.bench_function(format!("Handshake/DTLS-1.2/{name}"), |b| {
            b.iter(|| {
                let start = Instant::now();
                let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
                let mut server = Endpoint::new(
                    server_addr,
                    TransportProtocol::UDP,
                    Some(Arc::clone(&server_config)),
                );
                client
                    .connect(start, server_addr, Arc::clone(&client_config), None)
                    .unwrap();
                let (mut client_done, mut server_done) = (false, false);
                for _ in 0..4 {
                    server_done |= transfer(&mut client, &mut server, client_addr, start);
                    client_done |= transfer(&mut server, &mut client, server_addr, start);
                }
                assert!(client_done && server_done, "the handshake completed");
                (client, server)
            });
        });
    }
}

fn benches() {
    let mut criterion = Criterion::default().configure_from_args();
    let mut group = criterion.benchmark_group("DTLS");
    benchmark_gcm(&mut group);
    benchmark_cbc(&mut group);
    benchmark_ccm(&mut group);
    benchmark_chacha20(&mut group);
    benchmark_handshake(&mut group);
    group.finish();
}

criterion_main!(benches);
