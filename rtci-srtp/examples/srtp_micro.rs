//! Fixed-work SRTP micro-benchmark harness for `perf`/`poop`.
//!
//! Unlike the criterion bench, this does *no* per-iteration setup: it marshals a
//! single representative RTP packet once, then calls encrypt/decrypt in a tight
//! loop, black-boxing and dropping each result. This isolates the steady-state
//! per-packet cost so before/after `poop` comparisons and `perf` profiles are
//! not polluted by benchmark scaffolding.
//!
//! Usage: srtp_micro <encrypt|decrypt> [iterations]

use std::hint::black_box;

/// The built-in provider, for tests only. Library code never resolves a default: every public
/// constructor takes the provider from its caller.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

use bytes::BytesMut;
use rtci_srtp::option::{
    srtcp_no_replay_protection, srtp_no_replay_protection, srtp_replay_protection,
};
use rtci_srtp::{context::Context, protection_profile::ProtectionProfile};
use shared::marshal::Marshal;

const MASTER_KEY: &[u8] = &[
    96, 180, 31, 4, 119, 137, 128, 252, 75, 194, 252, 44, 63, 56, 61, 55,
];
const MASTER_SALT: &[u8] = &[247, 26, 49, 94, 99, 29, 79, 94, 5, 111, 252, 216, 62, 195];

fn new_ctx() -> Context {
    Context::new(
        MASTER_KEY,
        MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        Some(srtp_no_replay_protection()),
        Some(srtcp_no_replay_protection()),
        test_crypto_provider().crypto(),
    )
    .unwrap()
}

/// AES-GCM contexts (the default browser-negotiated profile) use a 12-byte salt.
const GCM_MASTER_SALT: &[u8] = &[247, 26, 49, 94, 99, 29, 79, 94, 5, 111, 252, 216];

fn new_gcm_ctx() -> Context {
    Context::new(
        MASTER_KEY,
        GCM_MASTER_SALT,
        ProtectionProfile::AeadAes128Gcm,
        Some(srtp_no_replay_protection()),
        Some(srtcp_no_replay_protection()),
        test_crypto_provider().crypto(),
    )
    .unwrap()
}

/// Decrypt context with replay protection enabled, matching the production
/// remote SRTP context (see peer_connection/handler/dtls.rs).
fn new_ctx_replay() -> Context {
    Context::new(
        MASTER_KEY,
        MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        Some(srtp_replay_protection(128).unwrap()),
        None,
        test_crypto_provider().crypto(),
    )
    .unwrap()
}

/// Rewrites the RTP sequence number (header bytes 2..4) of a marshalled packet.
fn set_sequence_number(packet: &mut BytesMut, sequence_number: u16) {
    packet[2..4].copy_from_slice(&sequence_number.to_be_bytes());
}

/// Build a representative ~1200-byte media RTP packet, matching the criterion bench.
fn sample_packet() -> BytesMut {
    let mut pld = BytesMut::new();
    for i in 0..1200 {
        pld.extend_from_slice(&[i as u8]);
    }
    let pkt = rtp::packet::Packet {
        header: rtp::header::Header {
            sequence_number: 1,
            timestamp: 1,
            extension_profile: 48862,
            marker: true,
            padding: false,
            extension: true,
            payload_type: 96,
            ..Default::default()
        },
        payload: pld.freeze(),
    };
    pkt.marshal().unwrap()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "encrypt".to_string());
    let iters: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(50_000);

    let mut plaintext = sample_packet();

    match mode.as_str() {
        "encrypt" => {
            let mut ctx = new_ctx();
            for i in 0..iters {
                // Each iteration sends the next sequence number: the steady-state path of a
                // new packet index, not a retransmission.
                set_sequence_number(&mut plaintext, i as u16);
                let out = ctx.encrypt_rtp(black_box(&plaintext)).unwrap();
                black_box(&out);
            }
        }
        // Replay protection enabled: isolates the per-call ssrc-state /
        // replay-detector allocation in Context::get_srtp_ssrc_state — the exact
        // allocation production incurs on every decrypted packet. encrypt is
        // used because it never rejects a new sequence number.
        "encrypt-replay" => {
            let mut ctx = new_ctx_replay();
            for i in 0..iters {
                // Each iteration sends the next sequence number: the steady-state path of a
                // new packet index, not a retransmission.
                set_sequence_number(&mut plaintext, i as u16);
                let out = ctx.encrypt_rtp(black_box(&plaintext)).unwrap();
                black_box(&out);
            }
        }
        "decrypt" => {
            // Pre-encrypt once with a separate context so decrypt has valid input.
            let encrypted = new_ctx().encrypt_rtp(&plaintext).unwrap();
            let mut ctx = new_ctx();
            for _ in 0..iters {
                let out = ctx.decrypt_rtp(black_box(&encrypted)).unwrap();
                black_box(&out);
            }
        }
        "gcm-encrypt" => {
            let mut ctx = new_gcm_ctx();
            for i in 0..iters {
                // Each iteration sends the next sequence number: the steady-state path of a
                // new packet index, not a retransmission.
                set_sequence_number(&mut plaintext, i as u16);
                let out = ctx.encrypt_rtp(black_box(&plaintext)).unwrap();
                black_box(&out);
            }
        }
        "gcm-decrypt" => {
            let encrypted = new_gcm_ctx().encrypt_rtp(&plaintext).unwrap();
            let mut ctx = new_gcm_ctx();
            for _ in 0..iters {
                let out = ctx.decrypt_rtp(black_box(&encrypted)).unwrap();
                black_box(&out);
            }
        }
        other => {
            eprintln!(
                "unknown mode: {other} (expected encrypt|encrypt-replay|decrypt|gcm-encrypt|gcm-decrypt)"
            );
            std::process::exit(2);
        }
    }
}
