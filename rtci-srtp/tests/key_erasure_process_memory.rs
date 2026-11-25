//! RFC 7714 section 13.1: "All keys MUST be properly erased when no longer needed", searched
//! for in the whole process, Linux only.
//!
//! `key_schedule_erasure.rs` sees what an SRTP context keeps in the Rust heap. A provider may
//! keep its key schedules elsewhere: AWS-LC allocates its `EVP_AEAD_CTX` in C, and a cipher
//! built per call on the stack leaves its schedule in a dead stack frame. Here a worker thread
//! makes a sending and a receiving context, protects and unprotects RTP and RTCP, and waits;
//! the test thread reads every readable and writable mapping of the process
//! (`/proc/self/maps`, `/proc/self/mem`) and looks for every key the contexts derive, in every
//! form (`key_material`): first while the contexts are alive (a key not found then proves
//! nothing, so the search must find the keys it is meant to see), then after the worker has
//! dropped them and exited (its stack stays mapped: the C library keeps a finished thread's
//! stack for the next thread). The test thread's own stack, where the test computed the keys
//! it looks for, and the scan buffer are not searched.
//!
//! macOS and Windows would need `mach_vm_read`/`mach_vm_region` or
//! `VirtualQuery`/`ReadProcessMemory` on the process itself; the providers' code is the same
//! there, so the statement is "measured on Linux".

#![cfg(target_os = "linux")]

mod key_material;

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::mpsc;

use crypto::RTCCryptoProvider;
use key_material::{MAX_NEEDLE, Needle, context_needles, rtcp, rtp};
use rtci_srtp::context::Context;
use rtci_srtp::protection_profile::ProtectionProfile;

const MASTER_KEY: [u8; 32] = [
    0xc7, 0x08, 0x5d, 0xe2, 0x31, 0x9f, 0x46, 0xbb, 0x1a, 0x73, 0xe0, 0x2c, 0x95, 0x4e, 0xd8, 0x67,
    0x0f, 0xa9, 0x52, 0x3c, 0xe5, 0x81, 0x16, 0xdb, 0x74, 0x2a, 0xbf, 0x48, 0x93, 0x0d, 0x6e, 0xf1,
];
const MASTER_SALT: [u8; 14] = [
    0xa4, 0x19, 0x7e, 0xd3, 0x62, 0x05, 0xbc, 0x48, 0xf7, 0x2e, 0x91, 0x6a, 0x3d, 0xc0,
];

#[allow(clippy::vec_init_then_push)]
fn providers() -> Vec<Arc<dyn RTCCryptoProvider>> {
    let mut providers: Vec<Arc<dyn RTCCryptoProvider>> = Vec::new();
    #[cfg(feature = "crypto-ring")]
    providers.push(Arc::new(crypto::providers::RingProvider::new()));
    #[cfg(feature = "crypto-aws-lc-rs")]
    providers.push(Arc::new(crypto::providers::AwsLcRsProvider::new()));
    providers
}

/// A readable and writable mapping: its range and what `/proc/self/maps` calls it.
struct Region {
    start: usize,
    end: usize,
    name: String,
}

fn writable_regions() -> Vec<Region> {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("/proc/self/maps");
    maps.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let range = fields.next()?;
            let perms = fields.next()?;
            if !perms.starts_with("rw") {
                return None;
            }
            let name = fields.nth(3).unwrap_or("anonymous").to_owned();
            let (start, end) = range.split_once('-')?;
            Some(Region {
                start: usize::from_str_radix(start, 16).ok()?,
                end: usize::from_str_radix(end, 16).ok()?,
                name,
            })
        })
        .collect()
}

/// Where each needle was found: one label per region holding it. `skip` are address ranges
/// left out (the scan buffer); `test_stack` is an address on the searching thread's stack,
/// whose mapping is left out; `worker_stack` names the worker's mapping.
fn search(needles: &[Needle], test_stack: usize, worker_stack: usize) -> Vec<Vec<String>> {
    const CHUNK: usize = 1 << 20;
    let mut prefixes = vec![false; 1 << 16];
    for needle in needles {
        prefixes[needle.prefix() as usize] = true;
    }
    let mem = File::open("/proc/self/mem").expect("/proc/self/mem");
    let mut buffer = vec![0u8; CHUNK + MAX_NEEDLE];
    let buffer_range = buffer.as_ptr() as usize..buffer.as_ptr() as usize + buffer.len();
    let mut found: Vec<Vec<String>> = vec![Vec::new(); needles.len()];
    for region in writable_regions() {
        if (region.start..region.end).contains(&test_stack) {
            continue;
        }
        let label = if (region.start..region.end).contains(&worker_stack) {
            "the worker thread's stack".to_owned()
        } else {
            region.name.clone()
        };
        let mut at = region.start;
        while at < region.end {
            let len = (region.end - at).min(CHUNK + MAX_NEEDLE);
            let chunk_range = at..at + len;
            let overlaps_buffer =
                chunk_range.start < buffer_range.end && buffer_range.start < chunk_range.end;
            if !overlaps_buffer && mem.read_exact_at(&mut buffer[..len], at as u64).is_ok() {
                let chunk = &buffer[..len];
                for i in 0..len.saturating_sub(1) {
                    if !prefixes[u16::from_le_bytes([chunk[i], chunk[i + 1]]) as usize] {
                        continue;
                    }
                    for (n, needle) in needles.iter().enumerate() {
                        if needle.prefix() == u16::from_le_bytes([chunk[i], chunk[i + 1]])
                            && i + needle.len() <= len
                            && needle.found_in(&chunk[i..i + needle.len()])
                            && !found[n].contains(&label)
                        {
                            found[n].push(label.clone());
                        }
                    }
                }
            }
            at += CHUNK;
        }
    }
    buffer.fill(0);
    found
}

struct Session {
    provider: &'static str,
    profile: ProtectionProfile,
    needles: Vec<Needle>,
    before: Vec<Vec<String>>,
    after: Vec<Vec<String>>,
}

/// One session of `profile` with `provider` on a worker thread, searched for while its
/// contexts are alive and after the worker has dropped them and exited.
fn session(provider: &Arc<dyn RTCCryptoProvider>, profile: ProtectionProfile) -> Session {
    let (key, salt) = key_material::per_profile(profile, &MASTER_KEY, &MASTER_SALT);
    let master_key = &key[..profile.key_len()];
    let master_salt = &salt[..if profile.is_aead() { 12 } else { 14 }];
    let needles = context_needles(profile, master_key, master_salt);
    let test_stack = &needles as *const _ as usize;

    let (ready_tx, ready_rx) = mpsc::channel::<usize>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let worker_provider = provider.clone();
    let worker = std::thread::spawn(move || {
        // The master key and salt as the engine holds them: in zeroizing buffers.
        let (mut key, mut salt) = key_material::per_profile(profile, &MASTER_KEY, &MASTER_SALT);
        let master_key = crypto::SecretVec::new(key[..profile.key_len()].to_vec());
        let master_salt =
            crypto::SecretVec::new(salt[..if profile.is_aead() { 12 } else { 14 }].to_vec());
        key_material::wipe(&mut key);
        key_material::wipe(&mut salt);
        let context = || {
            Box::new(
                Context::new(
                    master_key.as_ref(),
                    master_salt.as_ref(),
                    profile,
                    None,
                    None,
                    worker_provider.crypto(),
                )
                .expect("a context"),
            )
        };
        let mut sender = context();
        let mut receiver = context();
        for sequence_number in 0..4 {
            let protected = sender.encrypt_rtp(&rtp(sequence_number)).expect("SRTP");
            receiver.decrypt_rtp(&protected).expect("unprotected SRTP");
            let protected = sender.encrypt_rtcp(&rtcp()).expect("SRTCP");
            receiver
                .decrypt_rtcp(&protected)
                .expect("unprotected SRTCP");
        }
        let marker = 0u8;
        ready_tx
            .send(&marker as *const u8 as usize)
            .expect("the test thread waits");
        go_rx.recv().expect("the test thread says when");
        drop(sender);
        drop(receiver);
        drop(master_key);
        drop(master_salt);
    });
    let worker_stack = ready_rx.recv().expect("the worker is ready");
    let before = search(&needles, test_stack, worker_stack);
    go_tx.send(()).expect("the worker waits");
    worker.join().expect("the worker ends");
    let after = search(&needles, test_stack, worker_stack);
    Session {
        provider: provider.name(),
        profile,
        needles,
        before,
        after,
    }
}

fn every_session() -> Vec<Session> {
    key_material::check_local_primitives();
    let mut sessions = Vec::new();
    for provider in providers() {
        for profile in ProtectionProfile::ALL {
            let s = session(&provider, profile);
            for (n, needle) in s.needles.iter().enumerate() {
                println!(
                    "PROCESS {:<10} {:<22} {:<58} before {:?} after {:?}",
                    s.provider,
                    format!("{:?}", s.profile),
                    needle.describe(),
                    s.before[n],
                    s.after[n]
                );
            }
            sessions.push(s);
        }
    }
    sessions
}

/// The search finds what it is meant to see: while the contexts are alive, the session
/// encryption key (or, with a NULL cipher, the session salting key) of SRTP is somewhere in the
/// process, with every provider and profile. Without this a key "not found after the drop"
/// would prove nothing.
fn check_the_search_sees_live_keys(sessions: &[Session]) {
    for s in sessions {
        let expected = if s.profile.is_null_cipher() {
            "SRTP salting key"
        } else {
            "SRTP encryption key"
        };
        let seen = s
            .needles
            .iter()
            .zip(&s.before)
            .any(|(needle, before)| needle.key == expected && !before.is_empty());
        assert!(
            seen,
            "{} {:?}: the {expected} was not found while the contexts were alive",
            s.provider, s.profile
        );
    }
}

fn left_behind(sessions: &[Session], keep: impl Fn(&Session, &Needle) -> bool) -> Vec<String> {
    sessions
        .iter()
        .flat_map(|s| {
            s.needles
                .iter()
                .zip(&s.after)
                .filter(|(needle, after)| !after.is_empty() && keep(s, needle))
                .map(move |(needle, after)| {
                    format!(
                        "{} {:?}: {} in {after:?}",
                        s.provider,
                        s.profile,
                        needle.describe()
                    )
                })
        })
        .collect()
}

/// AWS-LC erases its AES-GCM contexts: the session keys of the AEAD profiles, their round keys
/// and the GHASH key, found in the process while the contexts are alive, are nowhere in it once
/// they are dropped (`EVP_AEAD_CTX_cleanup`, and `OPENSSL_free` cleanses what it frees).
#[cfg(feature = "crypto-aws-lc-rs")]
#[test]
fn aws_lc_erases_its_aes_gcm_contexts_from_process_memory() {
    let sessions: Vec<Session> = every_session()
        .into_iter()
        .filter(|s| s.provider == "aws-lc-rs")
        .collect();
    check_the_search_sees_live_keys(&sessions);
    let left = left_behind(&sessions, |s, needle| {
        s.profile.is_aead() && needle.key != "master key"
    });
    assert!(left.is_empty(), "found after the drop: {left:#?}");
}

/// KNOWN LIMIT (RFC 7714 section 13.1): not every key is gone from the process once the
/// contexts are dropped, with either provider. What is left, and where, is the table this
/// prints: the AES counter-mode schedules the AES-CM profiles build per packet on the stack
/// (RustCrypto `aes` without its `zeroize` feature, both providers), the master key's schedule
/// built the same way by the key derivation, and with the ring provider its AES-GCM key and the
/// HMAC-SHA1 states in freed heap blocks. Fails when run.
#[test]
#[ignore = "KNOWN LIMIT: AES schedules on the stack (both providers) and ring's AES-GCM and HMAC-SHA1 state in freed memory outlive the contexts; fails when run (-- --ignored known_limit_)"]
fn known_limit_no_key_outlives_its_contexts_in_process_memory() {
    let sessions = every_session();
    check_the_search_sees_live_keys(&sessions);
    let left = left_behind(&sessions, |_, _| true);
    assert!(left.is_empty(), "found after the drop: {left:#?}");
}
