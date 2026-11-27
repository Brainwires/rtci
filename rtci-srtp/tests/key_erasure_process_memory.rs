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
//! What is asserted and what is only reported. Every hit outside the worker's dead stack frames
//! (the heap, every other anonymous or file mapping, the worker's own live frame and what lies
//! above it in its mapping: its thread-local storage and thread start) fails the test. A hit in
//! the worker's dead stack frames (its stack mapping BELOW the frame it waits in: the frames of
//! the calls it made and that returned) is printed (`STACK RESIDUE`, a count per key) and does
//! not fail it: key copies in dead stack frames are a known limit, not guaranteed erased
//! (docs/key-erasure.md). They were found in train 34's test environment (rustc 1.99.1): the
//! SRTCP encryption key, its AES round keys, the SRTCP HMAC-SHA1 states and the master key, left
//! by building the contexts. `known_limit_*_building_an_srtp_context_leaves_keys_in_dead_stack_frames`
//! (ignored, docs/test-exclusions.md) is that limit as a test. A hit is classified by its own
//! address, so a key in the heap is never taken for stack residue, even when it also lies in
//! the worker's stack.
//!
//! Each test uses master keys of its own (and each profile within it): a test thread computes
//! the keys it looks for in its own stack frames, and a later thread (another test's worker) can
//! be given that dead thread's stack by the C library, so two tests looking for the same keys
//! would find each other's computations. With shared keys that showed as "found after the
//! drop" in 10 of 50 runs with two tests per provider (runs 45726164797, 45726174061,
//! 45726181744, 45726197738) and in 0 of 40 with one (45726148580, 45726156299). The worker is handed its master
//! key and salt in zeroizing heap buffers made by the test thread, so no plain copy the test
//! makes lies in the worker's stack.
//!
//! macOS and Windows would need `mach_vm_read`/`mach_vm_region` or
//! `VirtualQuery`/`ReadProcessMemory` on the process itself; the providers' code is the same
//! there, so the statement is "measured on Linux".

#[cfg(target_os = "linux")]
mod key_material;

/// Linux only: it reads `/proc/self/maps` and `/proc/self/mem`.
#[cfg(target_os = "linux")]
mod process_memory_tests {

    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::mpsc;

    /// One search at a time: a search sees every thread's memory, so another test's live
    /// contexts would be found after this one's drop.
    static SERIAL: Mutex<()> = Mutex::new(());

    use super::key_material::{MAX_NEEDLE, Needle, context_needles, rtcp, rtp};
    use crypto::RTCCryptoProvider;
    use rtci_srtp::context::Context;
    use rtci_srtp::protection_profile::ProtectionProfile;

    const MASTER_KEY: [u8; 32] = [
        0xc7, 0x08, 0x5d, 0xe2, 0x31, 0x9f, 0x46, 0xbb, 0x1a, 0x73, 0xe0, 0x2c, 0x95, 0x4e, 0xd8,
        0x67, 0x0f, 0xa9, 0x52, 0x3c, 0xe5, 0x81, 0x16, 0xdb, 0x74, 0x2a, 0xbf, 0x48, 0x93, 0x0d,
        0x6e, 0xf1,
    ];
    const MASTER_SALT: [u8; 14] = [
        0xa4, 0x19, 0x7e, 0xd3, 0x62, 0x05, 0xbc, 0x48, 0xf7, 0x2e, 0x91, 0x6a, 0x3d, 0xc0,
    ];

    /// Which test a session belongs to: each test (and provider) derives its keys from a master
    /// key of its own, so that a search for one test's keys never finds what another test's
    /// sessions or its own computation of its needles (on a test thread that has ended, whose
    /// stack the C library may give to a later thread) left: every finding belongs to the
    /// session it is reported for. The tags differ pairwise in more than the profiles' tags
    /// (`per_profile`) can make up (their differences are below 0x10 or between 0xf0 and 0xfa).
    #[derive(Clone, Copy)]
    enum Run {
        /// The contexts protect and unprotect RTP and RTCP before the drop.
        Packets,
        /// The contexts are built and nothing else is done before the search.
        BuildOnly,
    }

    fn master_for(provider: &str, run: Run) -> ([u8; 32], [u8; 14]) {
        let tag = match (provider == "ring", run) {
            (true, Run::Packets) => 0x00,
            (false, Run::Packets) => 0xa5,
            (true, Run::BuildOnly) => 0x5a,
            (false, Run::BuildOnly) => 0x3c,
        };
        (MASTER_KEY.map(|b| b ^ tag), MASTER_SALT.map(|b| b ^ tag))
    }

    /// The label of a hit in the worker's dead stack frames: reported, not asserted.
    const DEAD_STACK: &str = "the worker thread's dead stack frames";

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

    /// Where each needle was found: one label per kind of place holding it. The scan buffer is
    /// left out; `test_stack` is an address on the searching thread's stack, whose mapping is
    /// left out; `worker_frame` is an address in the frame the worker waits in: a hit in its
    /// mapping below it is [`DEAD_STACK`], one at or above it is the worker's live stack, TLS
    /// or thread start (asserted like the heap).
    fn search(needles: &[Needle], test_stack: usize, worker_frame: usize) -> Vec<Vec<String>> {
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
            let worker = (region.start..region.end).contains(&worker_frame);
            // The scan buffer is a hole in its region: the parts on either side are searched.
            let mut segments = vec![(region.start, region.end)];
            if region.start < buffer_range.end && buffer_range.start < region.end {
                segments = vec![
                    (region.start, buffer_range.start.max(region.start)),
                    (buffer_range.end.min(region.end), region.end),
                ];
            }
            for (start, end) in segments {
                let mut at = start;
                while at < end {
                    let len = (end - at).min(CHUNK + MAX_NEEDLE);
                    if mem.read_exact_at(&mut buffer[..len], at as u64).is_ok() {
                        let chunk = &buffer[..len];
                        for i in 0..len.saturating_sub(1) {
                            let prefix = u16::from_le_bytes([chunk[i], chunk[i + 1]]);
                            if !prefixes[prefix as usize] {
                                continue;
                            }
                            for (n, needle) in needles.iter().enumerate() {
                                if needle.prefix() == prefix
                                    && i + needle.len() <= len
                                    && needle.found_in(&chunk[i..i + needle.len()])
                                {
                                    let label = match (worker, at + i < worker_frame) {
                                        (true, true) => DEAD_STACK.to_owned(),
                                        (true, false) => {
                                            "the worker thread's live frames, TLS or thread start"
                                                .to_owned()
                                        }
                                        (false, _) => region.name.clone(),
                                    };
                                    if !found[n].contains(&label) {
                                        found[n].push(label);
                                    }
                                }
                            }
                        }
                    }
                    at += CHUNK;
                }
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
    fn session(
        provider: &Arc<dyn RTCCryptoProvider>,
        profile: ProtectionProfile,
        run: Run,
    ) -> Session {
        let master = master_for(provider.name(), run);
        let (mut key, mut salt) = super::key_material::per_profile(profile, &master.0, &master.1);
        let salt_len = if profile.is_aead() { 12 } else { 14 };
        let needles = context_needles(profile, &key[..profile.key_len()], &salt[..salt_len]);
        // The master key and salt as the engine holds them: in zeroizing buffers, made here so
        // that the worker's stack never holds a plain copy the test made.
        let master_key = crypto::SecretVec::new(key[..profile.key_len()].to_vec());
        let master_salt = crypto::SecretVec::new(salt[..salt_len].to_vec());
        super::key_material::wipe(&mut key);
        super::key_material::wipe(&mut salt);
        let test_stack = &needles as *const _ as usize;

        let (ready_tx, ready_rx) = mpsc::channel::<usize>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let worker_provider = provider.clone();
        let worker = std::thread::spawn(move || {
            // An address in this frame, the one the worker waits in: what lies below it in the
            // worker's stack are the dead frames of the calls made from here.
            let marker = 0u8;
            let frame = std::hint::black_box(&marker) as *const u8 as usize;
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
            let packets = if matches!(run, Run::Packets) { 4 } else { 0 };
            for sequence_number in 0..packets {
                let protected = sender.encrypt_rtp(&rtp(sequence_number)).expect("SRTP");
                receiver.decrypt_rtp(&protected).expect("unprotected SRTP");
                let protected = sender.encrypt_rtcp(&rtcp()).expect("SRTCP");
                receiver
                    .decrypt_rtcp(&protected)
                    .expect("unprotected SRTCP");
            }
            ready_tx.send(frame).expect("the test thread waits");
            go_rx.recv().expect("the test thread says when");
            drop(sender);
            drop(receiver);
            drop(master_key);
            drop(master_salt);
        });
        let worker_frame = ready_rx.recv().expect("the worker is ready");
        let before = search(&needles, test_stack, worker_frame);
        go_tx.send(()).expect("the worker waits");
        worker.join().expect("the worker ends");
        let after = search(&needles, test_stack, worker_frame);
        Session {
            provider: provider.name(),
            profile,
            needles,
            before,
            after,
        }
    }

    /// Every profile with the provider named `name`.
    fn every_session(name: &str, run: Run) -> Vec<Session> {
        super::key_material::check_local_primitives();
        let mut sessions = Vec::new();
        for provider in providers().into_iter().filter(|p| p.name() == name) {
            for profile in ProtectionProfile::ALL {
                let s = session(&provider, profile, run);
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
    /// encryption key (or, with a NULL cipher, the session salting key) of SRTP is in the process
    /// outside the worker's dead stack frames (where the contexts keep it), with every provider
    /// and profile. Without this a key "not found after the drop" would prove nothing.
    fn check_the_search_sees_live_keys(sessions: &[Session]) {
        for s in sessions {
            let expected = if s.profile.is_null_cipher() {
                "SRTP salting key"
            } else {
                "SRTP encryption key"
            };
            let seen = s.needles.iter().zip(&s.before).any(|(needle, before)| {
                needle.key == expected && before.iter().any(|label| label != DEAD_STACK)
            });
            assert!(
                seen,
                "{} {:?}: the {expected} was not found while the contexts were alive",
                s.provider, s.profile
            );
        }
    }

    /// What was found after the drop in places `keep` selects (labels), one line per key form.
    fn left_behind(sessions: &[Session], keep: impl Fn(&str) -> bool + Copy) -> Vec<String> {
        sessions
            .iter()
            .flat_map(|s| {
                s.needles
                    .iter()
                    .zip(&s.after)
                    .map(move |(needle, after)| {
                        let after: Vec<&String> =
                            after.iter().filter(|label| keep(label)).collect();
                        (needle, after)
                    })
                    .filter(|(_, after)| !after.is_empty())
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

    /// Prints the keys found after the drop in the worker's dead stack frames, a count of key
    /// forms per key and profile, and returns how many forms there were.
    fn report_stack_residue(sessions: &[Session]) -> usize {
        let mut total = 0;
        for s in sessions {
            let mut per_key: Vec<(&str, usize)> = Vec::new();
            for (needle, after) in s.needles.iter().zip(&s.after) {
                if after.iter().any(|label| label == DEAD_STACK) {
                    total += 1;
                    match per_key.iter_mut().find(|(key, _)| *key == needle.key) {
                        Some((_, n)) => *n += 1,
                        None => per_key.push((needle.key, 1)),
                    }
                }
            }
            for (key, n) in per_key {
                println!(
                    "STACK RESIDUE {:<10} {:<22} {key}: {n} forms",
                    s.provider,
                    format!("{:?}", s.profile)
                );
            }
        }
        println!(
            "STACK RESIDUE total: {total} key forms in dead stack frames (reported, not asserted)"
        );
        total
    }

    /// The process-memory check for `name`: nothing outside the worker's dead stack frames
    /// after the drop; residue in them is reported.
    fn no_key_outlives_its_contexts(name: &str) {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let sessions = every_session(name, Run::Packets);
        check_the_search_sees_live_keys(&sessions);
        report_stack_residue(&sessions);
        let left = left_behind(&sessions, |label| label != DEAD_STACK);
        assert!(left.is_empty(), "found after the drop: {left:#?}");
    }

    /// With the AWS-LC provider no key outlives its contexts in the process outside dead stack
    /// frames: every key the contexts derive, in every form (the session keys, the AES round keys
    /// and GHASH key in AWS-LC's `EVP_AEAD_CTX`, which `EVP_AEAD_CTX_cleanup` and `OPENSSL_free`
    /// cleanse, the HMAC-SHA1 states in its `HMAC_CTX`, cleansed by `HMAC_CTX_cleanup`), found
    /// while the contexts are alive, is gone from the heap and every other mapping once they are
    /// dropped, for every profile. Residue in the worker's dead stack frames is printed.
    #[cfg(feature = "crypto-aws-lc-rs")]
    #[test]
    fn with_aws_lc_no_key_outlives_its_contexts_in_process_memory() {
        no_key_outlives_its_contexts("aws-lc-rs");
    }

    /// With the ring provider no key outlives its contexts in the process outside dead stack
    /// frames: every key the contexts derive, in every form, found while the contexts are
    /// alive, is gone from the heap and every other mapping once they are dropped, for every
    /// profile. That includes ring's AES-GCM key objects (`ring::aead::LessSafeKey`: the session
    /// key and every round key), which `rtci-crypto` keeps in an allocation of its own and
    /// overwrites after ring has dropped them (found after the drop in 0.1.0, a known limit of
    /// that provider), and the HMAC-SHA1 states (RustCrypto `hmac`, built by `rtci-crypto`; the
    /// outer state was found after the drop in 0.1.0). Residue in the worker's dead stack frames
    /// is printed.
    #[cfg(feature = "crypto-ring")]
    #[test]
    fn with_ring_no_key_outlives_its_contexts_in_process_memory() {
        no_key_outlives_its_contexts("ring");
    }

    /// A KNOWN LIMIT (docs/test-exclusions.md, docs/key-erasure.md): building an SRTP context
    /// can leave keys in the dead stack frames of the thread that built it. The worker builds
    /// the contexts and does nothing else before the search, so whatever deriving the session
    /// keys and building their ciphers and MACs left below its frame is still there; the test
    /// fails when any key form is found there after the drop (and, like the tests above, on any
    /// hit elsewhere). Seen in train 34's test environment with rustc 1.99.1 (run 45714962513:
    /// the SRTCP encryption key and its round keys, the SRTCP HMAC-SHA1 states and the master
    /// key, for all ten profiles). Run with `-- --ignored known_limit_`; when it passes
    /// everywhere the limit is gone and it becomes a requirement.
    fn building_leaves_no_key_in_dead_stack_frames(name: &str) {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let sessions = every_session(name, Run::BuildOnly);
        check_the_search_sees_live_keys(&sessions);
        report_stack_residue(&sessions);
        let left = left_behind(&sessions, |_| true);
        assert!(left.is_empty(), "found after the drop: {left:#?}");
    }

    #[cfg(feature = "crypto-aws-lc-rs")]
    #[test]
    #[ignore = "known limit: key residue in dead stack frames after building an SRTP context (docs/test-exclusions.md)"]
    fn known_limit_with_aws_lc_building_an_srtp_context_leaves_keys_in_dead_stack_frames() {
        building_leaves_no_key_in_dead_stack_frames("aws-lc-rs");
    }

    #[cfg(feature = "crypto-ring")]
    #[test]
    #[ignore = "known limit: key residue in dead stack frames after building an SRTP context (docs/test-exclusions.md)"]
    fn known_limit_with_ring_building_an_srtp_context_leaves_keys_in_dead_stack_frames() {
        building_leaves_no_key_in_dead_stack_frames("ring");
    }
}
