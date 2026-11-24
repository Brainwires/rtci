//! RFC 7714 section 13.1 (and RFC 3711 section 3.2.1): the master key and the master salt are
//! erased when they are no longer needed. A test allocator looks at every block of memory as
//! it is given back: while the check is on, a freed block that still holds the master key or
//! the master salt is a key left behind. The keys are handed over as `SessionKeys` (heap
//! vectors, as the engine's DTLS-SRTP export makes them), contexts are made from them with
//! and without a key derivation rate (a context then keeps its master key), packets are
//! protected and unprotected, and everything is dropped.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crypto::RTCCryptoProvider;
use rtci_srtp::config::SessionKeys;
use rtci_srtp::context::Context;
use rtci_srtp::keying::{KeyDerivationRate, Keying};
use rtci_srtp::protection_profile::ProtectionProfile;

/// A master key no other memory of the process holds by chance.
const MASTER_KEY: [u8; 32] = [
    0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed, 0xc8, 0x34,
    0x10, 0x82, 0x27, 0x6b, 0xf3, 0xa2, 0x72, 0x37, 0xd2, 0xe3, 0x9b, 0x6e, 0x0f, 0x5a, 0x4c, 0x91,
];
const MASTER_SALT: [u8; 14] = [
    0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82, 0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8,
];

static CHECKING: AtomicBool = AtomicBool::new(false);
static LEFT_BEHIND: AtomicUsize = AtomicUsize::new(0);

struct Checking;

fn holds(block: &[u8], secret: &[u8]) -> bool {
    block.len() >= secret.len() && block.windows(secret.len()).any(|w| w == secret)
}

unsafe impl GlobalAlloc for Checking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if CHECKING.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until it is freed below.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            // The 16-byte prefix covers the AES-128 profiles' keys, 12 bytes of the salt the
            // GCM profiles' salts.
            if holds(block, &MASTER_KEY[..16]) || holds(block, &MASTER_SALT[..12]) {
                LEFT_BEHIND.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Checking = Checking;

/// One test at a time looks at the allocator.
static SERIAL: Mutex<()> = Mutex::new(());

fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider")
}

fn rtp(sequence_number: u16) -> Vec<u8> {
    let mut packet = vec![0x80, 96];
    packet.extend_from_slice(&sequence_number.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 1, 0x11, 0x22, 0x33, 0x44]);
    packet.extend_from_slice(b"payload");
    packet
}

fn session(profile: ProtectionProfile, rate: KeyDerivationRate) {
    let key_len = profile.key_len();
    let salt_len = profile.salt_len();
    let keys = SessionKeys {
        local_master_key: MASTER_KEY[..key_len].to_vec(),
        local_master_salt: MASTER_SALT[..salt_len].to_vec(),
        remote_master_key: MASTER_KEY[..key_len].to_vec(),
        remote_master_salt: MASTER_SALT[..salt_len].to_vec(),
    };
    let keying = Keying {
        key_derivation_rate: rate,
        mki: None,
    };
    let context = |key: &[u8], salt: &[u8]| {
        Context::with_keying(key, salt, profile, keying.clone(), None, None, provider())
            .expect("a context")
    };
    let mut sender = context(&keys.local_master_key, &keys.local_master_salt);
    let mut receiver = context(&keys.remote_master_key, &keys.remote_master_salt);
    for sequence_number in 0..4 {
        let protected = sender
            .encrypt_rtp(&rtp(sequence_number))
            .expect("protected");
        receiver.decrypt_rtp(&protected).expect("unprotected");
    }
    drop(sender);
    drop(receiver);
    drop(keys);
}

#[test]
fn master_keys_and_salts_are_erased_when_dropped() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
        ProtectionProfile::AeadAes256Gcm,
    ] {
        for rate in [
            KeyDerivationRate::ZERO,
            KeyDerivationRate::new(1 << 16).expect("a rate"),
        ] {
            LEFT_BEHIND.store(0, Ordering::SeqCst);
            CHECKING.store(true, Ordering::SeqCst);
            session(profile, rate);
            CHECKING.store(false, Ordering::SeqCst);
            assert_eq!(
                LEFT_BEHIND.load(Ordering::SeqCst),
                0,
                "{profile:?}, rate {rate:?}: blocks freed with the master key or salt in them"
            );
        }
    }
}

/// The check itself: a vector freed without erasure is seen.
#[test]
fn the_allocator_sees_a_key_left_behind() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    LEFT_BEHIND.store(0, Ordering::SeqCst);
    CHECKING.store(true, Ordering::SeqCst);
    let careless = MASTER_KEY.to_vec();
    drop(careless);
    CHECKING.store(false, Ordering::SeqCst);
    assert!(LEFT_BEHIND.load(Ordering::SeqCst) > 0);
}
