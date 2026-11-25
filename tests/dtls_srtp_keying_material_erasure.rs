//! RFC 7714 section 13.1 ("All keys MUST be properly erased when no longer needed") for the
//! SRTP master keys and salts a DTLS-SRTP association exports (RFC 5764 section 4.2): the
//! keying material is exported, split into the four master keys and salts and made into the
//! two SRTP contexts as the engine does (`update_srtp_contexts` in
//! `src/peer_connection/handler/dtls.rs`), and everything is dropped. A test allocator looks at
//! every block freed meanwhile: one that still holds a key or salt of the material, or the
//! material itself, is key material left behind.
//!
//! The material is known only once exported, so it is exported twice from the same completed
//! association (the exporter is a function of the session's secrets and the label): the first
//! time to learn what to look for (kept only inverted, as the needles of
//! `rtci-srtp/tests/key_material`), the second time with the check on.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rtci::crypto::default_provider;
use rtci::dtls::config::{ClientAuthType, ConfigBuilder, DtlsVersion};
use rtci::dtls::crypto::Certificate;
use rtci::dtls::endpoint::{Endpoint, EndpointEvent};
use rtci::dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use rtci::shared::TransportProtocol;
use rtci::srtp::config::{Config, LABEL_EXTRACTOR_DTLS_SRTP};
use rtci::srtp::context::Context;
use rtci::srtp::protection_profile::ProtectionProfile;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// What to look for, inverted: the material, then each key and salt in it.
struct Needles {
    inverted: Vec<Vec<u8>>,
}

impl Needles {
    fn found_in(&self, block: &[u8]) -> Option<usize> {
        self.inverted.iter().position(|needle| {
            block.len() >= needle.len()
                && block
                    .windows(needle.len())
                    .any(|w| w.iter().zip(needle).all(|(b, n)| *b == !*n))
        })
    }
}

static CHECKING: AtomicBool = AtomicBool::new(false);
static LEFT_BEHIND: AtomicUsize = AtomicUsize::new(0);
static NEEDLES: Mutex<Needles> = Mutex::new(Needles {
    inverted: Vec::new(),
});

struct Checking;

unsafe impl GlobalAlloc for Checking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if CHECKING.load(Ordering::SeqCst) {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until it is freed below.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if let Ok(needles) = NEEDLES.try_lock()
                && needles.found_in(block).is_some()
            {
                LEFT_BEHIND.fetch_add(1, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Checking = Checking;

static SERIAL: Mutex<()> = Mutex::new(());

/// A client and a server endpoint whose handshake has completed.
fn associate(
    version: DtlsVersion,
    profile: SrtpProtectionProfile,
) -> Result<(Endpoint, SocketAddr), Box<dyn std::error::Error>> {
    let provider = default_provider()?;
    let certificate =
        Certificate::generate_self_signed(vec!["localhost".into()], provider.crypto())?;
    let configuration = ConfigBuilder::default()
        .with_crypto_provider(provider)
        .with_certificates(vec![certificate])
        .with_insecure_skip_verify(true)
        .with_client_auth(ClientAuthType::RequireAnyClientCert)
        .with_srtp_protection_profiles(vec![profile])
        .with_protocol_versions(version, version);
    let client_addr: SocketAddr = "127.0.0.1:44101".parse()?;
    let server_addr: SocketAddr = "127.0.0.1:44102".parse()?;
    let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr,
        TransportProtocol::UDP,
        Some(Arc::new(configuration.clone().build(false, None)?)),
    );
    let now = Instant::now();
    client.connect(
        now,
        server_addr,
        Arc::new(configuration.build(true, None)?),
        None,
    )?;
    let mut completed = false;
    for _ in 0..8 {
        while let Some(packet) = client.poll_transmit() {
            server.read(now, client_addr, packet.transport.ecn, packet.message)?;
        }
        while let Some(packet) = server.poll_transmit() {
            completed |= client
                .read(now, server_addr, packet.transport.ecn, packet.message)?
                .iter()
                .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        }
    }
    assert!(completed, "{version:?}: the handshake completes");
    Ok((client, server_addr))
}

/// The engine's steps from the exporter to the two SRTP contexts, then the drop.
fn keys_from_the_association(client: &Endpoint, server_addr: SocketAddr) -> TestResult {
    let state = client
        .get_connection_state(server_addr)
        .expect("an association");
    let profile = ProtectionProfile::from_dtls_srtp_id(state.srtp_protection_profile() as u16)
        .expect("a negotiated profile");
    let mut config = Config {
        profile,
        ..Default::default()
    };
    let material = state.export_keying_material(
        LABEL_EXTRACTOR_DTLS_SRTP,
        &[],
        config.keying_material_len(),
    )?;
    config.set_session_keys_from_keying_material(material.as_ref(), state.is_client())?;
    let provider = default_provider()?;
    let local = Context::new(
        &config.keys.local_master_key,
        &config.keys.local_master_salt,
        profile,
        None,
        None,
        provider.crypto(),
    )?;
    let remote = Context::new(
        &config.keys.remote_master_key,
        &config.keys.remote_master_salt,
        profile,
        None,
        None,
        provider.crypto(),
    )?;
    drop(material);
    drop(config);
    drop(local);
    drop(remote);
    Ok(())
}

fn left_behind(
    version: DtlsVersion,
    srtp: SrtpProtectionProfile,
) -> Result<usize, Box<dyn std::error::Error>> {
    let (client, server_addr) = associate(version, srtp)?;
    {
        let state = client
            .get_connection_state(server_addr)
            .expect("an association");
        let profile = ProtectionProfile::from_dtls_srtp_id(state.srtp_protection_profile() as u16)
            .expect("a negotiated profile");
        let (key_len, salt_len) = (profile.key_len(), profile.salt_len());
        let config = Config {
            profile,
            ..Default::default()
        };
        let material = state.export_keying_material(
            LABEL_EXTRACTOR_DTLS_SRTP,
            &[],
            config.keying_material_len(),
        )?;
        let material = material.as_ref();
        let mut inverted = vec![material.iter().map(|b| !b).collect::<Vec<u8>>()];
        let mut at = 0;
        for len in [key_len, key_len, salt_len, salt_len] {
            inverted.push(material[at..at + len].iter().map(|b| !b).collect());
            at += len;
        }
        *NEEDLES.lock().unwrap_or_else(|e| e.into_inner()) = Needles { inverted };
    }
    LEFT_BEHIND.store(0, Ordering::SeqCst);
    CHECKING.store(true, Ordering::SeqCst);
    let outcome = keys_from_the_association(&client, server_addr);
    CHECKING.store(false, Ordering::SeqCst);
    outcome?;
    Ok(LEFT_BEHIND.load(Ordering::SeqCst))
}

/// DTLS 1.3 (RFC 8446 section 7.5 exporter, HKDF in zeroizing buffers): the exported SRTP
/// master keys and salts are left in no freed block, for an AES-CM and an AES-GCM profile.
#[test]
fn dtls13_srtp_keying_material_is_erased_once_the_contexts_are_made() -> TestResult {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for profile in [
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
    ] {
        let left = left_behind(DtlsVersion::Dtls1_3, profile)?;
        assert_eq!(
            0, left,
            "DTLS 1.3, {profile:?}: blocks freed with keying material in them"
        );
    }
    Ok(())
}

/// DTLS 1.2 (RFC 5705 exporter over the TLS PRF, RFC 5246 section 5): the same.
#[test]
fn dtls12_srtp_keying_material_is_erased_once_the_contexts_are_made() -> TestResult {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for profile in [
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
    ] {
        let left = left_behind(DtlsVersion::Dtls1_2, profile)?;
        assert_eq!(
            0, left,
            "DTLS 1.2, {profile:?}: blocks freed with keying material in them"
        );
    }
    Ok(())
}

/// The check itself: the material copied into a vector that is freed without erasure is seen.
#[test]
fn the_allocator_sees_keying_material_left_behind() -> TestResult {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (client, server_addr) = associate(
        DtlsVersion::Dtls1_3,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    )?;
    let state = client
        .get_connection_state(server_addr)
        .expect("an association");
    let material = state.export_keying_material(LABEL_EXTRACTOR_DTLS_SRTP, &[], 60)?;
    *NEEDLES.lock().unwrap_or_else(|e| e.into_inner()) = Needles {
        inverted: vec![material.as_ref().iter().map(|b| !b).collect()],
    };
    LEFT_BEHIND.store(0, Ordering::SeqCst);
    CHECKING.store(true, Ordering::SeqCst);
    let careless = material.as_ref().to_vec();
    drop(careless);
    CHECKING.store(false, Ordering::SeqCst);
    assert!(LEFT_BEHIND.load(Ordering::SeqCst) > 0);
    Ok(())
}
