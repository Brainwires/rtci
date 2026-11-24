//! `EndpointConfig::random_source`: every random value of an endpoint and its associations
//! comes from the provider it names, so a seeded provider makes a run reproducible.

use super::*;
use crate::chunk::chunk_type::CT_INIT;
use crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom};
use std::sync::Mutex;

/// The built-in provider with a counter for its randomness: the same bytes in every run.
struct Seeded {
    inner: Arc<dyn RTCCryptoProvider>,
    next: Mutex<u64>,
    draws: Mutex<usize>,
}

impl Seeded {
    fn new(seed: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: crypto::default_provider().expect("a crypto provider"),
            next: Mutex::new(seed),
            draws: Mutex::new(0),
        })
    }
}

impl RTCCryptoProvider for Seeded {
    fn name(&self) -> &'static str {
        "seeded"
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        self.inner.crypto()
    }

    fn random(&self) -> &dyn RTCRandom {
        self
    }
}

impl RTCRandom for Seeded {
    fn fill(&self, output: &mut [u8]) -> std::result::Result<(), CryptoError> {
        let mut next = self
            .next
            .lock()
            .map_err(|_| CryptoError::RandomnessFailed)?;
        for byte in output.iter_mut() {
            *next = next
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (*next >> 56) as u8;
        }
        *self
            .draws
            .lock()
            .map_err(|_| CryptoError::RandomnessFailed)? += 1;
        Ok(())
    }
}

fn server_addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 2], 5000))
}

/// The INIT an endpoint configured with `random` sends first: its Initiate Tag and initial
/// TSN (RFC 9260 3.3.2).
fn first_init(random: Option<Arc<Seeded>>) -> (u32, u32) {
    let mut config = EndpointConfig::default();
    if let Some(random) = random {
        config.random_source(random);
    }
    let mut endpoint = Endpoint::new(
        SocketAddr::from(([10, 0, 0, 1], 5000)),
        TransportProtocol::UDP,
        Arc::new(config),
        None,
    );
    let now = Instant::now();
    let (_, mut association) = endpoint
        .connect(now, ClientConfig::default(), server_addr())
        .expect("connect");
    let transmit = association.poll_transmit(now).expect("the INIT");
    let Payload::RawEncode(contents) = transmit.message else {
        panic!("an encoded packet");
    };
    let packet = &contents[0];
    // Common header (12 bytes), then the chunk: type, flags, length, Initiate Tag, a_rwnd,
    // the stream counts and the initial TSN.
    assert_eq!(packet[12], CT_INIT.0);
    let initiate_tag = u32::from_be_bytes(packet[16..20].try_into().unwrap());
    let initial_tsn = u32::from_be_bytes(packet[28..32].try_into().unwrap());
    (initiate_tag, initial_tsn)
}

#[test]
fn a_seeded_random_source_makes_the_same_init_every_time() {
    let seeded = Seeded::new(7);
    let first = first_init(Some(seeded.clone()));
    assert!(
        *seeded.draws.lock().unwrap() >= 2,
        "the verification tag and the initial TSN come from the provider"
    );
    assert_eq!(first_init(Some(Seeded::new(7))), first);
    assert_ne!(first_init(Some(Seeded::new(8))), first);
    assert_ne!(first.0, 0, "a verification tag is never zero");
    assert_ne!(first.1, 0);
}

#[test]
fn without_a_random_source_the_values_differ_between_runs() {
    // `rand`'s thread-local CSPRNG: 64 random bits that two runs share with probability 2^-64.
    assert_ne!(first_init(None), first_init(None));
}
