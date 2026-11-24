//! The `o=` line of generated descriptions (RFC 9429 sections 5.2.2 and 5.3.2, RFC 3264
//! section 8): it stays the same but for the session version, which goes up by one with each
//! description that differs from the one generated before.

mod jsep_common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsep_common::{TestResult, default_peer, video_track};
use rtci::crypto::{CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom, default_provider};
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtci::shared::time::SystemInstant;

/// (everything of the `o=` line but the version, the version).
fn origin(sdp: &str) -> (String, u64) {
    let line = sdp
        .lines()
        .find(|l| l.starts_with("o="))
        .unwrap_or_else(|| panic!("an o= line in:\n{sdp}"));
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields.len(), 6, "{line}");
    let version = fields[2].parse().expect("a numeric session version");
    let mut rest = fields.clone();
    rest.remove(2);
    (rest.join(" "), version)
}

/// The built-in crypto provider with its random source replaced by a seeded generator
/// (SplitMix64), so what a peer connection draws through `random()` is the same for the same
/// seed. Not secure; the test needs repeatability, not secrecy.
struct SeededProvider {
    inner: Arc<dyn RTCCryptoProvider>,
    state: Mutex<u64>,
}

impl RTCCryptoProvider for SeededProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        self.inner.crypto()
    }

    fn random(&self) -> &dyn RTCRandom {
        self
    }
}

impl RTCRandom for SeededProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CryptoError::RandomnessFailed)?;
        for chunk in output.chunks_mut(8) {
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

/// A peer on the given wall clock whose random numbers come from `seed`.
fn peer_on(
    now: Instant,
    wall_clock: SystemInstant,
    seed: u64,
) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let provider = Arc::new(SeededProvider {
        inner: default_provider()?,
        state: Mutex::new(seed),
    });
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_crypto_provider(provider)
                .with_wall_clock(wall_clock)
                .build(),
        )
        .build(now)?)
}

/// RFC 8866 section 5.2: "<sess-version> is a version number for this session description
/// ... it is RECOMMENDED that a timestamp be used", as for `<sess-id>`: "a timestamp, in
/// seconds since January 1, 1900 UTC". The first description's version is the peer
/// connection's wall clock in those seconds when it was built, and the session id is drawn from the crypto
/// provider (RFC 9429 section 5.2.1), so the same clock and the same seeded provider give the
/// same `o=` line: nothing else is read.
#[test]
fn the_first_session_version_is_the_wall_clocks_seconds_since_1900() -> TestResult {
    let now = Instant::now();
    // 2023-11-14T22:13:20Z.
    let wall_clock = SystemInstant::at(now, Duration::from_secs(1_700_000_000));
    let o_line = |pc: &mut RTCPeerConnection| -> Result<String, Box<dyn std::error::Error>> {
        pc.add_track(video_track("first", 0x0101_0101))?;
        let offer = pc.create_offer(None)?;
        Ok(offer
            .sdp
            .lines()
            .find(|l| l.starts_with("o="))
            .expect("an o= line")
            .to_owned())
    };

    let mut a = peer_on(now, wall_clock, 7)?;
    let line = o_line(&mut a)?;
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(
        fields[2],
        (1_700_000_000u64 + 2_208_988_800).to_string(),
        "{line}"
    );
    let session_id: u64 = fields[1].parse()?;
    assert!(session_id < (1u64 << 63) - 1, "{line}");

    // Another peer connection on the same clock with the same seed: the same o= line.
    let mut b = peer_on(now, wall_clock, 7)?;
    assert_eq!(o_line(&mut b)?, line);
    // Built five seconds later: the version is five seconds on.
    let mut later = peer_on(now + Duration::from_secs(5), wall_clock, 7)?;
    assert_eq!(
        o_line(&mut later)?.split(' ').nth(2),
        Some((1_700_000_005u64 + 2_208_988_800).to_string().as_str())
    );
    // Another seed: another session.
    let mut c = peer_on(now, wall_clock, 8)?;
    let other = o_line(&mut c)?;
    assert_ne!(other.split(' ').nth(1), Some(fields[1]), "{other}");
    assert_eq!(other.split(' ').nth(2), Some(fields[2]), "{other}");
    Ok(())
}

#[test]
fn the_session_version_goes_up_by_one_with_each_changed_description() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    a.add_track(video_track("first", 0x0101_0101))?;

    let first = a.create_offer(None)?;
    let (session, version) = origin(&first.sdp);

    // The same offer again: the same text, version included.
    let again = a.create_offer(None)?;
    assert_eq!(again.sdp, first.sdp);

    // A changed offer: one more, same session.
    a.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(rtci::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    let second = a.create_offer(None)?;
    assert_eq!(origin(&second.sdp), (session.clone(), version + 1));

    a.set_local_description(Instant::now(), second.clone())?;
    b.set_remote_description(Instant::now(), second)?;
    let answer = b.create_answer(None)?;
    let (b_session, b_version) = origin(&answer.sdp);
    assert_ne!(b_session, session, "each endpoint has its own session id");
    b.set_local_description(Instant::now(), answer.clone())?;
    a.set_remote_description(Instant::now(), answer)?;

    // `b` now offers: its next description, one more than its answer.
    b.add_track(video_track("b", 0x0202_0202))?;
    let offer = b.create_offer(None)?;
    assert_eq!(origin(&offer.sdp), (b_session, b_version + 1));
    b.set_local_description(Instant::now(), offer.clone())?;
    a.set_remote_description(Instant::now(), offer)?;

    // `a` answers: its third description.
    let answer = a.create_answer(None)?;
    assert_eq!(origin(&answer.sdp), (session, version + 2));
    Ok(())
}

/// RFC 9429 section 5.8: compliant SDP is accepted even where it does not follow the
/// generation rules; `<sess-id>` and `<sess-version>` are `1*DIGIT` of any length (RFC 8866
/// section 9), so a remote offer whose values do not fit 64 bits is set and answered, and a
/// later offer of that session with the version one higher is set too.
#[test]
fn a_remote_origin_beyond_64_bits_is_accepted() -> TestResult {
    let mut a = default_peer()?;
    let mut b = default_peer()?;
    a.add_track(video_track("first", 0x0101_0101))?;
    let offer = a.create_offer(None)?;
    let line = offer
        .sdp
        .lines()
        .find(|l| l.starts_with("o="))
        .expect("an o= line")
        .to_owned();
    let long = |version: &str| {
        offer.sdp.replace(
            &line,
            &format!("o=- 98765432109876543210987654321 {version} IN IP4 0.0.0.0"),
        )
    };
    b.set_remote_description(
        Instant::now(),
        rtci::peer_connection::sdp::RTCSessionDescription::offer(long("18446744073709551616"))?,
    )?;
    let answer = b.create_answer(None)?;
    b.set_local_description(Instant::now(), answer)?;
    b.set_remote_description(
        Instant::now(),
        rtci::peer_connection::sdp::RTCSessionDescription::offer(long("18446744073709551617"))?,
    )?;
    let answer = b.create_answer(None)?;
    assert!(answer.sdp.contains("m=video"), "{}", answer.sdp);
    Ok(())
}
