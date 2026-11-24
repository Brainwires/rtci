//! Unit tests of the send pipeline: one per reaction to the engine's signals.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::*;
use crate::encoder::{EncodedPicture, VideoEncoder};
use crate::picture::TestSource;
use shared::marshal::MarshalSize;

/// What the fake encoders saw, shared with the test.
#[derive(Debug, Default)]
struct Log {
    /// (width, height, framerate, bitrate) of each encoder made.
    created: Vec<(u32, u32, f64, u32)>,
    /// (bitrate, framerate) of each `set_rates`.
    rates: Vec<(u32, f64)>,
    /// (width, height, forced key frame) of each picture encoded.
    encoded: Vec<(u32, u32, bool)>,
}

/// An encoder whose pictures are the size the rate allows (a key frame five times that), the
/// first picture and every forced one a key frame; its minimum is 30 kbit/s like VP8's.
struct FakeEncoder {
    log: Arc<Mutex<Log>>,
    bitrate: u32,
    framerate: f64,
    first: bool,
    index: u64,
}

impl VideoEncoder for FakeEncoder {
    fn encode(
        &mut self,
        picture: &I420<'_>,
        keyframe: bool,
    ) -> Result<Option<EncodedPicture>, EncodeError> {
        let key = keyframe || std::mem::take(&mut self.first);
        self.log
            .lock()
            .expect("log")
            .encoded
            .push((picture.width, picture.height, keyframe));
        let budget = (f64::from(self.bitrate) / 8.0 / self.framerate) as usize;
        let size = if key { budget * 5 } else { budget }.max(16);
        let index = self.index;
        self.index += 1;
        Ok(Some(EncodedPicture {
            data: vec![if key { 0x10 } else { 0x11 }; size],
            keyframe: key,
            temporal_id: 0,
            qp: Some(30),
            source_index: index,
        }))
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) {
        self.bitrate = bitrate_bps;
    }

    fn set_rates(&mut self, bitrate_bps: u32, framerate: f64) {
        self.bitrate = bitrate_bps;
        self.framerate = framerate;
        self.log
            .lock()
            .expect("log")
            .rates
            .push((bitrate_bps, framerate));
    }

    fn min_bitrate_bps(&self) -> u32 {
        30_000
    }

    fn implementation_name(&self) -> &str {
        "fake"
    }
}

const SSRC: u32 = 0x1234_5678;
const FRAME: Duration = Duration::from_micros(33_333);

struct Bench {
    pipeline: SendPipeline,
    log: Arc<Mutex<Log>>,
    source: TestSource,
    now: Instant,
}

impl Bench {
    fn new(config: SendConfig, width: u32, height: u32) -> Self {
        let log = Arc::new(Mutex::new(Log::default()));
        let l = log.clone();
        let factory = move |w: u32,
                            h: u32,
                            fps: f64,
                            bps: u32|
              -> Result<Box<dyn VideoEncoder>, EncodeError> {
            l.lock().expect("log").created.push((w, h, fps, bps));
            Ok(Box::new(FakeEncoder {
                log: l.clone(),
                bitrate: bps,
                framerate: fps,
                first: true,
                index: 0,
            }))
        };
        let mut payloader = rtp::codec::vp8::Vp8Payloader::default();
        payloader.enable_picture_id = true;
        let pipeline = SendPipeline::new(
            Box::new(factory),
            Box::new(payloader),
            RtpStreamConfig {
                ssrc: SSRC,
                payload_type: 96,
                first_sequence_number: 65_530,
                first_timestamp: 4_000_000_000,
                mtu: 1200,
            },
            config,
        );
        let t0 = Instant::now();
        Self {
            pipeline,
            log,
            source: TestSource::new(width, height),
            now: t0,
        }
    }

    /// The next picture, captured now, then the clock moves a frame interval on.
    fn frame(&mut self) -> FrameOutcome {
        let picture = self.source.next_picture();
        let now = self.now;
        let out = self
            .pipeline
            .send_frame(now, now, &picture.view())
            .expect("send");
        self.now += FRAME;
        out
    }

    fn sent(&mut self) -> SentFrame {
        match self.frame() {
            FrameOutcome::Sent(f) => f,
            other => panic!("not sent: {other:?}"),
        }
    }

    fn target(&mut self, bps: f64) {
        let now = self.now;
        self.pipeline.set_target_bitrate(now, bps);
    }

    fn request(&mut self, trigger: KeyFrameTrigger) -> KeyFrameDecision {
        let now = self.now;
        self.pipeline.request_key_frame(now, trigger)
    }

    fn advance(&mut self, d: Duration) {
        self.now += d;
    }

    fn last_rate(&self) -> (u32, f64) {
        *self.log.lock().expect("log").rates.last().expect("rates")
    }
}

#[test]
fn the_target_sets_the_encoder_rate_and_the_packets_carry_the_stream() {
    let mut b = Bench::new(SendConfig::default(), 320, 240);
    b.target(400_000.0);
    let first = b.sent();
    assert!(first.keyframe, "an encoder's first picture is a key frame");
    assert_eq!(b.last_rate(), (400_000, 30.0));
    b.target(250_000.0);
    assert_eq!(b.last_rate(), (250_000, 30.0));
    let second = b.sent();
    assert!(!second.keyframe);
    // RTP: the configured SSRC and payload type, sequence numbers continuing across the
    // wrap, the marker bit on each picture's last packet, the timestamp from the capture time
    // on the 90 kHz clock.
    let all: Vec<_> = first.packets.iter().chain(&second.packets).collect();
    for (i, p) in all.iter().enumerate() {
        assert_eq!(p.header.ssrc, SSRC);
        assert_eq!(p.header.payload_type, 96);
        assert_eq!(p.header.sequence_number, 65_530u16.wrapping_add(i as u16));
    }
    assert!(
        first.packets.len() > 1,
        "a key frame of 400 kbit/s spans packets"
    );
    assert!(first.packets.last().expect("one").header.marker);
    assert!(
        first.packets[..first.packets.len() - 1]
            .iter()
            .all(|p| !p.header.marker)
    );
    assert!(first.packets.iter().all(|p| p.marshal_size() <= 1200));
    assert_eq!(first.timestamp, 4_000_000_000);
    assert_eq!(second.timestamp, 4_000_000_000u32.wrapping_add(3000));
}

#[test]
fn a_target_under_the_encoders_minimum_keeps_the_minimum_and_drops_pictures() {
    // No degradation, so that the encoder's minimum alone drops pictures.
    let config = SendConfig {
        degradation_preference: DegradationPreference::MaintainFramerateAndResolution,
        ..SendConfig::default()
    };
    let mut b = Bench::new(config, 320, 240);
    b.target(300_000.0);
    b.sent();
    // 15 kbit/s is half the encoder's 30 kbit/s: the encoder stays at 30 and every other
    // picture is dropped, so what is sent is about the target.
    b.target(15_000.0);
    assert_eq!(b.last_rate().0, 30_000);
    let mut sent = 0;
    for _ in 0..30 {
        if matches!(b.frame(), FrameOutcome::Sent(_)) {
            sent += 1;
        }
    }
    assert!((14..=16).contains(&sent), "{sent} of 30 pictures sent");
    b.target(300_000.0);
    assert_eq!(b.last_rate().0, 300_000);
    assert!((0..30).all(|_| matches!(b.frame(), FrameOutcome::Sent(_))));
}

#[test]
fn a_pause_stops_the_encoder_and_the_resume_starts_with_a_key_frame() {
    let mut b = Bench::new(SendConfig::default(), 320, 240);
    b.target(300_000.0);
    b.sent();
    b.sent();
    let encoded = b.log.lock().expect("log").encoded.len();
    b.target(0.0);
    assert!(b.pipeline.is_paused());
    for _ in 0..20 {
        assert!(matches!(
            b.frame(),
            FrameOutcome::Dropped(DropReason::Paused)
        ));
    }
    assert_eq!(
        b.log.lock().expect("log").encoded.len(),
        encoded,
        "nothing encoded"
    );
    // A key-frame request during the pause is kept for the resume.
    b.target(0.0);
    b.target(280_000.0);
    assert!(!b.pipeline.is_paused());
    let resumed = b.sent();
    assert!(
        resumed.keyframe,
        "the first picture after a pause is a key frame"
    );
    assert!(!b.sent().keyframe);
    let st = b.pipeline.stats(b.now);
    assert_eq!(st.pauses, 1, "two zero targets in a row are one pause");
    assert_eq!(st.resume_key_frames, 1);
    assert_eq!(st.frames_dropped_paused, 20);
}

#[test]
fn the_chrome_profile_resumes_without_a_key_frame() {
    let mut b = Bench::new(SendConfig::chrome(), 320, 240);
    b.target(300_000.0);
    b.sent();
    b.target(0.0);
    b.frame();
    b.target(300_000.0);
    assert!(!b.sent().keyframe);
}

#[test]
fn key_frame_requests_within_two_round_trips_of_a_key_frame_are_not_served() {
    let mut b = Bench::new(SendConfig::default(), 320, 240);
    b.target(300_000.0);
    b.sent(); // the encoder's first key frame
    // No round trip known: 500 ms (RFC 7728 8.1), so a 1 s window.
    b.advance(Duration::from_millis(900));
    assert_eq!(
        b.request(KeyFrameTrigger::Pli),
        KeyFrameDecision::Suppressed
    );
    assert!(!b.sent().keyframe);
    b.advance(Duration::from_millis(100));
    assert_eq!(b.request(KeyFrameTrigger::Pli), KeyFrameDecision::Served);
    // A FIR and the pacer's discard while the key frame is due coalesce into it.
    assert_eq!(b.request(KeyFrameTrigger::Fir), KeyFrameDecision::Coalesced);
    assert_eq!(
        b.request(KeyFrameTrigger::PacerDiscard),
        KeyFrameDecision::Coalesced
    );
    assert!(b.sent().keyframe);
    assert!(!b.sent().keyframe, "one key frame for the three requests");
    // With a measured round trip of 100 ms the window is 200 ms from that key frame.
    b.pipeline.set_rtt(Duration::from_millis(100));
    b.advance(Duration::from_millis(100));
    assert_eq!(
        b.request(KeyFrameTrigger::PacerDiscard),
        KeyFrameDecision::Suppressed
    );
    b.advance(Duration::from_millis(100));
    assert_eq!(
        b.request(KeyFrameTrigger::PacerDiscard),
        KeyFrameDecision::Served
    );
    assert!(b.sent().keyframe);
    let st = b.pipeline.stats(b.now);
    assert_eq!(
        (
            st.key_frame_requests_served,
            st.key_frame_requests_coalesced,
            st.key_frame_requests_suppressed,
            st.pacer_discards
        ),
        (2, 2, 2, 3)
    );
    assert_eq!(st.key_frames_encoded, 3);
}

#[test]
fn the_chrome_profile_serves_one_request_per_300_ms_whatever_was_sent() {
    let mut b = Bench::new(SendConfig::chrome(), 320, 240);
    b.target(300_000.0);
    b.sent();
    // Right after the encoder's first key frame: served (libwebrtc counts from the last
    // request served, not from the key frame).
    assert_eq!(b.request(KeyFrameTrigger::Pli), KeyFrameDecision::Served);
    assert!(b.sent().keyframe);
    b.advance(Duration::from_millis(250));
    assert_eq!(
        b.request(KeyFrameTrigger::Pli),
        KeyFrameDecision::Suppressed
    );
    b.advance(Duration::from_millis(20));
    assert_eq!(b.request(KeyFrameTrigger::Pli), KeyFrameDecision::Served);
}

fn format_at(preference: DegradationPreference, target: f64) -> (u32, u32, f64) {
    let config = SendConfig {
        degradation_preference: preference,
        ..SendConfig::default()
    };
    let mut b = Bench::new(config, 640, 360);
    b.target(target);
    b.sent();
    b.pipeline.current_format().expect("a source")
}

#[test]
fn a_target_under_what_the_resolution_needs_degrades_as_the_preference_says() {
    // 640x360 needs 150 kbit/s at 30 fps (libwebrtc's VP8 minimum); 100 kbit/s does not do.
    assert_eq!(min_bitrate_for(640 * 360, 30.0), 150_000);
    assert_eq!(
        format_at(DegradationPreference::MaintainFramerate, 100_000.0),
        (384, 216, 30.0),
        "resolution steps of 3/5 of the pixels until the target does"
    );
    assert_eq!(
        format_at(DegradationPreference::MaintainResolution, 100_000.0),
        (640, 360, 20.0),
        "frame-rate steps of 2/3"
    );
    assert_eq!(
        format_at(DegradationPreference::Balanced, 100_000.0),
        (496, 278, 20.0),
        "a resolution step, then a frame-rate step"
    );
    assert_eq!(
        format_at(
            DegradationPreference::MaintainFramerateAndResolution,
            100_000.0
        ),
        (640, 360, 30.0)
    );
    // Enough for the source's format: nothing degrades.
    assert_eq!(
        format_at(DegradationPreference::Balanced, 200_000.0),
        (640, 360, 30.0)
    );
    // The floors: never under 320x180 nor 2 fps.
    assert_eq!(
        format_at(DegradationPreference::MaintainFramerate, 10_000.0),
        (384, 216, 30.0)
    );
    assert_eq!(
        format_at(DegradationPreference::MaintainResolution, 1_000.0)
            .2
            .round(),
        3.0
    );
}

#[test]
fn degraded_pictures_are_scaled_and_encoded_at_the_lower_resolution_and_recover_with_margin() {
    let config = SendConfig {
        degradation_preference: DegradationPreference::MaintainFramerate,
        ..SendConfig::default()
    };
    let mut b = Bench::new(config, 640, 360);
    b.target(500_000.0);
    assert_eq!((b.sent().width, b.sent().height), (640, 360));
    b.target(100_000.0);
    let f = b.sent();
    assert_eq!((f.width, f.height), (384, 216));
    assert!(f.keyframe, "a new resolution starts with a key frame");
    let created = b.log.lock().expect("log").created.clone();
    assert_eq!(
        created.last().map(|c| (c.0, c.1, c.3)),
        Some((384, 216, 100_000))
    );
    assert_eq!(
        b.log
            .lock()
            .expect("log")
            .encoded
            .last()
            .map(|e| (e.0, e.1)),
        Some((384, 216)),
        "the encoder is given the scaled picture"
    );
    // 190 kbit/s meets 640x360's 150 with the quarter's margin, but not within 5 s of the
    // step down.
    b.advance(Duration::from_secs(4));
    b.target(190_000.0);
    assert_eq!((b.sent().width, b.sent().height), (384, 216), "held");
    // After the hold, 160 kbit/s meets 640x360's 150 but not with the margin: no step up.
    b.advance(Duration::from_secs(1));
    b.target(160_000.0);
    assert_eq!((b.sent().width, b.sent().height), (384, 216));
    b.target(190_000.0);
    assert_eq!((b.sent().width, b.sent().height), (640, 360));
    b.advance(Duration::from_secs(1));
    let st = b.pipeline.stats(b.now);
    assert_eq!(st.quality_limitation_resolution_changes, 2);
    assert!(!st.quality_limited);
    assert!(st.quality_limitation_bandwidth > 0.0);
    assert!(st.quality_limitation_none > 1.0);
}

#[test]
fn a_lower_frame_rate_step_encodes_two_pictures_of_three_and_tells_the_encoder() {
    let config = SendConfig {
        degradation_preference: DegradationPreference::MaintainResolution,
        ..SendConfig::default()
    };
    let mut b = Bench::new(config, 640, 360);
    b.target(100_000.0);
    let mut sent = 0;
    for _ in 0..30 {
        if matches!(b.frame(), FrameOutcome::Sent(_)) {
            sent += 1;
        }
    }
    assert_eq!(sent, 20, "20 fps from a 30 fps source");
    assert_eq!(b.last_rate(), (100_000, 20.0));
}
