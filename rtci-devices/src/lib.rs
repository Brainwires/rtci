//! Audio capture and playout for the `rtci-audio` pipeline.
//!
//! [`AudioDevices`] owns one input and one output stream of a [`Backend`] and moves audio
//! between them and the pipeline in 10 ms frames of 48 kHz mono:
//!
//! - the device callbacks run on the system's real-time audio threads and only copy samples
//!   into or out of a wait-free single-producer single-consumer ring ([`rtrb`]) and update a
//!   few atomics; they never allocate, lock, log or block;
//! - [`AudioDevices::read_capture`] and [`AudioDevices::write_playout`] run on the
//!   application's audio thread: channel conversion and sample-rate conversion between the
//!   device's rate and the pipeline's happen there;
//! - devices are listed ([`AudioDevices::devices`]), chosen by id, switched while running
//!   ([`AudioDevices::open_input`] on an open device replaces it), and replaced by the
//!   system default when they fail or disappear ([`AudioDevices::poll`], reported as
//!   [`DeviceEvent`]s).
//!
//! | Backend | Feature | |
//! |---|---|---|
//! | [`fake::FakeBackend`] | - | no hardware; tests drive its callbacks |
//! | `cpal_backend::CpalBackend` | `devices` | CoreAudio, WASAPI, ALSA through cpal |
//!
//! Nothing opens a device or starts a thread until the application calls `open_input` or
//! `open_output` with the `devices` backend.

pub mod backend;
#[cfg(feature = "devices")]
pub mod cpal_backend;
pub mod fake;

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use audio::AudioFrame;
use audio::dsp::resample::MultiResampler;
use audio::frame::convert_channels;
pub use backend::{
    Backend, CaptureSink, DeviceInfo, DeviceStream, Direction, PlayoutSource, StreamShared,
};

/// The pipeline's rate.
pub const PIPELINE_RATE: u32 = 48_000;
/// Samples in a pipeline frame (10 ms).
pub const FRAME: usize = 480;

/// What can go wrong with a device.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// No such device, or none at all.
    #[error("no such audio device")]
    NoDevice,
    /// The system refused access (macOS / Windows privacy settings).
    #[error("audio device access denied")]
    PermissionDenied,
    /// The device or its backend failed.
    #[error("audio device: {0}")]
    Device(String),
    /// A sample format or layout the backend cannot convert.
    #[error("audio format: {0}")]
    Format(String),
}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Something that happened to the devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceEvent {
    /// The input in use failed or disappeared.
    InputLost(String),
    /// The output in use failed or disappeared.
    OutputLost(String),
    /// The input is now this device (after a switch or a replacement).
    InputOpened(DeviceInfo),
    /// The output is now this device.
    OutputOpened(DeviceInfo),
}

struct OpenInput {
    stream: Box<dyn DeviceStream>,
    consumer: rtrb::Consumer<f32>,
    resampler: Option<MultiResampler>,
    pending: Vec<f32>,
    /// The device the application asked for (`None`: the default).
    requested: Option<String>,
}

struct OpenOutput {
    stream: Box<dyn DeviceStream>,
    producer: rtrb::Producer<f32>,
    capacity: usize,
    resampler: Option<MultiResampler>,
    requested: Option<String>,
}

/// Capture and playout through a backend (see the crate docs).
pub struct AudioDevices<B: Backend> {
    backend: B,
    input: Option<OpenInput>,
    output: Option<OpenOutput>,
    events: VecDeque<DeviceEvent>,
    /// Playout queued beyond this is dropped, so delay cannot build up.
    max_playout_queue: Duration,
}

impl<B: Backend> std::fmt::Debug for AudioDevices<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudioDevices")
            .field("backend", &self.backend.name())
            .field(
                "input",
                &self.input.as_ref().map(|i| i.stream.info().clone()),
            )
            .field(
                "output",
                &self.output.as_ref().map(|o| o.stream.info().clone()),
            )
            .finish()
    }
}

impl<B: Backend> AudioDevices<B> {
    /// Devices of `backend`; nothing is opened yet.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            input: None,
            output: None,
            events: VecDeque::new(),
            max_playout_queue: Duration::from_millis(200),
        }
    }

    /// The backend.
    pub fn backend(&mut self) -> &mut B {
        &mut self.backend
    }

    /// The devices of a direction.
    pub fn devices(&mut self, direction: Direction) -> Vec<DeviceInfo> {
        self.backend.devices(direction)
    }

    /// The input in use.
    pub fn input(&self) -> Option<&DeviceInfo> {
        self.input.as_ref().map(|i| i.stream.info())
    }

    /// The output in use.
    pub fn output(&self) -> Option<&DeviceInfo> {
        self.output.as_ref().map(|o| o.stream.info())
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<DeviceEvent> {
        self.events.pop_front()
    }

    fn open_input_stream(&mut self, id: Option<&str>) -> Result<OpenInput> {
        let info = self.backend.probe(Direction::Input, id)?;
        // Half a second at the device's rate: far more than the audio thread leaves unread.
        let capacity = (info.sample_rate as usize / 2) * usize::from(info.channels.max(1));
        let (producer, consumer) = rtrb::RingBuffer::new(capacity.max(1024));
        let shared = Arc::new(StreamShared::default());
        let stream = self
            .backend
            .open_input(id, CaptureSink { producer, shared })?;
        let resampler = (stream.info().sample_rate != PIPELINE_RATE)
            .then(|| MultiResampler::new(stream.info().sample_rate, PIPELINE_RATE, 1));
        Ok(OpenInput {
            stream,
            consumer,
            resampler,
            pending: Vec::new(),
            requested: id.map(str::to_owned),
        })
    }

    fn open_output_stream(&mut self, id: Option<&str>) -> Result<OpenOutput> {
        let info = self.backend.probe(Direction::Output, id)?;
        let capacity = (info.sample_rate as usize / 2) * usize::from(info.channels.max(1));
        let (producer, consumer) = rtrb::RingBuffer::new(capacity.max(1024));
        let shared = Arc::new(StreamShared::default());
        let stream = self
            .backend
            .open_output(id, PlayoutSource { consumer, shared })?;
        let resampler = (stream.info().sample_rate != PIPELINE_RATE)
            .then(|| MultiResampler::new(PIPELINE_RATE, stream.info().sample_rate, 1));
        Ok(OpenOutput {
            stream,
            producer,
            capacity: capacity.max(1024),
            resampler,
            requested: id.map(str::to_owned),
        })
    }

    /// Opens input `id` (the default for `None`), replacing the one in use: the new device is
    /// opened before the old one is closed, so a failed switch leaves the old in place.
    pub fn open_input(&mut self, id: Option<&str>) -> Result<DeviceInfo> {
        let input = self.open_input_stream(id)?;
        let info = input.stream.info().clone();
        self.input = Some(input);
        self.events
            .push_back(DeviceEvent::InputOpened(info.clone()));
        Ok(info)
    }

    /// Opens output `id` (the default for `None`), replacing the one in use.
    pub fn open_output(&mut self, id: Option<&str>) -> Result<DeviceInfo> {
        let output = self.open_output_stream(id)?;
        let info = output.stream.info().clone();
        self.output = Some(output);
        self.events
            .push_back(DeviceEvent::OutputOpened(info.clone()));
        Ok(info)
    }

    /// Closes the input.
    pub fn close_input(&mut self) {
        self.input = None;
    }

    /// Closes the output.
    pub fn close_output(&mut self) {
        self.output = None;
    }

    /// Checks the streams: a failed or vanished device is replaced by the system default
    /// (or closed when there is none), and the event says so. Call it from the audio thread
    /// now and then (every frame is fine: it is a few atomic loads).
    pub fn poll(&mut self) {
        if let Some(input) = &self.input
            && input.stream.shared().failed.load(Ordering::Relaxed)
        {
            let lost = input.stream.info().id.clone();
            let requested = input.requested.clone();
            self.input = None;
            self.events.push_back(DeviceEvent::InputLost(lost.clone()));
            // The device asked for, if it is back; else the default.
            let retry = requested
                .clone()
                .filter(|r| *r != lost && self.backend.probe(Direction::Input, Some(r)).is_ok());
            if self.open_input(retry.as_deref()).is_ok()
                && let Some(i) = self.input.as_mut()
            {
                i.requested = requested;
            }
        }
        if let Some(output) = &self.output
            && output.stream.shared().failed.load(Ordering::Relaxed)
        {
            let lost = output.stream.info().id.clone();
            let requested = output.requested.clone();
            self.output = None;
            self.events.push_back(DeviceEvent::OutputLost(lost.clone()));
            let retry = requested
                .clone()
                .filter(|r| *r != lost && self.backend.probe(Direction::Output, Some(r)).is_ok());
            if self.open_output(retry.as_deref()).is_ok()
                && let Some(o) = self.output.as_mut()
            {
                o.requested = requested;
            }
        }
    }

    /// The next 10 ms of captured audio (48 kHz mono), once the device has delivered it.
    pub fn read_capture(&mut self) -> Option<AudioFrame> {
        let input = self.input.as_mut()?;
        let channels = input.stream.info().channels;
        let n = input.consumer.slots();
        if n > 0 {
            let mut raw = Vec::with_capacity(n);
            if let Ok(chunk) = input
                .consumer
                .read_chunk(n - n % usize::from(channels.max(1)))
            {
                let (a, b) = chunk.as_slices();
                raw.extend_from_slice(a);
                raw.extend_from_slice(b);
                chunk.commit_all();
            }
            let mut mono = Vec::with_capacity(raw.len());
            if convert_channels(&raw, channels, 1, &mut mono).is_err() {
                // More than two channels: the first one.
                mono = raw
                    .iter()
                    .step_by(usize::from(channels.max(1)))
                    .copied()
                    .collect();
            }
            match input.resampler.as_mut() {
                Some(r) => r.process(&mono, &mut input.pending),
                None => input.pending.extend(mono),
            }
        }
        if input.pending.len() < FRAME {
            return None;
        }
        let samples: Vec<f32> = input.pending.drain(..FRAME).collect();
        Some(AudioFrame {
            samples,
            sample_rate: PIPELINE_RATE,
            channels: 1,
        })
    }

    /// Queues audio for playout (any rate the frame states, mono or stereo): converted to the
    /// device's rate and channels. Audio beyond the queue limit (200 ms) is dropped.
    pub fn write_playout(&mut self, frame: &AudioFrame) {
        let Some(output) = self.output.as_mut() else {
            return;
        };
        let info = output.stream.info().clone();
        let mut mono = Vec::with_capacity(frame.samples.len());
        if convert_channels(&frame.samples, frame.channels, 1, &mut mono).is_err() {
            return;
        }
        let mut at_device = Vec::new();
        if frame.sample_rate == info.sample_rate {
            at_device = mono;
        } else {
            let rebuild = output
                .resampler
                .as_ref()
                .is_none_or(|r| r.from_rate() != frame.sample_rate);
            if rebuild {
                output.resampler =
                    Some(MultiResampler::new(frame.sample_rate, info.sample_rate, 1));
            }
            if let Some(r) = output.resampler.as_mut() {
                r.process(&mono, &mut at_device);
            }
        }
        let mut interleaved = Vec::with_capacity(at_device.len() * usize::from(info.channels));
        for s in at_device {
            for _ in 0..info.channels.max(1) {
                interleaved.push(s);
            }
        }
        let limit = (self.max_playout_queue.as_secs_f64() * f64::from(info.sample_rate)) as usize
            * usize::from(info.channels.max(1));
        let queued = output.capacity - output.producer.slots();
        let room = limit.saturating_sub(queued).min(output.producer.slots());
        let n = interleaved.len().min(room);
        if let Ok(chunk) = output.producer.write_chunk_uninit(n) {
            chunk.fill_from_iter(interleaved[..n].iter().copied());
        }
    }

    /// How long audio written now takes to be heard: the queue plus the device's latency
    /// (the echo canceller's delay hint).
    pub fn playout_delay(&self) -> Duration {
        let Some(output) = self.output.as_ref() else {
            return Duration::ZERO;
        };
        let info = output.stream.info();
        let queued =
            (output.capacity - output.producer.slots()) / usize::from(info.channels.max(1));
        Duration::from_secs_f64(queued as f64 / f64::from(info.sample_rate.max(1)))
            + output.stream.latency()
    }

    /// Samples lost on capture (the application read too late) and played as silence on
    /// output (it wrote too late), so far.
    pub fn xruns(&self) -> (u64, u64) {
        (
            self.input
                .as_ref()
                .map_or(0, |i| i.stream.shared().xruns.load(Ordering::Relaxed)),
            self.output
                .as_ref()
                .map_or(0, |o| o.stream.shared().xruns.load(Ordering::Relaxed)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeBackend;
    use audio::signal::{Tone, best_lag};

    fn device(id: &str, rate: u32, channels: u16, default: bool) -> DeviceInfo {
        DeviceInfo {
            id: id.into(),
            name: format!("Fake {id}"),
            sample_rate: rate,
            channels,
            is_default: default,
        }
    }

    #[test]
    fn a_stereo_44_1_khz_microphone_becomes_48_khz_mono_frames() {
        let fake = FakeBackend::new();
        let control = fake.control();
        control.add_device(Direction::Input, device("mic", 44_100, 2, true));
        let mut devices = AudioDevices::new(fake);
        assert_eq!(devices.devices(Direction::Input).len(), 1);
        devices.open_input(None).unwrap();
        let mut tone = Tone::new(44_100, 1000.0, 0.5);
        let mut frames = Vec::new();
        // One second in 441-frame callbacks.
        for _ in 0..100 {
            let mut mono = vec![0.0f32; 441];
            tone.fill(&mut mono);
            let stereo: Vec<f32> = mono.iter().flat_map(|&s| [s, s]).collect();
            assert!(control.capture("mic", &stereo));
            while let Some(f) = devices.read_capture() {
                frames.push(f);
            }
        }
        assert!((98..=100).contains(&frames.len()), "{}", frames.len());
        assert!(
            frames
                .iter()
                .all(|f| f.sample_rate == 48_000 && f.channels == 1 && f.samples.len() == 480)
        );
        // Still a 1 kHz tone: it repeats every 48 samples.
        let x: Vec<f32> = frames[50..60]
            .iter()
            .flat_map(|f| f.samples.clone())
            .collect();
        let lag = best_lag(&x[..2400], &x[48..2448], 4);
        assert_eq!(lag, 0);
        assert_eq!(devices.xruns().0, 0);
    }

    #[test]
    fn playout_is_converted_to_the_device_and_underruns_are_counted() {
        let fake = FakeBackend::new();
        let control = fake.control();
        control.add_device(Direction::Output, device("spk", 16_000, 2, true));
        let mut devices = AudioDevices::new(fake);
        devices.open_output(Some("spk")).unwrap();
        for _ in 0..5 {
            devices.write_playout(&AudioFrame {
                samples: vec![0.25; 480],
                sample_rate: 48_000,
                channels: 1,
            });
        }
        // 50 ms at 16 kHz is 800 frames, less the resampler's delay.
        let played = control.play("spk", 1000).unwrap();
        assert_eq!(played.len(), 2000);
        // 2000 samples asked for, about 1600 queued: the rest played as silence.
        let (_, under) = devices.xruns();
        assert!((360..=440).contains(&under), "{under}");
        let settled = &played[400..1400];
        assert!(settled.iter().all(|v| (v - 0.25).abs() < 1e-3));
        assert!(devices.playout_delay() < Duration::from_millis(5));
    }

    #[test]
    fn a_device_that_disappears_is_replaced_by_the_default() {
        let fake = FakeBackend::new();
        let control = fake.control();
        control.add_device(Direction::Input, device("builtin", 48_000, 1, true));
        control.add_device(Direction::Input, device("usb", 48_000, 1, false));
        let mut devices = AudioDevices::new(fake);
        devices.open_input(Some("usb")).unwrap();
        assert!(control.is_open(Direction::Input, "usb"));
        // A hot swap: open another while running; the first closes.
        devices.open_input(Some("builtin")).unwrap();
        assert!(!control.is_open(Direction::Input, "usb"));
        devices.open_input(Some("usb")).unwrap();
        while devices.poll_event().is_some() {}
        control.remove_device(Direction::Input, "usb");
        devices.poll();
        assert_eq!(
            devices.poll_event(),
            Some(DeviceEvent::InputLost("usb".into()))
        );
        assert!(
            matches!(devices.poll_event(), Some(DeviceEvent::InputOpened(d)) if d.id == "builtin")
        );
        assert_eq!(devices.input().map(|d| d.id.as_str()), Some("builtin"));
        assert!(control.capture("builtin", &[0.1; 480]));
        assert!(devices.read_capture().is_some());
        // Asking for a device that is not there fails and keeps the one in use.
        assert_eq!(devices.open_input(Some("gone")), Err(Error::NoDevice));
        assert_eq!(devices.input().map(|d| d.id.as_str()), Some("builtin"));
    }

    #[test]
    fn playout_cannot_build_up_more_than_the_queue_limit() {
        let fake = FakeBackend::new();
        let control = fake.control();
        control.add_device(Direction::Output, device("spk", 48_000, 1, true));
        let mut devices = AudioDevices::new(fake);
        devices.open_output(None).unwrap();
        for _ in 0..100 {
            devices.write_playout(&AudioFrame {
                samples: vec![0.1; 480],
                sample_rate: 48_000,
                channels: 1,
            });
        }
        assert!(devices.playout_delay() <= Duration::from_millis(201));
        let _ = control;
    }
}
