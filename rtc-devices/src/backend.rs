//! What a device backend provides, and the real-time ends of the rings its callbacks use.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use crate::Result;

/// Capture or playout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Microphones and other inputs.
    Input,
    /// Speakers and other outputs.
    Output,
}

/// A device a backend offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The backend's stable identifier (what [`crate::AudioDevices::open_input`] takes).
    pub id: String,
    /// A human-readable name.
    pub name: String,
    /// The rate the device runs at.
    pub sample_rate: u32,
    /// Its channels.
    pub channels: u16,
    /// Whether it is the system's default for its direction.
    pub is_default: bool,
}

/// State shared between a stream's real-time callback and its owner: atomics only.
#[derive(Debug, Default)]
pub struct StreamShared {
    /// The device reported an error that ends the stream (unplugged, revoked).
    pub failed: AtomicBool,
    /// Samples the ring could not take (capture) or did not have (playout).
    pub xruns: AtomicU64,
    /// The device-side latency the last callback reported, in microseconds.
    pub latency_us: AtomicU32,
    /// Sample frames moved by callbacks.
    pub frames: AtomicU64,
}

impl StreamShared {
    /// Marks the stream failed.
    pub fn fail(&self) {
        self.failed.store(true, Ordering::Relaxed);
    }
}

/// The producer end a capture callback writes interleaved device samples into. Real-time
/// safe: no allocation, no lock.
pub struct CaptureSink {
    pub(crate) producer: rtrb::Producer<f32>,
    pub(crate) shared: Arc<StreamShared>,
}

impl CaptureSink {
    /// Pushes interleaved samples; what the ring cannot take is counted as an overrun.
    pub fn write(&mut self, samples: &[f32], channels: u16) {
        let n = samples.len().min(self.producer.slots());
        if let Ok(chunk) = self.producer.write_chunk_uninit(n) {
            chunk.fill_from_iter(samples[..n].iter().copied());
        }
        let lost = samples.len() - n;
        if lost > 0 {
            self.shared.xruns.fetch_add(lost as u64, Ordering::Relaxed);
        }
        self.shared.frames.fetch_add(
            (samples.len() / usize::from(channels.max(1))) as u64,
            Ordering::Relaxed,
        );
    }

    /// The shared state, for the backend's error and latency reports.
    pub fn shared(&self) -> &Arc<StreamShared> {
        &self.shared
    }
}

/// The consumer end a playout callback reads interleaved device samples from. Real-time
/// safe.
pub struct PlayoutSource {
    pub(crate) consumer: rtrb::Consumer<f32>,
    pub(crate) shared: Arc<StreamShared>,
}

impl PlayoutSource {
    /// Fills `out`; what the ring does not have is silence, counted as an underrun.
    pub fn read(&mut self, out: &mut [f32], channels: u16) {
        let n = out.len().min(self.consumer.slots());
        if let Ok(chunk) = self.consumer.read_chunk(n) {
            let (a, b) = chunk.as_slices();
            out[..a.len()].copy_from_slice(a);
            out[a.len()..a.len() + b.len()].copy_from_slice(b);
            chunk.commit_all();
        }
        for v in &mut out[n..] {
            *v = 0.0;
        }
        let missing = out.len() - n;
        if missing > 0 {
            self.shared
                .xruns
                .fetch_add(missing as u64, Ordering::Relaxed);
        }
        self.shared.frames.fetch_add(
            (out.len() / usize::from(channels.max(1))) as u64,
            Ordering::Relaxed,
        );
    }

    /// The shared state.
    pub fn shared(&self) -> &Arc<StreamShared> {
        &self.shared
    }
}

/// An open device stream. Dropping it closes the device.
pub trait DeviceStream: Send {
    /// The device.
    fn info(&self) -> &DeviceInfo;
    /// The shared state of its callback.
    fn shared(&self) -> &Arc<StreamShared>;
    /// The device-side latency the backend reports.
    fn latency(&self) -> Duration {
        Duration::from_micros(u64::from(self.shared().latency_us.load(Ordering::Relaxed)))
    }
}

/// A source of devices: the system's (cpal, feature `devices`) or a fake.
pub trait Backend: Send {
    /// The backend's name.
    fn name(&self) -> &'static str;
    /// The devices of a direction.
    fn devices(&mut self, direction: Direction) -> Vec<DeviceInfo>;
    /// Opens the input `id` (the default for `None`); the callback writes into `sink`.
    fn open_input(&mut self, id: Option<&str>, sink: CaptureSink) -> Result<Box<dyn DeviceStream>>;
    /// Opens the output `id` (the default for `None`); the callback reads from `source`.
    fn open_output(
        &mut self,
        id: Option<&str>,
        source: PlayoutSource,
    ) -> Result<Box<dyn DeviceStream>>;
    /// The configuration a device would open with, without opening it.
    fn probe(&mut self, direction: Direction, id: Option<&str>) -> Result<DeviceInfo>;
}
