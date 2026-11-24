//! Microphones and speakers through cpal (CoreAudio, WASAPI, ALSA), feature `devices`.
//!
//! Ported from `parolnet-media` (`crates/parolnet-media/src/audio_io.rs`, Brainwires,
//! MIT OR Apache-2.0): the stream-owning thread, the device lookup and the real-time
//! callbacks are that file's, adapted to the [`Backend`] trait (interleaved device samples
//! into the manager's rings, any sample format cpal reports).
//!
//! The callbacks run on the operating system's real-time audio threads. They convert the
//! device's samples to or from `f32`, move them through the ring, and store a few atomics;
//! they never allocate, lock, log or block. A device that disappears is reported by cpal's
//! error callback into an atomic, which [`crate::AudioDevices::poll`] acts on.
//!
//! Opening a device is what asks the system for microphone access (macOS prompts on first
//! use); listing devices does not open any.

use std::str::FromStr as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cpal::traits::{DeviceTrait as _, HostTrait as _, StreamTrait as _};
use cpal::{FromSample, SampleFormat, SizedSample};

use crate::backend::{
    Backend, CaptureSink, DeviceInfo, DeviceStream, Direction, PlayoutSource, StreamShared,
};
use crate::{Error, Result};

/// How long to wait for the device thread to open a stream.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest callback the conversion buffers are prepared for, in samples.
const MAX_CALLBACK: usize = 48_000;

fn device_error(e: cpal::Error) -> Error {
    match e.kind() {
        cpal::ErrorKind::PermissionDenied => Error::PermissionDenied,
        cpal::ErrorKind::DeviceNotAvailable | cpal::ErrorKind::HostUnavailable => Error::NoDevice,
        _ => Error::Device(e.to_string()),
    }
}

/// Whether a stream error ends the stream (a reroute of the default device does not).
fn is_fatal(e: &cpal::Error) -> bool {
    !matches!(
        e.kind(),
        cpal::ErrorKind::DeviceChanged | cpal::ErrorKind::RealtimeDenied
    )
}

/// The system's devices through cpal's default host.
#[derive(Debug, Default)]
pub struct CpalBackend;

impl CpalBackend {
    /// The default host's backend.
    pub fn new() -> Self {
        Self
    }
}

fn describe(
    d: &cpal::Device,
    direction: Direction,
    default_id: Option<&str>,
) -> Option<DeviceInfo> {
    let id = d.id().ok()?.to_string();
    let name = d
        .description()
        .map(|desc| desc.name().to_owned())
        .unwrap_or_else(|_| id.clone());
    let config = match direction {
        Direction::Input => d.default_input_config().ok()?,
        Direction::Output => d.default_output_config().ok()?,
    };
    Some(DeviceInfo {
        is_default: default_id == Some(id.as_str()),
        id,
        name,
        sample_rate: config.sample_rate(),
        channels: config.channels().max(1),
    })
}

fn find(id: Option<&str>, direction: Direction) -> Result<cpal::Device> {
    let host = cpal::default_host();
    let device = match id {
        Some(id) => {
            let id = cpal::DeviceId::from_str(id).map_err(|_| Error::NoDevice)?;
            host.device_by_id(&id)
        }
        None if direction == Direction::Input => host.default_input_device(),
        None => host.default_output_device(),
    };
    device.ok_or(Error::NoDevice)
}

/// A stream kept on a thread of its own until it is dropped: a cpal stream need not be
/// `Send`, and this way the owner is.
struct CpalStream {
    info: DeviceInfo,
    shared: Arc<StreamShared>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DeviceStream for CpalStream {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn shared(&self) -> &Arc<StreamShared> {
        &self.shared
    }
}

impl Drop for CpalStream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            let _ = thread.join();
        }
    }
}

fn own_stream<F>(
    name: &str,
    info: DeviceInfo,
    shared: Arc<StreamShared>,
    build: F,
) -> Result<CpalStream>
where
    F: FnOnce() -> Result<cpal::Stream> + Send + 'static,
{
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<()>>(1);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread = std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let stream = match build().and_then(|s| s.play().map(|()| s).map_err(device_error)) {
                Ok(stream) => {
                    let _ = ready_tx.send(Ok(()));
                    stream
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            while !thread_stop.load(Ordering::Relaxed) {
                std::thread::park_timeout(Duration::from_millis(200));
            }
            drop(stream);
        })
        .map_err(|e| Error::Device(format!("audio thread: {e}")))?;
    let mut owner = CpalStream {
        info,
        shared,
        stop,
        thread: Some(thread),
    };
    match ready_rx.recv_timeout(OPEN_TIMEOUT) {
        Ok(Ok(())) => Ok(owner),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            // Still opening: do not wait for it when the owner drops.
            owner.thread = None;
            Err(Error::Device(
                "the audio device did not open in time".into(),
            ))
        }
    }
}

fn input_stream<T>(
    device: &cpal::Device,
    config: cpal::StreamConfig,
    channels: u16,
    mut sink: CaptureSink,
) -> Result<cpal::Stream>
where
    T: SizedSample,
    f32: FromSample<T>,
{
    let shared = sink.shared().clone();
    let err_shared = shared.clone();
    // Allocated here, before the stream starts; the callback only writes into it.
    let mut scratch = vec![0.0f32; MAX_CALLBACK];
    device
        .build_input_stream::<T, _, _>(
            config,
            move |data: &[T], info: &cpal::InputCallbackInfo| {
                let ts = info.timestamp();
                let latency = ts.callback.duration_since(ts.capture);
                shared
                    .latency_us
                    .store(latency.as_micros().min(1_000_000) as u32, Ordering::Relaxed);
                for chunk in data.chunks(MAX_CALLBACK) {
                    let out = &mut scratch[..chunk.len()];
                    for (o, &s) in out.iter_mut().zip(chunk) {
                        *o = f32::from_sample_(s);
                    }
                    sink.write(out, channels);
                }
            },
            move |e| {
                if is_fatal(&e) {
                    err_shared.fail();
                }
            },
            None,
        )
        .map_err(device_error)
}

fn output_stream<T>(
    device: &cpal::Device,
    config: cpal::StreamConfig,
    channels: u16,
    mut source: PlayoutSource,
) -> Result<cpal::Stream>
where
    T: SizedSample + FromSample<f32>,
{
    let shared = source.shared().clone();
    let err_shared = shared.clone();
    let mut scratch = vec![0.0f32; MAX_CALLBACK];
    device
        .build_output_stream::<T, _, _>(
            config,
            move |data: &mut [T], info: &cpal::OutputCallbackInfo| {
                let ts = info.timestamp();
                let latency = ts.playback.duration_since(ts.callback);
                shared
                    .latency_us
                    .store(latency.as_micros().min(1_000_000) as u32, Ordering::Relaxed);
                for chunk in data.chunks_mut(MAX_CALLBACK) {
                    let buf = &mut scratch[..chunk.len()];
                    source.read(buf, channels);
                    for (o, &s) in chunk.iter_mut().zip(buf.iter()) {
                        *o = T::from_sample_(s);
                    }
                }
            },
            move |e| {
                if is_fatal(&e) {
                    err_shared.fail();
                }
            },
            None,
        )
        .map_err(device_error)
}

impl Backend for CpalBackend {
    fn name(&self) -> &'static str {
        "cpal"
    }

    fn devices(&mut self, direction: Direction) -> Vec<DeviceInfo> {
        let host = cpal::default_host();
        let default = match direction {
            Direction::Input => host.default_input_device(),
            Direction::Output => host.default_output_device(),
        }
        .and_then(|d| d.id().ok())
        .map(|id| id.to_string());
        let devices = match direction {
            Direction::Input => host.input_devices().map(|d| d.collect::<Vec<_>>()),
            Direction::Output => host.output_devices().map(|d| d.collect::<Vec<_>>()),
        };
        devices
            .unwrap_or_default()
            .iter()
            .filter_map(|d| describe(d, direction, default.as_deref()))
            .collect()
    }

    fn probe(&mut self, direction: Direction, id: Option<&str>) -> Result<DeviceInfo> {
        let device = find(id, direction)?;
        describe(&device, direction, None).ok_or(Error::NoDevice)
    }

    fn open_input(&mut self, id: Option<&str>, sink: CaptureSink) -> Result<Box<dyn DeviceStream>> {
        let device = find(id, Direction::Input)?;
        let info = describe(&device, Direction::Input, None).ok_or(Error::NoDevice)?;
        let supported = device.default_input_config().map_err(device_error)?;
        let format = supported.sample_format();
        let config = supported.config();
        let channels = info.channels;
        let shared = sink.shared().clone();
        let stream = own_stream("rtc-capture", info, shared, move || match format {
            SampleFormat::F32 => input_stream::<f32>(&device, config, channels, sink),
            SampleFormat::I16 => input_stream::<i16>(&device, config, channels, sink),
            SampleFormat::U16 => input_stream::<u16>(&device, config, channels, sink),
            SampleFormat::I32 => input_stream::<i32>(&device, config, channels, sink),
            other => Err(Error::Format(format!("microphone sample format {other:?}"))),
        })?;
        Ok(Box::new(stream))
    }

    fn open_output(
        &mut self,
        id: Option<&str>,
        source: PlayoutSource,
    ) -> Result<Box<dyn DeviceStream>> {
        let device = find(id, Direction::Output)?;
        let info = describe(&device, Direction::Output, None).ok_or(Error::NoDevice)?;
        let supported = device.default_output_config().map_err(device_error)?;
        let format = supported.sample_format();
        let config = supported.config();
        let channels = info.channels;
        let shared = source.shared().clone();
        let stream = own_stream("rtc-playout", info, shared, move || match format {
            SampleFormat::F32 => output_stream::<f32>(&device, config, channels, source),
            SampleFormat::I16 => output_stream::<i16>(&device, config, channels, source),
            SampleFormat::U16 => output_stream::<u16>(&device, config, channels, source),
            SampleFormat::I32 => output_stream::<i32>(&device, config, channels, source),
            other => Err(Error::Format(format!("speaker sample format {other:?}"))),
        })?;
        Ok(Box::new(stream))
    }
}
