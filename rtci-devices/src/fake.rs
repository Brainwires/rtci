//! A backend without hardware: the test drives its "device callbacks" by hand, adds and
//! removes devices and makes them fail, so capture, playout, rate conversion, device
//! selection and hot-swapping are exercised deterministically on any machine.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::backend::{
    Backend, CaptureSink, DeviceInfo, DeviceStream, Direction, PlayoutSource, StreamShared,
};
use crate::{Error, Result};

#[derive(Default)]
struct State {
    inputs: Vec<DeviceInfo>,
    outputs: Vec<DeviceInfo>,
    sinks: HashMap<String, CaptureSink>,
    sources: HashMap<String, PlayoutSource>,
    opened: Vec<(Direction, String)>,
}

/// The fake backend (give it to [`crate::AudioDevices`]); [`FakeBackend::control`] drives it.
#[derive(Clone, Default)]
pub struct FakeBackend {
    state: Arc<Mutex<State>>,
}

/// The test's side of a [`FakeBackend`].
#[derive(Clone)]
pub struct FakeControl {
    state: Arc<Mutex<State>>,
}

fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

impl FakeBackend {
    /// A backend with no devices.
    pub fn new() -> Self {
        Self::default()
    }

    /// The control handle.
    pub fn control(&self) -> FakeControl {
        FakeControl {
            state: self.state.clone(),
        }
    }
}

impl FakeControl {
    /// Adds a device.
    pub fn add_device(&self, direction: Direction, info: DeviceInfo) {
        let mut s = lock(&self.state);
        let list = match direction {
            Direction::Input => &mut s.inputs,
            Direction::Output => &mut s.outputs,
        };
        list.retain(|d| d.id != info.id);
        list.push(info);
    }

    /// Removes a device: an open stream on it fails, as an unplugged device's does.
    pub fn remove_device(&self, direction: Direction, id: &str) {
        let mut s = lock(&self.state);
        match direction {
            Direction::Input => {
                s.inputs.retain(|d| d.id != id);
                if let Some(sink) = s.sinks.remove(id) {
                    sink.shared().fail();
                }
            }
            Direction::Output => {
                s.outputs.retain(|d| d.id != id);
                if let Some(source) = s.sources.remove(id) {
                    source.shared().fail();
                }
            }
        }
    }

    /// Runs the capture callback of input `id` with interleaved `samples`. False when the
    /// device is not open.
    pub fn capture(&self, id: &str, samples: &[f32]) -> bool {
        let mut s = lock(&self.state);
        let Some(channels) = s.inputs.iter().find(|d| d.id == id).map(|d| d.channels) else {
            return false;
        };
        match s.sinks.get_mut(id) {
            Some(sink) => {
                sink.write(samples, channels);
                true
            }
            None => false,
        }
    }

    /// Runs the playout callback of output `id` for `frames` sample frames; returns what it
    /// played (interleaved), or `None` when the device is not open.
    pub fn play(&self, id: &str, frames: usize) -> Option<Vec<f32>> {
        let mut s = lock(&self.state);
        let channels = s.outputs.iter().find(|d| d.id == id).map(|d| d.channels)?;
        let source = s.sources.get_mut(id)?;
        let mut out = vec![0.0f32; frames * usize::from(channels)];
        source.read(&mut out, channels);
        Some(out)
    }

    /// Every device opened so far, in order.
    pub fn opened(&self) -> Vec<(Direction, String)> {
        lock(&self.state).opened.clone()
    }

    /// Whether a stream on input or output `id` is open.
    pub fn is_open(&self, direction: Direction, id: &str) -> bool {
        let s = lock(&self.state);
        match direction {
            Direction::Input => s.sinks.contains_key(id),
            Direction::Output => s.sources.contains_key(id),
        }
    }
}

struct FakeStream {
    info: DeviceInfo,
    shared: Arc<StreamShared>,
    direction: Direction,
    state: Arc<Mutex<State>>,
}

impl DeviceStream for FakeStream {
    fn info(&self) -> &DeviceInfo {
        &self.info
    }

    fn shared(&self) -> &Arc<StreamShared> {
        &self.shared
    }
}

impl Drop for FakeStream {
    fn drop(&mut self) {
        let mut s = lock(&self.state);
        match self.direction {
            Direction::Input => {
                if s.sinks
                    .get(&self.info.id)
                    .is_some_and(|k| Arc::ptr_eq(k.shared(), &self.shared))
                {
                    s.sinks.remove(&self.info.id);
                }
            }
            Direction::Output => {
                if s.sources
                    .get(&self.info.id)
                    .is_some_and(|k| Arc::ptr_eq(k.shared(), &self.shared))
                {
                    s.sources.remove(&self.info.id);
                }
            }
        }
    }
}

impl FakeBackend {
    fn pick(&self, direction: Direction, id: Option<&str>) -> Result<DeviceInfo> {
        let s = lock(&self.state);
        let list = match direction {
            Direction::Input => &s.inputs,
            Direction::Output => &s.outputs,
        };
        match id {
            Some(id) => list.iter().find(|d| d.id == id).cloned(),
            None => list.iter().find(|d| d.is_default).or(list.first()).cloned(),
        }
        .ok_or(Error::NoDevice)
    }
}

impl Backend for FakeBackend {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn devices(&mut self, direction: Direction) -> Vec<DeviceInfo> {
        let s = lock(&self.state);
        match direction {
            Direction::Input => s.inputs.clone(),
            Direction::Output => s.outputs.clone(),
        }
    }

    fn probe(&mut self, direction: Direction, id: Option<&str>) -> Result<DeviceInfo> {
        self.pick(direction, id)
    }

    fn open_input(&mut self, id: Option<&str>, sink: CaptureSink) -> Result<Box<dyn DeviceStream>> {
        let info = self.pick(Direction::Input, id)?;
        let shared = sink.shared().clone();
        let mut s = lock(&self.state);
        s.sinks.insert(info.id.clone(), sink);
        s.opened.push((Direction::Input, info.id.clone()));
        drop(s);
        Ok(Box::new(FakeStream {
            info,
            shared,
            direction: Direction::Input,
            state: self.state.clone(),
        }))
    }

    fn open_output(
        &mut self,
        id: Option<&str>,
        source: PlayoutSource,
    ) -> Result<Box<dyn DeviceStream>> {
        let info = self.pick(Direction::Output, id)?;
        let shared = source.shared().clone();
        let mut s = lock(&self.state);
        s.sources.insert(info.id.clone(), source);
        s.opened.push((Direction::Output, info.id.clone()));
        drop(s);
        Ok(Box::new(FakeStream {
            info,
            shared,
            direction: Direction::Output,
            state: self.state.clone(),
        }))
    }
}
