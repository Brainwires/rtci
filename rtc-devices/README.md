# rtc-devices

Audio capture and playout for the `rtc-audio` pipeline. `AudioDevices` owns one input and one
output stream of a backend and moves audio between them and the pipeline in 10 ms frames of
48 kHz mono: the device callbacks only copy into or out of wait-free rings; channel mixing and
rate conversion run on the application's thread. Devices are listed, chosen by id, switched
while running, and replaced by the system default when they fail or disappear (reported as
`DeviceEvent`s).

| Backend | Feature | |
|---|---|---|
| `fake::FakeBackend` | - | no hardware; tests drive its callbacks |
| `cpal_backend::CpalBackend` | `devices` | CoreAudio, WASAPI, ALSA through cpal |

## Status

Complete for audio. The cpal backend is compile-checked only (no CI machine has audio
hardware); the rest is tested with the fake backend. See
[docs/media-pipeline.md](../docs/media-pipeline.md).

## Use

With default features nothing opens a device or starts a thread. Feature `devices` adds the
cpal backend, which links the system's audio library (on Linux it needs the ALSA development
headers, `libasound2-dev`). `read_capture()` gives frames for `rtc-audio`'s send pipeline,
`write_playout(frame)` takes what its receive pipeline produced, and `playout_delay()` is the
echo canceller's delay hint.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtc`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.
