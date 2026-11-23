# The media pipeline

The engine (`rtc`) is a transport: it never encodes, decodes, captures or plays out media. A
browser does all of that. This document describes the crates that add it beside the engine,
what each part does, how to use it, and what was measured. Phase one is audio, complete; the
next phases (video) are listed at the end for approval.

The pipeline keeps the engine's rules:

- **Sans-I/O.** Nothing in `rtc-audio` reads a clock, opens a device or starts a thread. The
  caller passes the time in and moves audio in and out in 10 ms frames; every test runs on a
  virtual clock. Devices are a separate crate, `rtc-devices`, and open nothing until asked.
- **Pure Rust by default.** The default features need no system library (the workspace's CI
  installs none). C code is opt-in: `rtc-audio/libopus` (the reference Opus, bundled and built
  with CMake) and `rtc-devices/devices` (cpal, which links ALSA on Linux and CoreAudio /
  WASAPI elsewhere).
- **Usable without the peer connection.** Every part is a plain type: a codec, a jitter
  buffer, a processor, a send pipeline. `rtc-audio::engine` (feature `engine`, on by default)
  is the thin glue to an `RTCRtpSender` / `RTCRtpReceiver`.
- **Measured.** Quality is asserted with numbers (SNR, segmental SNR, ERLE, concealment
  ratio, delay) on synthetic and speech-like signals, never by ear.

## Crates

| Crate | What | Default features | Opt-in |
|---|---|---|---|
| `rtc-audio` | codecs, the receive pipeline (jitter buffer), audio processing, the send pipeline, the engine glue | `opus` (opus-rs), `engine` | `libopus` |
| `rtc-devices` | capture and playout: rings, device manager with hot-swap, rate conversion, a fake backend | none | `devices` (cpal) |

### Dependencies and licences

| Dependency | Version | Licence | Used by | Feature | Pure Rust |
|---|---|---|---|---|---|
| `opus-rs` | 0.1.42 | BSD-3-Clause | `rtc-audio` | `opus` (default) | yes (a port of libopus 1.6; SILK, CELT, hybrid, FEC, DTX, PLC) |
| `opusic-sys` | 0.7.7 | BSD-3-Clause (libopus itself BSD-3-Clause) | `rtc-audio` | `libopus` | no: bundled C, built with CMake |
| `rtc` | workspace | MIT / Apache-2.0 | `rtc-audio` | `engine` (default) | as the engine (ring) |
| `rtrb` | 0.4.1 | MIT OR Apache-2.0 | `rtc-devices` | always | yes |
| `cpal` | 0.18.2 | Apache-2.0 | `rtc-devices` | `devices` | no: links ALSA (Linux), CoreAudio, WASAPI |

`cargo deny --all-features check licenses bans sources` passes with these (no GPL, LGPL, AGPL
or MPL). Every dependency builds on the workspace's MSRV, 1.89.

**Not used, and why.** `sonora` (BSD-3-Clause), the pure-Rust port of libwebrtc's audio
processing module that `parolnet-media` uses for AEC3, NS and AGC2, declares
`rust-version = 1.91`; the workspace's MSRV is 1.89 and its MSRV job checks every feature, so
it cannot be a dependency, even an optional one, until the MSRV is raised. The processing here
is this crate's own (below). The `AudioProcessing` stages sit behind plain types, so a
`sonora` backend can be added as an option once the MSRV allows.

### What was ported, and from where

`parol-social`'s `crates/parolnet-media` (Brainwires, licensed MIT OR Apache-2.0, the same
owner) was read for what exists:

| From `parolnet-media` | Here | How |
|---|---|---|
| `resample.rs`: polyphase Kaiser-windowed sinc resampler | `rtc-audio/src/dsp/resample.rs` | ported unchanged; `MultiResampler` (interleaved channels) added |
| `audio_io.rs`: cpal microphone and speakers, stream-owning thread, real-time-safe callbacks | `rtc-devices/src/cpal_backend.rs` | ported and adapted to the `Backend` trait (interleaved device samples, any sample format) |
| `opus.rs`: opus-rs, 48 kHz mono, 20 ms | `rtc-audio/src/codec/opus.rs` | the same backend, rewritten: mono and stereo, 10 to 60 ms, bitrate, FEC, DTX, PLC, the RFC 7587 parameters |
| `processing.rs`: AEC3 / NS / AGC2 through `sonora` | - | not ported: `sonora` needs Rust 1.91 (above) |

Written here: G.711, G.722, the Opus packet reader (TOC, frame offsets, the LBRR flag), the
RFC 7587 parameter mapping, the jitter buffer and its concealment, time-stretching, comfort
noise, DTMF, the echo canceller, the delay estimator, the suppressor, the gain control, the
voice activity detector, the send pipeline, the engine glue, the device manager and the fake
backend.

## How the parts fit

```text
 capture (any rate, mono/stereo)                                   playout (any device)
        │  rtc-devices: ring → 48 kHz mono 10 ms                          ▲  rtc-devices: 48 kHz → device rate → ring
        ▼                                                                 │
 ┌──────────────── SendPipeline ────────────────┐         ┌──────────── JitterBuffer ─────────────┐
 │ AudioProcessing: HPF → AEC → suppressor      │         │ packet buffer (timestamp order, dups,  │
 │   (residual echo + noise) → VAD → AGC        │◀─render─│   late, RED blocks) + delay estimate   │
 │ level (RFC 6464, W3C source stats)           │         │ decode / FEC / PLC / DTX & CN /        │
 │ → codec rate → encoder (Opus/G.711/G.722)    │         │   accelerate / preemptive expand       │
 │ bitrate ← target_bitrates − overhead         │         │ → output rate, W3C inbound stats       │
 │ FEC ← RTCP loss, DTX / RFC 3389 CN           │         └──────────────────▲────────────────────┘
 └──────────────┬───────────────────────────────┘                            │
                ▼ engine::AudioSender                                       │ engine::AudioReceiver
   packetizer (OpusPayloader / G7xx / CN), RED,                RTP from poll_read (RTCMessage::RtpPacket),
   write_rtp_with_audio_level                                  update_audio_receiver_stats, jitterBufferTarget
                └──────────────► RTCPeerConnection ═══ network ═══ RTCPeerConnection ─────┘
```

## Codecs (`rtc_audio::codec`)

| Codec | Type | Rate / clock | Notes |
|---|---|---|---|
| Opus | `opus::OpusEncoder` / `OpusDecoder` | 48 kHz / 48 kHz | opus-rs; 10/20/40/60 ms; VBR or CBR; in-band FEC (`decode_fec`), DTX, PLC; mono or stereo |
| Opus (C) | `libopus::LibOpusEncoder` / `LibOpusDecoder` | 48 kHz | feature `libopus`; the same traits |
| PCMU / PCMA | `g711::G711Encoder` / `G711Decoder` | 8 kHz | ITU-T G.711; the pipeline conceals for it |
| G.722 | `g722::G722Encoder` / `G722Decoder` | 16 kHz / 8 kHz clock | ITU-T G.722 mode 1 (64 kbit/s); the pipeline conceals for it |

All implement `AudioEncoder` / `AudioDecoder`; the pipeline needs nothing else of a codec.

**RFC 7587 parameters** (`codec::fmtp`). `OpusFmtp` parses and writes every parameter
(`maxplaybackrate`, `sprop-maxcapturerate`, `maxptime`, `ptime`, `minptime`,
`maxaveragebitrate`, `stereo`, `sprop-stereo`, `cbr`, `useinbandfec`, `usedtx`; a
`maxaveragebitrate` outside 6000..510000 is ignored, unknown names are ignored).
`OpusEncoderConfig::for_remote(remote_fmtp, a=ptime, a=maxptime, capture_channels)` sets the
encoder from what the *receiver* stated, both ways:

- what this side receives is the fmtp line registered in the `MediaEngine` (the engine's
  default is `minptime=10;useinbandfec=1`, `OpusFmtp::webrtc_default()`);
- what this side sends follows the remote line, which the engine's negotiated codec carries
  after the answer: stereo only when the receiver said `stereo=1` and the capture is stereo,
  no wider than its `maxplaybackrate`, no more than its `maxaveragebitrate`, CBR, FEC and DTX
  as it asked, and its `a=ptime` (rounded down to a duration Opus codes, at most its
  `a=maxptime`; the engine exposes them as `RTCRtpTransceiver::remote_packet_time`).

**RED** (RFC 2198). The receive pipeline opens RED packets and files every block, so a
redundant copy stands in for a lost primary; `AudioSender` wraps packets in RED (one
redundant copy) when `audio/red` was negotiated and `AudioSenderOptions::red` is set. Neither
the engine's nor browsers' default codec lists offer `audio/red` today; an application
registers it (`red/48000/2`, fmtp `111/111`).

**Telephone events** (RFC 4733). Sending is the engine's `RTCRtpSender::dtmf()`
(`insertDTMF`), which numbers its event packets in the audio stream; the receive pipeline
takes event packets out of the stream (never into a decoder, RFC 7874 section 3) and reports
them as `ReceiveEvent::TelephoneEvent`. `dsp::dtmf` generates and detects (Goertzel) in-band
DTMF tones for gateways to legacy audio.

## The receive pipeline (`rtc_audio::jitter::JitterBuffer`)

libwebrtc's NetEq equivalent. `insert(arrival, header, payload)` for every packet, `pull(now)`
for every 10 ms of playout.

- **Packet buffer**: filed by unwrapped RTP timestamp; reordered packets fall into place, a
  second copy of a timestamp is dropped (`packets_duplicated`), a packet older than the
  playout position is dropped as late (`packets_late`, W3C `packetsDiscarded`). Overflow (200
  packets) flushes to the newest.
- **Delay**: the relative arrival delay of each packet against the fastest of the last two
  seconds, in a histogram with forgetting (0.9993 per packet in steady state), and its 95th
  percentile, plus one packet: the network estimate (`jitterBufferMinimumDelay`). The target
  (`jitterBufferTargetDelay`) is that estimate, or the application's `jitterBufferTarget`
  when it set one (W3C: "a target"; it may be below the estimate, at the risk of
  concealment), clamped to the minimum and maximum allowed targets
  (`JitterBufferConfig::min_delay`, never below one packet, and `max_delay`, 2 s).
  `AudioReceiver::update_stats` follows `RTCRtpReceiver::jitter_buffer_target`.
- **Playout** starts (and restarts after DTX) when the buffer holds the target delay of
  audio or the first packet has waited that long.
- **Every 10 ms**: decode the packet at the playout position; when it is missing and the next
  packet carries in-band FEC for exactly the gap (Opus LBRR, found by reading the first range-
  coded bits of the packet, `opus_packet::has_lbrr`), decode it from there; otherwise conceal:
  the codec's PLC (Opus), or the generic one (G.711 Appendix I style: the last pitch period
  repeated, full level for 10 ms, 20 % less per 10 ms, silent after 60 ms, cross-faded back).
  With nothing buffered the playout position holds still (a late packet still plays); with
  a later packet buffered, concealment covers the gap up to it.
- **Time-stretching**: the buffer level, filtered (time constant 0.5 s), is compared with the
  target: above `max(target, low + 20 ms)` one pitch period is removed (accelerate), below
  `low = max(3/4 target, target - 85 ms)` one is inserted (preemptive expand), by cross-fading
  whole periods found by normalised autocorrelation (2.5 to 15 ms lags, correlation above 0.9,
  or any lag in quiet audio). This is also the clock-drift compensation: a fast sender fills
  the buffer, a slow one drains it.
- **DTX and comfort noise**: after an Opus DTX packet (the TOC byte alone) the decoder's
  comfort noise plays until speech resumes; after an RFC 3389 SID the comfort noise generator
  does, with the SID's level and spectrum (reflection coefficients through an all-pole
  lattice). Neither counts as concealment.
- **Statistics** (`ReceiveStats`, webrtc-stats `RTCInboundRtpStreamStats`):
  `totalSamplesReceived`, `concealedSamples`, `silentConcealedSamples` (below -60 dBFS),
  `concealmentEvents`, `insertedSamplesForDeceleration`, `removedSamplesForAcceleration`,
  `jitterBufferDelay` (for each emitted sample, its packet's arrival to its playout),
  `jitterBufferTargetDelay`, `jitterBufferMinimumDelay`, `jitterBufferEmittedCount`,
  `audioLevel` (peak of the last 100 ms), `totalAudioEnergy` (sum of `x^2 / rate`),
  `totalSamplesDuration`, and the in-band FEC counts. `AudioReceiver::update_stats` hands
  them to `RTCPeerConnection::update_audio_receiver_stats`, so `getStats()` reports them.

## Processing (`rtc_audio::processing::AudioProcessing`)

10 ms frames of 48 kHz mono; `process_render` for what is about to be played,
`process_capture` for what the microphone recorded. Each stage is switched on its own
(`ProcessingConfig`); the order is libwebrtc's.

| Stage | What |
|---|---|
| High-pass | fourth-order Butterworth at 80 Hz |
| Delay estimation | 4 kHz decimated render and capture, the cross-correlation over 0 to 500 ms with forgetting, its peak once it stands out (6x the mean) for four frames |
| Echo canceller | partitioned-block frequency-domain adaptive filter (overlap-save, constrained gradient, per-bin NLMS normalisation): 10 ms blocks, FFT 1024, 13 partitions = 130 ms of tail after the bulk delay; a background filter adapts every block and the foreground filter, which produces the output, takes its coefficients only when they cancel better (so double talk cannot drive the output filter off) |
| Suppressor | one STFT (20 ms sqrt-Hann windows, 10 ms hop) for the residual echo (`leak * |Y|^2` per bin, `leak` tracked while only the far end talks) and stationary noise (minimum-tracking noise estimate, decision-directed Wiener gain, floor by level: 6, 12, 18 or 21 dB) |
| Voice activity | 10 ms frame energy against a tracked noise floor, 9 dB margin, 200 ms hangover; drives the RFC 6464 V flag, DTX for G.711 / G.722 and the gain control |
| Gain control | adaptive digital gain to RFC 7874's -19 dBm0 (-22 dBFS RMS) on speech only, +6 dB/s up, -30 dB/s down, -10..+30 dB, limiter at -1 dBFS |

`stats()` gives `echoReturnLoss`, `echoReturnLossEnhancement` (for
`update_audio_source_stats`), the delay found and the gain.

## The send pipeline (`rtc_audio::send::SendPipeline`)

Capture at any rate and channel count → 48 kHz → processing (mono; stereo sending bypasses
it, RFC 7874 section 4) → level and voice flag → codec rate → encoder → `SendOutput::Packet`
(payload, RTP duration, RFC 6464 level, V flag) or `SendOutput::Skip` (DTX: the packetizer
skips the time and the next packet starts a talkspurt).

- **Bitrate**: `set_target_bitrate(allocated)` takes the sender's share of the congestion
  controller's target (`RTCRtpSender::target_bitrates`), subtracts the packets' own overhead
  (58 bytes a packet by default: RTP, SRTP tag, UDP, IPv4, extensions) and clamps to 6 kbit/s
  .. `maxaveragebitrate`.
- **FEC**: `on_packet_loss(fraction)` (RTCP reception reports, smoothed) turns Opus in-band
  FEC on above 1 % and off below 0.5 %, only when the receiver said `useinbandfec=1`, and tells
  the encoder the loss rate.
- **DTX**: Opus DTX packets after the first are skipped (libwebrtc's rule); G.711 / G.722
  send an RFC 3389 SID at the start of silence and every 100 ms, when CN was negotiated.

`engine::AudioSender` packetizes with the engine's payloaders (`OpusPayloader`,
`G7xxPayloader`; CN packets get the CN payload type and no marker), wraps in RED when asked,
and writes with `write_rtp_with_audio_level`.

## Devices (`rtc-devices`)

`AudioDevices<B: Backend>`: one input and one output. Device callbacks only copy into or out
of a wait-free SPSC ring (`rtrb`) and set atomics. `read_capture()` returns 10 ms frames of 48
kHz mono (channel mixing and resampling on the caller's thread), `write_playout(frame)`
converts to the device's rate and channels (and drops what would queue past 200 ms).
`open_input(id)` / `open_output(id)` select a device and hot-swap a running one (the new one
opens before the old one closes); `poll()` replaces a device that failed or disappeared with
the system default and reports `DeviceEvent`s; `playout_delay()` is the echo canceller's
delay hint. Backends: `fake::FakeBackend` (tests drive its callbacks, add and remove devices)
and `cpal_backend::CpalBackend` (feature `devices`).

## How to use it

```rust,ignore
use rtc_audio::engine::{AudioReceiver, AudioSender, AudioSenderOptions, OpusBackend};
use rtc_audio::jitter::JitterBufferConfig;

// After negotiation (the remote answer applied):
let mut sender = AudioSender::new(&mut pc, sender_id, now, AudioSenderOptions::default())?;
// On RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) for audio:
let mut receiver = AudioReceiver::new(&mut pc, init.receiver_id, JitterBufferConfig::default(), 1, OpusBackend::Rust)?;

// Every 10 ms on the audio thread:
sender.push_capture(&mut pc, now, &mic_frame)?;          // processing, encode, packetize, write_rtp
let played = receiver.pull(now);                          // 10 ms of decoded audio
sender.push_render(&played);                              // the echo canceller's reference
// Now and then:
sender.update_bitrate(&mut pc);                           // follow the congestion controller
receiver.update_stats(&mut pc);                           // getStats() and jitterBufferTarget
sender.update_stats(&mut pc);

// For each message from pc.poll_read():
//   RTCMessage::RtpPacket(track, packet) if track == *receiver.track_id() => receiver.handle_rtp(now, &packet)
//   RTCMessage::RtcpPacket(_, packets) => sender.handle_rtcp(&packets)   // loss → FEC
```

`rtc-audio/examples/audio-loopback.rs` is all of it in one headless program (WAV or synthetic
speech in, WAV and Ogg out, two peer connections over a lossy link in virtual time); the test
environment's env stage runs it and decodes its Ogg output with GStreamer.

## Measured quality

MEASUREMENTS

## What runs where

| What | Where |
|---|---|
| Unit tests of every module (codecs, DSP, jitter buffer, processing, send pipeline, devices with the fake backend) | `cargo test -p rtc-audio -p rtc-devices`: GitHub CI (Linux, macOS, Windows), the test environment's unit stage |
| rtc to rtc through the whole pipeline at 0 / 2 / 5 / 10 / 20 % loss (`rtc-audio/tests/pipeline_rtc2rtc.rs`) | the same |
| libopus comparison (`codec::libopus` tests) | `cargo test -p rtc-audio --features libopus` (needs CMake) |
| The headless example, its Ogg output decoded by GStreamer | the test environment's env stage |
| Browser decodes our Opus, we decode the browser's (`audio pipeline` cell of `webrtc.spec.mjs`) | the test environment's interop stage (Chromium, Firefox, WebKit) |
| cpal backend | compile-checked only (macOS here; Linux in the MSRV job, which installs libasound2-dev); no CI machine has audio hardware |

## Not done in phase one

NOTDONE

## Next phases (for approval)

1. **Video codecs** (`rtc-video`): VP8 and VP9 through an opt-in libvpx binding (libvpx
   BSD-3-Clause; the binding written here, as `parolnet-media`'s, or `vpx-sys` if its licence
   checks out); AV1 encode with `rav1e` (BSD-2-Clause, pure Rust) and decode with a permissive
   decoder (`dav1d` through `dav1d-rs`, BSD-2-Clause, C and assembly, opt-in; a pure-Rust AV1
   decoder of adequate speed does not exist yet); H.264 through an opt-in permissive binding
   (OpenH264, BSD-2-Clause, through a binding of permissive licence; the codec's patents are
   the user's question, as in browsers). Default features stay pure Rust: AV1 encode only.
2. **The video receive pipeline**: frame assembly from the depacketizers, a frame buffer with
   dependency tracking (the existing Dependency Descriptor and the VP8 / VP9 descriptors),
   decodability and key-frame requests (`RTCRtpReceiver::send_key_frame_request`) on
   undecodable frames, render timing, `report_received_frame` and `DecoderStatsUpdate`
   (framesDecoded, freezes, pauses, totalDecodeTime, ...).
3. **A/V synchronisation**: audio and video playout aligned on the RTCP sender reports' NTP /
   RTP mapping (the engine's existing RTCP timing and rapid synchronisation, RFC 6051).
4. **Encoder rate control, simulcast and SVC**: encoders driven by `target_bitrates()` per
   encoding, `send_resolution` and the key-frame request event, simulcast encoders per RID,
   SVC encoders for the scalability modes the engine already signals, quality-limitation
   statistics.
5. **Camera and screen capture** (`rtc-devices`, opt-in features): camera through a permissive
   backend (`nokhwa`, Apache-2.0, as `parolnet-media` uses), screen capture per platform;
   pixel-format conversion to I420 (`yuv`, MIT / Apache-2.0).
6. **Hardware acceleration**: VideoToolbox, Media Foundation, VA-API encoders and decoders
   behind opt-in features.
