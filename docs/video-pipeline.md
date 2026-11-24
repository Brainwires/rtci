# The video pipeline: design

The engine (`rtc`) carries video; it never captures, encodes, decodes or renders it. This
document designs the crates that do that beside the engine, as `docs/media-pipeline.md` did
for audio, and fixes the phases in which they are built. It is measured against libwebrtc
(Chrome's stack): every behaviour that libwebrtc has is either built, or listed here with the
reason it is not.

Rules carried over from the audio pipeline and the engine:

- **Sans-I/O.** No pipeline type reads a clock, opens a device or starts a thread. The caller
  passes `now` in. Capture and hardware backends are opt-in features that open what the
  application asks for and nothing else.
- **Pure Rust by default.** Default features need no system library and no C or assembly
  toolchain (the workspace's CI installs none). Anything else is opt-in, named after what it
  links.
- **Licences**: permissive only (`deny.toml`: MIT, Apache-2.0, BSD-2/3, ISC, Zlib, ...; no
  GPL, LGPL, AGPL, MPL). MSRV 1.89.
- **Spec first, libwebrtc as a profile.** Where an RFC or a W3C document defines the
  behaviour, the default follows it; where libwebrtc chooses differently, its choice is a
  `BehaviourProfile::Chrome` setting (`docs/behaviour-profiles.md`).
- **Measured.** Each phase states acceptance figures, asserts them in tests that run in
  virtual time with fixed seeds, and mutation-checks the assertions.

References: libwebrtc sources at `a222406d49ecffb8e045d113e45f89f62b3819e8` (2026-11-23),
cited as `file:line @ a222406d`; RFC and W3C texts as in the conformance work
(`specs/`). Engine references are to this repository at `2cdbe502`.

---

## 1. Inventory

### 1.1 What the engine already provides for video

| Area | Where | What it gives the pipeline |
|---|---|---|
| Payload formats | `rtc-rtp/src/codec/{vp8,vp9,av1,h264,h265}` | packetizers and depacketizers; `Vp8Packet` (PictureID with its width, TL0PICIDX, TID, Y, KEYIDX, N, S, PID), `Vp9Packet` (I, P, L, F, B, E, V, Z, PictureID, TID, U, SID, D, P_DIFF, the scalability structure with its GOF), `Av1Depacketizer` (OBU aggregation, Z / Y / N bits), `H264Packet` (RFC 6184 single NAL, STAP-A, FU-A, packetization modes, interleaved), `H265Packet` (RFC 7798) |
| Dependency Descriptor | `rtc-rtp/src/codec/dependency_descriptor/` | `DependencyDescriptor` (frame number, template, DTIs, fdiffs, chains, attached structure, active decode targets), `DependencyDescriptorReader` (keeps the structure across packets), `DependencyDescriptorWriter`, `DecodeTargetSelector` with chain integrity |
| SVC / simulcast signalling | `rtc-rtp/src/codec/svc/`, `RTCRtpSender::set_configured_scalability_mode` | the webrtc-svc mode table, `ScalabilityPattern` (per-picture layer frames with their dependencies, VP8 / VP9 info, the DD structure and the VP9 scalability structure for a mode); RID simulcast in SDP (RFC 8853), `send_restrictions` (rid restrictions, `max-fr` / `max-fs` / `max-mbps` / `max-br`, `b=TIAS`), `send_resolution` (`a=imageattr`) |
| Containers | `rtc-media/src/io/{ivf_reader,ivf_writer,h26x_reader,h26x_writer,sample_builder}` | IVF and Annex B readers and writers; `SampleBuilder` (the upstream frame assembler the capacity test uses) |
| Retransmission | `rtc-interceptor/src/nack/` (generator and responder), `src/peer_connection/handler/endpoint.rs` | NACK generation (RFC 4585) with reordering allowance, round-trip spacing, optional age and count limits; RTX (RFC 4588) answered by the responder, and an RTX packet reaches the application as the original packet it carries (`interceptor_rtx_test.rs::the_chain_sees_the_original_packet_an_rtx_packet_carries`) |
| FEC | `rtc-interceptor/src/{flexfec,ulpfec}` | FlexFEC (draft-03 and RFC 8627) and ULPFEC (RFC 5109) encoders and decoders; not in the default interceptors (`tests/default_codecs_omit_ulpfec.rs`) |
| Key-frame requests | `rtc-interceptor/src/keyframe.rs`, `src/peer_connection/event/mod.rs` (`OnKeyFrameRequest`), `RTCRtpReceiver::send_key_frame_request` (FIR), `RTCRtpReceiver::write_rtcp` | inbound PLI / FIR reach the application, and a sender gets `OnKeyFrameRequest { sender, rid }`; a receiver can send FIR (webrtc-encoded-transform) and any RTCP (PLI) |
| Congestion control | `rtc-interceptor/src/{gcc,twcc,rfc8888,cc,pacing}` | GCC on transport-cc or RFC 8888, probing, the pacer, TMMBR, REMB; `RTCRtpSender::target_bitrates()` is the share of the target per encoding (W3C webrtc-priority split, capped at `maxBitrate`) |
| Header extensions | `rtc-rtp/src/extension/` | `playout_delay_extension`, `abs_capture_time_extension`, `video_orientation_extension`, `transport_cc_extension`, `abs_send_time_extension`, `corruption_detection_extension`, `sdes` (MID, RID, repaired RID) |
| Frame metadata | `src/rtp_transceiver/rtp_receiver/frame_metadata.rs` | `RTCRtpReceiver::encoded_frame_metadata(packets)`: receive time, capture time (abs-capture-time, or from the sender reports), the DD frame id and dependencies, frame type, size, layer indices |
| Receiver track | `RTCRtpReceiver::report_received_frame(now, w, h)`, `jitter_buffer_target()` | track settings (size, aspect, frame rate) and the W3C `jitterBufferTarget` |
| SFrame | `rtc-sframe`, `encoded_transform_sframe_rtc2rtc.rs` | per-frame end-to-end encryption |
| Statistics | `src/statistics/feed.rs`, `accumulator/media/app_provided.rs` | `update_decoder_stats(ssrc, DecoderStatsUpdate)` (framesReceived, framesDecoded, keyFramesDecoded, framesRendered, framesDropped, frameWidth / Height, framesPerSecond, qpSum, totalDecodeTime, totalInterFrameDelay, totalSquaredInterFrameDelay, totalProcessingDelay, pauseCount, totalPausesDuration, freezeCount, totalFreezesDuration, packetsDiscarded, totalAssemblyTime, framesAssembledFromMultiplePackets, decoderImplementation, corruption measurements); `update_encoder_stats`; `update_video_source_stats`. The engine itself counts packets, bytes, NACK, PLI and FIR counts, RTX and FEC packets |

What none of this does: assemble frames that survive loss and reordering correctly per codec,
track decodability, time playout, decide when a picture is lost, decode, render, capture,
scale, encode, allocate bitrate across layers, or adapt quality.

### 1.2 What a complete receiver needs beyond the engine

1. **Packet buffer and frame assembly** per codec: sequence-ordered storage with wrap-safe
   unwrapping, duplicate removal, growth to a cap, frame boundaries from the marker bit and
   the codec's partition head (VP8 S=1 and PID=0, VP9 B / E, AV1 Z / Y and the DD
   start / end of frame, H.264 / H.265 first NAL of an access unit), key-frame detection per
   codec, padding-only packets (bandwidth probes) closing sequence gaps.
2. **Frame reference finder**: frame ids and references from the codec descriptors: VP8
   (PictureID, TL0PICIDX, TID, Y), VP9 (flexible P_DIFF, non-flexible GOF, inter-layer), the
   Dependency Descriptor (AV1 and any codec that carries it), and sequence-number continuity
   for streams with none of these (H.264, H.265, VP8 without PictureID).
3. **Frame buffer**: continuity and decodability, the next decodable temporal unit, drop of
   stale or undecodable frames, a bound on what is held.
4. **Playout timing**: inter-frame delay variation and a jitter estimate, the mapping from
   RTP time to local time, render time, `playout-delay`, `jitterBufferTarget`, a minimum
   delay from A/V synchronisation, decode-time estimate, render delay.
5. **Key-frame request policy**: PLI when the chain is broken (first frame not a key frame,
   packet buffer overflow, NACK list overflow, no decodable frame within the wait, decoder
   error), repeated at a bounded rate until a key frame arrives.
6. **The boundary with the NACK generator**: the generator asks for packets that the
   pipeline no longer needs unless it is told (section 2.6).
7. **Decoder abstraction**, a decode queue, frame dropping under decode overload.
8. **Render statistics**: freezes, pauses, inter-frame delay, frames rendered.
9. **A/V synchronisation** with `rtc-audio`'s jitter buffer.

### 1.3 What a complete sender needs beyond the engine

1. **Capture abstraction**: camera, screen, synthetic sources; a timestamped frame type
   (I420 / NV12 / RGB), rotation, colour space.
2. **Frame cadence**: zero-hertz screen content (repeat the last frame at a low rate so the
   receiver converges), frame rate limits from `maxFramerate` and `max-fr`.
3. **Scaling, cropping, pixel-format conversion** to the encoder's input, per simulcast
   layer, with the aspect ratio of the source.
4. **Encoder abstraction**: rate control (`set_rates` per layer), key-frame requests per
   layer, temporal and spatial layers, simulcast, screen-content mode, QP reporting, encoder
   information (QP thresholds for the quality scaler, resolution alignment).
5. **Bitrate allocation** from the congestion target: across simulcast streams and across
   temporal / spatial layers; encoder bitrate adjustment for over- and under-shoot.
6. **Quality scaler and degradation preference**: resolution vs frame rate under bandwidth
   and CPU limits; `qualityLimitationReason` and its durations.
7. **FEC / RTX budget**: the share of the target spent on protection.
8. **RTP timestamping and packetization hand-off**: the 90 kHz clock from the capture time,
   the Dependency Descriptor and codec descriptors, `abs-capture-time`, video orientation.
9. **CPU overuse adaptation**: encode time against the frame interval.
10. **Encoder statistics**: `framesEncoded`, `keyFramesEncoded`, `qpSum`, `totalEncodeTime`,
    `qualityLimitation*`, `encoderImplementation`, `scalabilityMode`, PSNR.

---

## 2. Receive side: element by element

Each element: what libwebrtc does, what the specifications require, what this project does.

### 2.1 Packet buffer and frame assembly

**libwebrtc.** `modules/video_coding/packet_buffer.cc @ a222406d` keeps packets in a ring
indexed by sequence number. It starts at 512 entries and grows to 2048
(`video/rtp_video_stream_receiver2.cc:110-111`, `kPacketBufferStartSize = 512`,
`kPacketBufferMaxSize = 2048`). A duplicate is dropped (`packet_buffer.cc:92-96`); when the
slot is taken by another packet and the buffer cannot grow, it clears itself and returns
`buffer_cleared` (`:105-113`), on which the receiver requests a key frame
(`rtp_video_stream_receiver2.cc:1054-1058`). A backward jump of half the buffer clears it
(`packet_buffer.cc:82-89`). `FindFrames` (`:237`) walks forward from a packet that may
complete a frame back to a `is_first_packet_in_frame` packet with no gap. For H.264 an
access unit is a key frame when it has an IDR (or SPS + PPS + IDR when
`sps_pps_idr_is_h264_keyframe_` is set, `:311-313`, false by default `:54`). Padding older
than 1000 sequence numbers is forgotten (`:415`).

**Specifications.** RFC 3550 A.1 (sequence-number extension), the payload formats: RFC 7741
4.2 (VP8 S and PID: "the first packet of a frame"), RFC 9628 (VP9 B and E bits), the AV1 RTP
specification 4.4 (Z, Y, N) and appendix A (`start_of_frame`, `end_of_frame`), RFC 6184 5.1
(the marker bit "set for the very last packet of the access unit") and RFC 7798. They define
the boundaries; buffering policy is left to the receiver.

**This project.** `rtc_video::assembly::PacketBuffer`, one per SSRC (RTX already folded back
by the engine): unwrapped sequence numbers (`i64`), a `BTreeMap` window instead of a ring
(same complexity for the sizes involved, no aliasing), capacity 2048 packets by default
(libwebrtc's maximum; configurable), duplicate drop counted, overflow and large backward
jumps clear the buffer and raise `KeyFrameNeeded::BufferCleared`. Boundaries and key frames
come from a per-codec `PayloadReader` built on the engine's depacketizers, so the bitstream
handed to the decoder is the depacketizer's output (VP8 / VP9 / AV1 payload without the
descriptor, H.264 / H.265 as Annex B). Each frame records first and last arrival (W3C
`totalAssemblyTime`), packet count, whether any packet was a retransmission (the engine marks
RTX-repaired packets; section 2.6), and padding fills sequence gaps.

### 2.2 Frame reference finder

**libwebrtc.** `modules/video_coding/rtp_frame_reference_finder.cc:62-115 @ a222406d`
dispatches on what the packets carry: a generic descriptor (the Dependency Descriptor) wins
(`:66-69`, `RtpGenericFrameRefFinder`, references = frame id minus each fdiff); VP8 with TID
and TL0PICIDX uses `RtpVp8RefFinder`, VP8 with a PictureID only `RtpFrameIdOnlyRefFinder`,
without one `RtpSeqNumOnlyRefFinder` (`:72-86`); VP9 likewise with `RtpVp9RefFinder`
(`:88-101`); every other codec (H.264, H.265) uses sequence numbers only (`:111-114`). The VP8
and VP9 finders stash frames whose references are not known yet (100 frames,
`rtp_vp8_ref_finder.h:42`, `rtp_vp9_ref_finder.h:43`), keep 50 GOF structures for VP9
(`rtp_vp9_ref_finder.h:40`) and use 15-bit unwrapped picture ids (`kFrameIdLength = 1 << 15`).

**Specifications.** RFC 7741 4.2 (PictureID; TL0PICIDX "a running index for the temporal base
layer frames"; TID; Y "layer sync": the frame depends only on the base layer), RFC 9628 4.2
(flexible mode P_DIFF; non-flexible mode with the scalability structure's GOF), AV1 RTP
specification appendix A (frame_number, fdiffs: "the frame dependencies"). The payload
formats make the references explicit; nothing is left to policy except what to do with a
frame whose references are unknown.

**This project.** `rtc_video::reference::ReferenceFinder`, an enum over the same five
finders with libwebrtc's dispatch, written from the RFCs; frame ids unwrapped to `i64`
(picture ids per their width, which RFC 7741 4.2 lets change mid-session: the engine's
`picture_id_15_bits`), the DD frame number to `i64`. Stash limits as libwebrtc's. A finder
that sees a key frame starts afresh. For sequence-number-only streams a delta frame refers to
the last frame of an unbroken sequence; a gap that padding does not explain leaves it waiting
(and ends in a key-frame request, section 2.5).

### 2.3 Frame buffer

**libwebrtc.** `api/video/frame_buffer.cc @ a222406d`. `InsertFrame` (`:76-126`) refuses
frames with invalid references and frames at or before the last decoded id (a newer key
frame clears instead, `:84-96`), clears on a key frame into a full buffer (`:98-107`); the
buffer holds 800 frames and remembers 8192 decoded ids
(`video/video_stream_buffer_controller.cc:46-48`). `FindNextAndLastDecodableTemporalUnit`
(`frame_buffer.cc:225-...`) finds the first temporal unit (frames of one RTP timestamp)
whose references were all decoded or lie inside the unit. Frames passed over are dropped
and counted (`DropNextDecodableTemporalUnit`, `:145`).

**Specifications.** W3C webrtc-stats: `framesDropped` "dropped prior to decode or dropped
because the frame missed its display deadline"; `framesReceived` "complete frames received";
`packetsDiscarded` "discarded by the jitter buffer due to late or early-arrival".

**This project.** `rtc_video::buffer::FrameBuffer` with the same rules and limits; a temporal
unit is what is handed out (all spatial layers of one picture); every frame that leaves the
buffer undecoded is counted in `framesDropped`, its packets in `packetsDiscarded`.

### 2.4 Playout timing

**libwebrtc.**

- *Jitter estimate*: `video/timing/jitter_estimator.cc @ a222406d`, a Kalman filter on frame
  delay variation against frame size (`frame_delay_variation_kalman_filter.cc`), a noise
  variance with outlier rejection (15 standard deviations for delay, 3 for size,
  `:52-55`), the estimate `size slope * (max size - avg size) + max(2.33 * sigma - 30 ms, 1 ms)`
  (`:390-430`), plus 10 ms of "operating system jitter" (`:73`), plus `min(0.9 * RTT, 200 ms)`
  after 3 NACKed frames in 60 s (`:76-81`), scaled to zero below 5 fps and linearly up to
  10 fps (`:452-466`). The inter-frame delay variation is
  `inter_frame_delay_variation_calculator.cc`; RTP time maps to local time through
  `timestamp_extrapolator.cc` (a recursive least squares fit). Retransmitted frames do not
  update it (`video/timing/default_video_jitter_timing.cc:54-58`).
- *Delays*: `modules/video_coding/timing/timing.cc @ a222406d`. Target delay =
  `max(min_playout_delay, minimum_delay + estimated_max_decode_time + render_delay)` (`:66-69`,
  render delay 10 ms, `timing.h`), the decode time the 95th percentile of recent decode times
  (`decode_time_percentile_filter.cc`). The current delay rises towards the target as frames
  are late (`UpdateCurrentDelay`, `:163-178`). Render time = local time of the RTP timestamp +
  `clamp(current_delay, min_playout_delay, max_playout_delay)` (`RenderTime`, `:197-...`);
  with `min_playout_delay` 0 and `max_playout_delay` at most 500 ms the frame is rendered at
  once (low-latency rendering, `:37-38`, `:76-79`).
- *Scheduling*: `video/frame_decode_timing.cc @ a222406d`: a frame whose render time is more
  than 5 ms past (`frame_decode_timing.h:34`, `kMaxAllowedFrameDelay`) is skipped when a
  later one is decodable; low-latency frames are paced 8 ms apart (`:35`) unless more than 8
  are queued (`video_stream_buffer_controller.cc:54`). A render time more than 10 s off resets
  the timing (`modules/video_coding/frame_helpers.cc:32-60`).
- *jitterBufferDelay*: first packet received to the decodable frame released
  (`video_stream_buffer_controller.cc:338-350`).

**Specifications.** W3C webrtc-stats `jitterBufferDelay`: "from the time the first packet is
received by the jitter buffer (ingest timestamp) to the time it exits the jitter buffer
(emit timestamp) ... the ingest timestamp is the earliest packet of the frame that entered
the jitter buffer and the emit timestamp is when the whole frame exits the jitter buffer";
`jitterBufferTargetDelay`, `jitterBufferMinimumDelay` ("not affected by external mechanisms
... such as jitterBufferTarget ... AV sync"), `jitterBufferEmittedCount`. W3C
webrtc-extensions `jitterBufferTarget` (the engine's `RTCRtpReceiver::jitter_buffer_target`).
The playout-delay extension is a webrtc.org experiment
(`http://www.webrtc.org/experiments/rtp-hdrext/playout-delay`, engine
`rtc-rtp/src/extension/playout_delay_extension`), no RFC.

**This project.** `rtc_video::timing` ports the model: jitter estimator (Kalman filter,
noise, outliers, NACK term, frame-rate scaling), timestamp extrapolator, decode-time
percentile, target / current / render time, scheduling with the 5 ms skip rule, the
low-latency path, the 10 s reset. `jitterBufferTarget` raises the minimum (as libwebrtc's
`base_minimum_playout_delay`); the A/V sync input raises it too; the stats report target and
minimum per W3C. One deliberate change: the 8-frame low-latency queue bound is kept, but its
dropping is counted in `framesDropped` (W3C), which libwebrtc also does.

### 2.5 Key-frame request policy

**libwebrtc.** Requests (PLI by default, FIR when configured,
`rtp_video_stream_receiver2.cc:946-950`) are made when: the first assembled frame is not a
key frame (`:1067-1072`); the packet buffer cleared itself (`:1054-1058`); the NACK list
would pass 1000 entries (`nack_requester.cc:35`, `:206-219`); a Dependency Descriptor
arrives before any structure (at most once a second, `:808-814`); a large sequence-number
discontinuity is waiting for a key frame (`:649-682`); no decodable frame came within the
wait, 200 ms when a key frame is needed and 3 s otherwise
(`video/video_receive_stream2.h:74-75`; with `rtx-time` the wait is the RTX time for a key
frame and three times it otherwise, `video_receive_stream2.cc:218-229`), and only if a packet
arrived in the last 5 s (`:1033-1037`) and no key frame is being received
(`IsReceivingKeyFrame`, `:1216-1226`); a decode error (`:1098-1102`). Once a key frame is
asked for, the request is repeated every wait (200 ms) until a key frame decodes
(`HandleKeyFrameGeneration`, `:1187-1213`).

**Specifications.** RFC 5104 4.3.1.2: "FIR SHALL NOT be sent as a reaction to picture losses
-- it is RECOMMENDED to use PLI [RFC4585] instead." RFC 4585 6.3.1.1: with PLI "a decoder
informs the encoder about the loss of an undefined amount of coded video data belonging to
one or more pictures". RFC 8834 5.1.2: "Receivers MAY send PLI messages." PLI needs `nack
pli` negotiated (RFC 4585 4.2; the engine registers it for video by default).

**This project.** PLI, written through `RTCRtpReceiver::write_rtcp` when `nack pli` was
negotiated; FIR only when the application asks (`send_key_frame_request`, webrtc-encoded-
transform). The triggers and the waits are libwebrtc's (they are policy, no RFC fixes a
number); the repetition interval is the key-frame wait. The pipeline exposes the reason of
each request (`KeyFrameReason`), so tests assert why a request was made.

### 2.6 The NACK boundary

**libwebrtc.** NACK lives in the receive stream: `NackRequester` (`nack_requester.cc`) is
told when a frame was decoded (`ClearUpTo`, `:189-198`, via `RtpVideoStreamReceiver2::
FrameDecoded` and `packet_buffer_.ClearTo` / `reference_finder_->ClearTo`,
`rtp_video_stream_receiver2.cc:1730-1734`), so packets older than the last decoded frame are
never asked for again; packets recovered by FEC or RTX are not asked for (`:163-172`); 100
retries at most (`:39`).

**Specifications.** RFC 4588 6.3: "The receiver should generally assess whether the
retransmitted packet would still be useful at the time it is received."

**Engine today.** `rtc-interceptor/src/nack/generator.rs` asks for a missing packet for as long
as its receive log holds it, unless an age (`with_max_packet_age`, or the sender's
`rtx-time`) or a count limit is set; its documentation states the gap: "How long a packet
stays useful is the receiving application's playout (RFC 4588 6.3), which this interceptor
does not know".

**This project.** The boundary is: the generator decides *how* to ask (timing, RTT spacing,
reordering allowance, RTX); the pipeline decides *until when* a packet is useful. The
pipeline computes, after each decoded or dropped frame, the oldest sequence number still
useful (the first packet of the oldest frame still in the frame buffer or packet buffer),
and hands it to the generator. That needs one engine addition (phase 1b):
`RTCRtpReceiver::set_nack_horizon(ssrc, seq)` carried to the generator like the existing
`NackControl` (an `Attribute::Custom` on an empty RTCP packet), so the generator drops older
entries. Until it exists, phase 1 runs with the generator's own limits and measures what the
missing horizon costs (retransmissions of dropped frames).

### 2.7 Decoder abstraction, decode queue, overload

**libwebrtc.** `api/video_codecs/video_decoder.h @ a222406d`: `Configure(Settings)` (`:98`),
`Decode(EncodedImage, render_time_ms)` (`:102-109`), a `DecodedImageCallback` (`:30-35`),
`DecoderInfo` (`:46`). The receive stream decodes on its own task queue; decode results set
`keyframe_required` (`video_receive_stream2.cc:1064-1110`). Under overload the buffer
controller skips late frames (2.4) and the low-latency path releases at most what the queue
bound allows.

**This project.** `rtc_video::decoder::VideoDecoder` trait: `decode(&mut self, frame:
&EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError>` with `DecodeError::
NeedKeyFrame` / `Corrupt`, `implementation_name()`, `is_hardware()`, the QP of the last frame
when the decoder knows it. Synchronous and `Send`, so the application runs it where it likes:
the pipeline itself is sans-I/O and hands out `DecodeRequest`s (`poll_frame(now)`) and takes
results back (`on_decoded(now, outcome)`), so a decode thread is the application's (section
4.4). Overload: the frame buffer skips frames whose render time passed (2.4); the number of
frames handed out and not yet returned is bounded (default 2, libwebrtc's
`kMaxPendingPostDecodeFrames`, `video_receive_stream2.cc:780`), beyond which the pipeline
holds frames back and, if they go stale, drops them as libwebrtc does.

### 2.8 Render statistics: freezes and pauses

**libwebrtc.** `video/video_quality_observer2.cc @ a222406d`: a freeze when the interval
between two rendered frames is at least `max(3 * avg, avg + 150 ms)` over the last 30
intervals (`:29-31`, `:155-176`), only once 5 intervals are known (`kMinFrameSamplesToDetect
Freeze = 5`), measured on decode timestamps; a pause after 5 s without packets
(`video_receive_stream2.cc:1033`, `OnStreamInactive`).

**Specifications.** W3C webrtc-stats `freezeCount`: "It is a freeze if frame duration, which
is time interval between two consecutively rendered frames, is equal or exceeds Max(3 *
avg_frame_duration_ms, avg_frame_duration_ms + 150), where avg_frame_duration_ms is linear
average of durations of last 30 rendered frames." `pauseCount`: "paused if time passed since
last rendered frame exceeds 5 seconds"; `totalFreezesDuration`, `totalPausesDuration`,
`totalInterFrameDelay`, `totalSquaredInterFrameDelay`, `framesRendered` are recorded "just
after a frame has been rendered".

**This project.** `rtc_video::render::RenderStats`, fed by the application's renderer
(`on_rendered(now, width, height)`), or by the pipeline at the frame's render time when the
application has no renderer of its own. Default: the W3C definition, on render times, from
the first interval. `BehaviourProfile::Chrome`: libwebrtc's five-interval warm-up. A pause is
the W3C definition (5 s since the last rendered frame); its interval is not a freeze.

### 2.9 Statistics: which exist, which the pipeline supplies

| W3C member (inbound-rtp, video) | Engine | Pipeline supplies |
|---|---|---|
| packetsReceived, bytesReceived, headerBytesReceived, packetsLost, jitter, nackCount, firCount, pliCount, retransmittedPackets/BytesReceived, rtxSsrc, fecPacketsReceived, fecBytesReceived, fecSsrc, lastPacketReceivedTimestamp | counted | - |
| framesReceived, framesAssembledFromMultiplePackets, totalAssemblyTime | field exists, `DecoderStatsUpdate` | assembly (2.1) |
| framesDropped, packetsDiscarded | field exists | frame buffer (2.3) |
| framesDecoded, keyFramesDecoded, totalDecodeTime, qpSum, frameWidth, frameHeight, framesPerSecond, totalProcessingDelay, decoderImplementation, powerEfficientDecoder | field exists | decode results (2.7) |
| framesRendered, totalInterFrameDelay, totalSquaredInterFrameDelay, freezeCount, totalFreezesDuration, pauseCount, totalPausesDuration | field exists | render statistics (2.8) |
| jitterBufferDelay, jitterBufferTargetDelay, jitterBufferMinimumDelay, jitterBufferEmittedCount | inbound fields exist, fed only through `AudioReceiverStatsUpdate` | timing (2.4); phase 1b adds them to `DecoderStatsUpdate` (an engine addition: a video stream has no audio update) |
| estimatedPlayoutTimestamp | inbound field exists | A/V sync phase |
| totalCorruptionProbability, ... | field exists | not planned (needs the corruption-detection extension's decoder-side computation) |

---

## 3. Send side: element by element

Summarised here; each is specified in full when its phase starts.

| Element | libwebrtc @ a222406d | Specification | This project |
|---|---|---|---|
| Encoder interface | `api/video_codecs/video_encoder.h`: `Encode` (`:446`), `SetRates(RateControlParameters)` (`:452`, a per-layer allocation), `GetEncoderInfo` (`:495`, QP thresholds `:87`, resolution alignment, `is_qp_trusted` `:277`) | webrtc-svc (modes), RFC 7741 / 9628 / AV1 RTP (layer signalling) | `VideoEncoder` trait: `encode(frame, keyframe: LayerMask) -> Vec<EncodedLayerFrame>`, `set_rates(&LayerAllocation)`, `info()`; one call can yield every spatial layer |
| Frame cadence | `video/frame_cadence_adapter.cc`: zero-hertz mode for screen content repeats frames; `kMaxAllowedDelay` 34 ms (`:790`) | none | `CadenceAdapter`: pass-through for cameras, zero-hertz for screen content (profile-independent) |
| Simulcast layers | `video/config/simulcast.cc`: the resolution / bitrate table for VP8 (`:82`) and VP9 (`:132`), 3 temporal layers by default (`:58`), 2 layers for screen share (`:59-60`) | RFC 8853, W3C `scaleResolutionDownBy` / `maxBitrate` / `maxFramerate` | the application's `encodings` first; libwebrtc's table for defaults it leaves out (Chrome profile and default alike: no RFC number) |
| Rate allocation | `modules/video_coding/utility/simulcast_rate_allocator.cc` (temporal split `kLayerRateAllocation` `:36`, hysteresis 1.2 / 1.35 `:50-51`); `svc/svc_rate_allocator.cc` (0.55 scaling `:37-38`) | W3C webrtc-priority (between senders; the engine does it) | port both; input `RTCRtpSender::target_bitrates()` per SSRC |
| Encoder bitrate adjuster | `video/encoder_bitrate_adjuster.cc`, `encoder_overshoot_detector.cc` | none | port |
| Quality scaler, degradation | `modules/video_coding/utility/quality_scaler.cc` (2 s window `:34`, 60 % frame drop `:36`); `api/rtp_parameters.h:182-196` (`DegradationPreference`: MAINTAIN_FRAMERATE, MAINTAIN_RESOLUTION, BALANCED); `call/adaptation/video_stream_adapter.cc` (min 2 fps, `:40`) | W3C mediacapture / webrtc-pc `degradationPreference` (in webrtc-extensions) | port; `qualityLimitationReason` / durations / resolution changes through `update_encoder_stats` |
| CPU overuse | `video/adaptation/overuse_frame_detector.cc` (ramp-up delays 10 / 40 / 240 s `:51-54`, 7..30 fps `:74-75`) | none | port; the application reports encode time |
| FEC / RTX budget | `modules/video_coding/fec_controller_default.*`, `media_opt_util.cc` (protection tables by loss and RTT) | RFC 8854 (FEC for WebRTC), RFC 4588 | port the protection-overhead split; the engine already holds retransmissions under the target |
| Packetization hand-off | `call/rtp_video_sender.cc` | the payload formats, AV1 RTP appendix A | engine payloaders plus `DependencyDescriptorWriter`; `write_rtp_with_capture_time` |

---

## 4. Codecs under the constraints

All figures read on 2026-11-23 from `https://crates.io/api/v1/crates/<name>` (licence of the
newest version, `rust_version`, recent downloads) and the repository through `gh api`.
"Evidence" says where a speed or conformance claim comes from: the project's own README
unless stated; none of these was run here yet (no test binary runs on this machine). Phase 2
measures each one used on hosted runners.

### 4.1 Software codecs

| Codec | Crate (version) | Licence | Pure Rust | MSRV | Platforms | Real-time evidence | Feature |
|---|---|---|---|---|---|---|---|
| VP8 decode | `vp8-decoder` 0.1.3 (repo `AlakazamLabs/vp8`) | (MIT OR Apache-2.0) AND BSD-3-Clause (a port of the RFC 6386 section 20 reference decoder) | yes (small NEON / SSE2 loop-filter kernels via `std::arch`; `--cfg vp8_portable` removes them) | 1.80 | any | README: 560 fps at 1280x720 1.2 Mbit/s on an Apple M4, 270 fps on a Xeon E-2288G, one core; "matches the WebM project's 59 VP8 test vectors bit for bit" | `vp8` (default, **pending the phase 2 checks**) |
| VP8 encode | `vp8-encoder` 0.1.3 (same repo) | same | yes, `#![forbid(unsafe_code)]` | 1.80 | any | README: 720p camera clip at 2 Mbit/s, 47 fps on one Ryzen 7 3800X core, 124 fps on an Apple M4; rate control within 12 % of target; key frames on request; L1T2 / L1T3; streams decoded by libvpx and Chrome's WebCodecs "byte-identical" | `vp8` (default, pending) |
| VP8 / VP9 encode + decode | libvpx (BSD-3-Clause, C and assembly) through a binding written here, as `parolnet-media` has one (MIT OR Apache-2.0, same owner) | BSD-3-Clause | no: system library | - | Linux, macOS, Windows (vcpkg) | the reference implementation | `libvpx` (opt-in) |
| AV1 encode | `rav1e` 0.8.1 | BSD-2-Clause | yes with `default-features = false` (the default `asm` feature needs NASM on x86_64) | 1.83 | any | README: "11 speed settings (0-10, exhaustive to near real-time)"; no figure without assembly; to be measured at speed 10, low-latency mode | `av1` (default: encode) |
| AV1 decode | `rav1d` 1.1.0 (Rust port of dav1d) | BSD-2-Clause | yes without its default `asm` feature (which needs NASM on x86) | 1.79 (crates.io) | stable for x86, x86_64, aarch64; "requires a nightly compiler for `arm` and `riscv64`" (README) | none for the Rust fallback; the API is dav1d's C API in Rust ("A Rust API is planned") | `av1` (default: decode), to be measured |
| AV1 decode | `dav1d` 0.12.0 / `dav1d-sys` 0.9.0 (bindings) to libdav1d | bindings MIT; libdav1d BSD-2-Clause | no: C and assembly, system or built library | 1.85 | any | dav1d is the decoder browsers ship | `dav1d` (opt-in) |
| H.264 encode + decode | `openh264` 0.9.10 / `openh264-sys2` | BSD-2-Clause (wrapper and OpenH264) | no: C++ (feature `source` builds the bundled source with `cc`; `libloading` loads a Cisco binary) | 1.85 | any | the codec Firefox ships (as Cisco's binary) | `openh264` (opt-in) |
| H.264 decode | `rust_h264` 0.6.1 (repo `roticv/rust_h264`, created 2026-02) | MIT OR Apache-2.0 (repository LICENSE: Apache-2.0) | yes (SIMD) | 1.89 | any | README: "199 of 204" JVT conformance vectors, byte-identical to FFmpeg on its streams; speed in its BENCHMARK.md | candidate for a later `h264-rust` (opt-in) |
| H.264 encode + decode | `rusty_h264-encoder` / `-decoder` 0.17.4 (repo `Remade-With-Rust/rusty_h264`) | BSD-2-Clause | yes | 1.85 | any | README: decoder byte-identical on 35 openh264 conformance streams | **not used**: the repository describes itself as "x264 remade with rust"; x264 is GPL-2.0-or-later, and a remake of it may be a derived work. Not usable until its provenance is shown to be clean |
| H.265 decode | `rust_h265` 0.4.1 (repo `roticv/rust_h265`) | MIT OR Apache-2.0 | yes | 1.88 | any | README: passes the 147 JCT-VC HEVC_v1 vectors | candidate for `h265-rust` (opt-in), decode only |
| H.265 encode | none in pure Rust found | - | - | - | - | - | hardware backends only |

Searched and rejected: `vpx-sys` 0.1.1 (MIT, last release 2021), `env-libvpx-sys` and
`libvpx-native-sys` (MPL-2.0: not in `deny.toml`), `oxideav-vp8` / `oxideav-h264` /
`oxideav-av1` (descriptions: "scaffold pending clean-room re-implementation", MSRV 1.95),
`gamut-av1` (intra frames only, MSRV 1.92), `less-avc` (lossless intra-only H.264).

**VP8 pure Rust: say it plainly.** Until 2026-11-23 there was no real pure-Rust VP8 encoder
or decoder on crates.io. `vp8-decoder` and `vp8-encoder` were published that day by a
repository created that day, with one commit and no users. Their READMEs claim conformance on
the WebM test vectors, libvpx / Chrome cross-checks and real-time speed; none of that has been
reproduced by anyone else. They become the default VP8 backend only after phase 2 reproduces
on hosted runners: the conformance vectors (their script), decode of this repository's
`examples/test-data/output_vp8.ivf` (libvpx-made, 176x144, 300 frames), encode-decode PSNR
and speed, fuzzing of the decoder, and a browser decoding the encoder's stream in the train's
matrix. If any check fails, VP8 is `libvpx`-only and the default build has no VP8.

**H.264 and H.265 licensing, plainly.** The code licences are permissive (OpenH264 BSD-2,
`rust_h264` / `rust_h265` MIT or Apache-2.0). The patents are a separate matter, and no crate
licence covers them. Cisco's arrangement covers only Cisco's own binary, under conditions
(`specs/openh264-BINARY_LICENSE.txt`, from `http://www.openh264.org/BINARY_LICENSE.txt`, v1.0):
"this binary is licensed under Cisco's AVC/H.264 Patent Portfolio License from MPEG LA, at no
cost to you, provided that the requirements and conditions shown below ... are met", among
them "1. The Cisco-provided binary is separately downloaded to an end user's device, and not
integrated into or combined with third party software prior to being downloaded", "2. The end
user must have the ability to control (e.g., to enable, disable, or re-enable) the use of the
Cisco-provided binary", and the text "OpenH264 Video Codec provided by Cisco Systems, Inc."
shown where the user controls it. Built from source (the `openh264` crate's default `source`
feature) or written in Rust, an H.264 codec carries no patent licence; Cisco's FAQ, quoted in
`ralfbiedert/openh264-rs` issue 43: "a team can choose to use the source code, in which case
the team is responsible for paying all applicable license fees". So: H.264 is opt-in; the
`openh264` feature defaults to loading Cisco's binary at run time (`libloading`), which only
the application can obtain from Cisco and present to the user under those conditions; building
from source is a second, explicitly named feature. H.265 is in the same position, with several
patent pools and no free binary arrangement.

### 4.2 Hardware encoders and decoders (later, opt-in)

| Backend | Crate | Licence | Notes |
|---|---|---|---|
| VideoToolbox (macOS, iOS) | `objc2-video-toolbox` 0.3.2 | Zlib OR Apache-2.0 OR MIT | H.264, H.265 (and VP9 / AV1 decode on recent hardware); system framework, no extra install |
| Media Foundation (Windows) | `windows` (Microsoft) | MIT OR Apache-2.0 | H.264, H.265, AV1 / VP9 decode where the drivers have them |
| VA-API (Linux) | `cros-codecs` 0.0.6 / `cros-libva` 0.0.13 | BSD-3-Clause | needs libva at run time; H.264, H.265, VP8, VP9, AV1 per driver |
| NVENC / NVDEC | `shiguredo_nvcodec` 2026.2.0 | Apache-2.0 | MSRV 1.93: cannot be a dependency at MSRV 1.89 (as `sonora` for audio) |

Platform encoders ship with the platform's own H.264 / H.265 patent arrangements; that is the
practical route to H.264 encoding for an application that cannot take the Cisco conditions.

### 4.3 Scaling and colour conversion

| Crate | Licence | Pure Rust | MSRV | Use |
|---|---|---|---|---|
| `yuv` 0.8.21 (repo `awxkee/yuvutils-rs`) | BSD-3-Clause OR Apache-2.0 | yes (SIMD through `std::arch`) | 1.82 | RGB / NV12 / YUY2 to I420 and back (`parolnet-media` uses it) |
| `pic-scale` 0.7.14 | BSD-3-Clause OR Apache-2.0 | yes | 1.89 | high-quality resampling of planes |
| `fast_image_resize` 6.2.0 | MIT OR Apache-2.0 | yes | 1.87 | alternative resampler |
| `dcv-color-primitives` 1.0.0 | MIT-0 | yes | 1.87 | not in `deny.toml`'s list: not used |

A box / bilinear I420 down-scaler written here covers simulcast and the quality scaler in
the default build; `yuv` and `pic-scale` are the opt-in `convert` feature for capture formats
and better filters.

### 4.4 Capture (later, opt-in)

Camera: `nokhwa` 0.10.11 (Apache-2.0; AVFoundation, Media Foundation, V4L2), as
`parolnet-media` uses. Screen: `xcap` 0.9.10 (Apache-2.0) or per-platform APIs
(ScreenCaptureKit, Windows Graphics Capture, PipeWire). Every one opens a system privacy
prompt; none runs in CI.

### 4.5 What the default build can and cannot do

| | Receive (decode) | Send (encode) |
|---|---|---|
| Default (pure Rust) | VP8 (if `vp8-decoder` passes phase 2), AV1 (`rav1d` without assembly; speed to be measured) | VP8 (if `vp8-encoder` passes), AV1 (`rav1e` without assembly; near real time at best, low resolutions) |
| `libvpx` | VP8, VP9 | VP8, VP9 (SVC included) |
| `dav1d` | AV1 at browser speed | - |
| `openh264` | H.264 Constrained Baseline | H.264 Constrained Baseline |
| hardware | H.264, H.265, others per platform | H.264, H.265 per platform |

The default build cannot do VP9 or H.264 at all. The receive pipeline of phase 1 is
codec-agnostic: it assembles, orders, times and requests key frames for every payload format
the engine depacketizes, and hands frames to whichever decoder the application registers.

---

## 5. Crate layout, attachment, threading

### 5.1 Crates

- **`rtc-video`** (new): the receive pipeline (assembly, reference finder, frame buffer,
  timing, key-frame policy, render statistics), the decoder and encoder traits, the send
  pipeline (cadence, scaling, allocation, adaptation), the codec backends behind features,
  and `engine` (feature, default) for the glue to `RTCRtpReceiver` / `RTCRtpSender`, as
  `rtc-audio` does. Default features: `engine` and, once phase 2 accepts them, `vp8` and `av1`.
- **Capture**: not in `rtc-devices`, which is audio-only and another agent's; a crate
  `rtc-video-devices` (or features of `rtc-video`) for cameras and screens is an owner decision
  (section 7). Synthetic sources (test patterns, moving shapes, noise) are in `rtc-video` itself
  and are what every test uses.

### 5.2 Attachment to the engine

Receive: `rtc_video::engine::VideoReceiver::new(&mut pc, receiver_id, config)`; for every
`RTCMessage::RtpPacket(track, packet)` of its track `handle_rtp(now, &packet)`; `poll(&mut pc,
now)` writes due PLI, returns `DecodeRequest`s; `on_decoded(&mut pc, now, outcome)` reports
the decoded size (`report_received_frame`) and statistics; `poll_timeout()` for the next
deadline; `update_stats(&mut pc)` for `update_decoder_stats`. The receiver's RTT comes from the
engine's statistics (remote-inbound / candidate pair RTT) for the jitter estimator's NACK term.

Send (phase 3): `VideoSender` takes frames, follows `target_bitrates()` and
`OnKeyFrameRequest`, packetizes with the negotiated codec's payloader and the DD writer, and
reports encoder statistics.

### 5.3 A/V synchronisation

Both pipelines know each frame's capture time on the sender's clock
(`encoded_frame_metadata().capture_time`, from `abs-capture-time` or the RTCP sender reports'
NTP / RTP mapping, RFC 3550 6.4.1; RFC 6051 rapid synchronisation where negotiated). The sync
module computes, as libwebrtc's `video/stream_synchronization.cc @ a222406d`, the relative
delay (`:35-63`), filters it (`kFilterLength = 4`, `:24`), ignores differences under 30 ms
(`kMinDeltaMs`, `:26`), moves at most 80 ms per step (`kMaxChangeMs`, `:22`) once a second
(`rtp_streams_synchronizer2.cc:35`), adding delay to the earlier stream: to video through
the timing's minimum delay, to audio through `rtc_audio::jitter::JitterBuffer::
set_target_delay` (an existing API; no change to `rtc-audio`). One clock: both pipelines are
given the same `now`.

### 5.4 Threading, back-pressure, allocation

The engine is single-threaded; so is the pipeline's control part (cheap: bookkeeping per
packet and per frame). Decoding and encoding are the only heavy work and are synchronous calls
on trait objects that are `Send`: an application runs them on the engine's thread (tests,
small resolutions) or on a worker and returns the results. Back-pressure: on receive, at most
`max_pending_decodes` frames are out (2.7); on send, the encoder input is a single-slot
mailbox (the newest captured frame replaces an unencoded one, counted as a frame dropped by
the source; libwebrtc's `kMaxFramesInPreparation = 10`, `video/video_stream_encoder.cc:125`,
bounds the same queue). Allocation: encoded frame payloads are `Bytes` slices of the
depacketized packets (one copy to join packets); decoded pictures come from a `FramePool`
(reference-counted planes returned on drop), so steady state allocates nothing per frame.

---

## 6. Phases

Every phase: a branch `conf/vp-<n>-<name>` stacked on the previous one, `cargo check`,
clippy, fmt, the `scripts/check-*.py` gates and `cargo deny --all-features` locally; the new
crate's tests and `cargo test --workspace` on GitHub-hosted runners (ubuntu; macOS and
Windows at phase milestones); CHANGELOG under `[Unreleased]`. Browser cells are added to the
test environment's matrix (`scripts/test-env/interop/webrtc.spec.mjs`) and run only on the
integration train.

### Phase 1: the receive pipeline, codec-agnostic (`conf/vp-2-receive`)

Scope: `rtc-video` with `assembly`, `reference`, `buffer`, `timing`, `keyframe`, `render`,
`stats`, `decoder` (trait only, plus a test decoder that models reference validity),
`engine::VideoReceiver`. No codec dependency.

Tests (no camera, no browser):

- Unit: each finder with descriptor sequences from the RFCs' examples (VP8 L1T3 with Y bits,
  VP9 flexible and non-flexible GOF, DD L1T3 / L3T3 structures from the engine's own
  `ScalabilityPattern`), sequence-number wrap, duplicates, padding, overflow, the jitter
  estimator against constructed delay series.
- Golden streams: `examples/test-data/output_vp8.ivf` and `output_vp9.ivf` (libvpx, 176x144,
  300 frames at 29.97 fps), `output.264` and `output.265` (Annex B), packetized with the
  engine's payloaders, shuffled and lost by a seeded network model; every frame the pipeline
  releases must be byte-identical to the IVF frame and released in order with its references
  released before it. Test-environment GStreamer fixtures (`vp8.ivf`, `h264` 640x480) where
  the env stage runs.
- Virtual-time networks: two `rtc` peer connections (the `rtc-audio/tests/common` world:
  seeded loss, uniform jitter that reorders) with default interceptors (NACK, RTX, PLI),
  a synthetic VP8 sender (frames sized by a bitrate, PictureID / TL0PICIDX, key frame on PLI)
  and the pipeline on the receiver; and the capacity scenario of
  `tests/capacity_cap_video_rtc2rtc.rs` (300 kbit/s for 20 s) with the sender following GCC.

Acceptance (asserted, seeded, each assertion mutation-checked). The first version of this
table, written before anything ran, set `freezeCount` = 0 at 2 % loss in the two-peer call,
"under 500 ms" at 10 % and a jitter buffer "within p95 - 10 .. p95 + 50 ms" of the network
jitter. Measurement showed the first two depend on how fast the engine repairs a loss, not on
the pipeline (section 6.1), and the third on libwebrtc's estimator, which this port follows;
the figures below replace them, each with its reason.

| Scenario | Figure | Source of the threshold |
|---|---|---|
| golden streams (VP8, VP9, H.264, H.265 fixtures), 5 % loss, 25 ms + 0..40 ms, a retransmission one 60 ms round trip after each loss | every released picture byte-identical to the source; no delta picture before the one it predicts from (the fixtures' own I-P-P order, independent of the reference finder); at least 99 % decoded; `freezeCount` = 0 | correctness; W3C `freezeCount` |
| two-peer call, 2 % and 10 % loss, 25 ms + 0..40 ms, 500 kbit/s, 30 s, the engine's NACK and RTX | no corrupt picture, no decode out of order, no delta picture without its predecessor (the source's frame numbers); longest interval between rendered pictures at most the slowest repair + 100 ms (the pipeline waits for nothing but repairs) | `ReceiveStats::max_repair_delay`, measured on the same run |
| capacity 300 kbit/s for 20 s, then open, the sender following GCC | longest interval between rendered pictures under 1 s over the whole run (the last release froze 7 s) | regression bound for the engine's known failure |
| key frame lost at start | first PLI at the first delta frame; at most one request per 200 ms; decoding resumes at the next key frame | `rtp_video_stream_receiver2.cc:1067-1072`, `video_receive_stream2.cc:1187-1213` |
| pictures stuck behind a gap retransmission never fills | a key frame asked for (`RepairWindow`) between 5 RTT (at least 1 s) and that + 50 ms after the last release; with `ReceiveConfig::chrome()` only the 3 s decode timeout | RFC 4588 6.3 ("would still be useful"); libwebrtc `video_receive_stream2.h:75` |
| `jitterBufferTarget` 100 ms, steady stream | a picture is not released before render time - decode time - render delay, and its render time is arrival + 100 ms (+-5 ms) | `frame_decode_timing.cc` `MaxWaitingTime`; W3C webrtc-extensions `jitterBufferTarget` |
| clean link, 0..40 ms jitter | no freeze, no frame dropped, mean `jitterBufferDelay` per picture 10..60 ms (measured 25.9 ms: libwebrtc's estimate for this jitter is about 20 ms, `2.33 sigma - 30 ms + 10 ms` with `sigma = 40 / sqrt(6)` ms) | `jitter_estimator.cc:62-73` |

Browser cells: none yet (no decoder); phase 2 adds them.

#### 6.1 Phase 1: what was measured

GitHub-hosted runs of `cargo test -p rtc-video -- --nocapture` on `conf/vp-2-receive`
(ubuntu-latest; the `MEASURE` lines), virtual time, fixed seeds:

| Scenario | Decoded | Freezes (W3C) | Longest interval | Mean jitter buffer delay | Repairs: count, mean, max |
|---|---|---|---|---|---|
| VP8 fixture, clean / 5 % loss | 300 / 298 of 300 | 0 / 0 | 54 / 131 ms | | |
| VP9 fixture, clean / 5 % loss | 300 / 299 | 0 / 0 | 54 / 113 ms | | |
| H.264 fixture, clean / 5 % loss | 300 / 298 | 0 / 0 | 54 / 164 ms | | |
| H.265 fixture, clean / 5 % loss | 300 / 300 | 0 / 0 | 54 / 164 ms | | |
| call, clean, 0..40 ms jitter, 20 s | 599 of 599 | 0 | 45 ms | 25.9 ms | 0 |
| call, 2 % loss, 30 s | 897 of 899 | 13 (2.98 s) | 319 ms | 98.3 ms | 24, 227 ms, 375 ms |
| call, 10 % loss, 30 s | 887 of 896 | 51 (13.2 s) | 654 ms | 249 ms | 175, 321 ms, 877 ms |
| call, 300 kbit/s for 20 s then open, 50 s | 1498 of 1500 | 5 (2.23 s) | 620 ms | 86.6 ms | 28, 605 ms, 1089 ms |

No run released a picture that differed from what was sent or that its references did not
allow, on any codec.

**Engine finding: repair latency.** In the calls a lost packet comes back 227 ms (mean, 2 %
loss) to 605 ms (capacity drop) after the first packet past its gap, against a round trip of
about 70 ms on that link. libwebrtc asks as soon as a gap shows (`nack_requester.cc`
`OnReceivedPacket` sends `GetNackBatch(kSeqNumOnly)` on the packet that reveals it) and again
every round trip; the engine's generator waits for its learned reordering allowance (up to
500 ms) and runs on a 100 ms cycle. Shortening the cycle to 20 ms made it worse (2 % loss:
repairs 554 ms mean, 28 freezes; run 45308589888), so the cause is not the cycle alone; it is
reported to the congestion / retransmission work and not changed here (outside this crate).
The W3C freezes in the loss rows are those repairs: the pipeline waits for nothing else (the
asserted bound), and with repairs one round trip late (the golden streams) there is none.

**Mutation check.** Each mutation on a throwaway branch, `cargo test -p rtc-video` on a hosted
runner; all killed:

| Mutation | Killed by |
|---|---|
| frame buffer ignores references (`decodable` never cleared) | buffer unit tests, golden H.264 / H.265, the 10 % loss and capacity calls, the repair-window test (11 failures) |
| picture-id finder gives no references | golden VP8 / VP9, all three loss calls, the jitter call, the repair-window test (7) |
| release ignores render time | `a_picture_is_held_until_its_render_time_less_decode_and_render_delay` (added after the first round, where this mutation survived) |
| repair window never asks | `frames_stuck_behind_an_unrepaired_gap_ask_for_a_key_frame_after_the_repair_window` |
| freeze margin 300 ms instead of 150 | `a_long_interval_after_steady_frames_is_a_freeze` |
| retransmissions never detected | `a_packet_late_against_the_packet_after_its_gap_counts_as_a_retransmission` (added after the first round) |

### Phase 1b: the engine boundary (`conf/vp-3-boundary`)

`RTCRtpReceiver::set_nack_horizon` (2.6) and the four jitter-buffer members in
`DecoderStatsUpdate` (2.9), each with a failing-first test. Acceptance: in the capacity
scenario, retransmissions of packets older than the horizon = 0.

### Phase 2: codecs (`conf/vp-4-codecs`)

`VideoDecoder` / `VideoEncoder` backends: `vp8` (vp8-decoder / vp8-encoder), `av1` (rav1e,
rav1d), `libvpx` (VP8, VP9), `dav1d`, `openh264`. Tests: conformance vectors where licensable
(fetched in CI, not committed), golden fixtures decoded with frame checksums, encode-decode
PSNR at stated bitrates, decode and encode speed at 360p and 720p (reported, and asserted
against real time on the runner for the defaults), fuzzing of the decoders' entry.
Acceptance: VP8 decode 720p at 30 fps or more on one GitHub-hosted core; PSNR of
encode-decode at 640x360, 600 kbit/s at least 32 dB on the synthetic source; AV1 figures
reported, no real-time claim unless measured. Browser cells: Rust sends VP8 (and AV1) through
the pipeline, the browser decodes (framesDecoded > 0, no freeze at 0 % loss); the browser
sends, `rtc-video` decodes (frames decoded, sizes right) — Chromium, Firefox, WebKit.

### Phase 3: the send pipeline (`conf/vp-5-send`)

Synthetic sources, cadence adapter, I420 scaler, encoder driver with rate control from
`target_bitrates()`, key frames on `OnKeyFrameRequest`, simulcast (one encoder per RID),
temporal layers, SVC with the DD, the rate allocators, the encoder bitrate adjuster, encoder
statistics. Acceptance: encoded bitrate within 15 % of the allocation over 10 s windows
(vp8-encoder claims 12 %); key frame within one frame interval of a PLI; simulcast layers at
the signalled resolutions; capacity scenario with the real encoder meets phase 1's freeze
figure. Browser cells: simulcast to the browser's receiver (layers switched by the app),
resolution and frame-rate adaptation observed in the browser's inbound stats.

### Phase 4: adaptation and A/V sync (`conf/vp-6-adapt`)

Quality scaler, degradation preference, CPU overuse, FEC budget, `qualityLimitation*`;
the sync module with `rtc-audio`. Acceptance: under a 300 kbit/s cap, resolution steps down
within 2 s (`quality_scaler.cc:34`) under MAINTAIN_FRAMERATE and frame rate under
MAINTAIN_RESOLUTION; audio-video skew within 30 ms (`stream_synchronization.cc:26`) after
5 s with 80 ms of extra video delay injected. Browser cells: lip-sync measured on a
flash / beep source in both directions.

### Phase 5: capture and hardware (owner decisions, section 7)

---

## 7. Decisions for the owner

| Decision | Recommendation | Meanwhile |
|---|---|---|
| 1. H.264 software encoding in scope at all | Yes, opt-in only: `openh264` with the Cisco binary loaded at run time (the only route with a patent licence that costs the application nothing, under Cisco's four conditions); building from source as a separate named feature; no pure-Rust H.264 encoder (the only candidate's provenance is unclear) | H.264 receive is fully supported by the codec-agnostic pipeline; no H.264 code is written until decided |
| 2. Accept `vp8-decoder` / `vp8-encoder` (published 2026-11-23, unproven) as default dependencies | Yes, conditional on phase 2's checks; otherwise VP8 only through `libvpx` | phase 1 needs no codec |
| 3. Hardware backends: order | VideoToolbox, then Media Foundation, then VA-API; NVENC when the MSRV reaches 1.93 | none built |
| 4. Capture: where and how much | A new crate `rtc-video-devices` (camera via `nokhwa`; screen per platform), opt-in features, never run in CI | synthetic sources only |
| 5. Screen capture in scope | Yes, after camera; with the zero-hertz cadence and screen-content encoder modes it needs | the cadence adapter and screen-content mode are designed in phase 3 |
| 6. MSRV | Keep 1.89; it excludes `shiguredo_nvcodec` and newer pure-Rust codecs (`oxideav-*` 1.95, `gamut-av1` 1.92) | none of these needed now |
