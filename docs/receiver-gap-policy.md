# How long a video receiver waits for a missing packet

The engine repairs losses (NACK and RTX, RFC 4588; FEC where negotiated), but it does not
assemble frames or decide when to give up on one: that is the receiving application's video
pipeline (with `rtci-media`'s `SampleBuilder`, `rtci-video`'s receive pipeline, or its own). This
page is the rule such a pipeline should follow, why, and how `SampleBuilder` follows it by
default. Nothing here changes what the engine puts on the wire.

## The rule

1. **Bound the wait in time, not in packets.** A gap that the sender will repair is repaired
   within a few round trips: the NACK generator asks a round trip apart while the packet is
   missing, the responder answers within the congestion controller's share
   (`RetransmissionRateLimit`), and a repair is not resent within 20 ms of leaving
   (`MIN_RETRANSMIT_INTERVAL`; a request that crosses a repair in flight can be answered
   again, and the copy arrives after the first). Wait for a
   missing packet about as long as that takes (the repair window: a few round-trip times, and no
   longer than the playout delay the application accepts, typically 200 ms to 1 s for
   interactive video). A bound in packets is a bound in time only at one bit rate: 256 packets
   are 0.3 s at 2.5 Mbit/s and 8.6 s at the 100 kbit/s floor of the congestion controller.
2. **When a gap outlives the repair window, skip it and ask for a key frame at once.** Every
   frame after the gap depends on it until the next key frame; waiting longer only freezes the
   picture. Ask with PLI (RFC 4585 section 6.3.1) or FIR (RFC 5104 section 3.5.1), at most once
   per round trip or so while the decoder has no reference (RFC 4585 section 3.5 limits the rate
   of feedback anyway).
3. **A gap the sender will never fill is skipped at once.** After a key frame arrives, packets
   older than it are no longer needed.

libwebrtc's receiver follows the same idea in its own terms: when its NACK list would grow past
1000 packets it clears the list and requests a key frame
(`modules/video_coding/nack_requester.cc:213-219` at revision a222406d: "NACK list full,
clearing NACK list and requesting keyframe."), and it forgets packets older than 10 000
sequence numbers (`kMaxPacketAge`, line 34).

## With `rtci-media`'s `SampleBuilder`

The builder follows the three rules by default for the video formats (a depacketizer whose
`Depacketizer::has_key_frames` is true: VP8, VP9, AV1, H.264, H.265). An audio builder, or one
with a depacketizer that does not say, waits by `max_late` alone, as it always did.

- **Rule 1, the bound in time.** `SampleBuilder::new(max_late, ..)` waits for a missing packet
  at most `DEFAULT_MAX_GAP_WAIT`, 300 ms, also while nothing arrives. The wait for the oldest
  missing packet runs from the arrival of the first packet after it; once it has lasted the
  bound the builder gives the gap up as `max_late` does (the incomplete sample and the missing
  packets are dropped, counted in the next sample's `prev_dropped_packets`, and building
  resumes at the next packet that starts a sample). The bound is checked on `push` and `pop`
  with the `now` they are given; `poll_timeout()` names the instant to call `pop` at while a
  gap waits. `with_max_gap_wait(duration)` sets another bound and `with_max_gap_wait(None)`
  removes it (the behaviour before 0.2: the gap is held for `max_late` packets). A gap filled
  before the bound changes nothing. `max_late` and `with_max_time_delay(duration)` (a bound in
  media time, checked as packets are pushed) still apply.
- **Rule 2, the key-frame request.** When the time bound gives a gap up the builder raises a
  key-frame request, read with `take_key_frame_request()`: the sample building resumes at may
  refer to what was lost. The builder is a helper outside the engine and sends nothing: the
  application sends the PLI (or FIR) with `RTCRtpReceiver::write_rtcp`, at most once per round
  trip or so. The engine itself never asks for a key frame for a received stream, because it
  does not assemble frames: its NACK generator stops asking for a packet at its own bounds
  (age and number of requests) and says nothing more. `rtci-video`'s receive pipeline
  (`ReceivePipeline::poll_key_frame_request`, sent by `rtci_video::engine::VideoReceiver`) is the receiver
  that does all of it by itself.
- **Rule 3, the key frame.** When every packet of a key frame is buffered behind a gap, the
  builder gives up everything before the key frame at once: the samples complete before the
  gap come out, the missing packets and the frames between them and the key frame are dropped
  (a decoder could not use those frames without what is missing), and the key frame is the
  next sample, counting what was dropped in `prev_dropped_packets`. No key-frame request is
  raised. The first packet of a key frame is what the payload format says it is
  (`Depacketizer::is_key_frame_start`): VP8's payload header with P=0 on the first packet of a
  frame (RFC 7741 section 4.3), VP9's descriptor with P=0 at the start of a base-layer frame
  (RFC 9628 section 4.2), AV1's aggregation header with N=1 (AV1 RTP specification section
  4.4), the first slice of an H.264 IDR picture (RFC 6184; parameter sets sent in packets of
  their own before it, with the same timestamp, stay with it) and the first slice segment of
  an H.265 IRAP picture (RFC 7798). `with_key_frame_release(false)` turns the rule off (a
  recorder that would rather wait for every repair).
- **Late packets.** A packet older than everything the builder has built or given up is
  ignored by `push` (a repair of a gap that was given up, a duplicate): it used to be
  buffered, where it looked like the start of a new gap. `nack_horizon()` is the oldest
  sequence number still of use; given to `RTCRtpReceiver::set_nack_horizon` after popping, it
  stops the engine's NACK generator asking for anything older (RFC 4588 section 6.3: "the
  receiver should generally assess whether the retransmitted packet would still be useful at
  the time it is received").

### Why 300 ms, and what a browser does

No RFC gives a number. RFC 8834 section 6.1 has retransmission be useful only when "the
retransmitted packet arrives in time to be useful"; RFC 8836 section 2 puts interactive media
"within a very limited time window (no more delay than hundreds of milliseconds end-to-end)".
So the default is the value this repository's capacity instrument measured
(`tests/capacity_instrument.rs`, cells `cap/{paced,nopacer}/gap{300,600,1000}/up/q300/rl0`, 200
seeds each on master d914b929): without a pacer a picture older than 2 s for more than 0.5 s
in 8, 10 and 37 per cent of runs at 300, 600 and 1000 ms (oldest picture 1.33, 1.79 and
2.34 s); with the pacer no difference (9.04, 8.91, 9.01 s: the sender's pause decided).

libwebrtc has no per-packet bound of this kind. Its receiver asks for a key frame when no
frame could be decoded for 3 s, or for 200 ms while it is waiting for a key frame
(`video/video_receive_stream2.h:74-75`, `kMaxWaitForKeyFrame` and `kMaxWaitForFrame`, at
revision a222406d), and when its NACK list would pass 1000 packets
(`modules/video_coding/nack_requester.cc:213-219`); it decodes from a complete key frame
whatever is missing before it, which is rule 3. That receiver is `rtci-video`'s
`ReceiveConfig::chrome()`; `SampleBuilder` has no such mode.

## Measured

In `tests/capacity_cap_video_rtc2rtc.rs` (and ParolNet's simulation it is ported from) the
receiver used `SampleBuilder::new(256, ..)` when that had no time bound. When packets went
missing for good (a pacer that discarded queued media at a rate drop), the picture stayed frozen
for about 8.6 s: the time 256 packets took to arrive at the floor rate, after which the builder
skipped the gap and the first key-frame request went out. With repairs that do arrive, the same
receiver recovered in about 1.3 s. The capacity instrument (`docs/capacity-instrument.md`)
measures both receivers: `gap300` cells (the bound) and `gap0` cells (`with_max_gap_wait(None)`).
