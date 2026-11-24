# How long a video receiver waits for a missing packet

The engine repairs losses (NACK and RTX, RFC 4588; FEC where negotiated), but it does not
assemble frames or decide when to give up on one: that is the receiving application's video
pipeline (with `rtc-media`'s `SampleBuilder`, or its own). This page is the rule such a pipeline
should follow, and why. Nothing here changes engine behaviour.

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

## With `rtc-media`'s `SampleBuilder`

- `SampleBuilder::new(max_late, ..)` bounds the wait in packets (`max_late`).
  `with_max_time_delay(duration)` adds a bound in media time: a sample is given up once the
  buffered packets span more than `duration` of RTP time. That is the time bound of rule 1, as
  long as packets keep arriving (it is checked as they are pushed, not on a wall clock).
- The next sample a gap was skipped before carries the count in `Sample::prev_dropped_packets`
  (with `prev_padding_packets` to tell padding from loss): that is the moment for rule 2's key
  frame request.
- `with_max_gap_wait(duration)` bounds the wait in wall-clock time, also while nothing arrives
  (off by default). The wait for the oldest missing packet runs from the arrival of the first
  packet after it; once it has lasted `duration` the builder gives the gap up as `max_late`
  does (the incomplete sample and the missing packets are dropped, counted in the next sample's
  `prev_dropped_packets`, and building resumes at the next packet that starts a sample) and
  raises a key-frame request, read with `take_key_frame_request()` (rule 2). The bound is
  checked on `push` and `pop` with the `now` they are given; `poll_timeout()` names the instant
  to call `pop` at while a gap waits. The generic `Depacketizer` cannot tell a key frame, so the
  sample building resumes at may refer to what was lost: the key-frame request is what repairs
  the picture. A gap filled before the bound changes nothing.
- A receiver without a time bound freezes for the length of its packet window on a gap that
  never fills: 256 packets were 8.6 s at 100 kbit/s in `tests/capacity_cap_video_rtc2rtc.rs`
  (below).
- Not expressible in the builder today: skipping everything older than a key frame the moment it
  is complete (rule 3), for the same reason (the depacketizer cannot say which sample is a key
  frame). That is the video pipeline's to decide.

## Measured

In `tests/capacity_cap_video_rtc2rtc.rs` (and ParolNet's simulation it is ported from) the
receiver uses `SampleBuilder::new(256, ..)` with no time bound. When packets went missing for
good (a pacer that discarded queued media at a rate drop), the picture stayed frozen for about
8.6 s: the time 256 packets took to arrive at the floor rate, after which the builder skipped the
gap and the first key-frame request went out. With repairs that do arrive, the same receiver
recovered in about 1.3 s.
