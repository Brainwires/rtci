# How long a video receiver waits for a missing packet

The engine repairs losses (NACK and RTX, RFC 4588; FEC where negotiated), but it does not
assemble frames or decide when to give up on one: that is the receiving application's video
pipeline (with `rtci-media`'s `SampleBuilder`, or its own). This page is the rule such a pipeline
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

A receiver that plays in order without a gap bound never recovers from an outage whose loss
outlasts its packet window: after a 4 s outage and an ICE restart in
`tests/capacity_cap_video_rtc2rtc.rs` (the default chain, `SampleBuilder::new(256)`), it
released no frame for the rest of the run and, seeing no frame to judge, asked for no key frame
either, while the sender, the repairs and the congestion controller behaved as the RFCs ask
(hosted runs 45356693998, 45352461984). Use `SampleBuilder::with_max_gap_wait` with its
key-frame request, or the `rtc-video` receive pipeline (on the `conf/vp-*` line), whose NACK
horizon gives up packets it can no longer use and asks for a key frame.

### Measured: how long the bound should be after a capacity drop and after an outage

`tests/capacity_cap_video_rtc2rtc.rs` measures both cases with the receiver of a port of
ParolNet's call (`SampleBuilder::new(256)`, a decoder that asks for a key frame while it has no
reference): `measure_the_capacity_cap` (a call at up to 2.5 Mbit/s whose path drops to
300 kbit/s for 20 s, six seeds on three wall clocks) and `measure_the_ice_restart` (a 4 s
outage, then an ICE restart). Environment variables give that receiver a gap bound
(`RTC_CAP_GAP_WAIT_MS`), a least time between its key-frame requests (`RTC_CAP_PLI_MIN_MS`,
1 s otherwise), no further request while one is unanswered (`RTC_CAP_PLI_UNTIL_KEY`), and
make the sender's application produce a key frame when the selected pair changes
(`RTC_CAP_KEY_ON_SWITCH`). Hosted runs 45417676638, 45417689445, 45417706262, 45422456552,
45417716278, 45422466844 (with the repairs of `conf/rtx-2r-smooth-limiter`); longest time
without a usable frame / oldest picture shown, in seconds:

| receiver | capacity drop, chain without pacer | capacity drop, default chain | outage, chain without pacer | outage, default chain |
|---|---|---|---|---|
| no time bound | 0.74-1.08 / 2.88-3.12 | 0.81-1.05 / 3.97-5.91 | 0.09-0.14 | 7.95-8.02 (no frame to the end) |
| bound 2 s, key frames at most every 2 s | 1.00-1.73 / 2.21-2.31 | 2.13-4.13 / 2.35-2.47 | 0.09-0.14 | 1.88-2.11 |
| bound 3 s | unchanged | 0.81-3.30 / 3.18-3.97 | 0.09-0.14 | 2.49-2.56 |
| bound 6 s | unchanged | unchanged | 0.09-0.14 | 5.59-5.62 |
| no bound, key frame on the path change | unchanged | unchanged | 0.09-0.14 | 7.67-7.97 |
| bound 3 s and key frame on the path change | | | 0.09-0.14 | 2.02-2.03 |

So after a sudden capacity drop the repairs that a bound gives up on are ones still coming:
the repair of 60 packets lost at 2.5 Mbit/s inside 200 kbit/s takes several seconds, and a
bound shorter than that trades a younger picture for longer freezes (each give-up asks for a
key frame, five times a frame's budget, squeezed through the same narrow path). After an outage
the bound is what recovers the picture at all. A bound above the longest repair the call sees
(6 s here) costs nothing at the drop and shortens the outage from no picture to 5.6 s; a
shorter one is a choice between the two. A key frame the sender makes on the path change does
not help a receiver without a bound (the key frame waits behind the gap), and helps one with a
bound by about half a second. The engine asks no key frame on a path change (libwebrtc neither:
`call/rtp_transport_controller_send.cc` `OnNetworkRouteChanged` resets the bandwidth estimate
only).

libwebrtc's receiver follows the same idea in its own terms: when its NACK list would grow past
1000 packets it clears the list and requests a key frame
(`modules/video_coding/nack_requester.cc:213-219` at revision a222406d: "NACK list full,
clearing NACK list and requesting keyframe."), and it forgets packets older than 10 000
sequence numbers (`kMaxPacketAge`, line 34).

## With `rtci-media`'s `SampleBuilder`

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
