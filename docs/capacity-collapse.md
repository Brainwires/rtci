# What happens to the backlog when the path's capacity collapses

A call sends 2.5 Mbit/s of video and the path drops to 300 kbit/s. The congestion controller
brings the target down within about 0.6 s, but what the application wrote meanwhile, and the
retransmissions of what the path dropped, were sized for the old rate: 0.4 s of 2.5 Mbit/s
video and its repairs take 8 s to leave at 100 to 250 kbit/s. Delivered in order, the picture
on the receiver's screen is 8 s old. This page says what the engine does instead, which texts
permit it, what an application has to do, what was measured, and what is still not met.

## The rule

The pacer (`rtci-interceptor/src/pacing/sender.rs`, "A capacity collapse") keeps the targets
the congestion controller set, back to the one in force when the oldest queued new media was
written or two seconds ago (the queue time bound), whichever reaches further back.

A **collapse** is: what waits in the pacer (new media, retransmissions or both) would take one
second or more to leave at the target (half the queue time bound: the mark at which a pause
would begin), and the target is at most **half** of the highest in that history.

At a collapse, with `PacerBacklog::Flush` (the default):

- every queued packet is discarded: new media and FEC whole frames at a time
  (`PacerDiscard`, `RTCPeerConnectionEvent::OnPacerDiscard`), queued retransmissions
  (`RetransmissionsLeft`). Padding stays. Audio is never queued and is not touched; SCTP does
  not pass the pacer.
- the NACK responder forgets everything sent before on the video streams (`PacerFlush`): a
  later NACK for any of it is answered by nothing. What is written afterwards is buffered and
  repaired as ever.
- the application is asked for a key frame of every video stream, once per stream (one per
  simulcast layer: each is its own SSRC).
- the source is **not** paused. A pause in force ends. The next frame it writes, at the target
  it now reads, is the key frame.
- the history is cleared: no target from before the flush counts again.

`PacerBacklog::Keep` (`DefaultInterceptorOptions::pacer_backlog`,
`PacerBuilder::with_backlog`) is the behaviour before this change: the source is paused, the
queue and every retransmission asked for are delivered in order. It is for a receiver that
plays strictly in order and cannot resume at a key frame. `QueueOverflow::Drain` (libwebrtc's
form, the `Chrome` profile) never discards and is unchanged: see "The Chrome profile keeps its
backlog" below for what that costs.

### Why half, and why a flush does not repeat

A pause that begins at a steady target (a key frame larger than a second of the floor rate, a
source above the target) is not a collapse. Flushing there would discard the very key frame the
flush asked for, ask again, and loop. Two things prevent it. A single decrease of the
delay-based controller is 0.85 and a loss report cuts by at most half, so a target that halved
within the life of the queue separates a path that lost its capacity from a controller
adapting. And because the history is cleared at a flush, the key frame written in answer is
judged only against targets set since: however long it takes to leave, it is a pause and it
is delivered. The target has to halve again from what it was at the flush for another flush:
at most log2(highest / lowest target) in a row, four from 2.5 Mbit/s to a 100 kbit/s floor.
No RFC gives the factor; it is a constant (`COLLAPSE_AT`), not a setting.

### Why the repairs alone count, and why two seconds

Behind a deep queue on the path the receiver sees the gap a second after the drop, when the
packets behind it arrive, and its NACKs reach a sender whose pacer no longer holds any media
written for the old rate. Those repairs are of media written for the old rate all the same.
Two seconds is the pacer's own bound on how long anything may wait before it is stale.

### Why the mark is one second and not lower

Flushing as soon as the target has halved, with 0.5 s or 0.25 s of queue, was measured (200
seeds per cell): the standard cell gains little (oldest picture 1.33 to 1.27 s in the median,
2.08 to 1.64 s at worst) and the deep-queue cell loses: the key frame asked for early goes into
a path queue that is still full, runs with more than 2 s without any frame rise from 6 to 46
(0.5 s) and 69 (0.25 s) of 200, and runs with more than a second without audio from 69 to 96
(0.25 s). One second, the pause mark, is kept.

### The sequence-number gap

The application numbered the discarded packets, so the receiver sees a gap before the key frame
and its NACKs for it go unanswered. Renumbering in the engine was rejected: the packets the
path lost at the drop are gaps anyway, and a renumbering pacer would have to translate every
NACK and RTX original sequence number. The receiver counts the discarded packets as lost in its
RTCP reports (RFC 3550 A.3). The RTP circuit breaker sits wire-ward of the pacer
(`Slot::CircuitBreaker` 2 500, `Slot::Pacer` 3 000, the NACK responder and the FEC encoder
above), so it never saw them leave and does not count them as sent or lost.

## The texts

No text obliges a sender to deliver what it queued, or to answer a NACK.

- RFC 8834 section 6.1: "Retransmission needs to be used with care in interactive real-time
  applications to ensure that the retransmitted packet arrives in time to be useful [...] It
  is not appropriate to blindly retransmit RTP packets in response to a NACK. The importance of
  lost packets and the likelihood of them arriving in time to be useful need to be considered
  before RTP retransmission is used."
- RFC 4588 section 7: "In a best-effort environment, the sender SHOULD NOT send retransmission
  packets without reducing the packet rate and bitrate of the original stream [...] In
  addition, the sender MAY selectively retransmit only the packets that it deems important and
  ignore NACK messages for other packets in order to limit the bitrate." There is no "gone"
  message: silence is the answer.
- RFC 8836 section 2: interactive media is useful "within a very limited time window (no more
  delay than hundreds of milliseconds end-to-end)", and the controller "reacts quickly [...] to
  avoid delay buildup" (requirement 1).
- RFC 5104 section 4.3.1.2: "Upon reception of FIR, the encoder MUST send a decoder refresh
  point [...] as soon as possible"; section 2.2: a decoder refresh point "completely resets the
  decoder to a known state". Nothing sent before it is needed after it. RFC 4585 section
  6.3.1: "The sender MAY react to a PLI by transmitting an intra-picture".
- Precedent for discarding at the sender, RFC 8298 (SCReAM) section 3: "The reaction to reduced
  throughput MUST be prompt in order to avoid getting too much data queued in the RTP packet
  queue(s) in the sender. [...] In cases where the sender's frame queues increase rapidly, such
  as in the case of a Radio Access Type (RAT) handover, the SCReAM sender MAY implement
  additional actions, such as discarding of encoded media frames or frame skipping in order to
  ensure that the RTP queues are drained quickly."

libwebrtc, for comparison, drops frames before they are encoded and numbered and drains its
pacer above the target once the queue passes 2 s; its receiver gives a NACK list up and asks
for a key frame. Its sender-side form is `QueueOverflow::Drain` here.

## What an application must do

**Produce a key frame when asked.** At a flush the application of the sending peer gets, for
each video stream, at the instant of the flush:

- on `RTCPeerConnection::poll_read`, an `RTCMessage::RtcpPacket` holding a Picture Loss
  Indication for the stream's SSRC with sender SSRC 0, the same message a receiver's request
  arrives as; and
- on `poll_event`, `RTCPeerConnectionEvent::OnKeyFrameRequest { sender, rid }`.

An application that answers either with a key frame, as it must for a remote request anyway,
needs no new code. `OnPacerDiscard` names the media that was queued. The key frame should be
sized for the target read then (`RTCRtpSender::target_bitrates`).

**On the receiving side**, bound the wait for a missing packet in time, or resume at a key
frame. `rtci-media`'s `SampleBuilder` does both by default for video
(`docs/receiver-gap-policy.md`); browsers decode from a key frame whatever is missing before it.
A receiver that waits for a gap by packet count only and cannot skip to a key frame needs the
sender on `PacerBacklog::Keep`.

Tests: `rtci-interceptor/tests/pacer_flush.rs` (the rule),
`tests/capacity_cap_video_rtc2rtc.rs::a_capacity_collapse_asks_the_application_for_a_key_frame_of_its_video_stream`
(through the peer connection), `tests/capacity_instrument.rs` (the ensembles below).

## What was measured

`tests/capacity_instrument.rs`, 200 seeds per cell, 2.5 Mbit/s each way, the caller's uplink
capped at 300 kbit/s for 20 s (or dead for 4 s, the outage). "Missed" is a picture older than
2 s on the screen for more than 0.5 s. Before = the pause (the circuit breaker's corrected
rules, the estimator's collapse changes and the receiver's gap bound already in); after = the
flush. Oldest picture is the median.

| cell | missed before | missed after | oldest picture before | after (median / 90th / worst) |
|---|---|---|---|---|
| standard (300 ms path queue, bounded receiver) | 200 | 0 | 7.9 s | 1.33 / 1.55 / 2.08 s |
| receiver without a bound in time | 200 | 0 | 7.2 s | 1.33 / 1.57 / 1.82 s |
| 5 % loss on the reverse path | 200 | 1 | 7.6 s | 1.34 / 1.61 / 2.77 s |
| 1000 ms path queue | 200 | 109 | 7.0 s | 2.52 / 2.89 / 3.13 s |
| both directions capped | 200 | 119 | 12.9 s | 2.60 / 3.42 / 10.87 s |
| outage, bounded receiver: resume later than 2 s | 134 | 0 | | |
| outage, receiver without a bound: resume later than 2 s | 200 | 66 | | |

Key frames the caller sends per run: 5 in the median (4 before), 8 at most. Key-frame
requests the callee sends: 2 (8 before). Audio, the target under the cap (about 245 kbit/s),
the target 15 to 25 s after the cap is lifted and the time to recover are not moved. The
chains without a pacer are not touched by the flush.

## The Chrome profile keeps its backlog

The flush applies with `QueueOverflow::Drop` only. The `Chrome` behaviour profile sets
`pacer_queue_overflow` to `Drain`, libwebrtc's form (`drain_large_queues`): its pacer never
discards. At a collapse the source is paused (a target of zero) and what is queued, the
retransmissions of what the path dropped at the drop, is delivered in order; the key frame
the receiver asks for is written only when the pause ends. The profile does what it says, and
after a sharp capacity drop its picture is about 5 s old where the default's is about 1 s.
This is not a defect of the profile; it is what libwebrtc's sender-side form costs with a
receiver that plays in order.

One call (seed 1, the cap at 20.0 s; run 45608112012): both chains cut the estimate first at
20.3 s. Under `Chrome` the target is zero from 20.8 to 24.3 s, 73 retransmissions leave
meanwhile at 110 to 240 kbit/s, and the next usable frame arrives at 25.4 s. The default
flushes once, is never paused, and has frames again at 21.3 s.

`tests/capacity_instrument.rs`, cell `cap/<chain>/gap300/up/q300/rl0`, seeds 1 to 200, means
(run 45615240747; tree: train 32 at ff4d06af with `conf/rtcpbudget-4`, `conf/red-1`, `-3`, `-2`
and two chain tokens made for this measurement and not kept: the `Chrome` profile with
`pacer_queue_overflow = Drop`, and the default with `Drain`). In brackets the difference per
seed from the chain the row varies, with its 95 % half-width.

| | `Chrome` | `Chrome` with `Drop` | default | default with `Drain` |
|---|---|---|---|---|
| oldest picture, s | 5.50 | 1.46 (-4.04 +-0.09) | 1.32 | 6.60 (+5.28 +-0.13) |
| freeze, s | 5.18 | 1.14 (-4.04 +-0.09) | 1.01 | 6.29 (+5.28 +-0.13) |
| picture older than 2 s for over 0.5 s (runs of 200) | 200 | 0 | 0 | 200 |
| time the source was paused, s | 4.87 | 0.02 | 0.00 | 5.12 |
| pacer flushes | 0 | 1.0 | 1.2 | 0 |
| retransmissions | 176 | 35 | 1.9 | 102 |
| key frames sent; requests received | 8.7; 7.2 | 5.4; 2.4 | 5.1; 2.1 | 5.2; 3.3 |
| target under the cap, kbit/s | 196 | 274 (+78 +-4) | 246 | 231 (-15 +-1) |
| time to detect, s | 0.588 | 0.588 | 0.590 | 0.590 |
| time to recover, s | 14.5 | 14.2 (-0.3 +-0.3) | 17.2 | 17.7 (+0.4 +-0.3) |
| audio packets lost | 27.8 | 26.8 (-1.0 +-0.7) | 27.2 | 32.0 (+4.8 +-1.1) |
| flows ceased by the circuit breaker | 0 | 0 | 0 | 0 |

Both directions capped (`cap/<chain>/gap300/both/q300/rl0`, 200 seeds): `Chrome` oldest picture
11.52 s, paused 9.6 s, target under the cap 117 kbit/s; with `Drop` 2.66 s (-8.86 +-0.53),
0.3 s and 201 kbit/s (the default: 2.64 s and 271 kbit/s).

The whole difference follows the one setting, in both directions: the `Chrome` profile with
`Drop` is within 0.14 +-0.05 s of the default, and the default with `Drain` is as stale as
`Chrome`. What it is not: the estimator reacts at the same instant in every column (0.59 s);
the circuit breaker, off under `Chrome`, ceases no flow in any; the FEC of the profile's RED
video takes 42 to 100 kbit/s of the stream under the cap in the traced calls (run 45615247297) (so the media target is 196 against
246 kbit/s) without overloading the path, and is the same in the `Drop` column; and answering
a NACK for a lost FEC packet (`conf/red-2`) halved the gaps the receiver gave up on (353 to
156 a call) and did not move the freeze.

**An application that wants the `Chrome` profile's other rows and a fresh picture after a
collapse** sets `DefaultInterceptorOptions::pacer_queue_overflow` to
`PacerQueueOverflow::Drop` on the options `DefaultInterceptorOptions::for_profile` returns
(`pacer_backlog` is `Flush` already). It then also takes `Drop`'s rule for a source that
writes above the target: the excess is discarded at the pacer, not put on the path.

## Known limits

- **Both directions capped.** Each sender's feedback crosses the other's overloaded uplink and
  most of it is dropped, so the estimate falls only by the rule for missing feedback, once per
  half second: four halvings from 2.5 Mbit/s take 2.0 to 2.5 s. Until then the pacer has no
  backlog (it sends at a target far above the path): the backlog is in the network and there is
  nothing to flush. Honest target today: reaction 2.0 to 2.5 s + the path queue 0.3 s + a key
  frame 0.3 s, about 3 s of oldest picture; measured 2.6 s in the median. The remedy is the
  estimator's reaction to missing feedback, not the flush.
- **A deep queue on the path (1000 ms).** The second of media already in the path's queue
  cannot be recalled. Honest target: reaction 0.6 s + 1.0 s in the queue + a key frame 0.2 s,
  oldest picture about 2.0 s in the median; measured 2.52 s. The rest is a pacer queue of about
  0.45 s that stands for a second while the estimate holds at the path's rate (a source that
  writes at the target does not drain it), until the target falls again and the flush fires.
  With such a queue the voice is still held by the circuit breaker for some seconds in about a
  third of runs (`docs/circuit-breaker.md`).
- **An outage with a receiver that has no bound in time.** In an outage nothing queues at the
  sender (the target halves on missing feedback and the source follows), so whether a flush
  fires depends on how the halvings fall against the application's reading of the target: in
  a third of the runs none does, and 294 packets sent into the dead path are repaired in order
  when it returns. A bounded receiver resumes within 2 s either way; one without a bound waits
  8.7 s. Not fixed here: it needs the NACK responder to decline repairs by age and ask for a
  key frame itself.
