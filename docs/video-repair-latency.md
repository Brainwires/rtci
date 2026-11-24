# Repair latency of a lost video packet: a per-packet trace

What this is: a measurement of how long the engine takes to bring back a lost RTP packet with
NACK (RFC 4585) and RTX (RFC 4588), taken apart into its steps, from the video pipeline's
two-peer test. It is a finding for the retransmission work (generator, responder, pacer); the
video pipeline does not change any of it. See `docs/video-pipeline.md` section 6.1 for what it
costs a viewer.

## How it was measured

`rtc-video/tests/receive_rtc2rtc.rs`, `two_percent_loss_with_reordering_waits_only_for_repairs`:
two `rtc` peer connections in virtual time; VP8 at 500 kbit/s, 30 frames a second, one SSRC
with RTX; the uplink drops 2 % of the RTP datagrams (seeded) and delays each by 25 ms plus a
uniform 0..40 ms (so it reorders); RTCP in both directions takes 25 ms. Round trip about 70 ms
(the receiver is told 70 ms). The interceptor chains are those of
`tests/capacity_cap_video_rtc2rtc.rs`: NACK generator and responder with their defaults, the
RTCP session, key-frame requests, transport-cc with GCC.

Tap interceptors record, in virtual time:

- *gap seen*: the first media packet with a higher sequence number reaches the receiver (from
  the cleartext RTP header of the SRTP datagram);
- *NACK generated*: right after the receiver's NACK generator (`Slot::Custom(10_550)`);
- *NACK left*: at the receiver's wire side of the chain (`Slot::Custom(100)`, below the RTCP
  session);
- *NACK arrived*: at the sender's wire side, read leg;
- *RTX left*: at the sender's wire side, write leg, by the original sequence number the RTX
  payload carries (still in the clear there: SRTP is applied after the chain);
- *RTX arrived*: the repaired packet reaches the receiving application.

Hosted run 45313254085 (ubuntu-latest), branch `conf/vp-4-engine-boundary` at `b0549020`.

## The trace

Milliseconds after the gap was seen, per lost packet (24 losses in 30 s):

| Seq | Dropped at (ms into the call) | First NACK generated | NACK left | NACK arrived | RTX left | RTX arrived | NACKs / RTX sent |
|---|---|---|---|---|---|---|---|
| 4054 | 767 | 198 | 198 | 223 | 223 | 288 | 1 / 1 |
| 4080 | 1200 | 155 | 155 | 180 | 180 | 216 | 1 / 1 |
| 4114 | 1767 | 102 | 102 | 127 | 127 | 167 | 1 / 1 |
| 4253 | 4100 | 184 | 184 | 209 | 209 | 236 | 1 / 1 |
| 4349 | 5700 | 169 | 169 | 194 | 194 | 223 | 1 / 1 |
| 4350 | 5700 | 169 | 169 | 194 | 194 | 257 | 1 / 1 |
| 4431 | 7067 | 139 | 139 | 164 | 164 | 196 | 1 / 1 |
| 4564 | 9267 | 199 | 199 | 224 | 224 | 261 | 1 / 1 |
| 4598 | 9834 | 139 | 139 | 164 | 164 | 222 | 1 / 1 |
| 4620 | 10200 | 158 | 158 | 183 | 183 | 225 | 1 / 1 |
| 4691 | 11400 | 107 | 107 | 132 | 132 | 190 | 1 / 1 |
| 4772 | 12734 | 139 | 139 | 164 | 164 | 197 | 1 / 1 |
| 4805 | 13300 | 184 | 184 | 209 | 209 | 250 | 1 / 1 |
| 4843 | 13934 | 155 | 155 | 180 | 180 | 218 | 1 / 1 |
| 4870 | 14367 | 197 | 197 | 222 | 222 | 261 | 1 / 1 |
| 4937 | 15500 | 200 | 200 | 225 | 225 | 281 | 1 / 1 |
| 4986 | 16300 | 175 | 175 | 200 | 200 | 252 | 1 / 1 |
| 5016 | 16800 | 170 | 170 | 195 | 195 | 249 | 1 / 1 |
| 5108 | 18334 | 128 | 128 | 153 | 153 | 193 | 1 / 1 |
| 5207 | 20000 | 178 | 178 | 203 | 203 | 251 | 1 / 1 |
| 5269 | 21034 | 143 | 143 | 168 | 168 | 212 | 1 / 1 |
| 5499 | 24867 | 109 | 109 | 134 | 134 | 176 | 1 / 1 |
| 5570 | 26034 | 125 | 125 | 150 | 150 | 190 | 1 / 1 |
| 5733 | 28767 | 139 | 139 | 164 | 364 | 375 | 3 / 3 |

Summary: the first NACK is generated **157 ms** after the gap is seen on average (102 to
200 ms); the repaired packet arrives **233 ms** after it on average (167 to 375 ms; the
pipeline's own count, from the first packet past the gap, is 227 ms mean, 375 ms max: the same
losses). Of each repair:

- *gap seen to first NACK generated*: 102 to 200 ms, two thirds of the total;
- *generated to left*: 0 ms every time (the RTCP session sends the NACK at once);
- *left to arrived*: 25 ms, the link;
- *arrived to RTX left*: 0 ms (the responder and the pacer answer at once), except seq 5733,
  whose first RTX was lost on the uplink: asked for twice more, RTX left at 364 ms;
- *RTX left to arrived*: 43 ms mean, the link (25 ms plus 0..40 ms).

So nearly all of the excess over a round trip is before the first request. The first request
waits 102 to 200 ms, spread evenly over one 100 ms band: a floor of about 100 ms, plus up to one
100 ms generator cycle. The generator holds a first request back by the reordering it learned
(`Reordering::allowance`: the latest a reordered packet came in the last 10 s, plus a quarter,
at most 500 ms; on this link reordering is real, up to 40 ms), and asks only on its 100 ms
cycle. libwebrtc asks as soon as a gap shows
(`modules/video_coding/nack_requester.cc` at a222406d, `OnReceivedPacket` sends
`GetNackBatch(kSeqNumOnly)` on the packet that reveals the gap) and again every round trip.
Phase 1's run with a 20 ms cycle (run 45308589888) made repairs slower (554 ms mean at 2 %
loss), so the cycle alone does not explain the floor; the allowance's lifetime and how the
"gap opened" instant is taken are the next things to look at. That is the retransmission
work's to decide; nothing here changes it.

## What the video pipeline asserts meanwhile, and the target figures

The pipeline's acceptance in calls (`docs/video-pipeline.md` 6) was relaxed because of this
latency: it asserts that the longest interval between rendered pictures is at most the slowest
repair plus 100 ms (it waits for nothing else). The figures the design set first stay the
**target**, to be asserted again once a repair takes about one round trip:

- two-peer call, 2 % loss, 25 ms + 0..40 ms, 500 kbit/s, 30 s: `freezeCount` = 0 (measured: 13
  freezes, 2.98 s);
- the same at 10 % loss: longest interval between rendered pictures under 500 ms (measured:
  654 ms).

## The NACK horizon (phase 1b)

Since phase 1b the pipeline tells the generator the oldest sequence number it can still use
(`RTCRtpReceiver::set_nack_horizon`, `NackControl::Horizon`). In the same runs, NACKs for
packets behind the horizon: 0 of 26 sequence numbers asked for (2 % loss) and 0 of 157 (the
capacity scenario, 1419 horizon moves).
