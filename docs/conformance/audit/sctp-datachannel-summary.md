# SCTP and data channels: audit summary

Area `sctp-datachannel`, audited against fork master 8916bc3 by reading the code and the tests;
nothing was run. One file per specification sits beside this one. Each row there has a stable ID,
the code location and the test that proves it, or says there is none.

Verdicts: `tested` (implemented, and a test would fail if it broke), `untested` (implemented, no
such test), `partial`, `missing`, `violated` (the code does the opposite), `n/a` (does not bind a
single-path, sans-I/O endpoint under DTLS). MUST includes MUST NOT, SHALL, REQUIRED and procedure
steps a specification states without a keyword; SHOULD includes SHOULD NOT and RECOMMENDED; MAY
counts optional features.

## Totals per specification

| Spec | Clauses | Level | tested | untested | partial | missing | violated | n/a |
|---|---|---|---|---|---|---|---|---|
| [RFC 9260](rfc9260.md) SCTP | 577 | MUST | 120 | 72 | 36 | 28 | 27 | 32 |
| | | SHOULD | 46 | 27 | 19 | 64 | 9 | 25 |
| | | MAY | 13 | 0 | 5 | 38 | 2 | 14 |
| [RFC 3758](rfc3758.md) PR-SCTP | 66 | MUST | 23 | 7 | 5 | 2 | 2 | 4 |
| | | SHOULD | 4 | 3 | 0 | 5 | 0 | 2 |
| | | MAY | 3 | 0 | 0 | 6 | 0 | 0 |
| [RFC 7496](rfc7496.md) PR policies | 10 | MUST | 2 | 2 | 1 | 1 | 0 | 0 |
| | | SHOULD | 0 | 0 | 0 | 0 | 0 | 0 |
| | | MAY | 2 | 0 | 0 | 1 | 0 | 1 |
| [RFC 6525](rfc6525.md) stream reconfiguration | 81 | MUST | 14 | 9 | 10 | 23 | 7 | 0 |
| | | SHOULD | 0 | 1 | 0 | 10 | 0 | 1 |
| | | MAY | 0 | 0 | 0 | 5 | 0 | 1 |
| [RFC 8260](rfc8260.md) I-DATA, schedulers | 52 | MUST | 5 | 2 | 0 | 33 | 0 | 0 |
| | | SHOULD | 1 | 0 | 0 | 1 | 0 | 0 |
| | | MAY | 0 | 0 | 1 | 8 | 0 | 1 |
| [RFC 8261](rfc8261.md) SCTP over DTLS | 27 | MUST | 2 | 4 | 0 | 3 | 0 | 4 |
| | | SHOULD | 0 | 1 | 1 | 2 | 1 | 2 |
| | | MAY | 2 | 0 | 0 | 5 | 0 | 0 |
| [RFC 8831](rfc8831.md) data channels | 42 | MUST | 19 | 4 | 1 | 1 | 1 | 1 |
| | | SHOULD | 2 | 2 | 0 | 6 | 1 | 1 |
| | | MAY | 1 | 0 | 0 | 2 | 0 | 0 |
| [RFC 8832](rfc8832.md) DCEP | 34 | MUST | 20 | 6 | 2 | 1 | 3 | 0 |
| | | SHOULD | 0 | 0 | 0 | 0 | 0 | 0 |
| | | MAY | 0 | 2 | 0 | 0 | 0 | 0 |
| [RFC 8841](rfc8841.md) SDP for SCTP over DTLS | 60 | MUST | 12 | 8 | 8 | 13 | 4 | 8 |
| | | SHOULD | 2 | 0 | 0 | 0 | 0 | 1 |
| | | MAY | 2 | 0 | 0 | 2 | 0 | 0 |
| [RFC 9653](rfc9653.md) zero checksum | 22 | MUST | 3 | 3 | 0 | 3 | 0 | 6 |
| | | SHOULD | 0 | 0 | 0 | 1 | 0 | 0 |
| | | MAY | 0 | 0 | 0 | 5 | 0 | 1 |
| **Area** | **971** | MUST | 220 | 117 | 63 | 108 | 44 | 55 |
| | | SHOULD | 55 | 34 | 20 | 89 | 11 | 32 |
| | | MAY | 23 | 2 | 6 | 72 | 2 | 18 |

Of the 552 MUST clauses that bind this engine, 220 are tested; 117 are implemented without a test;
215 are partial, missing or violated.

## Top gaps

Ordered by what breaks for a real peer first. Sizes: S under a day, M a few days, L one to two
weeks, XL more. Details and row IDs are in the per-specification files.

1. **Tolerant parsing of chunks and parameters (M; RFC 9260 3.2, 3.2.1, 3.2.2; RFC 6525 4; RFC 8260 2).**
   One unknown chunk type, one unhandled standard parameter (Supported Address Types, Cookie
   Preservative, RE-CONFIG parameters 14, 15, 17, 18) or a HEARTBEAT ACK drops the whole packet,
   bundled DATA included, and nothing is reported back.
2. **Stream count negotiation and invalid stream ids (S; RFC 9260 5.1.1, 6.5).** The counts are
   paired crosswise, and a DATA chunk on a stream beyond the count is never acknowledged, which
   stalls the association.
3. **Unexpected INIT and failed chunk checks close a live association (M; RFC 9260 5.2, 3.3.2, 3.3.3).**
   A late copy of the peer's INIT, or any INIT / INIT ACK failing validation, ends an established
   association where the RFC says to answer or discard and leave it alone.
4. **Stream reset reliability (S to M; RFC 6525 5).** The answering reset is never retransmitted, a
   request is given up silently after five expiries, an empty stream list resets nothing, sequence
   numbers are not checked, and several requests fly at once.
5. **Bad DATA_CHANNEL_OPEN handling (M; RFC 8832 6).** An OPEN on a stream in use, a malformed OPEN
   and user data on an unopened stream must reset the stream; they are acknowledged or returned as
   an error. Ordered sending until the ACK is not kept.
6. **ABORT and out-of-the-blue handling (M; RFC 9260 8.4, 8.5.1, 5.1, 12.4).** No ABORT is sent for a
   refused or invalid INIT, a SACK of an unsent TSN or a stray packet; the T bit is never read or
   set; a closed association keeps processing packets.
7. **Congestion control to RFC 9260 (M; RFC 9260 7.2).** Slow start can double cwnd on one SACK,
   the Fast Recovery exit point is too low, `partial_bytes_acked` rules, idle decay, Max.Burst and
   a reset on an ICE path change are absent.
8. **Receive window and acknowledgement timing (S; RFC 9260 6.2, 5.1, 9.2).** No window-update SACK
   when the application drains a closed window (the sender waits for its T3 probe), no immediate
   SACK for the first DATA or in SHUTDOWN-SENT, no receiver silly-window avoidance.
9. **SDP-driven SCTP lifecycle (S for the checks, L for the rest; RFC 8841).** A rejected data
   m-section still starts SCTP, `a=sctp-port` is not validated (missing, 0 and out of range are
   accepted), only the DTLS client sends INIT, and port change / re-establishment / `a=tls-id`
   are absent.
10. **PR-SCTP negotiation and receive side (S; RFC 3758).** Forward-TSN-Supported (49152) is never
    sent and is ignored in a received INIT; FORWARD TSN is applied by the local stream setting, not
    by what the peer sent; an ordered timed message is sent after its lifetime ran out in the queue.
11. **Heartbeat and failure detection (M; RFC 9260 8.1, 8.3).** No HEARTBEAT is ever sent, there is
    no default retransmission limit, and shutdown retransmissions are unbounded.
12. **Path MTU discovery and packet size (L, interim S; RFC 8261 4, 6; RFC 9260 7.3).** Static 1191
    byte packets, no PAD chunk or probing, and FORWARD TSN / RE-CONFIG are not bounded by the MTU.
13. **Features listed as not implemented on purpose.** I-DATA and I-FORWARD-TSN (XL, RFC 8260; an
    ABORT on an un-negotiated I-DATA is S), zero checksum (M, RFC 9653), Incoming SSN Reset, SSN/TSN
    Reset and Add Streams (M to L, RFC 6525), State Cookie MAC and lifetime (M, RFC 9260 5.1.3).
    Each is `missing` and counted; reaching 100% needs either the work or a recorded decision.
14. **Tests for the 151 `untested` MUST and SHOULD rows (M in total).** Checksum rejection, tag and
    port rules, INIT validation, HEARTBEAT reply, simultaneous shutdown, timer retransmissions,
    cwnd bounds, DCEP edge cases.

## Bugs found

Thirty-seven in all, each with a reproduction idea in its file. The ones that can end or stall an
association with a conforming peer:

- RFC 9260 B1: Gap Ack Blocks are wrong across the TSN wrap, and a peer running this engine then
  closes the association (`rtc-sctp/src/queue/payload_queue.rs:205-236`).
- RFC 9260 B6: a late copy of the peer's INIT closes an established association
  (`rtc-sctp/src/association/mod.rs:1139-1146`, `632-634`).
- RFC 9260 B10 with B2: DATA on a stream beyond the (crosswise) negotiated count is never
  acknowledged (`mod.rs:1446-1457`, `1149-1152`).
- RFC 9260 B3 / B5: an unknown chunk or an unhandled standard parameter drops the packet
  (`rtc-sctp/src/packet.rs:155`, `rtc-sctp/src/param/mod.rs:74-78`).
- RFC 9260 B4: a zero-length `write` consumes a stream sequence number (`stream.rs:553-617`).
- RFC 6525 bug 1: the answering stream reset is never retransmitted (`mod.rs:2457-2474`).
- RFC 6525 bug 5: data written after `Stream::stop` keeps the old SSN sequence.
- RFC 3758 bugs 8 and 9: PR-SCTP negotiated by parameter 49152 is ignored on the accepting side;
  FORWARD TSN is applied by the local stream setting.
- RFC 8841 bug 7: a rejected data m-section still starts the SCTP transport.
- RFC 8832 bugs 1 and 2: an OPEN on an existing channel is acknowledged; a malformed OPEN leaves the
  stream half open.

The full lists: RFC 9260 B1 to B13, RFC 6525 bugs 1 to 7, RFC 3758 bugs 8 to 11, RFC 8260 bugs 12
and 13, RFC 8261 / 8831 / 8832 / 8841 bugs 1 to 11.

## Coverage

Every section of the ten specifications was read. Multi-homing, path verification, ICMP and the
IANA rules of RFC 9260 are `n/a` rows. RFC 9260 section 11 (the abstract upper-layer interface) and
sections 13 to 15 have summary rows, not one row per primitive. DTLS internals behind RFC 8261
(compression, record size) were checked at the call sites only and are `untested`.
