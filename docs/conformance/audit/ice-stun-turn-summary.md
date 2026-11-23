# Clause audit summary: ICE, STUN, TURN, mDNS (area `ice-stun-turn`)

Audited at fork master 8916bc3, by reading code and tests; nothing was run. One file per spec
in this directory holds every clause with its verdict, evidence, work packages and bugs.

Verdicts: `tested` (implemented, and a test that would fail if it broke), `untested`
(implemented, no such test), `partial`, `missing`, `violated` (code does the opposite),
`n/a` (does not bind this engine). A clause in "Not implemented, on purpose" is still
`missing`.

## Totals per spec

The table is recounted from the files' tables as they stand after the conformance work. The
sections after it ("What the numbers say", "Top gaps", "Bugs found") describe the audit as
first made at 8916bc3; each file's rows and notes say what has been done since.

Rows, not sentences: a few rows group several clauses that bind only a server or a spec
writer, and say so. Behaviour the RFCs state without a BCP 14 keyword ("the agent sets ...")
is listed too. Where a file counts those separately the "proc" row below carries them;
`rfc8445.md`, `rfc7675.md`, `rfc8489.md` and `rfc5780.md` count them as MUST.

| Spec | File | Level | tested | untested | partial | missing | violated | n/a |
|---|---|---|---|---|---|---|---|---|
| RFC 8445 ICE | `rfc8445.md` | MUST | 121 | 6 | 7 | 0 | 0 | 22 |
| | | SHOULD | 17 | 0 | 2 | 2 | 0 | 28 |
| | | MAY | 6 | 1 | 0 | 3 | 0 | 6 |
| RFC 8838 trickle ICE | `rfc8838.md` | MUST | 26 | 1 | 4 | 0 | 0 | 3 |
| | | SHOULD | 5 | 5 | 0 | 0 | 0 | 3 |
| | | MAY | 5 | 1 | 1 | 0 | 0 | 1 |
| RFC 8839 SDP for ICE | `rfc8839.md` | MUST | 33 | 17 | 13 | 17 | 3 | 14 |
| | | SHOULD | 1 | 0 | 1 | 4 | 0 | 2 |
| | | MAY | 6 | 1 | 0 | 2 | 0 | 3 |
| RFC 6544 ICE-TCP | `rfc6544.md` | MUST | 22 | 4 | 2 | 1 | 0 | 10 |
| | | SHOULD | 9 | 1 | 2 | 0 | 0 | 21 |
| | | MAY | 3 | 1 | 0 | 4 | 0 | 1 |
| RFC 7675 consent | `rfc7675.md` | MUST | 12 | 1 | 0 | 0 | 0 | 0 |
| | | SHOULD | 2 | 0 | 0 | 0 | 0 | 2 |
| | | MAY | 0 | 0 | 0 | 0 | 0 | 2 |
| RFC 8421 dual stack | `rfc8421.md` | MUST | 1 | 0 | 0 | 0 | 0 | 0 |
| | | SHOULD | 5 | 0 | 0 | 0 | 0 | 2 |
| | | MAY | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC 8489 STUN | `rfc8489.md` | MUST | 90 | 2 | 13 | 0 | 0 | 14 |
| | | SHOULD | 17 | 4 | 1 | 1 | 0 | 1 |
| | | MAY | 5 | 0 | 0 | 3 | 0 | 0 |
| RFC 5780 NAT discovery | `rfc5780.md` | MUST | 1 | 0 | 1 | 1 | 0 | 1 |
| | | SHOULD | 0 | 0 | 0 | 0 | 0 | 0 |
| | | MAY | 1 | 0 | 0 | 2 | 0 | 0 |
| RFC 8656 TURN client | `rfc8656.md` | MUST | 32 | 0 | 0 | 0 | 0 | 20 |
| | | SHOULD | 12 | 0 | 0 | 1 | 0 | 10 |
| | | MAY | 12 | 0 | 0 | 0 | 0 | 12 |
| | | proc | 36 | 1 | 1 | 2 | 0 | 0 |
| RFC 6062 TURN TCP allocations | `rfc6062.md` | MUST | 19 | 0 | 0 | 0 | 0 | 5 |
| | | SHOULD | 0 | 0 | 0 | 0 | 0 | 0 |
| | | MAY | 3 | 0 | 0 | 0 | 0 | 1 |
| | | proc | 10 | 0 | 0 | 0 | 0 | 0 |
| mDNS ICE candidates draft -03 | `draft-ietf-mmusic-mdns-ice-candidates.md` | MUST | 9 | 2 | 1 | 0 | 0 | 0 |
| | | SHOULD | 8 | 0 | 2 | 0 | 0 | 5 |
| | | MAY | 1 | 1 | 0 | 2 | 0 | 1 |
| | | proc | 7 | 1 | 2 | 0 | 0 | 0 |
| RFC 6762 mDNS (parts used) | `rfc6762.md` | MUST | 58 | 0 | 3 | 0 | 0 | 9 |
| | | SHOULD | 27 | 0 | 3 | 0 | 0 | 8 |
| | | MAY | 4 | 0 | 0 | 1 | 0 | 1 |
| | | proc | 2 | 0 | 0 | 0 | 0 | 0 |
| RFC 8828 IP handling | `rfc8828.md` | MUST | 0 | 0 | 0 | 0 | 0 | 7 |
| | | SHOULD | 0 | 0 | 0 | 0 | 0 | 3 |
| | | MAY | 0 | 0 | 0 | 0 | 0 | 1 |
| | | proc (controls) | 2 | 1 | 1 | 1 | 0 | 0 |

## What the numbers say

- **ICE is pion's simplified agent, not RFC 8445's.** There is no ordered checklist, no
  Frozen state, no triggered-check queue, no Ta pacing, no STUN retransmission and no
  checklist states; every pair gets a new request every 200 ms. It interoperates with
  browsers, which is why the feature-level claims hold, but about half of RFC 8445's
  procedure is `partial`, `missing` or `violated`.
- **STUN is RFC 5389**, and so is the TURN client (RFC 5766). Nothing RFC 8489 / 8656 added
  exists beyond code points: SHA-256 integrity, USERHASH, PASSWORD-ALGORITHMS, the nonce
  cookie, the ICMP attribute, dual allocation, address-family requests.
- **mDNS is a resolver and a bare responder**: no probing, announcing, goodbye, cache-flush
  bit, cache or rate limit.
- **Gathering is the application's** (sans-I/O). That turns most of RFC 8445 §5.1.1, all of
  RFC 8828 and the socket-level clauses of TURN and mDNS into `n/a`. If "implements all of
  it" is meant literally, a gathering layer the project owns needs its own audit.

## Top gaps

In order of importance. IDs are in the per-spec files; sizes are S / M / L / XL.

1. **The RFC 8445 checklist (XL).** Correct pair priority and ordering, pruning, Frozen state
   and foundations, triggered-check FIFO, Ta pacing (50 ms, 5 ms floor), real STUN
   transactions with RTO >= 500 ms, a 100-pair limit, checklist / ICE states including
   Completed, failure of a nomination. `rfc8445.md` WP-ICE-1; shared by `rfc8838.md` gaps 2
   and 4, `rfc6544.md` gap 5, `rfc8489.md` retransmission package.
2. **STUN message validation (S, security).** Attributes after MESSAGE-INTEGRITY are obeyed
   (a replayed check with an appended ICE-CONTROLLED flips the ICE role), FINGERPRINT is never
   verified, unknown comprehension-required attributes are never detected. `rfc8489.md`
   packages 1 and 2; `rfc8445.md` bug 13.
3. **Role conflict (M).** A request is answered with a 487 *and* a success; a 487 response
   from the peer is dropped unread; `>` instead of `>=`. `rfc8445.md` WP-ICE-2.
4. **Checks before the remote description (M).** Binding requests are dropped until remote
   credentials exist; RFC 8445 section 7.3 requires an immediate answer. `rfc8445.md`
   WP-ICE-3, `rfc8839.md` gap 5.
5. **Consent freshness timing and restart (S + M).** Checks every 2 s with no jitter (the
   RFC forbids under 4 s and requires randomization); during an ICE restart data flows on
   the old path with no consent checks; the 30 s expiry can be configured away.
   `rfc7675.md` WP-CONSENT-1..3.
6. **mDNS privacy leaks (M).** Local relay candidates pair with resolved remote mDNS
   candidates (the hidden address reaches the TURN server); a peer-reflexive address shows
   in stats; srflx `raddr` is never blanked; a relay-only agent still resolves `.local`
   names. `draft-ietf-mmusic-mdns-ice-candidates.md` gaps 1 to 3.
7. **TURN allocation life cycle (M).** A 437 or any error to a Refresh is swallowed, a lost
   release revives the allocation, channel bindings outlive their allocation, client-side
   permissions and channels never expire, the first Allocate response's code is never read.
   `rfc8656.md` gaps 1 and 2.
8. **End-of-candidates and trickle bookkeeping (M).** The remote and local end-of-candidates
   indications do not reach the agent: candidates are accepted after them and failure waits
   for a timer; a signalled candidate that duplicates a peer-reflexive one makes dead pairs.
   `rfc8838.md` gaps 1 to 3.
9. **RFC 8489 / RFC 8656 features (L).** SHA-256 integrity, USERHASH, PASSWORD-ALGORITHMS,
   nonce cookie; REQUESTED-ADDRESS-FAMILY (no IPv6 relay), dual allocation, ICMP attribute,
   300 Try Alternate, DONT-FRAGMENT / EVEN-PORT / RESERVATION-TOKEN on Allocate.
   `rfc8489.md` packages 3, 8, 9; `rfc8656.md` gaps 3 to 8.
10. **SDP for ICE (S to L).** One unparsable `a=candidate` fails the whole remote
    description; no `ice2`, `ice-pacing`, `remote-candidates` or `ice-mismatch`; candidates
    written as components 1 and 2 and remote component 2 paired as media; the answer's `m=`
    protocol is always UDP. `rfc8839.md` gaps 1 to 4, 8 to 10.

Next in line: candidate priorities and foundations with RFC 8421 ordering (`rfc8445.md`
WP-ICE-5, `rfc8421.md`); the lite agent (`rfc8445.md` WP-ICE-6); the mDNS responder life
cycle, flood control and probing (`rfc6762.md`); ICE-TCP reconnection and `tcptype` on
non-host candidates (`rfc6544.md` gaps 1 and 2); RFC 6062 as a whole (L to XL, on the
"not implemented, on purpose" list).

Owner decisions rather than work: whether the controlled agent keeps following the latest
nomination (RFC8445-8.1.1-4, violated by design for Chrome's renomination); whether data is
accepted only from the selected pair's remote (RFC8445-12.2-1, violated by design); whether
bad-credential requests stay silently dropped instead of answered 400 / 401; whether
gathering stays outside the project; RFC 5780 and RFC 6062 as explicit non-goals.

## Bugs found

Found by reading; none was run. Each has a reproduction idea in its file.

Most serious:

- An ICE-CONTROLLED / ICE-CONTROLLING attribute appended after MESSAGE-INTEGRITY flips the
  agent's role (`rtc-ice/src/agent/mod.rs:1572-1663`, `rtc-stun/src/integrity.rs:146-156`).
- Role conflict answers one request with both a 487 and a success response
  (`rtc-ice/src/agent/mod.rs:1600`, `:1760`); a 487 from the peer is ignored (`:1674`).
- Binding requests are dropped until the remote description is applied
  (`rtc-ice/src/agent/mod.rs:1690`).
- The nominated pair is never given up: the agent fails instead of using another Succeeded
  pair (`rtc-ice/src/agent/agent_selector.rs:269`).
- An ICE restart with `SettingEngine::set_ice_credentials` reuses the old credentials, so
  only one side restarts (`src/peer_connection/internal.rs:1682`).
- Data flows without consent checks during an ICE restart
  (`rtc-ice/src/agent/mod.rs:973-997`); consent checks run every 2 s without jitter.
- TURN: ChannelData length wraps at 64 KiB (`rtc-turn/src/proto/chandata.rs:91`); a 437 to a
  Refresh is swallowed (`rtc-turn/src/client/relay.rs:533`); a lost release revives the
  allocation (`relay.rs:307`); channel bindings outlive their allocation
  (`rtc-turn/src/client/mod.rs:186`); the first Allocate response is treated as a 401
  whatever it is (`mod.rs:748`).
- mDNS: a non-address record hides every record after it in a response
  (`rtc-mdns/src/proto/mod.rs:723`); only four answers are read (`:722`); query retries
  never back off and, without a timeout, never end (`:1064`).
- `rtc-stun::Client` truncates responses over 120 bytes (`rtc-stun/src/client.rs:203`,
  `message.rs:432`) and accepts any message with a known transaction id as the response.
- One unparsable remote `a=candidate` fails `set_remote_description`
  (`src/peer_connection/sdp/mod.rs:1899`); remote candidates are accepted after
  end-of-candidates (`src/peer_connection/mod.rs:1975`).
- A reopened TCP connection never becomes the media path (`rfc6544.md` B4).

Counts per file: `rfc8445.md` 13, `rfc7675.md` 3, `rfc8421.md` 1, `rfc8838.md` 3,
`rfc8839.md` 9, `rfc6544.md` 4, `rfc8489.md` 10, `rfc8656.md` 10,
`draft-ietf-mmusic-mdns-ice-candidates.md` and `rfc6762.md` 14 between them. A few appear in
two files (restart credentials, `tcptype` parsing, equal priorities).

## Not finished

- Every spec in the area has a file and every section was covered. Server-only and
  spec-writer clauses are grouped into `n/a` rows rather than itemised.
- RFC 5780 is not used by the code; its discovery procedures are not enumerated.
- RFC 6762: a few verdicts on long paragraphs (5.2 first-query jitter, 8.1 probe timing)
  rest on knowledge of the text rather than a second read; check them if they become work.
- Some `tested` verdicts rest on tests matched by name and flow, not on reading every
  assertion (noted in `rfc8489.md`).
- Levels are counted three ways across files ("proc" rows inside MUST, or apart); the table
  above says which.
- No bug was reproduced by running anything.
