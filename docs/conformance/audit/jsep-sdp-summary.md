# JSEP and SDP area: audit summary

Clause-level audit of the specifications behind `rtci-sdp/`, `src/peer_connection/{mod,internal}.rs`,
`src/peer_connection/sdp/`, `src/rtp_transceiver/` and
`src/peer_connection/configuration/media_engine.rs`, at fork master 8916bc3. No test was run: every
verdict comes from reading the code and the tests.

How it was done, and what that means for the numbers: for each RFC every sentence with a BCP 14 keyword
was extracted mechanically and given a row (or folded into a row that says how many clauses it covers);
JSEP's and RFC 8830's lower-case procedure lists were added by hand. `tested` means I found a named test
whose flow or assertion depends on the behaviour; I read the assertions of the central ones
(`sdp_test.rs::test_populate_sdp`, the inline tests of `sdp/mod.rs` and `peer_connection/mod.rs`) and
relied on test names and inputs for the rest, so some `tested` rows may deserve `untested`. Where I was
not sure the verdict is `untested` or `partial`.

## Totals per spec

Counts are tested / untested / partial / missing / violated / n-a.

| Spec | File | MUST | SHOULD | MAY | Rows |
|---|---|---|---|---|---|
| RFC 9429 JSEP | [rfc9429.md](rfc9429.md) | 111 / 54 / 52 / 57 / 28 / 7 | 1 / 7 / 2 / 2 / 1 / 6 | 3 / 0 / 0 / 3 / 0 / 3 | 337 |
| RFC 8866 SDP (with RFC 4566 leftovers) | [rfc8866.md](rfc8866.md) | 21 / 14 / 13 / 1 / 1 / 7 | 4 / 8 / 0 / 2 / 2 / 10 | 18 / 2 / 6 / 11 / 0 / 1 | 121 |
| RFC 3264 offer/answer | [rfc3264.md](rfc3264.md) | 30 / 9 / 6 / 0 / 3 / 7 | 5 / 3 / 0 / 3 / 0 / 2 | 17 / 1 / 0 / 5 / 0 / 2 | 93 |
| RFC 9143 BUNDLE (obsoletes RFC 8843) | [rfc9143.md](rfc9143.md) | 33 / 14 / 10 / 8 / 5 / 5 | 0 / 3 / 0 / 2 / 0 / 1 | 3 / 0 / 0 / 3 / 0 / 0 | 87 |
| RFC 8853 simulcast | [rfc8853.md](rfc8853.md) | 12 / 0 / 4 / 7 / 3 / 4 | 2 / 0 / 0 / 2 / 0 / 3 | 2 / 0 / 1 / 2 / 0 / 0 | 42 |
| RFC 8851 rid | [rfc8851.md](rfc8851.md) | 8 / 0 / 3 / 8 / 4 / 4 | 1 / 0 / 0 / 0 / 0 / 2 | 4 / 1 / 0 / 3 / 0 / 2 | 40 |
| RFC 8830 msid | [rfc8830.md](rfc8830.md) | 6 / 2 / 7 / 3 / 1 / 0 | 0 / 0 / 1 / 0 / 0 / 0 | 1 / 0 / 1 / 0 / 0 / 0 | 22 |
| RFC 5888 grouping | [rfc5888.md](rfc5888.md) | 8 / 2 / 4 / 2 / 1 / 2 | 1 / 0 / 0 / 1 / 0 / 1 | 0 / 1 / 1 / 0 / 0 / 0 | 24 |
| RFC 8858 rtcp-mux-only | [rfc8858.md](rfc8858.md) | 1 / 6 / 0 / 4 / 2 / 3 | 1 / 0 / 0 / 1 / 0 / 0 | 0 / 0 / 0 / 2 / 0 / 0 | 20 |
| RFC 5761 rtcp-mux | [rfc5761.md](rfc5761.md) | 4 / 3 / 2 / 0 / 3 / 1 | 1 / 2 / 0 / 0 / 0 / 3 | 0 / 0 / 0 / 0 / 0 / 1 | 20 |
| RFC 8285 extmap | [rfc8285.md](rfc8285.md) | 18 / 3 / 5 / 0 / 3 / 4 | 3 / 0 / 0 / 2 / 0 / 3 | 4 / 1 / 3 / 2 / 0 / 1 | 52 |
| RFC 5576 ssrc attributes | [rfc5576.md](rfc5576.md) | 12 / 3 / 3 / 6 / 1 / 1 | 0 / 0 / 1 / 1 / 0 / 0 | 2 / 1 / 0 / 2 / 0 / 1 | 34 |
| RFC 8859 mux categories | [rfc8859.md](rfc8859.md) | 13 / 3 / 15 / 6 / 0 / 4 | 0 / 2 / 0 / 0 / 0 / 0 | 1 / 0 / 0 / 0 / 0 / 1 | 45 |

All 13 files: 937 rows: tested 351, untested 145, partial 140, missing 151, violated 58, n-a 92.
To call the area finished, 494 rows have to move: 349 need code (partial, missing, violated) and 145
need a test only.

Notes on the spec list: RFC 8843 was audited as RFC 9143, which obsoletes it. RFC 4566-era behaviour is
in rfc8866.md (rows `RFC8866-4566-n`). RFC 8866 section 8 (IANA), RFC 9429 section 7 (examples) and the
RFC 8859 tables for attributes the engine never touches were not enumerated row by row (one n-a row).

## Top gaps

1. **Descriptions are applied before they are fully checked.** `set_remote_description` changes the
   signaling state and creates transceivers, then runs the ICE and fingerprint checks; an answer is not
   compared with the offer (m= count, media type, proto, feedback, bundle group). RFC9429-5.10-1,
   5.8.3-11, 5.8.3-12, 5.11-6; RFC9143-7.4-1; RFC5888-9.2-4. Size M.
2. **RTCP attributes are written, never read.** `a=rtcp-mux`, `a=rtcp-rsize` are in every description
   whatever the peer said; `a=rtcp-mux-only` does not exist; an answer without rtcp-mux is used
   multiplexed. RFC5761-5.1.1-3, 5.1.1-5; RFC8858-4.4-2, 4.2-1; RFC9429-5.2.2-25, 5.3.1-35, 5.3.1-37,
   5.8.3-8. Size M.
3. **BUNDLE group handling.** The answer's group is taken from the first `a=group` line of any
   semantics; an offer with no group is answered with every port zero; one group only; BUNDLE
   attributes repeated in every section; no bundle-only; bundle policy is a stored value with no effect.
   RFC9429-5.3.1-30, 5.3.1-31, 4.1.1-3; RFC9143-7.1.3-3, 7.2-1, 5-2. Size S for the bugs, L for policies.
4. **Session version and DTLS role across renegotiation.** The o= version does not increment; the
   answer's `a=setup` ignores the live DTLS association; session-level `a=setup` is not read.
   RFC9429-5.2.2-1, 5.3.2-7, 5.8.1-12; RFC3264-8-2. Size S.
5. **Direction default.** A media section without a direction attribute is skipped instead of being
   sendrecv, and `create_answer` then fails. RFC8866-6.7-2; RFC3264-6.1-4. Size S.
6. **Simulcast answers are not applied; rid restrictions do not exist.** A remote answer that drops or
   pauses layers changes nothing on the sender; `pt=` and max-* restrictions are neither parsed, echoed
   nor exposed; `~` is written without RFC 7728. RFC8853-5.3.3-1, 5.3.3-4, 5.2-9; RFC8851-6.3-4, 6.4-1,
   5-1. Size M.
7. **msid.** `a=msid` without appdata (the form RFC 9429 tells senders to use) is dropped; only the last
   of several msid lines is kept; a disappearing msid does not end the track. RFC9429-5.8.2-22;
   RFC8830-3-5, 2-2, 3-7. Size S to M.
8. **RTP stream association.** No payload-type fallback, no MID re-association, no RTCP SDES MID /
   RtpStreamId items; the sender does not stamp MID or RID extensions (the application must).
   RFC9143-9.2-9, 9.2-12, 15-1, 15-2; RFC8853-5.5-2; RFC8851-4-2. Size M.
9. **Profile strings and legacy data sections.** Answers hard-code UDP/TLS/RTP/SAVPF and UDP/DTLS/SCTP
   instead of echoing the offer; `DTLS/SCTP` + `a=sctpmap` is treated as RTP. RFC9429-5.1.2-4, 5.1.2-6,
   5.3.1-39. Size S.
10. **Attributes with no implementation at all.** `a=tls-id`, LS groups, `a=imageattr`, `a=ptime` /
    `a=maxptime`, `b=` (TIAS / AS), `a=rtcp`, default-candidate m= / c= lines, `ice2`, header-extension
    directions, extended extmap ids, SSRC collision handling and `previous-ssrc`. RFC9429-5.2.1-44,
    5.2.1-53, 5.10-11, 5.2.2-7; RFC8285-7-4; RFC5576-5-1. Size M each.

## Bugs found (each has a reproduction idea in its spec file)

| Row | Bug |
|---|---|
| RFC9429-5.2.2-1 | o= session-version: nanoseconds + 1 on each call, not previous + 1 |
| RFC9429-5.3.1-31 | answer's BUNDLE group read from the first `a=group` line (an LS group listed first breaks it) |
| RFC9429-5.3.1-30 | offer without `a=group`: every answered section gets port 0 |
| RFC9429-5.3.2-7 | answer's `a=setup` not taken from the live DTLS association |
| RFC9429-5.8.1-12 | session-level `a=setup` ignored |
| RFC9429-5.8.2-22 | `a=msid` without appdata dropped; only the last msid line kept |
| RFC9429-5.10-1 | failed ICE / fingerprint checks leave the remote description half applied |
| RFC9429-5.1.2-6 | legacy `DTLS/SCTP` data section treated as RTP; `sctpmap` reader unreachable |
| RFC9429-4.1.19-1 | remote candidate with neither mid nor m= index accepted |
| RFC9429-5.2.2-30 | `create_offer` works (and assigns mids) in any signaling state |
| RFC9429-5.7-2 | rollback only through the method that set the offer |
| RFC8866-6.7-2 | section without direction attribute: skipped, then `create_answer` fails |
| RFC8866-5.14-11 | `a=fmtp` parameters containing a space are dropped |
| RFC8866-5.12-2 | received `k=` kept and re-serialized |
| RFC8866-5.6-1 | second `e=` / `p=` line is a parse error |
| RFC8866-5.3-2 | values trimmed: `s= ` becomes empty `s=` |
| RFC3264-6-4 | answer's `t=` always `0 0` |
| RFC9143-6-1 | `a=bundle-only` keeps a port-0 section alive outside any BUNDLE group |
| RFC9143-9.2-9 | undeclared SSRC without MID dropped although its payload type names one section |
| RFC8858-4.4-2 | answer without `a=rtcp-mux` accepted, RTCP still multiplexed |
| RFC8858-5.3-2 | every candidate also written as an RTCP (component 2) candidate |
| RFC5761-5.1.1-3 | offer without `a=rtcp-mux` answered with it |
| RFC5761-4-3 | payload types 64 to 95 accepted; marker-bit packets read as RTCP |
| RFC5888-4-1 | remote description with a repeated mid accepted |
| RFC8830-2-1 | stream id with a space written verbatim into `a=msid` |
| RFC5576-4.1-6 | unregistered `mslabel` / `label` source attributes written |
| RFC5576-5-3 | local SSRCs random with no uniqueness or collision check |
| RFC8853-5.3.3-1 | answer that drops simulcast not honoured |
| RFC8853-5.3.2-2 | two `a=simulcast` lines: last one used instead of disabling simulcast |
| RFC8853-5.2-9 | `~rid` written without pause/resume support |
| RFC8851-6.3-4 | rid restrictions dropped from the answer |
| RFC8851-6.2.2-4 | duplicate rid: first kept instead of all discarded |
| RFC8285-4.3-3 | two-byte header with non-zero appbits not parsed |
| RFC8285-4.1.2-4 | one-byte element with id 0 and non-zero length not treated as terminator |
| RFC8285-5-3 | `a=extmap` id above 255 (or 0) fails the whole description |
| RFC8285-7-4 | extmap direction dropped: `sendonly` offer answered as sendrecv |
| RFC8285-5-8 | session-level `a=extmap` ignored |

None of these was reproduced by running code (the audit is read-only); each is a reading of the cited
lines and should be confirmed with the test sketched in its file before it is fixed.
