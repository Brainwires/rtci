# DTLS / SRTP conformance audit: summary (area `dtls-srtp`)

Clause-level audit of 18 specifications against fork master 8916bc3, read-only (no test was run; every bug below is a reading of the code with a reproduction idea, not an observed failure). One file per spec in this directory. Verdict order in every cell: tested / untested / partial / missing / violated / n-a.

| Spec | Subject | File | MUST | SHOULD | MAY |
|---|---|---|---|---|---|
| RFC 6347 | DTLS 1.2 | [rfc6347.md](rfc6347.md) | 29 / 11 / 2 / 4 / 1 / 1 | 6 / 6 / 3 / 9 / 3 / 3 | 5 / 1 / 0 / 2 / 0 / 2 |
| RFC 5246 | TLS 1.2 as DTLS uses it (+ RFC 8422 rows) | [rfc5246.md](rfc5246.md) | 36 / 20 / 10 / 12 / 6 / 8 | 1 / 4 / 0 / 0 / 0 / 3 | 7 / 2 / 0 / 1 / 0 / 0 |
| RFC 9147 | DTLS 1.3 (feature rows) | [rfc9147.md](rfc9147.md) | 0 / 1 / 0 / 31 / 0 / 1 | 0 / 0 / 0 / 11 / 0 / 0 | 0 / 0 / 0 / 1 / 0 / 0 |
| RFC 5764 | DTLS-SRTP | [rfc5764.md](rfc5764.md) | 17 / 3 / 1 / 1 / 2 / 10 | 4 / 1 / 1 / 3 / 0 / 6 | 4 / 0 / 0 / 4 / 0 / 3 |
| RFC 8842 | SDP for DTLS | [rfc8842.md](rfc8842.md) | 12 / 3 / 11 / 12 / 1 / 7 | 0 / 0 / 0 / 1 / 0 / 0 | 3 / 0 / 0 / 0 / 0 / 1 |
| RFC 8122 | Fingerprint attribute | [rfc8122.md](rfc8122.md) | 9 / 3 / 6 / 0 / 0 / 3 | 0 / 1 / 0 / 0 / 0 / 4 | 1 / 0 / 0 / 0 / 0 / 2 |
| RFC 7983 | Demultiplexing | [rfc7983.md](rfc7983.md) | 3 / 1 / 0 / 0 / 0 / 1 | 0 / 0 / 0 / 0 / 0 / 0 | 0 / 1 / 0 / 0 / 0 / 2 |
| RFC 9443 | Demultiplexing update (QUIC) | [rfc9443.md](rfc9443.md) | 3 / 2 / 0 / 0 / 0 / 2 | 0 / 0 / 0 / 0 / 0 / 0 | 0 / 1 / 0 / 1 / 0 / 1 |
| RFC 7627 | Extended master secret | [rfc7627.md](rfc7627.md) | 6 / 1 / 1 / 0 / 0 / 3 | 5 / 0 / 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 / 0 / 0 |
| RFC 5746 | Renegotiation indication | [rfc5746.md](rfc5746.md) | 2 / 1 / 3 / 6 / 0 / 6 | 2 / 2 / 0 / 0 / 0 / 1 | 0 / 0 / 0 / 0 / 0 / 0 |
| RFC 9146 | Connection ID for DTLS 1.2 (feature rows) | [rfc9146.md](rfc9146.md) | 2 / 1 / 0 / 10 / 0 / 0 | 0 / 0 / 0 / 0 / 0 / 1 | 0 / 0 / 0 / 1 / 0 / 0 |
| RFC 3711 | SRTP | [rfc3711.md](rfc3711.md) | 55 / 10 / 7 / 6 / 3 / 12 | 7 / 3 / 3 / 1 / 0 / 2 | 3 / 0 / 1 / 8 / 0 / 3 |
| RFC 7714 | AES-GCM SRTP | [rfc7714.md](rfc7714.md) | 18 / 4 / 6 / 5 / 2 / 4 | 1 / 1 / 0 / 0 / 0 / 1 | 1 / 0 / 0 / 3 / 0 / 1 |
| RFC 6904 | Encrypted header extensions | [rfc6904.md](rfc6904.md) | 0 / 1 / 0 / 12 / 0 / 10 | 0 / 0 / 0 / 2 / 0 / 1 | 0 / 0 / 0 / 1 / 0 / 0 |
| RFC 9335 | Cryptex | [rfc9335.md](rfc9335.md) | 16 / 5 / 1 / 0 / 0 / 1 | 0 / 0 / 0 / 0 / 0 / 1 | 1 / 1 / 1 / 1 / 0 / 0 |
| RFC 6188 | AES-192 / AES-256 CM | [rfc6188.md](rfc6188.md) | 4 / 0 / 0 / 0 / 0 / 1 | 1 / 0 / 2 / 1 / 0 / 0 | 4 / 1 / 0 / 8 / 0 / 1 |
| RFC 8827 | WebRTC security architecture | [rfc8827.md](rfc8827.md) | 14 / 11 / 1 / 10 / 1 / 17 | 1 / 0 / 0 / 1 / 0 / 4 | 1 / 0 / 0 / 2 / 0 / 0 |
| RFC 8826 | Security considerations | [rfc8826.md](rfc8826.md) | 2 / 2 / 1 / 0 / 0 / 2 | 6 / 1 / 0 / 1 / 0 / 0 | 0 / 0 / 0 / 0 / 0 / 0 |
| **All** | | | **228 / 80 / 50 / 109 / 16 / 89** | **34 / 19 / 9 / 30 / 3 / 27** | **30 / 7 / 2 / 33 / 0 / 16** |

782 rows in all. Of the 483 MUST rows that bind the engine, 228 are `tested` (47%), 80 `untested`, 50 `partial`, 109 `missing`, 16 `violated`. RFC 9147 and RFC 9146 are counted by feature row (one row stands for several clauses; each file says how many), so DTLS 1.3 weighs 31 MUST rows here and far more clauses in the text. Without those two specs and RFC 6904, which are not implemented at all, the MUST count is 226 tested of 425 binding.

## Top gaps, in order of importance

Sizes: S under a day, M a few days, L one to two weeks, XL more.

1. **The DTLS server never verifies the client's Finished (S).** RFC5246-7.4.9-2,
   `rtc-dtls/src/flight/flight4.rs:467`. The one check that confirms the handshake transcript to the
   server is absent; the client side has it but no negative test.
2. **Unauthenticated datagrams can end a handshake (S).** A plaintext application-data record
   (`conn/mod.rs:1025`) or a ClientHello with a wrong cookie (`flight2.rs:86`) fails the
   association; RFC6347-4.1.2.7-1, -4.2.1-18. The crate already defends against the same class
   after completion.
3. **SRTCP index wraps at 2^31 and keeps the key (S); no key-exhaustion handling at all (M).**
   RFC3711-3.4-16, RFC5764-4.4-2, RFC7714-9.4-1. Keystream / nonce reuse after 2^31 SRTCP packets;
   the receiver also follows a ROC wrap.
4. **Hello parsing (S).** A ClientHello with a non-empty session_id is misparsed, and hellos without
   an extensions block are dropped; RFC5246-7.4.1.2-1, -7.4.1.2-6.
5. **The answer to a re-offer can flip the established DTLS role (S).** RFC8842-5.3-6,
   `src/peer_connection/mod.rs:1036`; with an ICE restart in the same exchange the engine tears its
   own session down.
6. **Extension and algorithm negotiation in the DTLS 1.2 handshake (S + M).** ServerHello carries
   extensions the client did not send (RFC5246-7.4.1.4-1), unknown extensions from a server are not
   refused, renegotiation_info is never validated (RFC 5746 3.4, 3.6), and the peer's
   signature_algorithms / CertificateRequest lists are ignored (RFC5246-7.4.3-1, -7.4.8-2).
7. **A peer that negotiates no `use_srtp` cannot connect (S).** Client aborts, server leaves the
   transport in `connecting`; affects data-channel-only DTLS peers. RFC 5764, `handler/dtls.rs:543`.
8. **Fingerprint and setup handling (M).** Only sha-256 fingerprints are accepted or produced
   (RFC8122-5-8, -5-11), a changed fingerprint or setup without an ICE restart is ignored
   (RFC8842-3.1-1), session-level `a=setup` is not read (RFC8842-5.3-10), `tls-id` is absent
   (12 MUST rows of RFC 8842).
9. **Handshake transport robustness (S to M).** No retransmission backoff (fixed 1 s, gives up after
   8 s), overlapping fragments never reassemble, handshake datagrams exceed the configured MTU by
   25 bytes, no 2^14 record limit either way; RFC6347-4.2.4.1-2, -4.2.3-5, -4.1.1-2, -4.1.1.1-3.
10. **Known-answer coverage of the crypto that both ends share (S).** No RFC 7714 vectors (AES-256-GCM
    is in the default offer on round-trip tests only), no extended-master-secret vector, no
    transcript vector for the cookie exchange, GCM / ChaCha20 DTLS records tested only against
    themselves. A mistake made on both ends passes every test today. Also: E=0 SRTCP under GCM
    cannot be received (RFC7714-9.3-1).

Further down: secret hygiene (master secret, premaster, key block, SRTP master keys held in plain
`Vec<u8>`; RFC5246-7.2.2-1, RFC3711-3.2.1-4), replay-window lower bounds (32 for DTLS, 64 for SRTP)
not enforced, alert descriptions (no_certificate(41) is sent; no no_renegotiation), the
demultiplexer has no explicit drop and no 256-value table test, and the `untested` rows that hold by
construction and need a negative test each.

## Not implemented at all (decisions for the owner)

| Item | Spec | Size | In "Not implemented, on purpose" today |
|---|---|---|---|
| DTLS 1.3 | RFC 9147 | XL | yes |
| Connection ID | RFC 9146 | L | yes |
| Encrypted header extensions | RFC 6904 (and RFC 7714 8.3) | L | no |
| `tls-id` | RFC 8842 | M | no |
| Identity assertions (`a=identity`) | RFC 8827 5, 7.4 | L | no |
| TLS session resumption | RFC 5246 7.3 | L | no |
| TLS renegotiation | RFC 5246, RFC 5746 3.5 / 3.7 | L | no |
| Stateless cookie; new association on a live 5-tuple | RFC 6347 4.2.1, 4.2.8 | M | no |
| MKI, key derivation rate, AES-f8, NULL cipher, AES-192 | RFC 3711, RFC 6188 | M | MKI only |
| AES-256-CM profiles in `use_srtp` | RFC 6188 (implemented in `rtc-srtp`, not negotiable) | S | no |

Each of these is `missing` and counted in its file. To reach a literal 100% the list above is the
bulk of the work; to reach "every claim made is proven" the table needs the rows marked "no" added
to `docs/conformance.md`.

## Bugs found

DTLS 1.2 stack (`rfc6347.md`, `rfc5246.md`, `rfc5746.md`, `rfc7627.md`):

1. Server does not verify the client's Finished (`flight4.rs:467`, `flight6.rs:33`).
2. ClientHello with a non-empty session_id is misparsed (`handshake_message_client_hello.rs:157`).
3. ClientHello / ServerHello without an extensions block are dropped (`...client_hello.rs:175`,
   `...server_hello.rs:131`).
4. ServerHello carries renegotiation_info, supported_groups and ec_point_formats whether or not the
   client sent them (`flight4.rs:563`); a test pins the first.
5. A plaintext application-data record during the handshake fails the association
   (`conn/mod.rs:1025`).
6. A ClientHello with a wrong cookie fails the association, and the genuine one is then never
   accepted (`flight2.rs:86`); a test pins the failure.
7. The peer's signature algorithm lists are ignored on both sides (`flight4.rs:660`,
   `flight5.rs:415`, `flight3.rs:315`).
8. Handshake datagrams exceed the configured MTU by 25 bytes (`conn/mod.rs:498`).
9. Writes above 65535 bytes wrap the record length; nothing enforces 2^14 (`record_layer/mod.rs:55`).
10. Overlapping handshake fragments never reassemble (`fragment_buffer/mod.rs:245`).
11. The reserved alert no_certificate(41) is sent (`flight4.rs:133`).
12. No common curve is not an error: the server uses its default curve (`flight0.rs:162`).
13. One malformed trailing record drops the whole datagram (`record_layer/mod.rs:108`).
14. The retransmission timer never backs off (`handshaker.rs:229`).
15. A non-empty renegotiation_info in an initial handshake is accepted
    (`extension/renegotiation_info.rs:45`).
16. Crate level only: key export works without the extended master secret (`state.rs:303`); the
    engine's `Require` policy makes it unreachable.

DTLS-SRTP, SDP and demultiplexing (`rfc5764.md`, `rfc8842.md`, `rfc8122.md`, `rfc7983.md`,
`rfc9443.md`, `rfc8827.md`):

17. Role flip in the answer to a re-offer (`src/peer_connection/mod.rs:1036`,
    `transport/dtls/mod.rs:365`).
18. Transport stuck in `connecting` when the peer omits `use_srtp` (`handler/dtls.rs:543`).
19. Session-level `a=setup` ignored; `holdconn` read as no preference (`transport/dtls/role.rs:148`).
20. A changed remote fingerprint without an ICE restart is accepted and not applied
    (`src/peer_connection/mod.rs:1736`).
21. A peer whose only fingerprint is not sha-256 can never connect (`transport/dtls/mod.rs:242`).
22. `get_fingerprints` emits one fingerprint per chain certificate (`certificate/mod.rs:727`).
23. Malformed fingerprint values pass `set_remote_description` (`sdp/mod.rs:1655`).
24. ServerHello `use_srtp` with an MKI or several profiles is accepted (`flight3.rs:186`,
    `extension_use_srtp.rs:100`).
25. Datagrams with an out-of-range first byte reach the ICE agent, refresh a candidate's
    last-received time and log a warning each (`rtc-ice/src/agent/mod.rs:1848`).

SRTP (`rfc3711.md`, `rfc7714.md`, `rfc9335.md`):

26. SRTCP index wraps to 0 after 2^31 - 1 under the same key (`rtc-srtp/src/context/srtcp.rs:69`).
27. The receiver follows a ROC wrap (`rtc-srtp/src/context/srtp.rs:34`).
28. Valid E=0 AEAD SRTCP is rejected (`cipher_aead_aes_gcm.rs:181`, `:345`).
29. `Context::new` with `None` options accepts replays, against its doc comment
    (`rtc-srtp/src/config.rs:32`); replay windows below 64 are accepted.
30. First SRTCP packet carries index 1, not 0 (matches libsrtp and pion; pinned by a test).
31. Cryptex `Require` on send lets a packet with a non-RFC-8285 extension profile out in the clear
    (`rtc-srtp/src/cryptex.rs:107`); not reachable from the engine's own packetizer.

## Coverage and limits of this audit

- Done clause by clause: RFC 6347, RFC 5246 sections 4.7 to 9 and appendices A.5, E, F.1.1.3 (the
  parts DTLS 1.2 uses), RFC 7627, RFC 5746, RFC 5764, RFC 8842, RFC 8122, RFC 7983, RFC 9443,
  RFC 3711 (sections 6, 7 and 11 as one row each), RFC 7714 (SDES / MIKEY sections as one row),
  RFC 9335, RFC 6188, RFC 6904, RFC 8827, RFC 8826 (its lower-case requirements as SHOULD rows).
- Done at feature level, as asked: RFC 9147, RFC 9146.
- Not audited: RFC 4279 (PSK suites, which the engine does not offer), RFC 5288 / 6655 / 7905 beyond
  the nonce and additional-data rows, RFC 5705 beyond the export rows in `rfc5764.md`, RFC 8422
  beyond five rows in `rfc5246.md`. Provider internals (ring / aws-lc-rs) were not read.
- ICE-owned clauses in RFC 8827 6.3 / 6.4 and RFC 8826 4.2 are cross-references; the ICE area's
  verdicts should win. Three test citations in the DTLS-SRTP files rest on test file names rather
  than their bodies (listed in `rfc5764.md` context: `tests/reflect_*_interop.rs`,
  `tests/one_media_section_rtc_to_rtc_unicast.rs`, `tests/interceptor_rtcp_reports_interop.rs`).
- "Implicit" rows are requirements a spec states without an RFC 2119 keyword (wire formats, state
  machines); they are counted as MUST.
