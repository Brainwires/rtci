# Test environment

One command runs every test this workspace has, including the ones that need a real network,
real media or a real browser:

```sh
scripts/test-env/run.sh                 # all stages: unit env interop
scripts/test-env/run.sh env             # only the real-network tests
scripts/test-env/run.sh interop         # only the browser matrix
```

It needs Linux with Docker (no `--privileged`: the container gets `NET_ADMIN` and `SYS_ADMIN`
for its own network namespaces; the host's network is never changed and nothing is published
on it). Results go to `target/test-env/`: `report.md` (the summary, also the CI job summary),
one log per stage, the NAT matrix, the interop matrix and Playwright's JSON report.

| Variable | Meaning |
|---|---|
| `RTC_TESTENV_CPUS` | CPUs for the container (default 4) |
| `RTC_TESTENV_LOCK` | a lock file to hold while running (on a shared build host, e.g. `~/.fork-cargo.lock`) |
| `RTC_TESTENV_IMAGE` | an already-built image instead of building `Dockerfile` |
| `RTC_TESTENV_COPY` | `1` copies the checkout into an image instead of bind-mounting it (automatic when `DOCKER_HOST` is `tcp://`, such as CI's docker pool) |

## What is inside

`Dockerfile`: Playwright's image (Node, Chromium, Firefox, WebKit), Rust, iproute2 / iptables /
ipset / tc, coturn and GStreamer.

`topology.sh` builds, inside the container:

- **a WAN** (`br-wan`, 203.0.113.0/24): `turn` (.10, coturn), `open-a` (.50) and `open-b` (.51),
  public hosts for the impairment tests and the browser matrix;
- **eight NAT routers**, two of each RFC 4787 type, each with one host behind it
  (`h-<type>-a`, `h-<type>-b`): `fullcone` (endpoint-independent mapping and filtering),
  `restricted` (address-dependent filtering, an ipset of the addresses the host sent to),
  `portrestricted` (address-and-port-dependent filtering) and `symmetric` (a new external port
  per destination, `MASQUERADE --random-fully`);
- **an mDNS LAN** (`br-mdns`, 10.99.0.0/24) with `m-a` and `m-b` (.2, .3; the Rust mDNS tests)
  and `lan-a` and `lan-b` (.50, .51; the browser and Rust peer of the `-mdns` interop projects),
  where multicast works. mDNS resolves names on a link, and an mDNS answer is believed only from
  an on-link sender (private, link-local or loopback, naming its own address), so the hosts that
  resolve each other's names sit on this private LAN, as on a real one.

`coturn/` runs STUN and TURN on 203.0.113.10: UDP and TCP on 3478, TLS on 5349 with a CA made
for the run (user `test`, password `test`, realm `rtc.test`). Two more servers run beside it: one on
3479 whose nonces go stale after 10 s (`turnserver-stale.conf`), and one on 3480 for the TURN
client's own tests (`turnserver-client.conf`), which relays on an IPv6 address as well
(`fd00:203:113::10`, on the namespace's loopback) and knows a second user (`other`).

`entry.sh` also makes the media fixtures with GStreamer (`videotestsrc` / `audiotestsrc`
encoded to VP8 and VP9 IVF, H.264 Annex B and Opus Ogg) and exports the `RTC_TESTENV_*`
variables the tests read.

## The stages

- **unit**: `cargo test --workspace`, everything that needs no environment.
- **env**: the tests in `tests/testenv_*.rs`, which are `#[ignore]`d with their reason outside
  the environment and run here with `--ignored`. `tests/testenv/mod.rs` drives sans-I/O peers
  over sockets created inside the namespaces (`setns(2)`), gathering host, server-reflexive (STUN)
  and relayed (TURN over UDP, TCP or TLS) candidates the way an application does.
  - `testenv_ice`: relay-only connections over each TURN transport, server-reflexive-only,
    host-only, and every pairing of NAT types with and without TURN (a pair without a direct
    path must fail without TURN and connect through the relay with it; a pair with one must not
    use the relay).
  - `testenv_mdns`: mDNS host candidates resolved over real multicast (both sides hiding their
    addresses; one hiding, one only querying).
  - `testenv_impairment`: netem loss, delay, jitter, reordering and a rate limit: reliable and
    unreliable data channels (the unreliable one must deliver 800 to 960 of 1000 messages over
    10% loss and drain its queue in under 90 s, paced by T3-rtx at RTO.Min 1 s), NACK
    recovering every packet, the GStreamer VP8 stream through NACK and the jitter buffer into an IVF file that GStreamer then decodes, and
    GCC settling between 300 and 660 kbit/s on a 600 kbit/s link.
  - `testenv_turn`: a relayed call that must keep carrying messages for 50 s through a second
    coturn (port 3479, `coturn/turnserver-stale.conf`) whose nonces go stale after 10 s and whose
    allocations last 30 s, so the allocation survives only if a 438 Stale Nonce is retried.
  - `testenv_turn_client`: the TURN client alone against coturn (port 3480): Allocate with
    LIFETIME, DONT-FRAGMENT and EVEN-PORT, the reserved port taken with its RESERVATION-TOKEN, a
    Send indication with DONT-FRAGMENT relayed to a peer, an IPv6 and a dual (IPv4 + IPv6)
    allocation with one family released, 440 from the IPv4-only server, and 441 for a Refresh
    under another username; and a TCP allocation (RFC 6062) over a TCP control connection: a
    Connect to a listener in `open-b`, a connection from `open-b` to the relayed address
    accepted from its ConnectionAttempt, bytes both ways over each data connection.
  - `testenv_dtls`: a wrong `a=fingerprint` in the offer or the answer must end the checking
    side's connection as `failed`.
  - `testenv_ice_tcp`: ICE over TCP from an active candidate behind a symmetric NAT to a passive
    listener on the WAN, both agents TCP-only, each as the offerer.
  - `testenv_media_fixtures`: a multi-packet-per-page Ogg file and a four-slices-per-picture
    H.264 file sent over a real connection, checked byte for byte and for the RTP marker, and
    decoded by GStreamer after the trip.
- **interop**: `examples/interop-peer` (the Rust side; WebSocket signalling) in `open-b`, and
  Playwright with headless Chromium, Firefox and WebKit in `open-a`: data channels (ordered,
  unordered, unreliable, negotiated, 64 KiB and 256 KiB messages, both sides' max-message-size),
  renegotiation from either side, ICE restart, DTLS / SRTP state, media reflected per codec (VP8,
  VP9, H.264, H.265, AV1, Opus), the GStreamer fixtures sent from Rust and decoded by the browser
  (multi-slice H.264 and multi-packet Ogg included), three-layer simulcast (RIDs) with and
  without loss repaired by RTX, an encoded transform, Cryptex, NACK + RTX under netem, relay-only
  through coturn, ICE-TCP, the browser as answerer for media, transceiver stop and m-line reuse,
  direction changes, rollback and glare, a wrong fingerprint either way, `getStats()` against the
  Rust side's counters, and (in the `-mdns` projects, each browser's defaults) mDNS-hidden
  candidates, which run apart on the mDNS LAN: a second interop-peer in `lan-b` and the
  browsers in `lan-a`. The loss tests add a `tc` filter for their own session to a netem band that
  `interop/run.sh` sets up, so they run beside the others.

  Each cell is a pass, a failure, or one of two kinds of "not applicable", always with the
  reason and a citation written in the test (`interop/na.mjs`): **na-browser** (the browser
  lacks the feature, by its own capability API at run time or a release note) and **na-env**
  (the headless build in this image lacks it). `interop/matrix.mjs` writes the matrix and
  `interop-summary.json`; `interop/gate.mjs` fails the stage on a failure, a missing cell, a
  browser that ran nothing, or an uncited skip. An na-env cell is not tested, and the gate lists
  it as such.

## Limits of this environment

- **Real Safari cannot run here.** Playwright's WebKit is the Linux port with its own media and
  WebRTC stack; a WebKit cell says nothing about Safari on macOS or iOS.
- **Firefox has no H.264.** Firefox does H.264 through Cisco's OpenH264 plugin, which it
  downloads after install; the offline image never fetches it, so those cells are na-env (not
  tested), not passes.
- **TURN over TLS is TLS 1.2.** The image's coturn answers every TLS 1.3 ClientHello with a
  handshake failure, so the test client (`tests/testenv/mod.rs`) offers TLS 1.2 only.
- **Linux only**: network namespaces.

## CI

`.github/workflows/test-env.yml` runs it on push, pull request and dispatch: on our self-hosted
Linux docker pool first (the job's own rootless Docker daemon, so the checkout is copied in),
GitHub's `ubuntu-latest` when the pool is busy. Self-hosted runners take only a push, a dispatch
or a pull request from a branch of this repository; a fork's pull request runs on `ubuntu-latest`.
The image is cached in GHCR by the hash of `Dockerfile`, `interop/package.json` and
`interop/package-lock.json`. Only the workflow's `image` job, on a push to `master`, publishes it;
the jobs that run the environment have a read-only package token and build the image locally
when the registry lacks it. The base image is pinned by digest and `rustup-init` by version and
SHA-256. After changing
`interop/package.json`, refresh the lockfile with `npm install --package-lock-only` in
`interop/`.
