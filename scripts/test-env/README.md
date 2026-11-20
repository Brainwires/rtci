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
- **an mDNS LAN** (`br-mdns`, 10.99.0.0/24) with `m-a` and `m-b`, where multicast works.

`coturn/` runs STUN and TURN on 203.0.113.10: UDP and TCP on 3478, TLS on 5349 with a CA made
for the run (user `test`, password `test`, realm `rtc.test`).

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
    unreliable data channels, NACK recovery against the same link without it, the GStreamer VP8
    stream through NACK and the jitter buffer into an IVF file that GStreamer then decodes, and
    GCC following a 600 kbit/s link.
- **interop**: `examples/interop-peer` (the Rust side; WebSocket signalling) in `open-b`, and
  Playwright with headless Chromium, Firefox and WebKit in `open-a`: data channels (ordered,
  unordered, unreliable, negotiated, 64 KiB messages), renegotiation from either side, ICE
  restart, DTLS / SRTP state, media reflected per codec (VP8, VP9, H.264, Opus), the GStreamer
  fixtures sent from Rust and decoded by the browser, three-layer simulcast (RIDs), and an
  encoded transform (an SFrame-style XOR of every frame that the Rust side forwards untouched).
  A browser without a codec or API shows the test as not applicable, with the reason.

## CI

`.github/workflows/test-env.yml` runs it on push, pull request and dispatch: on our self-hosted
Linux docker pool first (the job's own rootless Docker daemon, so the checkout is copied in),
GitHub's `ubuntu-latest` when the pool is busy. Self-hosted runners take only a push, a dispatch
or a pull request from a branch of this repository; a fork's pull request runs on `ubuntu-latest`.
The image is cached in GHCR by the hash of `Dockerfile`, `interop/package.json` and
`interop/package-lock.json`, and only a push to `master` publishes it. After changing
`interop/package.json`, refresh the lockfile with `npm install --package-lock-only` in
`interop/`.
