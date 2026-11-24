# The rtci test environment: Rust, real network tooling (network namespaces, iptables
# NAT, ipset, netem), a TURN/STUN server (coturn), synthetic media (GStreamer), headless
# Chromium, Firefox and WebKit (Playwright), and what the non-browser interop peers
# (peers/) build from. Built and run by scripts/test-env/run.sh.
#
# Playwright's image carries Node and the three browsers with their system libraries; the
# version is pinned (by digest: the v1.64.1-noble index) and matches interop/package.json.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f

ARG RUST_VERSION=1.99.1
ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config cmake clang ca-certificates curl git python3 jq procps psmisc \
        iproute2 iptables ipset iputils-ping tcpdump conntrack dnsutils netcat-openbsd \
        openssl libssl-dev libevent-dev \
        gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
        gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-libav \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --set iptables /usr/sbin/iptables-nft

# coturn (BSD-3-Clause) built from its release tag, the source archive checked by SHA-256: the
# base's distribution package is 4.6.1 (Ubuntu 24.04 and Debian 13 ship it), whose TLS listener
# picks its SSL context by the ClientHello's legacy_version (0x0303 for TLS 1.3 too), so a
# client offering only TLS 1.3 gets handshake_failure and one offering 1.3 and 1.2 gets 1.2.
# Fixed in 4.6.2 (https://github.com/coturn/coturn/pull/989, one SSL context). 4.6.3 is the
# last release of that line: 4.18 removed the no-cli and no-dtls options coturn/*.conf use and
# moved the session id in its log lines, so moving further is a change of its own. No database
# backends (the configurations list their users); the environment runs turnserver per
# namespace (coturn/start.sh).
ARG COTURN_VERSION=4.6.3
ARG COTURN_SHA256=dc3a529fd9956dc8771752a7169c5ad4c18b9deef3ec96049de30fabf1637704
RUN set -eu; \
    curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/coturn.tgz \
      "https://github.com/coturn/coturn/archive/refs/tags/${COTURN_VERSION}.tar.gz"; \
    echo "${COTURN_SHA256}  /tmp/coturn.tgz" | sha256sum -c -; \
    mkdir /tmp/coturn; tar -C /tmp/coturn --strip-components=1 -xzf /tmp/coturn.tgz; \
    cd /tmp/coturn; \
    TURN_NO_SQLITE=1 TURN_NO_PQ=1 TURN_NO_MYSQL=1 TURN_NO_MONGO=1 TURN_NO_HIREDIS=1 \
      TURN_NO_PROMETHEUS=1 TURN_NO_SYSTEMD=1 ./configure --prefix=/usr/local; \
    make -j"$(nproc)" bin/turnserver; \
    install -m 0755 bin/turnserver /usr/local/bin/turnserver; \
    cd /; rm -rf /tmp/coturn /tmp/coturn.tgz; \
    turnserver --version 2>&1 | grep -F "${COTURN_VERSION}"

# rustup-init by version and SHA-256 (the checksums static.rust-lang.org publishes beside each
# binary), not the moving sh.rustup.rs script.
ARG RUSTUP_VERSION=1.28.2
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) triple=x86_64-unknown-linux-gnu; \
             sum=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c ;; \
      arm64) triple=aarch64-unknown-linux-gnu; \
             sum=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c ;; \
      *) echo "no pinned rustup-init for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -sSf -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init"; \
    echo "${sum}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain ${RUST_VERSION} \
      --component clippy,rustfmt; \
    rm /tmp/rustup-init; chmod -R a+w $RUSTUP_HOME $CARGO_HOME

# Playwright test runner, pinned to the browsers the base image ships, installed exactly as
# interop/package-lock.json resolved it (integrity-checked; no install scripts).
COPY interop/package.json interop/package-lock.json /opt/interop/
RUN cd /opt/interop && npm ci --ignore-scripts --no-audit --no-fund && npx playwright --version

# Go for the Pion peer (peers/pion): the toolchain by version and SHA-256 (the checksums
# go.dev/dl publishes), and every module peers/pion/image/go.sum pins, fetched (and checked
# against go.sum) into the image's module cache, so the peer builds offline at run time.
ARG GO_VERSION=1.27.4
RUN set -eu; \
    case "$(dpkg --print-architecture)" in \
      amd64) arch=amd64; sum=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840 ;; \
      arm64) arch=arm64; sum=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92 ;; \
      *) echo "no pinned Go for $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"; \
    echo "${sum}  /tmp/go.tgz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tgz; rm /tmp/go.tgz
ENV PATH=/usr/local/go/bin:$PATH GOMODCACHE=/opt/go/mod GOTOOLCHAIN=local
COPY peers/pion/image/go.mod peers/pion/image/go.sum /opt/peers/pion/
RUN cd /opt/peers/pion && go mod download && chmod -R a+rX /opt/go

# Python for the aiortc peer (peers/aiortc): a venv on the image's CPython with exactly the
# wheels peers/aiortc/image/requirements.txt pins by SHA-256 (no resolution), and aiortc itself
# (pure Python) built from upstream's main branch at a pinned commit, its source archive checked
# by SHA-256 and built offline with the pinned setuptools. The commit is the first with both
# fixes for parser bugs of aiortc 1.16.0 that the engine's SDP and RTCP meet; no release has
# them yet (1.16.0 is the latest), so this is to be dropped for the release that does:
# - 6a76d5e0 "Parse a=extmap lines into their own SDP description": an a=extmap extension
#   attribute (RFC 8285 5, the engine's RFC 6904 encrypted forms) made it refuse the
#   description, https://github.com/aiortc/aiortc/issues/1492;
# - 0ee2bd29 "Align RTCP SDES chunks to 32-bit boundaries": an RTCP SDES packet with several
#   chunks (RFC 3550 6.5) made it drop the whole compound packet, its RR and NACKs with it,
#   https://github.com/aiortc/aiortc/issues/1496.
# The whole package comes from that commit, not two files over the 1.16.0 wheel: the extmap fix
# also changes rtcpeerconnection.py (it reads the new SdpMedia.extmap), so a partial overlay
# would lose the negotiated header extensions. The codecs stay the pinned compiled wheels (av,
# pylibsrtp, cryptography, google-crc32c).
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY peers/aiortc/image/requirements.txt /opt/peers/aiortc/
ARG AIORTC_COMMIT=0ee2bd29ad77018dc2dae9c841ea5bd14d2550ee
ARG AIORTC_SHA256=9f2a6308e53813eb62fb604e38619178df72f5cfd4ccdc3dbca5b7f0b2c86ca7
RUN set -eu; \
    python3 -m venv /opt/peers/aiortc/venv; \
    /opt/peers/aiortc/venv/bin/pip install --no-cache-dir --disable-pip-version-check \
      --require-hashes --only-binary :all: --no-deps -r /opt/peers/aiortc/requirements.txt; \
    curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/aiortc.tgz \
      "https://github.com/aiortc/aiortc/archive/${AIORTC_COMMIT}.tar.gz"; \
    echo "${AIORTC_SHA256}  /tmp/aiortc.tgz" | sha256sum -c -; \
    mkdir /tmp/aiortc; tar -C /tmp/aiortc --strip-components=1 -xzf /tmp/aiortc.tgz; \
    /opt/peers/aiortc/venv/bin/pip install --no-cache-dir --disable-pip-version-check \
      --no-deps --no-build-isolation --no-index /tmp/aiortc; \
    rm -rf /tmp/aiortc /tmp/aiortc.tgz; \
    /opt/peers/aiortc/venv/bin/python -I -c 'from aiortc.sdp import ExtmapDescription'; \
    chmod -R a+rX /opt/peers/aiortc

WORKDIR /src
