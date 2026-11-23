# The webrtc-rs-rtc test environment: Rust, real network tooling (network namespaces, iptables
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
        coturn openssl \
        gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
        gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-libav \
    && rm -rf /var/lib/apt/lists/* \
    # coturn's package starts nothing in a container; the environment runs it per namespace.
    && update-alternatives --set iptables /usr/sbin/iptables-nft

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
# wheels peers/aiortc/image/requirements.txt pins by SHA-256 (no source builds, no resolution).
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY peers/aiortc/image/requirements.txt /opt/peers/aiortc/
RUN python3 -m venv /opt/peers/aiortc/venv \
    && /opt/peers/aiortc/venv/bin/pip install --no-cache-dir --disable-pip-version-check \
       --require-hashes --only-binary :all: --no-deps -r /opt/peers/aiortc/requirements.txt \
    && chmod -R a+rX /opt/peers/aiortc
# aiortc 1.16.0 refuses a description with an a=extmap extension attribute (RFC 8285 5; the
# RFC 6904 encrypted form the engine offers): https://github.com/aiortc/aiortc/issues/1492.
# Until upstream releases the fix, the wheel's sdp.py is replaced by the fork's (Brainwires/
# aiortc, branch fix/extmap-extension-attributes-1.16.0, commit 4982300: 1.16.0 plus the fix),
# both files checked by SHA-256. To be dropped when upstream releases the fix.
COPY peers/aiortc/image/sdp.py /opt/peers/aiortc/sdp.py
RUN set -eu; \
    target=$(/opt/peers/aiortc/venv/bin/python -I -c 'import aiortc.sdp; print(aiortc.sdp.__file__)'); \
    echo "0fae9213911b75a548deb434d4d1e2036da77d7c96a7049c9c315752e6135a22  $target" | sha256sum -c -; \
    echo "60de8a8818aa16fbc4d4f8d322c1f2655ace12f5999bab55a449ae1f0141fe7b  /opt/peers/aiortc/sdp.py" | sha256sum -c -; \
    cp /opt/peers/aiortc/sdp.py "$target"; rm -rf "$(dirname "$target")/__pycache__"

WORKDIR /src
