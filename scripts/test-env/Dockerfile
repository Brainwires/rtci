# The webrtc-rs-rtc test environment: Rust, real network tooling (network namespaces, iptables
# NAT, ipset, netem), a TURN/STUN server (coturn), synthetic media (GStreamer) and headless
# Chromium, Firefox and WebKit (Playwright). Built and run by scripts/test-env/run.sh.
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

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh \
    && sh /tmp/rustup.sh -y --no-modify-path --profile minimal --default-toolchain ${RUST_VERSION} \
        --component clippy,rustfmt \
    && rm /tmp/rustup.sh && chmod -R a+w $RUSTUP_HOME $CARGO_HOME

# Playwright test runner, pinned to the browsers the base image ships, installed exactly as
# interop/package-lock.json resolved it (integrity-checked; no install scripts).
COPY interop/package.json interop/package-lock.json /opt/interop/
RUN cd /opt/interop && npm ci --ignore-scripts --no-audit --no-fund && npx playwright --version

WORKDIR /src
