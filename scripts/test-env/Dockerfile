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

WORKDIR /src
