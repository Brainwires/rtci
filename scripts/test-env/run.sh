#!/usr/bin/env bash
# One command for the whole webrtc-rs-rtc test environment:
#
#   scripts/test-env/run.sh [stage ...]        stages: unit env interop (default: all three)
#
# Builds the image (scripts/test-env/Dockerfile) if needed, then runs entry.sh in a throwaway
# container that holds the network namespaces, NAT routers, coturn, netem and the browsers.
# Nothing is published on the host and the host's network is not changed: the container needs
# NET_ADMIN and SYS_ADMIN (for its own namespaces), not --privileged.
#
# Environment:
#   RTC_TESTENV_CPUS       CPUs for the container (default 4)
#   RTC_TESTENV_ARTIFACTS  where logs and the report go (default target/test-env)
#   RTC_TESTENV_LOCK       a lock file to hold while running (e.g. ~/.fork-cargo.lock)
#   RTC_TESTENV_IMAGE      use this image instead of building one
#   RTC_TESTENV_TARGET     cargo target directory on the host (default target/test-env/cargo)
#   RTC_TESTENV_COPY       1: copy the checkout into an image instead of bind-mounting it (the
#                          default when DOCKER_HOST is tcp://, a daemon that cannot see this
#                          filesystem, such as the CI docker pool's sidecar); artifacts come back
#                          with `docker cp`
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
ARTIFACTS=${RTC_TESTENV_ARTIFACTS:-$ROOT/target/test-env}
TARGET=${RTC_TESTENV_TARGET:-$ARTIFACTS/cargo}
mkdir -p "$ARTIFACTS" "$TARGET"

if [ -n "${RTC_TESTENV_IMAGE:-}" ]; then
  IMAGE=$RTC_TESTENV_IMAGE
else
  TAG=$(cat "$HERE/Dockerfile" "$HERE/interop/package.json" "$HERE/interop/package-lock.json" | sha256sum | cut -c1-12)
  IMAGE=rtc-testenv:$TAG
  if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "== building $IMAGE"
    docker build -t "$IMAGE" -f "$HERE/Dockerfile" "$HERE"
  fi
fi

NAME=rtc-testenv-$$
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

COPY_MODE=${RTC_TESTENV_COPY:-}
if [ -z "$COPY_MODE" ]; then
  case "${DOCKER_HOST:-}" in tcp://*) COPY_MODE=1 ;; *) COPY_MODE=0 ;; esac
fi

CAPS=(--cap-add NET_ADMIN --cap-add SYS_ADMIN --cap-add NET_RAW
  --security-opt apparmor=unconfined --security-opt systempaths=unconfined --tmpfs /run:exec)

run_copy() {
  # The checkout (tracked and untracked-but-not-ignored files) as the build context of an image
  # layered on the environment's.
  local ctx run_image=rtc-testenv-run:$$
  ctx=$(mktemp -d)
  (cd "$ROOT" && git ls-files -co --exclude-standard -z | tar --null -T - -cf "$ctx/src.tar")
  printf 'FROM %s\nADD src.tar /src/\n' "$IMAGE" > "$ctx/Dockerfile"
  docker build -q -t "$run_image" "$ctx" >/dev/null
  rm -rf "$ctx"
  local rc=0
  docker run --name "$NAME" --cpus "${RTC_TESTENV_CPUS:-4}" "${CAPS[@]}" \
    -e CARGO_TARGET_DIR=/target -e CARGO_INCREMENTAL=0 \
    -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_PROFILE_TEST_DEBUG=0 \
    -e CARGO_BUILD_JOBS="${RTC_TESTENV_CPUS:-4}" \
    -w /src "$run_image" bash /src/scripts/test-env/entry.sh "$@" || rc=$?
  docker cp "$NAME:/artifacts/." "$ARTIFACTS/" || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker rmi "$run_image" >/dev/null 2>&1 || true
  return $rc
}

run() {
  if [ "$COPY_MODE" = 1 ]; then run_copy "$@"; return; fi
  # No shared cargo registry volume: crate sources are fetched inside this throwaway container,
  # so one run (a pull request's) cannot alter the sources a later run builds.
  docker run --rm --name "$NAME" \
    --cpus "${RTC_TESTENV_CPUS:-4}" \
    "${CAPS[@]}" \
    -v "$ROOT:/src" -v "$TARGET:/target" -v "$ARTIFACTS:/artifacts" \
    -e CARGO_TARGET_DIR=/target -e CARGO_INCREMENTAL=0 \
    -e CARGO_PROFILE_DEV_DEBUG=0 -e CARGO_PROFILE_TEST_DEBUG=0 \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -w /src "$IMAGE" bash /src/scripts/test-env/entry.sh "$@"
}

if [ -n "${RTC_TESTENV_LOCK:-}" ]; then
  exec 9>"$RTC_TESTENV_LOCK"
  echo "== waiting for $RTC_TESTENV_LOCK"
  flock 9
fi
run "$@"
