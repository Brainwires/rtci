#!/usr/bin/env bash
# Builds pion-peer offline (GOPROXY=off): the image's module cache holds every module
# image/go.sum names (scripts/test-env/Dockerfile), so the build uses exactly those.
set -euo pipefail
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cp "$HERE/image/go.mod" "$HERE/image/go.sum" "$HERE/main.go" "$W/"
cd "$W"
go version
GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local go build -trimpath -o "$OUT/pion-peer" .
