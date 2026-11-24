#!/usr/bin/env bash
# THROWAWAY (never merged): the capacity review's battery, one row per run (RROW / BROW lines).
# Usage: review-battery.sh [seed_lo seed_hi standard_hi]; extra REVIEW_* knobs come from the
# caller's environment and apply to every scenario.
set -u
LO=${1:-1}
HI=${2:-60}
STD_HI=${3:-200}
rc=0
run() {
  tag=$1
  shift
  echo "=== BATTERY $tag"
  env REVIEW_TAG="$tag" "$@" cargo test --release -p rtci --test review_cap review_ensemble -- --ignored --nocapture || rc=1
}
cargo test --release -p rtci --test review_cap --no-run || exit 1
run standard REVIEW_SEED_LO=1 REVIEW_SEED_HI="$STD_HI"
run offsets REVIEW_SEED_LO=1 REVIEW_SEED_HI=10 REVIEW_OFFSETS=0,4,9,14,19,23,28,33,38,43
run symmetric REVIEW_SEED_LO="$LO" REVIEW_SEED_HI="$HI" REVIEW_SYMMETRIC=1
run revloss5 REVIEW_SEED_LO="$LO" REVIEW_SEED_HI="$HI" REVIEW_REV_LOSS_PCT=5
run q100 REVIEW_SEED_LO="$LO" REVIEW_SEED_HI="$HI" REVIEW_QUEUE_MS=100
run q1000 REVIEW_SEED_LO="$LO" REVIEW_SEED_HI="$HI" REVIEW_QUEUE_MS=1000
run burst REVIEW_SEED_LO="$LO" REVIEW_SEED_HI="$HI" REVIEW_SCENARIO=burst
exit $rc
