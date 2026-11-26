#!/usr/bin/env bash
# Runs the SRTP key residue measurement (rtci-srtp/tests/key_residue.rs) and prints what it
# found: the controls, anything left outside dead stack frames, the inventory per step and its
# digest, and (Linux) how this system treats thread stacks.
#
#   scripts/key-residue-report.sh [+toolchain] [features]
#
#   +toolchain  a rustup toolchain for cargo, e.g. +1.99.1 (default: the active one)
#   features    rtci-srtp features to add, e.g. crypto-aws-lc-rs (default: none: ring only)
#
# Environment: OUT (directory for the logs, default a new temporary one), REPEAT (how often the
# ignored known_limit_ tests are run to compare digests, default 3).
# Exit status: that of the tests that are not ignored; 2 when the build fails.
set -u
toolchain=
case "${1:-}" in +*) toolchain=$1; shift ;; esac
features=${1:-}
out=${OUT:-$(mktemp -d)}
repeat=${REPEAT:-3}
mkdir -p "$out"

# $toolchain is left unquoted on purpose: empty, it must vanish from the command line.
# shellcheck disable=SC2206
cargo_test=(cargo $toolchain test -p rtci-srtp --test key_residue)
[ -n "$features" ] && cargo_test+=(--features "$features")

# shellcheck disable=SC2086
echo "== $(rustc $toolchain --version), $(uname -srm), features: ${features:-default}"
"${cargo_test[@]}" --no-run > "$out/build.log" 2>&1 || { tail -30 "$out/build.log"; exit 2; }
"${cargo_test[@]}" -- --nocapture > "$out/live.log" 2>&1
status=$?
"${cargo_test[@]}" -- --ignored investigate_ --nocapture > "$out/investigate.log" 2>&1
for i in $(seq "$repeat"); do
  "${cargo_test[@]}" -- --ignored known_limit_ --nocapture > "$out/known-limit-$i.log" 2>&1
done

echo "== tests"
grep -h '^test ' "$out/live.log" "$out/known-limit-1.log"
echo "== thread stacks on this system"
grep -h '^ENV\|^ROUND\|^OWNED' "$out/investigate.log"
echo "== controls, notes, anything left outside dead stack frames"
grep -h '^CONTROL\|^NOTE\|^LEFT' "$out/live.log" "$out/known-limit-1.log" | sort -u
echo "== inventory digests (not ignored, then each known_limit_ run)"
grep -h '^INVENTORY' "$out/live.log"
grep -h '^INVENTORY' "$out"/known-limit-*.log | sort | uniq -c
echo "== per key, over the ten profiles"
grep -h '^SUMMARY' "$out/known-limit-1.log"
echo "== per step"
grep -h '^STAGE' "$out/known-limit-1.log"
echo "== every form, first AES-CM and first AES-GCM profile"
grep -h '^FORM [a-z-]*|Aes128CmHmacSha1_80|\|^FORM [a-z-]*|AeadAes128Gcm|' "$out/known-limit-1.log"
echo "== panics"
grep -h -A12 'panicked at' "$out/live.log" "$out/investigate.log" | head -80
grep -h -A3 'panicked at' "$out/known-limit-1.log" | head -24
exit $status
