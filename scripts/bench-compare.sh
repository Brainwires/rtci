#!/usr/bin/env bash
# Run criterion benchmarks of the checked-out tree (the head) and of a base commit on THIS
# machine, in alternating rounds, and compare them with scripts/bench-compare.py.
#
#   scripts/bench-compare.sh <base-ref-or-sha> <crate>:<bench> [<crate>:<bench> ...]
#
# Hosted runners differ by up to 2x between machines, so a figure is only ever compared with one
# measured in the same job. The base is checked out into a second worktree with a target
# directory of its own: with one shared target directory cargo gave both trees' bench executables
# the same name, so one tree's binary was measured as both (a mutation run measured 51.7 us of
# DTLS setup for base and head alike). Round r runs every benchmark of the base and then of the head
# for odd r and the other way round for even r, so drift during the job (a neighbour on the host,
# thermal state) falls on both trees alike.
#
# A bench whose trees come out separated after these rounds (every head round beyond every base
# round, bench-compare.py's second rule, row bench-2 of docs/performance.md) is run again, alone,
# for BENCH_CONFIRM_ROUNDS more alternating rounds before the verdict: two rounds are too few to
# tell a separation from noise, and re-running a few benches costs seconds.
#
# Each confirmation round RELINKS both trees' bench executables with the functions in another
# order (lld's --shuffle-sections over .text, seed = the round's number; row bench-3). The same
# pair of binaries measured again repeats its code-layout bias: train 36's
# `BenchmarkAlternateServer_AddTo` came out x1.08-1.12 slower, every round, on one kind of runner
# and x0.98-1.00 on others for the very same sources (rtci-stun and everything it links unchanged
# from round 5 to round 16), and the confirmation rounds of bench-2 confirmed it (run
# 46160736903). A cost in the code survives the reordering; an alignment accident does not. When
# the linker cannot shuffle (it is not lld), a separation is reported and does not fail the job.
#
# Environment (defaults in brackets): BENCH_ROUNDS [2], BENCH_CONFIRM_ROUNDS [4],
# BENCH_WARMUP seconds [1], BENCH_MEASURE seconds [2], BENCH_OUT directory
# [target/bench-compare-out], and any bench-compare.py option in BENCH_COMPARE_ARGS (for example
# --threshold 0.3).
# A benchmark target the base does not have (or cannot build) is reported as new, not compared.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <base-ref-or-sha> <crate>:<bench> [...]" >&2
  exit 2
fi
base_ref=$1
shift

root=$(git rev-parse --show-toplevel)
cd "$root"
rounds=${BENCH_ROUNDS:-2}
confirm_rounds=${BENCH_CONFIRM_ROUNDS:-4}
warmup=${BENCH_WARMUP:-1}
measure=${BENCH_MEASURE:-2}
out=${BENCH_OUT:-$root/target/bench-compare-out}
head_target=${CARGO_TARGET_DIR:-$root/target}
unset CARGO_TARGET_DIR
mkdir -p "$out"
rm -f "$out"/base-*.txt "$out"/head-*.txt

# The base commit: a ref or SHA known here, else fetched (a shallow checkout has neither).
if ! base_sha=$(git rev-parse --verify --quiet "$base_ref^{commit}"); then
  git fetch --no-tags --depth=1 origin "$base_ref"
  base_sha=$(git rev-parse FETCH_HEAD)
fi
head_sha=$(git rev-parse HEAD)
echo "base $base_sha, head $head_sha, $rounds rounds, warm-up ${warmup}s, measurement ${measure}s"

base_dir=${RUNNER_TEMP:-${TMPDIR:-/tmp}}/bench-compare-base
git worktree remove --force "$base_dir" 2>/dev/null || rm -rf "$base_dir"
git worktree add --detach "$base_dir" "$base_sha" >/dev/null
trap 'git -C "$root" worktree remove --force "$base_dir" 2>/dev/null || true' EXIT

target_of() { # tree
  if [ "$1" = "$root" ]; then echo "$head_target"; else echo "$base_dir/target"; fi
}

build() { # tree crate bench
  (cd "$1" && CARGO_TARGET_DIR=$(target_of "$1") cargo bench --quiet -p "$2" --bench "$3" --no-run)
}

# Criterion compares each bench with the results it saved last time in <target>/criterion. A
# restored cache can hold a half of that directory, and criterion then prints an error in the
# middle of the bencher line (run 45664707179); the comparison here needs none of it.
rm -rf "$head_target/criterion" "$base_dir/target/criterion"

base_has=()
for target in "$@"; do
  crate=${target%%:*} bench=${target#*:}
  echo "::group::build $target (head)"
  build "$root" "$crate" "$bench"
  echo "::endgroup::"
  echo "::group::build $target (base)"
  if build "$base_dir" "$crate" "$bench"; then
    base_has+=("$target")
  else
    echo "the base has no buildable $target: its benchmarks count as new"
  fi
  echo "::endgroup::"
done

run() { # tree crate bench output [criterion filter]
  (cd "$1" && CARGO_TARGET_DIR=$(target_of "$1") cargo bench --quiet -p "$2" --bench "$3" -- --output-format bencher \
     --warm-up-time "$warmup" --measurement-time "$measure" --noplot ${5:+"$5"}) >> "$4"
}

in_base() {
  local t
  for t in "${base_has[@]}"; do [ "$t" = "$1" ] && return 0; done
  return 1
}

round() { # r [criterion filter]
  : > "$out/base-$1.txt"
  : > "$out/head-$1.txt"
  for target in "${targets[@]}"; do
    crate=${target%%:*} bench=${target#*:}
    echo "round $1: $target ($((SECONDS - start)) s)"
    if [ $(($1 % 2)) -eq 0 ]; then
      run "$root" "$crate" "$bench" "$out/head-$1.txt" "${2:-}"
    fi
    if in_base "$target"; then
      run "$base_dir" "$crate" "$bench" "$out/base-$1.txt" "${2:-}"
    fi
    if [ $(($1 % 2)) -eq 1 ]; then
      run "$root" "$crate" "$bench" "$out/head-$1.txt" "${2:-}"
    fi
  done
}

relink() { # tree crate bench seed copy-to: the bench executable linked with its functions shuffled
  local exe
  exe=$(cd "$1" && CARGO_TARGET_DIR=$(target_of "$1") cargo rustc --quiet --profile bench -p "$2" \
          --bench "$3" --message-format=json -- -C "link-arg=-Wl,--shuffle-sections=.text*=$4" |
        python3 -c 'import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == sys.argv[1]:
        print(m["executable"])' "$3" | tail -1) || return 1
  [ -n "$exe" ] && cp "$exe" "$5"
}

run_exe() { # tree executable output criterion-filter
  (cd "$1" && "$2" --bench --output-format bencher --warm-up-time "$warmup" --measurement-time "$measure" \
     --noplot "$4") >> "$3"
}

shuffled_round() { # r filter: every target relinked with seed r in both trees, then measured
  : > "$out/base-$1.txt"
  : > "$out/head-$1.txt"
  for target in "${targets[@]}"; do
    in_base "$target" || continue
    crate=${target%%:*} bench=${target#*:}
    echo "round $1 (functions shuffled, seed $1): $target ($((SECONDS - start)) s)"
    relink "$root" "$crate" "$bench" "$1" "$out/exe-head" || return 1
    relink "$base_dir" "$crate" "$bench" "$1" "$out/exe-base" || return 1
    if [ $(($1 % 2)) -eq 0 ]; then run_exe "$root" "$out/exe-head" "$out/head-$1.txt" "$2"; fi
    run_exe "$base_dir" "$out/exe-base" "$out/base-$1.txt" "$2"
    if [ $(($1 % 2)) -eq 1 ]; then run_exe "$root" "$out/exe-head" "$out/head-$1.txt" "$2"; fi
  done
}

round_files() { # first last
  base_files=() head_files=()
  for r in $(seq "$1" "$2"); do
    base_files+=("$out/base-$r.txt")
    head_files+=("$out/head-$r.txt")
  done
}

targets=("$@")
start=$SECONDS
for r in $(seq 1 "$rounds"); do
  round "$r"
done
total=$rounds

# The separated benches, measured again alone (criterion takes one regular expression).
round_files 1 "$rounds"
# shellcheck disable=SC2086
mapfile -t suspect < <(python3 "$root/scripts/bench-compare.py" --base "${base_files[@]}" \
  --head "${head_files[@]}" --suspects ${BENCH_COMPARE_ARGS:-})
confirm_args=()
if [ "${#suspect[@]}" -gt 0 ] && [ "$confirm_rounds" -gt 0 ]; then
  echo "separated after $rounds rounds, measured again for $confirm_rounds rounds with the functions shuffled: ${suspect[*]}"
  filter=$(python3 -c 'import re, sys; print("^(" + "|".join(re.escape(n) for n in sys.argv[1:]) + ")$")' "${suspect[@]}")
  confirmed=yes
  for r in $(seq $((rounds + 1)) $((rounds + confirm_rounds))); do
    if ! shuffled_round "$r" "$filter"; then
      confirmed=no
      break
    fi
  done
  if [ "$confirmed" = yes ]; then
    total=$((rounds + confirm_rounds))
  else
    for r in $(seq $((rounds + 1)) $((rounds + confirm_rounds))); do rm -f "$out/base-$r.txt" "$out/head-$r.txt"; done
    echo "::warning::the bench executables could not be relinked with their functions shuffled (is the linker lld?): a separation is reported, not failed"
    confirm_args=(--separation-rounds 1000000)
  fi
fi
echo "benchmarks ran for $((SECONDS - start)) s"
for f in "$out"/base-*.txt "$out"/head-*.txt; do
  [ -e "$f" ] || continue
  echo "::group::$(basename "$f"): $(grep -c '^test ' "$f") bench lines"
  cat "$f"
  echo "::endgroup::"
done

round_files 1 "$total"
summary=()
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && summary=(--summary "$GITHUB_STEP_SUMMARY")
# shellcheck disable=SC2086
python3 "$root/scripts/bench-compare.py" --base "${base_files[@]}" --head "${head_files[@]}" \
  "${summary[@]}" "${confirm_args[@]}" ${BENCH_COMPARE_ARGS:-}
