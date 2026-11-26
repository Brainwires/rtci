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
# Environment (defaults in brackets): BENCH_ROUNDS [2], BENCH_WARMUP seconds [1],
# BENCH_MEASURE seconds [2], BENCH_OUT directory [target/bench-compare-out], and any
# bench-compare.py option in BENCH_COMPARE_ARGS (for example --threshold 0.3).
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

run() { # tree crate bench output
  (cd "$1" && CARGO_TARGET_DIR=$(target_of "$1") cargo bench --quiet -p "$2" --bench "$3" -- --output-format bencher \
     --warm-up-time "$warmup" --measurement-time "$measure" --noplot) >> "$4"
}

in_base() {
  local t
  for t in "${base_has[@]}"; do [ "$t" = "$1" ] && return 0; done
  return 1
}

start=$SECONDS
for r in $(seq 1 "$rounds"); do
  : > "$out/base-$r.txt"
  : > "$out/head-$r.txt"
  for target in "$@"; do
    crate=${target%%:*} bench=${target#*:}
    echo "round $r: $target ($((SECONDS - start)) s)"
    if [ $((r % 2)) -eq 0 ]; then
      run "$root" "$crate" "$bench" "$out/head-$r.txt"
    fi
    if in_base "$target"; then
      run "$base_dir" "$crate" "$bench" "$out/base-$r.txt"
    fi
    if [ $((r % 2)) -eq 1 ]; then
      run "$root" "$crate" "$bench" "$out/head-$r.txt"
    fi
  done
done
echo "benchmarks ran for $((SECONDS - start)) s"
for f in "$out"/base-*.txt "$out"/head-*.txt; do
  echo "::group::$(basename "$f"): $(grep -c '^test ' "$f") bench lines"
  cat "$f"
  echo "::endgroup::"
done

base_files=() head_files=()
for r in $(seq 1 "$rounds"); do
  base_files+=("$out/base-$r.txt")
  head_files+=("$out/head-$r.txt")
done
summary=()
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && summary=(--summary "$GITHUB_STEP_SUMMARY")
# shellcheck disable=SC2086
python3 "$root/scripts/bench-compare.py" --base "${base_files[@]}" --head "${head_files[@]}" \
  "${summary[@]}" ${BENCH_COMPARE_ARGS:-}
