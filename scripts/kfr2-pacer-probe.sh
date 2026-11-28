#!/usr/bin/env bash
# Probe for the Interceptor/Pacer/write+poll regression of train 36 (ledger row pacer-4).
# NOT for merging: it lives on conf/kfr2-pacer-probe only.
#
# Builds the criterion bench `rtci-interceptor:interceptor` of each tree below on THIS runner,
# then runs `Interceptor/Pacer/write+poll` of every tree in ROUNDS alternating rounds (odd
# rounds in the order listed, even rounds reversed, as scripts/bench-compare.sh alternates), and
# compares pairs with scripts/bench-compare.py (the pull-request job's rule: slower = every
# round beyond 20 % and the median difference over 25 ns).
#
# Exit 0: the regression reproduced (precondition) and the fix removes it.
# Exit 1: the regression reproduced and the fix does not remove it.
# Exit 3: inconclusive: this runner did not reproduce the regression of round 19.
set -euo pipefail

ROUNDS=${ROUNDS:-5}
BENCH='^Interceptor/Pacer/write\+poll$'
# label=sha, in build order (the 0.2.0 family first, then the 0.2.1 family: fewer rebuilds).
TREES=(
  "v020=ea78e88fc054122946112a7f52a5b04e38af4621"   # 0.2.0, parent of kfr-1 and pacer-3
  "kfr1=a6b4f264c1a1e7efe54abac6f2bdfd0557b36a60"   # conf/kfr-1 alone
  "pacer3=3a648d559b31d76e5052493b7fbb547f58d8707e" # conf/pacer-3 alone
  "kfr2=f94264d1f5a4c06c59d794b6efb0cc5578067ff1"   # conf/kfr-2: kfr-1 + pacer-3 + pacer-4
  "base=85aa2a715f8c91b5ff3e7b5a2c2ca57cc9068d66"   # master v0.2.1, the train PR's base
  "r6=e0ecd2ede1574488fcb454df5c78a04ad7fd4548"     # train 36 round 6, before pacer-3
  "r19rv=b33c2a7b273656a9033cf9dbee90aac3add50f78"  # train 36 now: pacer-3 in, kfr-1 reverted
  "r19=46b5130ec2e2810b5486e5c5565b57778104fcdf"    # train 36 round 19 with kfr-1 (failed run)
  "r19p4a=f2dd512bb06aa7d5455c4b704a94e786e5322d20" # r19 + pacer-4's first commit only
  "r19p4=0afcee2a8ef3867ff67df089eb59952108749b46"  # r19 + pacer-4 (= the train after integration)
)

root=$(git rev-parse --show-toplevel)
work=${RUNNER_TEMP:-/tmp}/kfr2-probe
rm -rf "$work"
mkdir -p "$work/bins" "$work/out"
cargo --version
rustc --version
git -C "$root" worktree add --detach "$work/tree" HEAD >/dev/null
export CARGO_TARGET_DIR=$work/target

labels=()
for t in "${TREES[@]}"; do
  label=${t%%=*} sha=${t#*=}
  labels+=("$label")
  git -C "$root" fetch -q --no-tags --depth=1 origin "$sha"
  git -C "$work/tree" checkout -q --detach "$sha"
  echo "::group::build $label ($sha)"
  exe=$(cd "$work/tree" && cargo bench -q -p rtci-interceptor --bench interceptor --no-run \
          --message-format=json 2>/dev/null |
        python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "interceptor":
        print(m["executable"])' | tail -1)
  [ -n "$exe" ] || { echo "no bench executable for $label"; exit 2; }
  cp "$exe" "$work/bins/$label"
  echo "::endgroup::"
done
# A stale build would measure one tree as two: every tree's binary must differ.
sha256sum "$work"/bins/* | tee "$work/sums"
if [ "$(cut -d' ' -f1 "$work/sums" | sort | uniq -d | wc -l)" -ne 0 ]; then
  echo "two trees built the same binary: stale build"; exit 2
fi

run() { # label round
  rm -rf "$work/crit"
  (cd "$work/tree" && CRITERION_HOME=$work/crit "$work/bins/$1" --bench --output-format bencher \
     --warm-up-time 1 --measurement-time 2 --noplot "$BENCH") | grep '^test ' >> "$work/out/$1-$2.txt"
}
for r in $(seq 1 "$ROUNDS"); do
  order=("${labels[@]}")
  if [ $((r % 2)) -eq 0 ]; then
    order=(); for ((i=${#labels[@]}-1; i>=0; i--)); do order+=("${labels[i]}"); done
  fi
  for l in "${order[@]}"; do run "$l" "$r"; done
  echo "round $r: $(for l in "${labels[@]}"; do printf '%s=%s ' "$l" "$(grep -oE '[0-9,]+ ns/iter' "$work/out/$l-$r.txt" | cut -d' ' -f1)"; done)"
done

compare() { # base head -> prints "verdict ratio min max"
  local bf=() hf=() r
  for r in $(seq 1 "$ROUNDS"); do bf+=("$work/out/$1-$r.txt"); hf+=("$work/out/$2-$r.txt"); done
  python3 "$root/scripts/bench-compare.py" --base "${bf[@]}" --head "${hf[@]}" 2>/dev/null |
    awk -F'\t' '$1=="BENCH" { n=split($7,a,","); mn=a[1]; mx=a[1]; for(i=2;i<=n;i++){ if(a[i]<mn) mn=a[i]; if(a[i]>mx) mx=a[i] }
                              printf "%s %s %s %s %s %s\n", $3, $6, mn, mx, $4, $5 }'
}
echo
printf '%-8s %-8s %-8s %-7s %-7s %-7s %s\n' base head verdict ratio min max "medians ns"
declare -A V R MN MX
for pair in base:v020 base:r6 base:r19rv base:r19 base:r19p4a base:r19p4 base:kfr2 \
            v020:kfr1 v020:pacer3 v020:kfr2 pacer3:kfr2 r19rv:r19 r19:r19p4a r19:r19p4 r6:r19p4; do
  bt=${pair%%:*} ht=${pair#*:}
  read -r verdict ratio mn mx bm hm < <(compare "$bt" "$ht")
  V[$pair]=$verdict R[$pair]=$ratio MN[$pair]=$mn MX[$pair]=$mx
  printf '%-8s %-8s %-8s %-7s %-7s %-7s %s -> %s\n' "$bt" "$ht" "$verdict" "$ratio" "$mn" "$mx" "$bm" "$hm"
done
echo

ge() { python3 -c "import sys; sys.exit(0 if float('$1') >= float('$2') else 1)"; }
# Precondition: the regression of round 19 reproduces on this runner (slower by the job's rule,
# or every round at least 15 % slower than the base).
if [ "${V[base:r19]}" != slower ] && ! ge "${MN[base:r19]}" 1.15; then
  echo "INCONCLUSIVE: r19 against base is ${V[base:r19]} (ratio ${R[base:r19]}, rounds ${MN[base:r19]}..${MX[base:r19]}): this runner did not reproduce the regression"
  exit 3
fi
echo "PRECONDITION: r19 against base ${V[base:r19]}, ratio ${R[base:r19]} (rounds ${MN[base:r19]}..${MX[base:r19]})"
ok=1
if [ "${V[base:r19p4]}" = slower ]; then echo "FAIL: r19p4 is still slower than base"; ok=0; fi
if ge "${MX[r19:r19p4]}" 0.92; then echo "FAIL: r19p4 is not faster than r19 in every round (max ${MX[r19:r19p4]})"; ok=0; fi
if [ "${V[v020:kfr2]}" = slower ]; then echo "FAIL: kfr2 is slower than 0.2.0"; ok=0; fi
[ $ok -eq 1 ] && { echo "PASS: the fix removes the regression"; exit 0; }
exit 1
