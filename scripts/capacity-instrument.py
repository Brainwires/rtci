#!/usr/bin/env python3
"""The analysis of the capacity instrument (``tests/capacity_instrument.rs``).

The instrument's ``measure`` test prints one line per run::

    IROW cell=cap/paced/gap300/up/q300/rl0 seed=17 phase=23 max_age=8.420 stale1=8.050 ...
    IROW cell=cap/paced/gap300/up/q300/rl0 seed=18 phase=0 failed=peer_0_failed

This script reads such lines out of any text (a job log with its own prefixes included) and:

``table LABEL=LOG [LABEL=LOG ...]``
    One Markdown table per cell: for each tree (label) its runs, the share of runs violating each
    requirement with a 95 % Wilson interval and the verdict of the instrument's own test at that
    sample size, and the figures' percentiles.

``compare --base LOG [LOG ...] --head LOG [LOG ...]``
    The merge-point rule of docs/capacity-instrument.md: for every cell both logs hold, every
    gated share (Fisher's exact test, one-sided: the head has more) and every gated mean (the
    head's worse than the base's by more than a stated margin, one-sided, on the per-seed
    differences) at a family-wise level of 1 % (Bonferroni over the tests made), and every
    requirement the base meets. The differences are printed with their 95 % intervals. Prints the table with each test's p-value
    and exits 1 when the rule is broken, 0 when it holds, 2 on unusable input.

``baseline LOG [LOG ...]``
    Writes the tripwire baseline (``tests/fixtures/capacity-instrument-baseline.tsv``) to
    standard output: per cell and figure a threshold (the measurement's median, 90th or 10th
    percentile with a tenth of slack, or a fixed limit) and how many runs were beyond it.

Standard library only. ``python3 scripts/test_capacity_instrument.py`` holds it.
"""

from __future__ import annotations

import argparse
import math
import re
import sys
from dataclasses import dataclass, field
from statistics import NormalDist

ROW = re.compile(r"IROW (cell=\S+ seed=\d+ phase=\d+(?: \S+=\S+)*)")

# A run that did not get somewhere reports this many seconds (the instrument's `NEVER`).
NEVER = 99.0


@dataclass(frozen=True)
class Requirement:
    name: str
    figure: str
    limit: float
    claim: str
    scenario: str  # the scenario it is a requirement of: "cap", "outage" or "" for both


# The instrument's requirements (`PICTURE`, `FREEZE`, `AUDIO`, `RESUME` in the test file).
REQUIREMENTS = [
    Requirement("picture", "stale2", 0.5, "a picture older than 2 s on the screen for no more than 0.5 s in all", "cap"),
    Requirement("freeze", "freeze", 2.0, "never more than 2 s without a new picture of any age (secondary)", "cap"),
    Requirement("audio", "audio_gap", 1.0, "never more than 1 s without audio", "cap"),
    Requirement("resume", "resume", 2.0, "a new picture within 2 s of the path's return", "outage"),
]
REQUIRED_SHARE = 0.05
REQUIREMENT_ALPHA = 0.05

# What a comparison gates. Shares: (name, figure, limit). A failed run counts in every share.
GATED_SHARES = [
    ("picture", "stale2", 0.5),
    ("freeze", "freeze", 2.0),
    ("audio", "audio_gap", 1.0),
    ("never back", "tail_gap", 5.0),
    ("slow resume", "resume", 2.0),
    ("slow recovery", "recover", 20.0),
    ("a flow ceased by the circuit breaker", "cb", 0.0),
    ("a peer left Connected", "disc", 0.0),
    ("audio silent to the end", "audio_tail", 1.0),
]
# Means: (figure, whether more is worse, the margin). The head is worse when its mean is beyond
# the base's by more than the margin: a tenth of a second of picture or of audio (five packets),
# 10 kbit/s under the cap, 50 kbit/s in the recovery window. With the same seeds on both sides
# the test is on the per-seed differences, which a small change leaves highly correlated (a
# difference of 0.03 s is measured to +-0.04 s on 1000 seeds): without a margin it would break
# the rule over eight milliseconds of audio.
GATED_MEANS = [
    ("max_age", True, 0.1),
    ("stale1", True, 0.1),
    ("stale2", True, 0.1),
    ("fresh_gap", True, 0.1),
    ("audio_lost", True, 5.0),
    ("under", False, 10.0),
    ("window", False, 50.0),
]
FAMILY_ALPHA = 0.01

# What the tables show as percentiles.
TABLE_FIGURES = ["max_age", "age_p50", "stale1", "stale2", "fresh_gap", "freeze", "audio_gap", "audio_share", "audio_lost", "recover", "under", "window", "paused", "rtx"]

# The tripwires a baseline records: (figure, direction, levels). A level is a percentile of the
# measurement (0.5, 0.9, 0.1) or ("limit", value).
SLACK = 0.10
BASELINE = [
    ("max_age", "hi", [0.5, 0.9]),
    ("stale1", "hi", [0.5, 0.9]),
    ("fresh_gap", "hi", [0.5, 0.9]),
    ("stale2", "hi", [("limit", 0.5)]),
    ("freeze", "hi", [0.9, ("limit", 2.0)]),
    ("tail_gap", "hi", [("limit", 5.0)]),
    ("resume", "hi", [("limit", 2.0)]),
    ("audio_gap", "hi", [0.9, ("limit", 1.0)]),
    ("audio_lost", "hi", [0.9]),
    ("recover", "hi", [0.9]),
    ("rtx", "hi", [0.9]),
    ("discards", "hi", [("limit", 0.0)]),
    ("cb", "hi", [("limit", 0.0)]),
    ("disc", "hi", [("limit", 0.0)]),
    ("disc_open", "hi", [("limit", 0.0)]),
    ("disc_max", "hi", [("limit", 2.0)]),
    ("back_mean", "lo", [0.1]),
    ("audio_share", "lo", [("limit", 0.9)]),
    ("audio_tail", "hi", [("limit", 1.0)]),
    ("under", "lo", [0.1]),
    ("window", "lo", [0.1]),
]


@dataclass
class Run:
    cell: str
    seed: int
    phase: int
    figures: dict[str, float] = field(default_factory=dict)
    failed: str | None = None

    def value(self, figure: str) -> float | None:
        """The figure, `None` for a run that did not complete."""
        if self.failed is not None:
            return None
        return self.figures.get(figure)


def parse(text: str) -> list[Run]:
    """Every run in `text`, one per (cell, seed, phase): a line met again is dropped."""
    runs: dict[tuple[str, int, int], Run] = {}
    for match in ROW.finditer(text):
        items = dict(item.split("=", 1) for item in match.group(1).split())
        run = Run(items.pop("cell"), int(items.pop("seed")), int(items.pop("phase")))
        if "failed" in items:
            run.failed = items["failed"]
        else:
            run.figures = {name: float(value) for name, value in items.items()}
        runs.setdefault((run.cell, run.seed, run.phase), run)
    return list(runs.values())


def by_cell(runs: list[Run]) -> dict[str, list[Run]]:
    cells: dict[str, list[Run]] = {}
    for run in runs:
        cells.setdefault(run.cell, []).append(run)
    return cells


# ----------------------------------------------------------------------------------------------
# Statistics
# ----------------------------------------------------------------------------------------------


def quantile(values: list[float], q: float) -> float:
    """The value at the share `q` of `values`, linear between ranks."""
    if not values:
        return math.nan
    ordered = sorted(values)
    rank = (len(ordered) - 1) * q
    low, high = math.floor(rank), math.ceil(rank)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """The Wilson score interval of `k` of `n`."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return (max(0.0, centre - half), min(1.0, centre + half))


def _ln_choose(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def binomial_cdf(n: int, k: int, p: float) -> float:
    """The probability that a binomial(n, p) variable is at most `k`."""
    if p <= 0 or k >= n:
        return 1.0
    if p >= 1:
        return 0.0
    total = sum(math.exp(_ln_choose(n, i) + i * math.log(p) + (n - i) * math.log(1 - p)) for i in range(k + 1))
    return min(1.0, total)


def critical(n: int, p: float, alpha: float) -> int:
    """The least count c with P(binomial(n, p) <= c) >= 1 - alpha."""
    for c in range(n + 1):
        if binomial_cdf(n, c, p) >= 1 - alpha:
            return c
    return n


def fisher_greater(head_k: int, head_n: int, base_k: int, base_n: int) -> float:
    """Fisher's exact test, one-sided: the probability of `head_k` or more of the pooled
    events falling to the head when the two shares are equal."""
    events, total = head_k + base_k, head_n + base_n
    if events == 0 or head_n == 0 or base_n == 0:
        return 1.0
    denominator = _ln_choose(total, events)
    p = 0.0
    for k in range(head_k, min(events, head_n) + 1):
        if events - k > base_n:
            continue
        p += math.exp(_ln_choose(head_n, k) + _ln_choose(base_n, events - k) - denominator)
    return min(1.0, p)


def welch_greater(head: list[float], base: list[float]) -> tuple[float, float, float]:
    """Welch's test, one-sided (the head's mean is higher), by the normal approximation: the
    difference of the means, its standard error, and the p-value. (1.0 with fewer than two
    values on a side; a zero standard error gives 0 or 1 by the sign of the difference.)"""
    if len(head) < 2 or len(base) < 2:
        return (math.nan, math.nan, 1.0)
    mean_head, mean_base = sum(head) / len(head), sum(base) / len(base)
    var_head = sum((x - mean_head) ** 2 for x in head) / (len(head) - 1)
    var_base = sum((x - mean_base) ** 2 for x in base) / (len(base) - 1)
    difference = mean_head - mean_base
    error = math.sqrt(var_head / len(head) + var_base / len(base))
    if error == 0:
        return (difference, 0.0, 0.0 if difference > 0 else 1.0)
    return (difference, error, 1 - NormalDist().cdf(difference / error))


def worse_by(head: list[Run], base: list[Run], figure: str, high: bool, margin: float) -> tuple[str, float, float, float]:
    """Whether the head's mean of `figure` is worse than the base's by more than `margin`
    (higher when `high`, else lower), one-sided, by the normal approximation: how it was tested
    ("paired" on the runs both sides completed with the same seed and phase when they are at
    least half of either side, else "welch"), the difference of the means (head less base), the
    standard error, and the p-value of "worse by more than the margin"."""
    sign = 1.0 if high else -1.0
    of_base = {(run.seed, run.phase): run.value(figure) for run in base}
    pairs = [(run.value(figure), of_base.get((run.seed, run.phase))) for run in head]
    differences = [h - b for h, b in pairs if h is not None and b is not None]
    xh, xb = values(head, figure), values(base, figure)
    if len(differences) >= 2 and 2 * len(differences) >= max(len(xh), len(xb)):
        how, n = "paired", len(differences)
        difference = sum(differences) / n
        error = math.sqrt(sum((d - difference) ** 2 for d in differences) / (n - 1) / n)
    elif len(xh) >= 2 and len(xb) >= 2:
        how = "welch"
        difference, error, _ = welch_greater(xh, xb)
    else:
        return ("none", math.nan, math.nan, 1.0)
    excess = sign * difference - margin
    if error == 0:
        return (how, difference, 0.0, 0.0 if excess > 0 else 1.0)
    return (how, difference, error, 1 - NormalDist().cdf(excess / error))


def beyond(runs: list[Run], figure: str, limit: float, high: bool = True) -> int:
    """How many runs have `figure` over (under, with `high` false) `limit` or did not complete."""
    count = 0
    for run in runs:
        value = run.value(figure)
        if value is None or (value > limit if high else value < limit):
            count += 1
    return count


def has(runs: list[Run], figure: str) -> bool:
    """Whether the runs' instrument reported `figure` at all (an older one may not)."""
    return any(figure in run.figures for run in runs)


def clean(runs: list[Run]) -> list[Run]:
    """The runs in which no flow was ceased by the circuit breaker and no peer left Connected
    (and that completed): a short freeze with dead audio is not a good run."""
    return [run for run in runs if run.failed is None and run.figures.get("cb", 0.0) == 0 and run.figures.get("disc", 0.0) == 0]


def values(runs: list[Run], figure: str) -> list[float]:
    return [v for v in (run.value(figure) for run in runs) if v is not None]


def mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else math.nan


def requirements_of(cell: str) -> list[Requirement]:
    scenario = cell.split("/", 1)[0]
    return [r for r in REQUIREMENTS if r.scenario in ("", scenario)]


def met(requirement: Requirement, runs: list[Run]) -> bool:
    """The instrument's own test at this sample size: consistent with at most 5 % of calls."""
    allowed = critical(len(runs), REQUIRED_SHARE, REQUIREMENT_ALPHA)
    return beyond(runs, requirement.figure, requirement.limit) <= allowed


# ----------------------------------------------------------------------------------------------
# table
# ----------------------------------------------------------------------------------------------


def share_text(k: int, n: int) -> str:
    low, high = wilson(k, n)
    return f"{k}/{n} = {100 * k / n:.1f} % ({100 * low:.1f}-{100 * high:.1f})"


def table(trees: list[tuple[str, list[Run]]]) -> str:
    """The Markdown tables of `trees` (label, runs), one section per cell."""
    cells: list[str] = []
    for _, runs in trees:
        for cell in by_cell(runs):
            if cell not in cells:
                cells.append(cell)
    out = []
    for cell in cells:
        requirements = requirements_of(cell)
        out.append(f"### {cell}\n")
        header = ["tree", "runs (failed)", "breaker ceased a flow (audio)", "a peer left Connected (failed)", "clean runs"]
        header += [f"{r.name}: {r.figure} > {r.limit:g}, all runs" for r in requirements]
        header += [f"{r.name}, clean runs" for r in requirements]
        out.append("| " + " | ".join(header) + " |")
        out.append("|" + "---|" * len(header))
        for label, runs in trees:
            of_cell = by_cell(runs).get(cell)
            if not of_cell:
                continue
            failed = sum(1 for run in of_cell if run.failed is not None)
            good = clean(of_cell)
            over = {figure: sum(1 for run in of_cell if run.figures.get(figure, 0.0) > 0) for figure in ("cb", "cb_audio", "disc", "pc_failed")}
            row = [label, f"{len(of_cell)} ({failed})", f"{over['cb']} ({over['cb_audio']})", f"{over['disc']} ({over['pc_failed']})", str(len(good))]
            for requirement in requirements:
                k = beyond(of_cell, requirement.figure, requirement.limit)
                verdict = "met" if met(requirement, of_cell) else "MISSED"
                row.append(f"{share_text(k, len(of_cell))} {verdict}")
            for requirement in requirements:
                k = beyond(good, requirement.figure, requirement.limit)
                row.append(share_text(k, len(good)) if good else "-")
            out.append("| " + " | ".join(row) + " |")
        out.append("")
        out.append("| tree | figure | p10 | p50 | p90 | p99 | max | mean |")
        out.append("|---|---|---|---|---|---|---|---|")
        for label, runs in trees:
            of_cell = by_cell(runs).get(cell)
            if not of_cell:
                continue
            for figure in TABLE_FIGURES:
                xs = values(of_cell, figure)
                if not xs:
                    continue
                cells_ = [f"{quantile(xs, q):.2f}" for q in (0.1, 0.5, 0.9, 0.99, 1.0)]
                out.append(f"| {label} | {figure} | " + " | ".join(cells_) + f" | {mean(xs):.2f} |")
        out.append("")
    return "\n".join(out)


# ----------------------------------------------------------------------------------------------
# compare
# ----------------------------------------------------------------------------------------------


@dataclass
class Test:
    cell: str
    what: str
    base: str
    head: str
    p: float | None  # None: a requirement (no p-value), judged by `broken` alone
    broken: bool = False


def compare(base: list[Run], head: list[Run]) -> tuple[list[Test], float]:
    """Every test of the merge-point rule on the cells both sides hold, each marked broken or
    not, and the per-test level used (the family level over the tests with a p-value)."""
    base_cells, head_cells = by_cell(base), by_cell(head)
    tests: list[Test] = []
    for cell in base_cells:
        if cell not in head_cells:
            continue
        b, h = base_cells[cell], head_cells[cell]
        failed_b = sum(1 for run in b if run.failed is not None)
        failed_h = sum(1 for run in h if run.failed is not None)
        tests.append(
            Test(cell, "share: runs that did not complete", f"{failed_b}/{len(b)}", f"{failed_h}/{len(h)}", fisher_greater(failed_h, len(h), failed_b, len(b)))
        )
        for name, figure, limit in GATED_SHARES:
            if not (has(b, figure) and has(h, figure)):
                continue
            kb, kh = beyond(b, figure, limit), beyond(h, figure, limit)
            tests.append(
                Test(
                    cell,
                    f"share: {name} ({figure} > {limit:g})",
                    f"{kb}/{len(b)} = {100 * kb / len(b):.1f} %",
                    f"{kh}/{len(h)} = {100 * kh / len(h):.1f} %",
                    fisher_greater(kh, len(h), kb, len(b)),
                )
            )
        for figure, high, margin in GATED_MEANS:
            if not (has(b, figure) and has(h, figure)):
                continue
            xb, xh = values(b, figure), values(h, figure)
            if not high and max(xb + xh, default=0) == 0:
                continue
            how, difference, error, p = worse_by(h, b, figure, high, margin)
            tests.append(
                Test(
                    cell,
                    f"mean: {figure} ({'more' if high else 'less'} by over {margin:g}, {how})",
                    f"{mean(xb):.3f}",
                    f"{mean(xh):.3f} ({difference:+.3f} +-{1.96 * error:.3f})",
                    p,
                )
            )
        for requirement in requirements_of(cell):
            # A requirement the base meets and the head misses, when the head also has more
            # violating runs than chance gives (5 %): a share near the bound passes its test on
            # one draw and fails it on the next, and that alone is not the head's doing.
            met_b, met_h = met(requirement, b), met(requirement, h)
            kb, kh = beyond(b, requirement.figure, requirement.limit), beyond(h, requirement.figure, requirement.limit)
            tests.append(
                Test(
                    cell,
                    f"requirement: {requirement.name}",
                    f"{'met' if met_b else 'missed'} ({kb}/{len(b)})",
                    f"{'met' if met_h else 'missed'} ({kh}/{len(h)})",
                    None,
                    broken=met_b and not met_h and fisher_greater(kh, len(h), kb, len(b)) < 0.05,
                )
            )
    with_p = [t for t in tests if t.p is not None]
    level = FAMILY_ALPHA / len(with_p) if with_p else FAMILY_ALPHA
    for test in with_p:
        test.broken = test.p < level
    return tests, level


def compare_text(tests: list[Test], level: float, base_label: str, head_label: str) -> str:
    out = [
        f"Merge-point rule: {head_label} against {base_label}. Family-wise level {FAMILY_ALPHA:g} over "
        f"{sum(1 for t in tests if t.p is not None)} one-sided tests: each at p < {level:.2e}.",
        "",
        f"| cell | statistic | {base_label} | {head_label} | p (head worse) | |",
        "|---|---|---|---|---|---|",
    ]
    for test in tests:
        p = "" if test.p is None else f"{test.p:.2e}"
        out.append(f"| {test.cell} | {test.what} | {test.base} | {test.head} | {p} | {'WORSE' if test.broken else ''} |")
    broken = [t for t in tests if t.broken]
    out.append("")
    if broken:
        out.append(f"RULE BROKEN: {len(broken)} statistic(s) worse on {head_label}:")
        out.extend(f"- {t.cell}: {t.what}: {t.base} -> {t.head}" for t in broken)
    else:
        out.append(f"RULE HOLDS: nothing gated is worse on {head_label}.")
    return "\n".join(out)


# ----------------------------------------------------------------------------------------------
# baseline
# ----------------------------------------------------------------------------------------------


def baseline_lines(runs: list[Run]) -> list[str]:
    """The tripwire lines of a measurement: cell, figure, direction, threshold, beyond, runs,
    level, tab separated."""
    lines = []
    for cell, of_cell in by_cell(runs).items():
        for figure, direction, levels in BASELINE:
            xs = values(of_cell, figure)
            if not xs or (figure in ("under", "window") and max(xs) == 0):
                continue
            high = direction == "hi"
            seen = set()
            for level in levels:
                if isinstance(level, tuple):
                    name, threshold = "limit", float(level[1])
                else:
                    slack = 1 + SLACK if high else 1 - SLACK
                    name, threshold = f"p{round(level * 100)}", quantile(xs, level) * slack
                threshold = round(threshold, 3)
                if threshold in seen:
                    continue
                seen.add(threshold)
                count = beyond(of_cell, figure, threshold, high)
                lines.append(f"{cell}\t{figure}\t{direction}\t{threshold:.3f}\t{count}\t{len(of_cell)}\t{name}")
    return lines


def baseline_text(runs: list[Run], source: str) -> str:
    head = [
        "# Baseline of tests/capacity_instrument.rs (its tripwires): per cell and figure a threshold and how",
        "# many of the baseline's runs were beyond it (over for hi, under for lo, or did not complete).",
        f"# A percentile's threshold is the baseline's value and {SLACK:.0%} of slack. Written by",
        "# scripts/capacity-instrument.py baseline; do not edit by hand.",
        f"# Source: {source}",
        "cell\tfigure\tdirection\tthreshold\tbeyond\truns\tlevel",
    ]
    return "\n".join(head + baseline_lines(runs)) + "\n"


# ----------------------------------------------------------------------------------------------


def read(*paths: str) -> list[Run]:
    """The runs of the logs at `paths`, each (cell, seed, phase) once."""
    text = []
    for path in paths:
        with open(path, errors="replace") as handle:
            text.append(handle.read())
    return parse("\n".join(text))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    table_command = commands.add_parser("table")
    table_command.add_argument("trees", nargs="+", metavar="LABEL=LOG")
    compare_command = commands.add_parser("compare")
    compare_command.add_argument("--base", required=True, nargs="+", metavar="LOG")
    compare_command.add_argument("--head", required=True, nargs="+", metavar="LOG")
    compare_command.add_argument("--base-label", default="base")
    compare_command.add_argument("--head-label", default="head")
    baseline_command = commands.add_parser("baseline")
    baseline_command.add_argument("logs", nargs="+")
    baseline_command.add_argument("--source", default="(not stated)")
    args = parser.parse_args(argv)

    if args.command == "table":
        trees = []
        for item in args.trees:
            label, _, path = item.partition("=")
            runs = read(path)
            if not runs:
                print(f"no IROW line in {path}", file=sys.stderr)
                return 2
            trees.append((label, runs))
        print(table(trees))
        return 0
    if args.command == "compare":
        base, head = read(*args.base), read(*args.head)
        tests, level = compare(base, head)
        if not tests:
            print("the two logs have no cell in common", file=sys.stderr)
            return 2
        print(table([(args.base_label, base), (args.head_label, head)]))
        print(compare_text(tests, level, args.base_label, args.head_label))
        return 1 if any(test.broken for test in tests) else 0
    runs = read(*args.logs)
    if not runs:
        print("no IROW line in the logs", file=sys.stderr)
        return 2
    sys.stdout.write(baseline_text(runs, args.source))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
