#!/usr/bin/env python3
"""Unit tests for scripts/capacity-instrument.py: the row parser, the statistics and the
merge-point rule.

    python3 scripts/test_capacity_instrument.py
"""

from __future__ import annotations

import importlib.util
import math
import random
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("capacity_instrument", HERE / "capacity-instrument.py")
ci = importlib.util.module_from_spec(spec)
# Registered before exec_module: the module declares dataclasses, which look themselves up there.
sys.modules["capacity_instrument"] = ci
spec.loader.exec_module(ci)

CELL = "cap/paced/gap300/up/q300/rl0"
FIGURES = ["max_age", "age_p50", "stale1", "stale2", "fresh_gap", "freeze", "tail_gap", "resume", "audio_gap", "audio_lost", "recover", "under", "window", "paused", "rtx", "discards", "cb", "cb_audio", "disc", "pc_failed", "audio_share", "audio_tail"]


def run(seed, cell=CELL, **figures):
    """A completed run whose figures are zero but for `figures`."""
    values = {name: 0.0 for name in FIGURES}
    values.update(figures)
    return ci.Run(cell, seed, seed % 3, values)


def failed(seed, cell=CELL):
    return ci.Run(cell, seed, 0, failed="peer_0_failed")


class Parse(unittest.TestCase):
    def test_reads_rows_out_of_a_job_log(self):
        text = "\n".join(
            [
                "Run (ubuntu-latest)\tRun the command\t2026-11-24T21:00:00.1Z IROW cell=cap/paced/gap300/up/q300/rl0 seed=17 phase=23 max_age=8.420 stale1=8.050 rtx=101.000",
                "test measure ... IROW cell=cap/paced/gap300/up/q300/rl0 seed=18 phase=0 failed=peer_0_failed",
                "cap/paced/gap300/up/q300/rl0: 2 runs, 1 did not complete",
                "IROW cell=outage/paced/gap300/up/q300/rl0 seed=17 phase=23 max_age=5.100",
            ]
        )
        runs = ci.parse(text)
        self.assertEqual(3, len(runs))
        self.assertEqual((CELL, 17, 23), (runs[0].cell, runs[0].seed, runs[0].phase))
        self.assertEqual({"max_age": 8.42, "stale1": 8.05, "rtx": 101.0}, runs[0].figures)
        self.assertEqual("peer_0_failed", runs[1].failed)
        self.assertIsNone(runs[1].value("max_age"))
        self.assertEqual(["cap/paced/gap300/up/q300/rl0", "outage/paced/gap300/up/q300/rl0"], list(ci.by_cell(runs)))

    def test_a_row_met_twice_counts_once(self):
        line = "IROW cell=cap/paced/gap300/up/q300/rl0 seed=1 phase=11 max_age=1.000\n"
        self.assertEqual(1, len(ci.parse(line * 3)))
        # Another phase of the same seed is another run.
        self.assertEqual(2, len(ci.parse(line + line.replace("phase=11", "phase=0"))))


class Statistics(unittest.TestCase):
    def test_quantile_is_linear_between_ranks(self):
        self.assertEqual(2.5, ci.quantile([4, 1, 3, 2], 0.5))
        self.assertEqual(1, ci.quantile([4, 1, 3, 2], 0))
        self.assertEqual(4, ci.quantile([4, 1, 3, 2], 1))
        self.assertAlmostEqual(3.7, ci.quantile([4, 1, 3, 2], 0.9))
        self.assertTrue(math.isnan(ci.quantile([], 0.5)))

    def test_wilson_interval(self):
        # The review's 91 of 1100: 6.8 to 10.0 %.
        low, high = ci.wilson(91, 1100)
        self.assertAlmostEqual(0.068, low, places=3)
        self.assertAlmostEqual(0.100, high, places=3)
        low, high = ci.wilson(0, 100)
        self.assertEqual(0.0, low)
        self.assertAlmostEqual(0.037, high, places=3)
        self.assertEqual((0.0, 1.0), ci.wilson(0, 0))

    def test_the_requirement_test_of_300_runs(self):
        # The instrument's power calculation (tests/capacity_instrument.rs).
        self.assertEqual(21, ci.critical(300, 0.05, 0.05))
        self.assertAlmostEqual(0.951, ci.binomial_cdf(300, 21, 0.05), places=3)
        self.assertAlmostEqual(0.046, ci.binomial_cdf(300, 21, 0.10), places=3)
        self.assertEqual(18, ci.critical(240, 0.05, 0.05))
        self.assertEqual(1.0, ci.binomial_cdf(10, 10, 0.5))
        self.assertEqual(0.0, ci.binomial_cdf(10, 9, 1.0))
        self.assertAlmostEqual(11 / 1024, ci.binomial_cdf(10, 1, 0.5))

    def test_fisher_one_sided(self):
        # The classic table: 11 of 14 against 1 of 10, one-sided p = 0.001380.
        self.assertAlmostEqual(0.001380, ci.fisher_greater(11, 14, 1, 10), places=6)
        # The other direction is no evidence at all.
        self.assertGreater(ci.fisher_greater(1, 10, 11, 14), 0.99)
        self.assertEqual(1.0, ci.fisher_greater(0, 50, 0, 50))
        self.assertAlmostEqual(0.5, ci.fisher_greater(1, 1, 0, 1))
        # The review's master against rtx-1r, the other way round: 91 of 1100 against 9 of 1100.
        self.assertLess(ci.fisher_greater(91, 1100, 9, 1100), 1e-17)

    def test_welch_one_sided(self):
        difference, error, p = ci.welch_greater([2, 3, 4, 5, 6], [1, 2, 3, 4, 5])
        self.assertEqual(1.0, difference)
        self.assertAlmostEqual(1.0, error)
        self.assertAlmostEqual(0.1587, p, places=4)
        self.assertEqual(1.0, ci.welch_greater([1], [1, 2])[2])
        self.assertEqual(0.0, ci.welch_greater([2, 2], [1, 1])[2])
        self.assertEqual(1.0, ci.welch_greater([1, 1], [1, 1])[2])

    def test_a_failed_run_is_beyond_every_limit(self):
        runs = [run(1, stale2=0.4), run(2, stale2=0.6), failed(3)]
        self.assertEqual(2, ci.beyond(runs, "stale2", 0.5))
        self.assertEqual(1, ci.beyond(runs, "stale2", 0.3, high=False))
        self.assertEqual([0.4, 0.6], ci.values(runs, "stale2"))


class Requirements(unittest.TestCase):
    def test_met_is_the_exact_test_at_the_sample_size(self):
        picture = ci.REQUIREMENTS[0]
        self.assertEqual(("picture", "stale2", 0.5), (picture.name, picture.figure, picture.limit))
        runs = [run(seed, stale2=1.0 if seed <= 21 else 0.0) for seed in range(1, 301)]
        self.assertTrue(ci.met(picture, runs))
        runs[21] = run(22, stale2=1.0)
        self.assertFalse(ci.met(picture, runs))

    def test_the_outage_has_its_own_requirement(self):
        self.assertEqual(["picture", "freeze", "audio"], [r.name for r in ci.requirements_of(CELL)])
        self.assertEqual(["resume"], [r.name for r in ci.requirements_of("outage/paced/gap300/up/q300/rl0")])


def ensemble(seed, runs, shift=0.0, violators=0.0, cell=CELL):
    """`runs` runs with a picture about 8 s old (spread 1 s), `shift` seconds older, and a
    share `violators` of them frozen for 3 s."""
    rng = random.Random(seed)
    out = []
    for i in range(1, runs + 1):
        age = max(0.0, rng.gauss(8.0 + shift, 1.0))
        out.append(run(i, cell, max_age=age, stale1=max(0.0, age - 1), stale2=max(0.0, age - 2), freeze=3.0 if rng.random() < violators else 1.0))
    return out


class Compare(unittest.TestCase):
    def test_two_draws_of_one_tree_hold_the_rule(self):
        tests, level = ci.compare(ensemble(1, 1000, violators=0.08), ensemble(2, 1000, violators=0.08))
        self.assertEqual([], [t.what for t in tests if t.broken])
        # Fifteen tests with a p-value in a cap cell (these runs have no rate under the cap):
        # the family's 1 % over them.
        self.assertEqual(15, sum(1 for t in tests if t.p is not None))
        self.assertAlmostEqual(0.01 / 15, level)

    def test_a_picture_half_a_second_older_breaks_it(self):
        tests, _ = ci.compare(ensemble(1, 1000), ensemble(2, 1000, shift=0.5))
        broken = [t.what for t in tests if t.broken]
        self.assertIn("mean: max_age (more by over 0.1, paired)", broken)
        self.assertIn("mean: stale1 (more by over 0.1, paired)", broken)

    def test_a_difference_inside_the_margin_does_not_break_it_however_well_measured(self):
        # The same seeds, every picture 0.05 s older: measured exactly, and under the margin.
        base = ensemble(1, 1000)
        head = [run(r.seed, max_age=r.figures["max_age"] + 0.05) for r in base]
        how, difference, error, p = ci.worse_by(head, base, "max_age", True, 0.1)
        self.assertEqual("paired", how)
        self.assertAlmostEqual(0.05, difference)
        self.assertLess(error, 1e-9)
        self.assertEqual(1.0, p)
        # 0.15 s older is over it.
        head = [run(r.seed, max_age=r.figures["max_age"] + 0.15) for r in base]
        self.assertEqual(0.0, ci.worse_by(head, base, "max_age", True, 0.1)[3])

    def test_a_lower_rate_under_the_cap_breaks_it(self):
        base = [run(i, under=200.0 + i % 7) for i in range(1, 201)]
        head = [run(i, under=180.0 + i % 5) for i in range(1, 201)]
        tests, _ = ci.compare(base, head)
        self.assertIn("mean: under (less by over 10, paired)", [t.what for t in tests if t.broken])
        tests, _ = ci.compare(head, base)
        self.assertEqual([], [t.what for t in tests if t.broken])

    def test_other_seeds_are_compared_without_pairing(self):
        base = ensemble(1, 300)
        head = [run(r.seed + 1000, max_age=r.figures["max_age"] + 1.0) for r in ensemble(2, 300)]
        how, difference, _, p = ci.worse_by(head, base, "max_age", True, 0.1)
        self.assertEqual("welch", how)
        self.assertLess(p, 1e-6)

    def test_a_better_head_is_not_a_breach(self):
        tests, _ = ci.compare(ensemble(1, 1000, violators=0.08), ensemble(2, 1000, shift=-2.0, violators=0.0))
        self.assertEqual([], [t.what for t in tests if t.broken])

    def test_twice_the_share_of_frozen_calls_breaks_it(self):
        tests, _ = ci.compare(ensemble(1, 1000, violators=0.08), ensemble(2, 1000, violators=0.16))
        self.assertIn("share: freeze (freeze > 2)", [t.what for t in tests if t.broken])

    def test_runs_that_stop_completing_break_it(self):
        base = ensemble(1, 200)
        head = ensemble(2, 180) + [failed(i) for i in range(181, 201)]
        tests, _ = ci.compare(base, head)
        self.assertIn("share: runs that did not complete", [t.what for t in tests if t.broken])

    def test_a_requirement_the_base_meets_and_the_head_misses(self):
        # 3 % against 9 % of 300: no single share test reaches the family level, the
        # requirement does.
        base = [run(i, freeze=3.0 if i <= 9 else 1.0) for i in range(1, 301)]
        head = [run(i, freeze=3.0 if i <= 27 else 1.0) for i in range(1, 301)]
        tests, _ = ci.compare(base, head)
        broken = [t.what for t in tests if t.broken]
        self.assertIn("requirement: freeze", broken)
        # A share at the bound that passes on one draw and fails on the next is not a breach.
        base = [run(i, freeze=3.0 if i <= 20 else 1.0) for i in range(1, 301)]
        head = [run(i, freeze=3.0 if i <= 23 else 1.0) for i in range(1, 301)]
        tests, _ = ci.compare(base, head)
        self.assertEqual([], [t.what for t in tests if t.broken])
        # One both miss is not the head's breach.
        tests, _ = ci.compare(head, head)
        self.assertEqual([], [t.what for t in tests if t.broken])

    def test_only_cells_on_both_sides_are_compared(self):
        other = "cap/nopacer/gap300/up/q300/rl0"
        tests, _ = ci.compare(ensemble(1, 50) + ensemble(1, 50, cell=other), ensemble(2, 50))
        self.assertEqual({CELL}, {t.cell for t in tests})
        self.assertEqual(([], ci.FAMILY_ALPHA), ci.compare(ensemble(1, 5, cell=other), ensemble(2, 5)))

    def test_the_text_names_what_broke(self):
        tests, level = ci.compare(ensemble(1, 1000), ensemble(2, 1000, shift=0.5))
        text = ci.compare_text(tests, level, "master", "head")
        self.assertIn("RULE BROKEN", text)
        self.assertIn(f"- {CELL}: mean: max_age (more by over 0.1, paired)", text)
        tests, level = ci.compare(ensemble(1, 1000), ensemble(1, 1000))
        self.assertIn("RULE HOLDS", ci.compare_text(tests, level, "master", "head"))


class Baseline(unittest.TestCase):
    def test_thresholds_and_counts(self):
        runs = [run(i, max_age=float(i), under=200.0 + i, freeze=1.0) for i in range(1, 101)] + [failed(101)]
        lines = [line.split("\t") for line in ci.baseline_lines(runs)]
        rows = {(figure, level): (direction, float(threshold), int(count), int(n)) for _, figure, direction, threshold, count, n, level in lines}
        # The median of 1..100 is 50.5, the threshold a tenth over it: 55.55, rounded to 55.55.
        direction, threshold, count, n = rows[("max_age", "p50")]
        self.assertEqual(("hi", 101), (direction, n))
        self.assertAlmostEqual(55.55, threshold)
        # 56..100 are over it, and the failed run counts.
        self.assertEqual(46, count)
        direction, threshold, count, n = rows[("under", "p10")]
        self.assertEqual("lo", direction)
        self.assertAlmostEqual((200 + 10.9) * 0.9, threshold, places=3)
        self.assertEqual(1, count)
        # A fixed limit is recorded as it is.
        self.assertEqual(("hi", 2.0, 1, 101), rows[("freeze", "limit")])
        self.assertEqual(("hi", 0.0, 1, 101), rows[("discards", "limit")])

    def test_key_frames_are_held_in_the_forward_loss_cells_only(self):
        loss = "fl3/paced/gap300/up/q300/rl0"
        runs = [run(i, keyframes=3.0) for i in range(1, 11)] + [run(i, cell=loss, keyframes=3.0 + (i >= 9)) for i in range(1, 11)]
        lines = [line.split("\t") for line in ci.baseline_lines(runs)]
        held = [(cell, level, float(threshold), int(count)) for cell, figure, _, threshold, count, _, level in lines if figure == "keyframes"]
        # Three key frames a call and a tenth of slack: the two calls with four are beyond the
        # median's threshold, none beyond the 90th percentile's.
        self.assertEqual([(loss, "p50", 3.3, 2), (loss, "p90", 4.4, 0)], held)

    def test_the_file_reads_back_as_the_test_reads_it(self):
        text = ci.baseline_text([run(i, max_age=float(i)) for i in range(1, 11)], "run 1 on abc")
        body = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual("cell\tfigure\tdirection\tthreshold\tbeyond\truns\tlevel", body[0])
        for line in body[1:]:
            fields = line.split("\t")
            self.assertEqual(7, len(fields), line)
            self.assertIn(fields[2], ("hi", "lo"))
            float(fields[3]), int(fields[4]), int(fields[5])
        self.assertIn("# Source: run 1 on abc", text)


class Clean(unittest.TestCase):
    def test_a_run_with_a_ceased_flow_or_a_peer_that_left_connected_is_not_clean(self):
        runs = [run(1), run(2, cb=1.0, cb_audio=1.0), run(3, disc=1.0), failed(4)]
        self.assertEqual([1], [r.seed for r in ci.clean(runs)])
        text = ci.table([("master", runs)])
        row = next(line for line in text.splitlines() if line.startswith("| master | 4 (1)"))
        self.assertIn("| 1 (1) | 1 (0) | 1 |", row)

    def test_a_ceased_flow_is_a_gated_share(self):
        base = [run(i) for i in range(1, 201)]
        head = [run(i, cb=1.0 if i <= 30 else 0.0) for i in range(1, 201)]
        tests, _ = ci.compare(base, head)
        self.assertIn("share: a flow ceased by the circuit breaker (cb > 0)", [t.what for t in tests if t.broken])

    def test_rows_of_an_older_instrument_are_compared_on_what_they_have(self):
        old = [ci.Run(CELL, i, 0, {"max_age": 8.0, "freeze": 1.0}) for i in range(1, 51)]
        tests, _ = ci.compare(old, old)
        whats = [t.what for t in tests]
        self.assertIn("mean: max_age (more by over 0.1, paired)", whats)
        self.assertFalse([w for w in whats if w.startswith("mean: stale1")])
        self.assertNotIn("share: a peer left Connected (disc > 0)", whats)


class Table(unittest.TestCase):
    def test_a_table_per_cell_with_the_requirements(self):
        text = ci.table([("master", ensemble(1, 300, violators=0.5)), ("head", ensemble(2, 300, shift=-7.5))])
        self.assertIn(f"### {CELL}", text)
        self.assertIn("picture: stale2 > 0.5", text)
        master = next(line for line in text.splitlines() if line.startswith("| master | 300 (0)"))
        self.assertIn("MISSED", master)
        head = next(line for line in text.splitlines() if line.startswith("| head | 300 (0)"))
        self.assertEqual(3, head.count(" met |"), head)
        self.assertNotIn("MISSED", head)
        self.assertIn("| master | max_age |", text)


if __name__ == "__main__":
    unittest.main()
