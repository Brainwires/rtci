#!/usr/bin/env python3
"""Unit tests for scripts/check-performance-ledger.py, on small trees made in a temporary
directory.

    python3 scripts/test_check_performance_ledger.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_performance_ledger", HERE / "check-performance-ledger.py")
cpl = importlib.util.module_from_spec(spec)
sys.modules["check_performance_ledger"] = cpl
spec.loader.exec_module(cpl)

HEADER = "| id | date | status | change | what moved | before → after | why | guard | evidence |\n|---|---|---|---|---|---|---|---|---|\n"
GOOD_ROW = "| gcc-9 | 2026-11-24 | master | `conf/gcc-9` | lost audio | 0 → 0.18 s | the draft | `tests/cap.rs::a_test` | run 1; `CHANGELOG.md` |\n"

CHANGELOG = """# Changelog

## [Unreleased]

### Behaviour changes

- **interceptor** (`conf/gcc-9`): the threshold time base.
  Performance: gcc-9

## [0.1.0] - 2026-11-24

- old entry
  Performance: not-checked-in-a-release
"""


class Tree:
    """A repository tree with the files the checker reads."""

    def __init__(self, ledger, changelog=CHANGELOG, allowlist=None, files=None):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        files = {"tests/cap.rs": "#[test]\nfn a_test() {}\n", **(files or {})}
        (self.root / "docs").mkdir()
        (self.root / "docs" / "performance.md").write_text(ledger)
        (self.root / "CHANGELOG.md").write_text(changelog)
        if allowlist is not None:
            (self.root / "benches").mkdir()
            (self.root / "benches" / "accepted-regressions.toml").write_text(allowlist)
        for name, text in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def problems(self):
        try:
            return cpl.check(self.root)
        finally:
            self.dir.cleanup()


class Ledger(unittest.TestCase):
    def test_a_good_tree_passes(self):
        self.assertEqual([], Tree("# Ledger\n\n" + HEADER + GOOD_ROW).problems())

    def test_rows_come_only_from_tables_headed_id(self):
        text = HEADER + GOOD_ROW + "\n| profile | RTCP |\n|---|---|\n| default | 122 |\n"
        rows = cpl.ledger_rows(text)
        self.assertEqual(["gcc-9"], [r.id for r in rows])
        self.assertEqual("master", rows[0].status)

    def test_an_escaped_bar_stays_in_its_cell(self):
        self.assertEqual(["a | b", "c"], cpl.split_row("| a \\| b | c |"))

    def test_a_missing_file_fails(self):
        row = GOOD_ROW.replace("tests/cap.rs::a_test", "tests/gone.rs")
        problems = Tree(HEADER + row).problems()
        self.assertTrue(any("tests/gone.rs` does not exist" in p for p in problems), problems)

    def test_a_missing_test_function_fails(self):
        row = GOOD_ROW.replace("a_test", "renamed_test")
        problems = Tree(HEADER + row).problems()
        self.assertTrue(any("has no `fn renamed_test`" in p for p in problems), problems)

    def test_a_master_row_must_name_something(self):
        row = GOOD_ROW.replace("`tests/cap.rs::a_test`", "the tripwires").replace("`CHANGELOG.md`", "-")
        problems = Tree(HEADER + row).problems()
        self.assertTrue(any("names a file or test" in p for p in problems), problems)

    def test_a_rejected_row_is_checked_like_master(self):
        row = GOOD_ROW.replace("| master |", "| rejected |").replace("tests/cap.rs", "tests/nope.rs")
        self.assertTrue(Tree(HEADER + row).problems())

    def test_a_queued_row_names_its_branch_and_nothing_else_is_checked(self):
        queued = "| zeroize-1 | 2026-11-25 | queued | `conf/zeroize-1-key-erasure` | setup | 0.3 → 12.4 µs | erasure | `tests/later.rs` | run 2 |\n"
        self.assertEqual([], Tree(HEADER + GOOD_ROW + queued).problems())
        unnamed = queued.replace("`conf/zeroize-1-key-erasure`", "the zeroize branch")
        problems = Tree(HEADER + GOOD_ROW + unnamed).problems()
        self.assertTrue(any("names its branch" in p for p in problems), problems)

    def test_unknown_status_and_duplicate_id(self):
        bad = GOOD_ROW.replace("| master |", "| maybe |")
        problems = Tree(HEADER + GOOD_ROW + bad).problems()
        self.assertTrue(any("duplicate id" in p for p in problems), problems)
        self.assertTrue(any("status 'maybe'" in p for p in problems), problems)

    def test_no_ledger_table_fails(self):
        self.assertTrue(Tree("# Ledger\n\nnothing yet\n").problems())


class Changelog(unittest.TestCase):
    def test_a_tag_without_a_row_fails(self):
        changelog = CHANGELOG.replace("Performance: gcc-9", "Performance: gcc-9, rtx-1r2")
        problems = Tree(HEADER + GOOD_ROW, changelog=changelog).problems()
        self.assertEqual(1, len(problems), problems)
        self.assertIn("`Performance: rtx-1r2` has no ledger row", problems[0])

    def test_only_unreleased_is_read(self):
        tags = [ident for _, ident in cpl.changelog_tags(CHANGELOG)]
        self.assertEqual(["gcc-9"], tags)

    def test_a_tag_may_be_a_bullet_and_backticked(self):
        changelog = CHANGELOG.replace("  Performance: gcc-9", "- Performance: `gcc-9`.")
        self.assertEqual(["gcc-9"], [i for _, i in cpl.changelog_tags(changelog)])


class Allowlist(unittest.TestCase):
    def test_an_entry_names_a_ledger_row(self):
        good = '[[accepted]]\nbench = "DTLS/Setup/*"\nmax_ratio = 60.0\nledger = "gcc-9"\n'
        self.assertEqual([], Tree(HEADER + GOOD_ROW, allowlist=good).problems())
        orphan = good.replace('"gcc-9"', '"zeroize-1"')
        problems = Tree(HEADER + GOOD_ROW, allowlist=orphan).problems()
        self.assertTrue(any("accepted-regressions.toml entry 1" in p for p in problems), problems)

    def test_a_comment_only_allowlist_is_fine(self):
        self.assertEqual([], Tree(HEADER + GOOD_ROW, allowlist="# nothing accepted\n").problems())


if __name__ == "__main__":
    unittest.main(verbosity=2)
