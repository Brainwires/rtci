#!/usr/bin/env python3
"""Unit tests for the clause-audit half of scripts/check-test-inventory.py (`--check`): every
backticked name in the Test cell of a MUST / SHOULD row names something in the tree. Small trees
made for each case.

    python3 scripts/test_check_test_inventory.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_test_inventory", HERE / "check-test-inventory.py")
gate = importlib.util.module_from_spec(spec)
# Registered before exec_module: the module declares dataclasses, which look themselves up there.
sys.modules["check_test_inventory"] = gate
spec.loader.exec_module(gate)

HEADER = "| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |\n|---|---|---|---|---|---|---|---|\n"


class Tree:
    """A throwaway repository root with the files a case writes."""

    def __init__(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)
        self.write(
            "crate/src/thing_test.rs",
            "#[test]\nfn a_refused_packet_is_dropped() {}\n\nstruct S {\n    pub initial_value_fn: u8,\n}\n",
        )
        self.write("crate/src/lib.rs", "mod thing_test;\nmod wire_framing;\n")
        self.write("crate/src/wire_framing.rs", "fn helper() {}\n")
        self.write("crate/fuzz/fuzz_targets/packet_unmarshal.rs", "fuzz_target!(|d: &[u8]| {});\n")
        self.write("tests/testenv_network.rs", "#[test]\nfn reaches_the_lan() {}\n")

    def write(self, rel: str, text: str) -> "Tree":
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return self

    def row(self, level: str, test_cell: str) -> "Tree":
        line = f"| RFC1-1-1 | 1 | {level} | a clause | tested | `x.rs` | {test_cell} | |\n"
        return self.write("docs/conformance/audit/rfc1.md", "# RFC 1\n\n" + HEADER + line)

    def errors(self) -> list[str]:
        return gate.audit_dead_names(self.root)

    def close(self) -> None:
        self._dir.cleanup()


class AuditNamesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = Tree()

    def tearDown(self) -> None:
        self.tree.close()

    def test_an_existing_test_passes(self) -> None:
        self.tree.row("MUST", "`a_refused_packet_is_dropped`")
        self.assertEqual(self.tree.errors(), [])

    def test_a_renamed_test_fails(self) -> None:
        self.tree.row("MUST", "`thing_test.rs::a_refused_packet_is_discarded`")
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("RFC1-1-1", errors[0])
        self.assertIn("a_refused_packet_is_discarded", errors[0])
        self.assertIn("rfc1.md:5", errors[0])

    def test_a_should_row_is_checked_too(self) -> None:
        self.tree.row("SHOULD NOT", "`no_such_test_anywhere`")
        self.assertEqual(len(self.tree.errors()), 1)

    def test_a_may_row_is_not_checked(self) -> None:
        self.tree.row("MAY", "`no_such_test_anywhere`")
        self.assertEqual(self.tree.errors(), [])

    def test_a_test_cited_under_another_file_fails(self) -> None:
        self.tree.row("MUST", "`other_test.rs::a_refused_packet_is_dropped`")
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("not in other_test.rs", errors[0])

    def test_the_directory_and_a_crate_prefix_are_not_compared(self) -> None:
        self.tree.row(
            "MUST",
            "`src/x/thing_test.rs::a_refused_packet_is_dropped`, `crate thing_test.rs::a_refused_packet_is_dropped`",
        )
        self.assertEqual(self.tree.errors(), [])

    def test_fuzz_targets_modules_test_files_and_fields_are_names(self) -> None:
        self.tree.row(
            "MUST",
            "`packet_unmarshal`, `wire_framing`, `thing_test::tests`, `testenv_network`, `initial_value_fn`",
        )
        self.assertEqual(self.tree.errors(), [])

    def test_text_that_is_not_a_test_name_is_not_checked(self) -> None:
        self.tree.row("MUST", "`hd` tests, `a=rtcp-mux`, `tests/x.rs`, `MAX_SIZE`, `foo(true)`")
        self.assertEqual(self.tree.errors(), [])

    def test_a_trailing_call_is_dropped_before_the_lookup(self) -> None:
        self.tree.row("MUST", "`a_refused_packet_is_dropped()`, `gone_away_test(1)`")
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("gone_away_test", errors[0])


if __name__ == "__main__":
    unittest.main()
