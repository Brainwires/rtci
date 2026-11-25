#!/usr/bin/env python3
"""Unit tests for scripts/check-changelog-released.py: which tag the gate compares with.

    python3 scripts/test_check_changelog_released.py

Each test builds a throwaway repository in a temporary directory.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "check_changelog_released", HERE / "check-changelog-released.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

UNRELEASED = "# Changelog\n\n## [Unreleased]\n\n"
OLD = "## [0.9.0] - 2026-01-01\n\n- the old line's release\n\n"
MAIN = "## [1.0.0] - 2026-02-01\n\n- this line's release\n\n"
SIDE = "## [0.9.1] - 2026-03-01\n\n- a maintenance release of the old line\n\n"


class Repo:
    """main: 0.9.0 (v0.9.0), 1.0.0 (v1.0.0), then work; side from v0.9.0: 0.9.1 (v0.9.1, newest)."""

    def __init__(self, root: Path):
        self.root = root
        self.clock = 1_700_000_000
        self.git("init", "--quiet", "--initial-branch=main")
        self.commit(UNRELEASED + OLD, "release 0.9.0")
        self.git("tag", "v0.9.0")
        self.commit(UNRELEASED + MAIN + OLD, "release 1.0.0")
        self.git("tag", "v1.0.0")
        self.git("switch", "--quiet", "-c", "side", "v0.9.0")
        self.commit(UNRELEASED + SIDE + OLD, "release 0.9.1")
        self.git("tag", "v0.9.1")
        self.git("switch", "--quiet", "main")

    def git(self, *args: str) -> str:
        self.clock += 60
        date = f"{self.clock} +0000"
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@example.invalid",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@example.invalid",
            GIT_AUTHOR_DATE=date,
            GIT_COMMITTER_DATE=date,
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_SYSTEM=os.devnull,
        )
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True, capture_output=True, text=True, env=env
        ).stdout

    def commit(self, changelog: str, message: str) -> None:
        (self.root / "CHANGELOG.md").write_text(changelog)
        self.git("add", "CHANGELOG.md")
        self.git("commit", "--quiet", "-m", message)

    def check(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.main(list(args), self.root)
        return code, out.getvalue()


class LatestTag(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Repo(Path(self.tmp.name))

    def test_the_fixture_has_a_newer_tag_on_the_side_branch(self):
        newest = self.repo.git("tag", "--list", "v*", "--sort=-creatordate").split()[0]
        self.assertEqual(newest, "v0.9.1")

    def test_a_newer_tag_on_another_branch_is_ignored(self):
        self.assertEqual(gate.latest_tag(self.repo.root), "v1.0.0")
        code, out = self.repo.check()
        self.assertEqual(code, 0, out)
        self.assertIn("v1.0.0", out)

    def test_work_under_unreleased_passes_and_an_entry_in_a_released_section_fails(self):
        self.repo.commit(UNRELEASED + "- new work\n\n" + MAIN + OLD, "work")
        self.assertEqual(self.repo.check()[0], 0)
        self.repo.commit(UNRELEASED + MAIN + "- misplaced\n\n" + OLD, "misplaced")
        code, out = self.repo.check()
        self.assertEqual(code, 1)
        self.assertIn("section [1.0.0] differs from v1.0.0", out)

    def test_the_side_branch_is_checked_against_its_own_release(self):
        self.repo.git("switch", "--quiet", "side")
        self.assertEqual(gate.latest_tag(self.repo.root), "v0.9.1")
        self.assertEqual(self.repo.check()[0], 0)

    def test_the_explicit_tag_overrides_the_search(self):
        code, out = self.repo.check("--tag", "v0.9.1")
        self.assertEqual(code, 1)
        self.assertIn("section [0.9.1] of v0.9.1 is missing", out)

    def test_a_history_without_a_release_has_nothing_to_compare(self):
        self.repo.git("switch", "--quiet", "--orphan", "fresh")
        self.repo.commit(UNRELEASED, "start")
        self.assertIsNone(gate.latest_tag(self.repo.root))
        self.assertEqual(self.repo.check()[0], 0)

    def test_a_shallow_clone_fetches_the_history_before_it_looks(self):
        with tempfile.TemporaryDirectory() as clone:
            self.repo.git(
                "clone", "--quiet", "--depth=1", "--no-tags", "--branch", "main",
                self.repo.root.as_uri(), clone,
            )
            self.assertEqual(gate.latest_tag(Path(clone)), "v1.0.0")


if __name__ == "__main__":
    unittest.main()
