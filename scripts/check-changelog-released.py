#!/usr/bin/env python3
"""Released CHANGELOG sections stay as they were released.

Every ``## [<version>]`` section of ``CHANGELOG.md`` other than ``## [Unreleased]`` must be
byte for byte the same as that section in ``CHANGELOG.md`` at the latest release tag of the
commit being checked: the newest ``v*`` tag, by creation date, that is an ANCESTOR of ``HEAD``.
A tag on another branch (a maintenance release of an earlier line, cut after this line's last
release) is not this history's release and is ignored, however new it is. A merge that unions
two branches' CHANGELOGs can place new entries in an already released section, or repeat a
released entry there; new entries belong under ``## [Unreleased]``.

A section the tag does not have yet (the release commit's new section) is not compared. A
section the tag has and the working tree lost fails.

Ancestry needs the history: in a shallow checkout (CI's default) the script first fetches the
rest of the history and the tags from ``origin``. ``--tag <tag>`` names the tag to compare with
and skips the search. Usage: ``python3 scripts/check-changelog-released.py [--tag <tag>]``.
Tests: ``python3 scripts/test_check_changelog_released.py``.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADING = re.compile(r"^## \[([^\]]+)\]", re.M)


def git(*args: str, root: Path = ROOT) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def latest_tag(root: Path = ROOT) -> str | None:
    """The newest ``v*`` tag (by creation date) that is an ancestor of ``HEAD``."""
    if git("rev-parse", "--is-shallow-repository", root=root).strip() == "true":
        # Which tags are ancestors cannot be told from a shallow history.
        subprocess.run(
            ["git", "fetch", "--quiet", "--unshallow", "--tags", "origin"], cwd=root, check=False
        )
    tags = git(
        "tag", "--list", "v*", "--merged", "HEAD", "--sort=-creatordate", root=root
    ).split()
    return tags[0] if tags else None


def released_sections(text: str) -> dict[str, str]:
    """The text of every released section, by its bracketed version."""
    marks = [(m.start(), m.group(1)) for m in HEADING.finditer(text)]
    sections = {}
    for i, (start, version) in enumerate(marks):
        if version.lower() == "unreleased":
            continue
        end = marks[i + 1][0] if i + 1 < len(marks) else len(text)
        if version in sections:
            sections[version] += text[start:end]
        else:
            sections[version] = text[start:end]
    return sections


def main(args: list[str] | None = None, root: Path = ROOT) -> int:
    args = sys.argv[1:] if args is None else args
    tag = args[args.index("--tag") + 1] if "--tag" in args else latest_tag(root)
    if tag is None:
        print("check-changelog-released: no v* tag is an ancestor of HEAD; nothing to compare")
        return 0
    released = released_sections(git("show", f"{tag}:CHANGELOG.md", root=root))
    current_text = (root / "CHANGELOG.md").read_text()
    current = released_sections(current_text)
    problems = []
    for version, text in released.items():
        if version not in current:
            problems.append(f"section [{version}] of {tag} is missing")
        elif current[version] != text:
            ours = current[version].splitlines()
            theirs = text.splitlines()
            added = [line for line in ours if line not in theirs]
            removed = [line for line in theirs if line not in ours]
            sample = (added or removed or ["(order or blank lines differ)"])[0]
            problems.append(
                f"section [{version}] differs from {tag}: {len(added)} line(s) not in the "
                f"release, {len(removed)} missing; first: {sample[:100]!r}"
            )
    for problem in problems:
        print(f"check-changelog-released: {problem}")
    if problems:
        print(
            "check-changelog-released: released sections must equal the tag's; "
            "new entries go under ## [Unreleased]"
        )
        return 1
    print(f"check-changelog-released: {len(released)} released sections equal {tag}'s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
