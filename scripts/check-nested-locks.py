#!/usr/bin/env python3
"""Every committed ``Cargo.lock`` of a nested workspace still resolves its manifest.

The root workspace commits no lock file, but the test environment's peers do
(``scripts/test-env/peers/*/Cargo.lock``), and some of them depend on the workspace's crates by
path. When a dependency is added to one of those crates, the nested lock goes stale: a build
with ``--locked`` (as the test environment's images do) fails far from the change. This runs
``cargo metadata --locked`` on each nested workspace with a committed lock, which fails when the
lock would have to change, so a stale one fails here, early. Regenerate it with
``cargo update --workspace --manifest-path <dir>/Cargo.toml`` (or ``cargo generate-lockfile``)
and commit it.

Usage: ``python3 scripts/check-nested-locks.py``. Needs cargo and the crates.io index.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def committed_locks() -> list[Path]:
    """The committed lock files of nested workspaces (not the root's)."""
    try:
        listed = subprocess.run(
            ["git", "ls-files", "--", "*Cargo.lock"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
        locks = [ROOT / path for path in listed]
    except (OSError, subprocess.CalledProcessError):
        locks = [p for p in ROOT.rglob("Cargo.lock") if "target" not in p.parts]
    return sorted(p for p in locks if p.parent != ROOT)


def main() -> int:
    locks = committed_locks()
    if not locks:
        print("check-nested-locks: no committed nested Cargo.lock")
        return 0
    stale = []
    for lock in locks:
        manifest = lock.parent / "Cargo.toml"
        name = lock.relative_to(ROOT)
        if not manifest.is_file():
            stale.append(f"{name}: no Cargo.toml beside it")
            continue
        result = subprocess.run(
            [
                "cargo",
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--manifest-path",
                str(manifest),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            stale.append(f"{name}:\n{result.stderr.strip()}")
        else:
            print(f"check-nested-locks: {name} is up to date")
    if stale:
        print("check-nested-locks: stale or broken lock files:", file=sys.stderr)
        for problem in stale:
            print(f"  {problem}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
