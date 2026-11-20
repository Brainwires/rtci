#!/usr/bin/env python3
"""CI supply-chain and runner hygiene.

Fails when a workflow under ``.github/workflows/``:

* uses an action by a tag or branch instead of a full commit SHA (``owner/repo@<40 hex>``;
  local ``./`` actions are fine), since whoever moves the tag decides what runs with the token;
* is triggered by ``pull_request_target`` (it runs with the base repository's secrets on code a
  fork controls);
* lets a pull request from a fork reach a self-hosted runner: in a workflow triggered by
  ``pull_request``, every job whose ``runs-on`` can name one of our labels (a ``self-hosted``
  label, or an expression over ``needs.*`` / ``vars.*`` / ``fromJSON``, which is how the
  pick-runners plan is read) must have an ``if:`` that admits pull requests only from this
  repository (``github.event.pull_request.head.repo.full_name == github.repository``).

The ``if:`` guard routes fork pull requests to GitHub's runners; it is not a boundary on its own,
because a fork can edit the workflow it proposes. The repository settings are the boundary: fork
runs need a maintainer's approval, and runner groups open to public repositories are restricted
to selected workflows. Review ``runs-on`` and ``.github/`` changes before approving a fork run.

Usage: ``python3 scripts/check-workflow-pins.py``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))

USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>[^\s#]+)")
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")
SAME_REPO_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"
SELF_HOSTED_CAPABLE = re.compile(r"self-hosted|needs\.|vars\.|fromJSON", re.I)


def on_block(lines: list[str]) -> str:
    """The text of the top-level `on:` trigger block."""
    out = []
    inside = False
    for line in lines:
        if re.match(r"^(on|\"on\"|'on'|true):", line):
            inside = True
            out.append(line)
            continue
        if inside:
            if line and not line[0].isspace() and not line.startswith("#"):
                break
            out.append(line)
    return "\n".join(out)


def jobs(lines: list[str]) -> dict[str, list[str]]:
    """Job id -> the lines of its block."""
    out: dict[str, list[str]] = {}
    inside = False
    current = None
    for line in lines:
        if re.match(r"^jobs:\s*$", line):
            inside = True
            continue
        if not inside:
            continue
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m.group(1)
            out[current] = []
            continue
        if current is not None:
            out[current].append(line)
    return out


def job_key(block: list[str], key: str) -> str:
    """A job-level key's value, folded scalars (`>-`, `|`) and continuation lines included."""
    for i, line in enumerate(block):
        m = re.match(rf"^    {key}:\s*(.*)$", line)
        if not m:
            continue
        value = [m.group(1)]
        for follow in block[i + 1 :]:
            if follow.startswith("      ") or not follow.strip():
                value.append(follow.strip())
            else:
                break
        return " ".join(v for v in value if v)
    return ""


def main() -> int:
    errors = []
    for workflow in WORKFLOWS:
        name = workflow.relative_to(ROOT).as_posix()
        lines = workflow.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines, 1):
            m = USES.match(line)
            if not m:
                continue
            ref = m.group("ref").strip("'\"")
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            if not PINNED.match(ref):
                errors.append(f"{name}:{n}: `{ref}` is not pinned to a commit SHA")
        triggers = on_block(lines)
        if "pull_request_target" in triggers:
            errors.append(f"{name}: triggered by pull_request_target")
        if not re.search(r"\bpull_request\b", triggers):
            continue
        for job, block in jobs(lines).items():
            runs_on = job_key(block, "runs-on")
            if not SELF_HOSTED_CAPABLE.search(runs_on):
                continue
            if SAME_REPO_GUARD not in job_key(block, "if"):
                errors.append(
                    f"{name}: job `{job}` can run on a self-hosted runner ({runs_on}) but its `if:`"
                    " does not keep fork pull requests off it"
                )

    if errors:
        print("Workflow check failed:\n")
        for e in errors:
            print(f"  {e}")
        return 1
    print(f"Workflows: {len(WORKFLOWS)} files, every action pinned by SHA, no self-hosted runner reachable from a fork pull request.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
