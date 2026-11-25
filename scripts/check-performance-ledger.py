#!/usr/bin/env python3
"""The performance ledger (`docs/performance.md`) stays tied to the CHANGELOG and to the tree.

Fails when:

* a CHANGELOG entry under ``[Unreleased]`` carries a line ``Performance: <id>[, <id>...]`` and
  the ledger has no row with that id (a branch that moves a measured figure adds its ledger row
  in the same branch);
* a ledger row has a malformed or duplicate id, or a status other than ``master``, ``queued`` or
  ``rejected``;
* a row whose status is ``master`` or ``rejected`` (the decision is in the tree: the change, or
  the default a measured alternative was refused for) names no file or test of the repository,
  or names one that does not exist. A backticked ``path/to/file.ext`` must exist, and a
  backticked ``path/to/file.rs::name`` must also have ``fn name`` in that file;
* a ``queued`` row does not name its branch (a backticked ``conf/...``);
* an entry of `benches/accepted-regressions.toml` names a ledger id that is not a row.

The ledger rows are the rows of every table in `docs/performance.md` whose first header cell is
``id``; the status column is the one headed ``status``. Prose is never parsed for figures.

Usage: ``python3 scripts/check-performance-ledger.py`` (``--root`` for another tree).
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STATUSES = {"master", "queued", "rejected"}
LEDGER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
TAG = re.compile(r"^\s*(?:[-*]\s+)?Performance:\s*(?P<ids>.+?)\s*$")
BACKTICKED = re.compile(r"`([^`]+)`")
PATH_LIKE = re.compile(
    r"^(?P<path>[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.(?:rs|md|py|toml|tsv|yml|yaml|sh|txt|json|mjs))"
    r"(?:::(?P<fn>[A-Za-z_][A-Za-z0-9_]*))?$"
)
BRANCH = re.compile(r"^conf/[A-Za-z0-9._/-]+$")


@dataclass
class Row:
    id: str
    status: str
    cells: list[str]
    line: int


def split_row(line: str) -> list[str]:
    """The cells of a markdown table row; ``\\|`` inside a cell is not a separator."""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    return [cell.strip().replace("\\|", "|") for cell in re.split(r"(?<!\\)\|", body)]


def ledger_rows(text: str) -> list[Row]:
    """Rows of the tables headed ``id``, in order."""
    rows = []
    header: list[str] | None = None
    for number, line in enumerate(text.splitlines(), 1):
        if not line.lstrip().startswith("|"):
            header = None
            continue
        cells = split_row(line)
        first = cells[0].strip("`").lower() if cells else ""
        if header is None:
            header = [c.lower() for c in cells] if first == "id" else []
            continue
        if not header or set("".join(cells)) <= set("-: "):
            continue
        status_at = header.index("status") if "status" in header else None
        status = cells[status_at].strip("`").split()[0].lower() if status_at is not None and status_at < len(cells) and cells[status_at].strip() else ""
        rows.append(Row(cells[0].strip("`"), status, cells, number))
    return rows


def unreleased(changelog: str) -> list[tuple[int, str]]:
    """(line number, line) of the ``[Unreleased]`` section."""
    out = []
    inside = False
    for number, line in enumerate(changelog.splitlines(), 1):
        if line.startswith("## "):
            inside = line.startswith("## [Unreleased]")
            continue
        if inside:
            out.append((number, line))
    return out


def changelog_tags(changelog: str) -> list[tuple[int, str]]:
    """(line number, ledger id) for every ``Performance:`` tag under ``[Unreleased]``."""
    out = []
    for number, line in unreleased(changelog):
        match = TAG.match(line)
        if match:
            for ident in re.split(r"[,\s]+", match["ids"]):
                ident = ident.strip("`.;")
                if ident:
                    out.append((number, ident))
    return out


def references(row: Row) -> list[tuple[str, str | None]]:
    """(path, fn or None) for each backticked path-like token of the row."""
    out = []
    for cell in row.cells:
        for token in BACKTICKED.findall(cell):
            match = PATH_LIKE.match(token.strip())
            if match:
                out.append((match["path"], match["fn"]))
    return out


def check(root: Path) -> list[str]:
    problems = []
    ledger_path = root / "docs" / "performance.md"
    if not ledger_path.exists():
        return [f"{ledger_path.relative_to(root)} is missing"]
    rows = ledger_rows(ledger_path.read_text())
    if not rows:
        problems.append("docs/performance.md has no ledger table (a table whose first column is `id`)")
    seen: dict[str, int] = {}
    for row in rows:
        where = f"docs/performance.md:{row.line} ({row.id})"
        if not LEDGER_ID.match(row.id):
            problems.append(f"{where}: an id is lower-case letters, digits, '.', '_' and '-'")
        if row.id in seen:
            problems.append(f"{where}: duplicate id (also line {seen[row.id]})")
        seen.setdefault(row.id, row.line)
        if row.status not in STATUSES:
            problems.append(f"{where}: status {row.status!r} is not one of {', '.join(sorted(STATUSES))}")
            continue
        if row.status == "queued":
            branches = [t for c in row.cells for t in BACKTICKED.findall(c) if BRANCH.match(t)]
            if not branches:
                problems.append(f"{where}: a queued row names its branch (`conf/...`)")
            continue
        refs = references(row)
        if not refs:
            problems.append(f"{where}: a {row.status} row names a file or test of the repository (backticked path)")
        for path, fn in refs:
            target = root / path
            if not target.is_file():
                problems.append(f"{where}: `{path}` does not exist")
            elif fn and not re.search(rf"\bfn {re.escape(fn)}\b", target.read_text(errors="replace")):
                problems.append(f"{where}: `{path}` has no `fn {fn}`")

    ids = set(seen)
    changelog = root / "CHANGELOG.md"
    if changelog.exists():
        for number, ident in changelog_tags(changelog.read_text()):
            if ident not in ids:
                problems.append(
                    f"CHANGELOG.md:{number}: `Performance: {ident}` has no ledger row; add the row "
                    "to docs/performance.md in the same branch"
                )

    allowlist = root / "benches" / "accepted-regressions.toml"
    if allowlist.exists():
        try:
            entries = tomllib.loads(allowlist.read_text()).get("accepted", [])
        except tomllib.TOMLDecodeError as error:
            return problems + [f"benches/accepted-regressions.toml: {error}"]
        for index, entry in enumerate(entries, 1):
            ledger = str(entry.get("ledger", ""))
            if not entry.get("bench") or ledger not in ids:
                problems.append(
                    f"benches/accepted-regressions.toml entry {index}: needs `bench` and a `ledger` "
                    f"id that is a row of docs/performance.md (got {ledger!r})"
                )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    problems = check(args.root.resolve())
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        print(f"performance ledger: {len(problems)} problem(s)")
        return 1
    rows = ledger_rows((args.root / "docs" / "performance.md").read_text())
    print(f"performance ledger: {len(rows)} rows, every CHANGELOG `Performance:` tag has one, every "
          "master/rejected row names files and tests that exist")
    return 0


if __name__ == "__main__":
    sys.exit(main())
