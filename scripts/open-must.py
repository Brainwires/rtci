#!/usr/bin/env python3
"""The open MUST rows of the clause audit, each with its class (``docs/conformance/audit/OPEN-MUST.md``).

Reads the clause tables of ``docs/conformance/audit/*.md`` (as ``scripts/audit-count.py`` does)
and the classes in ``docs/conformance/audit/open-must.tsv`` (ID, class, size, owner, what would
close it), and writes ``OPEN-MUST.md``: the arithmetic of the MUST rows, then every MUST row that
is ``untested``, ``partial``, ``missing``, ``violated``, ``setting`` or ``conflict`` with its class. The classes
are defined in ``docs/conformance/audit/RULES.md``.

It fails when an open MUST row has no class, a ``setting`` row is not class A or a class A row is
not ``setting``, a ``conflict`` row is not class E, a class or size is not one of the defined ones, or (with ``--check``) when
``OPEN-MUST.md`` is not what it would write. A classified row that has since been closed
(``tested`` / ``n/a``) is left out of the table and named on stderr, so its line can be removed.

Usage: ``python3 scripts/open-must.py [--check]``. Standard library only.
"""

from __future__ import annotations

import collections
import glob
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "docs", "conformance", "audit")
OUT = os.path.join(AUDIT, "OPEN-MUST.md")
CLASSES_FILE = os.path.join(AUDIT, "open-must.tsv")

OPEN = ["untested", "partial", "missing", "violated"]
# Listed with a class, though the RFC behaviour is tested (as a setting).
SETTLED = ["setting", "conflict"]
CLASSES = {
    "A": "RFC behaviour tested, a setting; the default differs for a named cell or peer",
    "B": "implemented, lacking a test that fails without it",
    "C": "partly implemented",
    "D": "not implemented",
    "E": "cannot be met or observed inside this engine",
    "F": "stale note: already tested on this tree",
}
SIZES = ["S", "M", "L"]


def load_audit_count():
    spec = importlib.util.spec_from_file_location(
        "audit_count", os.path.join(ROOT, "scripts", "audit-count.py")
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs: a dataclass looks its module up in sys.modules
    # (Python 3.14 fails on a module loaded from a file without it).
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def must_rows(ac) -> list[dict[str, str]]:
    rows = []
    for path in sorted(glob.glob(os.path.join(AUDIT, "*.md"))):
        name = os.path.basename(path)
        if name in ("COUNTS.md", "OPEN-MUST.md"):
            continue
        header = None
        in_table = False
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.startswith("|"):
                    header = None
                    in_table = False
                    continue
                row = ac.cells(line)
                if header is None:
                    header = row
                    in_table = row == ac.HEADER
                    continue
                if not in_table or set("".join(row)) <= set("-: "):
                    continue
                d = dict(zip(header, row))
                if ac.level_of(d.get("Level", "")) != "MUST":
                    continue
                d["file"] = name
                d["verdict"] = ac.verdict_of(d.get("Verdict", "")) or "?"
                rows.append(d)
    return rows


def load_classes(errors: list[str]) -> dict[str, dict[str, str]]:
    classes = {}
    with open(CLASSES_FILE, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 5:
                errors.append(f"open-must.tsv:{no}: {len(parts)} fields, 5 wanted")
                continue
            rid, cls, size, owner, close = (p.strip() for p in parts)
            if cls not in CLASSES:
                errors.append(f"open-must.tsv:{no}: class {cls!r} ({rid})")
            if size not in SIZES:
                errors.append(f"open-must.tsv:{no}: size {size!r} ({rid})")
            if rid in classes:
                errors.append(f"open-must.tsv:{no}: {rid} classified twice")
            classes[rid] = {"class": cls, "size": size, "owner": owner, "close": close}
    return classes


def few_words(text: str, limit: int = 70) -> str:
    text = text.replace("`", "")
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut + " ..."


def cell(text: str) -> str:
    return text.replace("|", "/")


def pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f} %" if whole else "-"


def render(rows: list[dict[str, str]], classes: dict[str, dict[str, str]]) -> str:
    total = len(rows)
    na = sum(r["verdict"] == "n/a" for r in rows)
    apply = total - na
    tested = sum(r["verdict"] == "tested" for r in rows)
    setting = sum(r["verdict"] == "setting" for r in rows)
    conflict = sum(r["verdict"] == "conflict" for r in rows)
    listed = [r for r in rows if r["verdict"] in OPEN + SETTLED]
    open_rows = [r for r in listed if r["verdict"] in OPEN]
    by_class = collections.Counter(classes[r["ID"]]["class"] for r in listed)
    by_verdict = collections.Counter(r["verdict"] for r in open_rows)
    running = lambda r: classes[r["ID"]]["owner"].endswith("(running)")  # noqa: E731

    out = [
        "# Open MUST rows",
        "",
        "Generated by `scripts/open-must.py` from the clause tables in this directory and the",
        "classes in `open-must.tsv`; do not edit by hand (CI runs the script with `--check`).",
        "Verdicts and classes are defined in `RULES.md`.",
        "",
        "## Arithmetic",
        "",
        f"- MUST rows: {total}; `n/a` (the clause does not bind this engine): {na}; rows that",
        f"  apply: {apply}.",
        f"- RFC behaviour tested (`tested` + `setting` + `conflict`):"
        f" {tested + setting + conflict} of {apply} ({pct(tested + setting + conflict, apply)}).",
        f"- Tested as the default (`tested`): {tested} of {apply} ({pct(tested, apply)});"
        f" `setting`: {setting}; `conflict` (two specifications conflict, the governing one's form is the"
        f" default): {conflict}.",
        f"- Open (not tested in any form): {len(open_rows)}: "
        + ", ".join(f"{by_verdict[v]} {v}" for v in OPEN)
        + ".",
        "",
        "| Class | Meaning | Rows | of them owned by a running agent |",
        "|---|---|---|---|",
    ]
    for cls, meaning in CLASSES.items():
        rs = [r for r in listed if classes[r["ID"]]["class"] == cls]
        out.append(f"| {cls} | {meaning} | {len(rs)} | {sum(running(r) for r in rs)} |")
    out.append(f"| all | | {len(listed)} | {sum(running(r) for r in listed)} |")

    # What it takes.
    work = [r for r in open_rows if classes[r["ID"]]["class"] in "BCDF"]
    sizes = collections.Counter(classes[r["ID"]]["size"] for r in work)
    never = [
        r
        for r in open_rows
        if classes[r["ID"]]["class"] == "E"
        and classes[r["ID"]]["close"].startswith("Never testable")
    ]
    decide = [r for r in open_rows if classes[r["ID"]]["class"] == "E" and r not in never]
    out += [
        "",
        "## What 100 % takes",
        "",
        f"- Work in code and tests (classes B, C, D, F): {len(work)} rows, "
        + ", ".join(f"{sizes[s]} of size {s}" for s in SIZES)
        + ". They are listed below by owner and size.",
        f"- Owner decisions (class E with a proposal: `n/a`, or an engine-side guarantee to test):"
        f" {len(decide)} rows.",
        f"- Never testable inside this engine (class E, reason stated): {len(never)} rows:",
    ]
    for r in never:
        out.append(f"  - {r['ID']} (`{r['file']}`): {cell(classes[r['ID']]['close'])}")
    out += [
        "",
        "Class C rows that say \"Owner decision\" are implemented as a setting whose default differs",
        "for a reason that is not a failing cell or peer (measured performance, a design rule); they",
        "become `setting` only if such a cell is named, or close when the default changes.",
        "",
        "## By owner",
        "",
        "| Owner | B | C | D | E | F | open rows | S | M | L |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    owners = sorted({classes[r["ID"]]["owner"] for r in open_rows})
    for owner in owners:
        rs = [r for r in open_rows if classes[r["ID"]]["owner"] == owner]
        c = collections.Counter(classes[r["ID"]]["class"] for r in rs)
        s = collections.Counter(classes[r["ID"]]["size"] for r in rs)
        out.append(
            f"| {owner} | "
            + " | ".join(str(c[k]) for k in "BCDEF")
            + f" | {len(rs)} | "
            + " | ".join(str(s[k]) for k in SIZES)
            + " |"
        )

    out += [
        "",
        "## Rows",
        "",
        "Sorted by class, then owner, size and ID.",
        "",
        "| ID | File | Clause | Verdict | Class | What would close it | Size | Owner |",
        "|---|---|---|---|---|---|---|---|",
    ]
    order = {s: i for i, s in enumerate(SIZES)}
    for r in sorted(
        listed,
        key=lambda r: (
            classes[r["ID"]]["class"],
            classes[r["ID"]]["owner"],
            order[classes[r["ID"]]["size"]],
            r["ID"],
        ),
    ):
        c = classes[r["ID"]]
        out.append(
            f"| {r['ID']} | `{r['file']}` | {cell(few_words(r.get('Clause (short paraphrase)', '')))}"
            f" | {r['verdict']} | {c['class']} | {cell(c['close'])} | {c['size']} | {c['owner']} |"
        )
    return "\n".join(out) + "\n"


def main() -> int:
    check = "--check" in sys.argv[1:]
    ac = load_audit_count()
    errors: list[str] = []
    rows = must_rows(ac)
    classes = load_classes(errors)
    by_id = {r["ID"]: r for r in rows}
    for r in rows:
        if r["verdict"] in OPEN + SETTLED and r["ID"] not in classes:
            errors.append(f"{r['file']}: {r['ID']} ({r['verdict']}) has no class in open-must.tsv")
        if r["ID"] in classes:
            cls = classes[r["ID"]]["class"]
            if r["verdict"] == "setting" and cls != "A":
                errors.append(f"{r['ID']}: `setting` row classed {cls}, not A")
            if cls == "A" and r["verdict"] != "setting":
                errors.append(f"{r['ID']}: class A row is `{r['verdict']}`, not `setting`")
            if r["verdict"] == "conflict" and cls != "E":
                errors.append(f"{r['ID']}: `conflict` row classed {cls}, not E")
    for rid in classes:
        r = by_id.get(rid)
        if r is None:
            errors.append(f"open-must.tsv: {rid} is not a MUST row of the audit")
        elif r["verdict"] not in OPEN + SETTLED:
            print(f"open-must: {rid} is `{r['verdict']}` now; its class line can go", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"open-must: {e}", file=sys.stderr)
        print(f"open-must: {len(errors)} problem(s)", file=sys.stderr)
        return 1
    text = render(rows, {k: v for k, v in classes.items() if k in by_id})
    if check:
        try:
            with open(OUT, encoding="utf-8") as f:
                current = f.read()
        except FileNotFoundError:
            current = ""
        if current != text:
            print(
                "open-must: docs/conformance/audit/OPEN-MUST.md is out of date; run "
                "python3 scripts/open-must.py",
                file=sys.stderr,
            )
            return 1
    else:
        with open(OUT, "w", encoding="utf-8") as f:
            f.write(text)
    print(f"open-must: {sum(r['verdict'] in OPEN for r in rows)} open MUST rows, all classified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
