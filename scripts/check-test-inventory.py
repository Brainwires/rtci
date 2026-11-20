#!/usr/bin/env python3
"""No hidden tests (criterion C1a of the 100% plan).

A test that never runs proves nothing and looks like coverage. This script fails when it finds:

* a test with ``#[ignore]``, except in ``tests/testenv_*.rs`` (the real-network environment
  runs those) where the attribute must carry its reason (``#[ignore = "..."]``);
* a commented-out ``#[test]`` / ``#[tokio::test]``;
* a ``*_test.rs`` file under a crate's ``src/`` that no ``mod`` declaration (or ``#[path]``)
  compiles;
* a test, or a ``mod`` holding tests, behind a platform ``cfg`` (``windows``, ``unix``,
  ``target_os``, ``target_family``, ``target_arch``, ``target_env``), so it silently does not
  exist on some platform;

unless ``docs/test-exclusions.md`` lists it with a reason and the test that covers the same
behaviour. An exclusion row that no longer matches anything also fails, so the list cannot go
stale.

It also checks every test that ``docs/conformance.md`` and ``docs/conformance/*.md`` name in
their "Test" column exists (criterion C5).

Usage: ``python3 scripts/check-test-inventory.py [--list]``. ``--list`` prints every finding,
excluded or not, in the exclusion table's format.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUSIONS = ROOT / "docs" / "test-exclusions.md"
CONFORMANCE = [ROOT / "docs" / "conformance.md", *sorted((ROOT / "docs" / "conformance").glob("*.md"))]

# Directories that hold no tests of the workspace: build output, fuzz crates (their own
# workspaces, no tests), vendored or generated trees.
SKIP_DIRS = {"target", ".git", "fuzz", "node_modules", "artifacts", "corpus"}

TEST_ATTR = re.compile(r"#\[\s*(?:tokio::test|async_std::test|test|rstest|test_case)\b[^\]]*\]")
IGNORE_ATTR = re.compile(r"#\[\s*ignore\s*(=\s*\"(?P<reason>[^\"]*)\")?\s*\]")
FN_DEF = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;")
PATH_ATTR = re.compile(r"#\[\s*path\s*=\s*\"(?P<path>[^\"]+)\"\s*\]")
COMMENTED_TEST = re.compile(r"^\s*(?://+|/\*+|\*)\s*#\[\s*(?:tokio::test|async_std::test|test)\b")
PLATFORM_CFG = re.compile(r"#\[\s*cfg\s*\((?P<expr>.*)\)\s*\]")
PLATFORM_WORDS = re.compile(r"\b(windows|unix|target_os|target_family|target_arch|target_env)\b")


@dataclass(frozen=True)
class Finding:
    kind: str  # ignored | commented | orphan | platform
    path: str  # relative to the repository root
    test: str  # the test (or module / "*")
    detail: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.kind, self.path, self.test)


def rust_files() -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if name.endswith(".rs"):
                out.append(Path(dirpath) / name)
    return sorted(out)


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def attributes_then_item(lines: list[str], start: int) -> tuple[list[str], int]:
    """The attribute lines from `start` on and the index of the first line that is not an
    attribute, a comment or blank (the item they apply to)."""
    attrs = []
    i = start
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("#["):
            # An attribute may span lines; join until its brackets balance.
            text = stripped
            depth = text.count("[") - text.count("]")
            while depth > 0 and i + 1 < len(lines):
                i += 1
                text += " " + lines[i].strip()
                depth = text.count("[") - text.count("]")
            attrs.append(text)
        elif stripped == "" or stripped.startswith("//"):
            pass
        else:
            return attrs, i
        i += 1
    return attrs, i


def scan_file(path: Path, findings: list[Finding], tests: dict[str, set[str]]) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    relpath = rel(path)
    is_testenv = relpath.startswith("tests/testenv_") and relpath.endswith(".rs")
    # Lines inside /* ... */ block comments (not nested; strings are not parsed, which is fine
    # for test code): a #[test] there is commented out like a `// #[test]`.
    in_block = []
    depth = 0
    for line in lines:
        starts_inside = depth > 0
        depth += len(re.findall(r"/\*", line)) - len(re.findall(r"\*/", line))
        depth = max(depth, 0)
        in_block.append(starts_inside or (depth > 0 and line.strip().startswith("/*")))
    i = 0
    while i < len(lines):
        line = lines[i]
        if in_block[i] and not COMMENTED_TEST.match(line):
            if TEST_ATTR.search(line):
                name = "*"
                for follow in lines[i + 1 : i + 6]:
                    m = re.search(r"fn\s+([A-Za-z_][A-Za-z0-9_]*)", follow)
                    if m:
                        name = m.group(1)
                        break
                findings.append(Finding("commented", relpath, name, f"line {i + 1}, in a block comment"))
            i += 1
            continue
        if COMMENTED_TEST.match(line):
            name = "*"
            for follow in lines[i + 1 : i + 4]:
                m = re.search(r"fn\s+([A-Za-z_][A-Za-z0-9_]*)", follow)
                if m:
                    name = m.group(1)
                    break
            findings.append(Finding("commented", relpath, name, f"line {i + 1}"))
            i += 1
            continue
        if line.strip().startswith("#["):
            attrs, item = attributes_then_item(lines, i)
            joined = " ".join(attrs)
            item_line = lines[item] if item < len(lines) else ""
            fn = FN_DEF.match(item_line)
            mod = MOD_DECL.match(item_line) or re.match(
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{", item_line
            )
            platform = [
                m.group("expr")
                for m in (PLATFORM_CFG.search(a) for a in attrs)
                if m and PLATFORM_WORDS.search(m.group("expr"))
            ]
            if fn and TEST_ATTR.search(joined):
                name = fn.group("name")
                tests.setdefault(name, set()).add(relpath)
                ignore = IGNORE_ATTR.search(joined)
                if ignore:
                    if not (is_testenv and ignore.group("reason")):
                        findings.append(Finding("ignored", relpath, name, ignore.group(0)))
                if platform:
                    findings.append(Finding("platform", relpath, name, "; ".join(platform)))
            elif mod and platform and ("test" in mod.group("name") or "cfg(test" in joined):
                findings.append(Finding("platform", relpath, "mod " + mod.group("name"), "; ".join(platform)))
            i = max(item, i + 1)
            continue
        i += 1


def declared_modules(files: list[Path]) -> tuple[set[tuple[str, str]], set[str]]:
    """(directory, module name) pairs every `mod x;` declares, and every `#[path]` target."""
    mods: set[tuple[str, str]] = set()
    paths: set[str] = set()
    for path in files:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        # A `mod x;` in foo/mod.rs or foo/lib.rs (or a crate root) looks in foo/; in foo/bar.rs
        # it looks in foo/bar/.
        if path.name in ("mod.rs", "lib.rs", "main.rs"):
            base = path.parent
        else:
            base = path.parent / path.stem
        for n, line in enumerate(lines):
            m = MOD_DECL.match(line)
            if m:
                mods.add((rel(base) if base != ROOT else ".", m.group("name")))
                # A `#[path]` on the line(s) before applies to this declaration.
                for back in lines[max(0, n - 3) : n]:
                    p = PATH_ATTR.search(back)
                    if p:
                        paths.add((path.parent / p.group("path")).resolve().as_posix())
    return mods, paths


def orphan_test_files(files: list[Path], findings: list[Finding]) -> None:
    mods, paths = declared_modules(files)
    for path in files:
        relpath = rel(path)
        if not path.stem.endswith("_test") or "/src/" not in "/" + relpath:
            continue
        parent = rel(path.parent) if path.parent != ROOT else "."
        if (parent, path.stem) in mods or path.resolve().as_posix() in paths:
            continue
        findings.append(Finding("orphan", relpath, "*", "no `mod` compiles this file"))


def parse_table(path: Path) -> list[list[str]]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|") or re.match(r"^\|\s*:?-{3,}", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        rows.append(cells)
    return rows


def unquote(cell: str) -> str:
    return cell.strip().strip("`").strip()


def backticked(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def test_exists(ref: str, tests: dict[str, set[str]]) -> bool:
    """`name`, or `path.rs::name`, names a test the scan found."""
    if "::" in ref:
        file, _, name = ref.rpartition("::")
        return name in tests and any(p == file or p.endswith("/" + file) for p in tests[name])
    return ref in tests


def main() -> int:
    files = rust_files()
    findings: list[Finding] = []
    tests: dict[str, set[str]] = {}
    for path in files:
        scan_file(path, findings, tests)
    orphan_test_files(files, findings)

    if "--list" in sys.argv:
        print("| Kind | File | Test | Reason | Covered by |")
        print("|---|---|---|---|---|")
        for f in sorted(findings, key=Finding.key):
            print(f"| {f.kind} | `{f.path}` | `{f.test}` | {f.detail} | |")
        return 0

    errors: list[str] = []

    # The exclusion table: Kind | File | Test | Reason | Covered by.
    excluded: dict[tuple[str, str, str], list[str]] = {}
    for cells in parse_table(EXCLUSIONS):
        if len(cells) < 5 or cells[0].lower() == "kind":
            continue
        key = (unquote(cells[0]), unquote(cells[1]), unquote(cells[2]))
        excluded[key] = cells
        if not cells[3].strip():
            errors.append(f"{EXCLUSIONS.name}: {key} has no reason")
        covered = cells[4].strip()
        if not covered:
            errors.append(f"{EXCLUSIONS.name}: {key} names no covering test")
        for ref in backticked(covered):
            if not test_exists(ref, tests):
                errors.append(f"{EXCLUSIONS.name}: {key} is covered by `{ref}`, which is not a test")

    found_keys = {f.key() for f in findings}
    for f in findings:
        if f.key() not in excluded:
            errors.append(f"{f.kind}: {f.path}: {f.test} ({f.detail}) is not in {EXCLUSIONS.name}")
    for key in excluded:
        if key not in found_keys:
            errors.append(f"{EXCLUSIONS.name}: {key} matches nothing any more; remove the row")

    # Conformance rows name the tests that prove a claim: each must exist.
    for doc in CONFORMANCE:
        if not doc.exists():
            continue
        rows = parse_table(doc)
        header = None
        for cells in rows:
            lowered = [c.lower() for c in cells]
            if "test" in lowered or "tests" in lowered:
                header = lowered
                continue
            if header is None:
                continue
            column = header.index("test") if "test" in header else header.index("tests")
            if column >= len(cells):
                continue
            for ref in backticked(cells[column]):
                if not test_exists(ref, tests):
                    errors.append(f"{rel(doc)}: the test `{ref}` does not exist")

    if errors:
        print("Test inventory check failed:\n")
        for e in errors:
            print(f"  {e}")
        print(
            "\nEither make the test run (remove the #[ignore], restore it, add the `mod`, drop the"
            f" platform cfg) or list it in {rel(EXCLUSIONS)} with the reason and the test that"
            " covers the same behaviour."
        )
        return 1
    print(f"Test inventory: {sum(len(v) for v in tests.values())} tests, {len(findings)} excluded, all accounted for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
