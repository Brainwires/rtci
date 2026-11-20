#!/usr/bin/env python3
"""Upstream test parity (criterion C6 of the 100% plan).

Every test function in upstream ``webrtc-rs/rtc`` (master) and in ``webrtc-rs/webrtc`` v0.17.1
(the top-level crate and its sub-crates) must have, in this fork, one of:

* a test with the same name in the corresponding crate;
* a mapped equivalent: a row in ``docs/upstream-test-parity.md`` with status ``mapped`` naming
  the fork test(s) that cover the same behaviour (each must exist);
* an exclusion: a row with status ``excluded`` and the reason the test cannot exist here
  (typically: it tests I/O, threads or an async API this sans-I/O engine does not have).

A row with status ``port`` (the test applies and is still to be written) is reported and fails
the check until the test lands.

The upstream names are committed under ``docs/upstream-tests/`` (one ``crate<TAB>file<TAB>test``
line per test) so the check runs offline. A parity row whose upstream test no longer appears in
the lists, or that a same-named fork test now satisfies, fails too, so the document cannot go
stale.

Usage:
  python3 scripts/check-test-parity.py                     check
  python3 scripts/check-test-parity.py --missing           print the tests that need a row
  python3 scripts/check-test-parity.py --generate RTC WEBRTC
      rewrite the lists from upstream checkouts (rtc at master, webrtc at v0.17.1)
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LISTS = ROOT / "docs" / "upstream-tests"
PARITY = ROOT / "docs" / "upstream-test-parity.md"
SOURCES = {"rtc-master.txt": "webrtc-rs/rtc master", "webrtc-v0.17.1.txt": "webrtc-rs/webrtc v0.17.1"}

SKIP_DIRS = {"target", ".git", "fuzz", "node_modules", "artifacts", "corpus"}
TEST_ATTR = re.compile(r"#\[\s*(?:tokio::test|async_std::test|test|rstest|test_case)\b")
FN_DEF = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")

# webrtc v0.17.1's crates and the fork crate (directory) each became. `.` is the fork's
# top-level `rtc` crate (src/ and tests/).
WEBRTC_CRATES = {
    "data": "rtc-datachannel",
    "dtls": "rtc-dtls",
    "ice": "rtc-ice",
    "interceptor": "rtc-interceptor",
    "mdns": "rtc-mdns",
    "media": "rtc-media",
    "rtcp": "rtc-rtcp",
    "rtp": "rtc-rtp",
    "sctp": "rtc-sctp",
    "sdp": "rtc-sdp",
    "srtp": "rtc-srtp",
    "stun": "rtc-stun",
    "turn": "rtc-turn",
    "util": "rtc-shared",
    "webrtc": ".",
}


def tests_in(tree: Path) -> list[tuple[str, str]]:
    """(file relative to `tree`, test name) for every test function under `tree`."""
    out = []
    for dirpath, dirnames, filenames in os.walk(tree):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = Path(dirpath) / name
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            pending = False
            depth = 0  # open brackets of an attribute that spans lines
            comment = 0  # open /* */ block comments (they nest in Rust)
            for line in lines:
                stripped = line.strip()
                was_comment = comment > 0
                comment = max(0, comment + len(re.findall(r"/\*", line)) - len(re.findall(r"\*/", line)))
                if was_comment or (comment > 0 and stripped.startswith("/*")):
                    # A test inside a block comment is commented out, not a test.
                    pending = False
                    continue
                if depth > 0:
                    depth += stripped.count("[") - stripped.count("]")
                    continue
                if stripped.startswith("//"):
                    continue
                if stripped.startswith("#["):
                    if TEST_ATTR.search(stripped):
                        pending = True
                    depth = stripped.count("[") - stripped.count("]")
                    continue
                if pending:
                    m = FN_DEF.match(line)
                    if m:
                        out.append((path.relative_to(tree).as_posix(), m.group(1)))
                        pending = False
                    elif stripped and not stripped.startswith("#["):
                        pending = False
    return sorted(out)


def crate_of(file: str, mapping: dict[str, str] | None) -> str:
    """The fork crate directory an upstream (or fork) file belongs to."""
    first = file.split("/", 1)[0]
    if mapping is not None:
        return mapping.get(first, ".")
    return first if first.startswith("rtc-") else "."


def generate(rtc: Path, webrtc: Path) -> None:
    LISTS.mkdir(parents=True, exist_ok=True)
    for out, tree, mapping in (("rtc-master.txt", rtc, None), ("webrtc-v0.17.1.txt", webrtc, WEBRTC_CRATES)):
        lines = [f"{crate_of(f, mapping)}\t{f}\t{n}" for f, n in tests_in(tree)]
        (LISTS / out).write_text(
            f"# Test functions of {SOURCES[out]}: fork crate, upstream file, test name.\n"
            "# Generated by scripts/check-test-parity.py --generate; do not edit by hand.\n"
            + "\n".join(lines)
            + "\n",
            encoding="utf-8",
        )
        print(f"{out}: {len(lines)} tests")


def upstream_tests() -> list[tuple[str, str, str, str]]:
    """(source list, fork crate, upstream file, test name)."""
    out = []
    for name in SOURCES:
        path = LISTS / name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            crate, file, test = line.split("\t")
            out.append((name, crate, file, test))
    return out


def fork_tests() -> tuple[dict[str, set[str]], set[str]]:
    """Fork test names by crate directory, and every fork test name."""
    by_crate: dict[str, set[str]] = {}
    every: set[str] = set()
    for file, name in tests_in(ROOT):
        by_crate.setdefault(crate_of(file, None), set()).add(name)
        every.add(name)
    return by_crate, every


def parity_rows() -> dict[tuple[str, str], list[str]]:
    """(fork crate, upstream test) -> cells: Crate | Upstream test | Status | Fork test or reason |
    Upstream file."""
    rows: dict[tuple[str, str], list[str]] = {}
    if not PARITY.exists():
        return rows
    for line in PARITY.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|") or re.match(r"^\|\s*:?-{3,}", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 4 or cells[0].lower() == "crate":
            continue
        crate = cells[0].strip("`")
        for test in re.findall(r"`([^`]+)`", cells[1]) or [cells[1]]:
            rows[(crate, test)] = cells
    return rows


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--generate":
        generate(Path(sys.argv[2]), Path(sys.argv[3]))
        return 0

    by_crate, every = fork_tests()
    rows = parity_rows()
    needed: dict[tuple[str, str], str] = {}
    for _source, crate, file, test in upstream_tests():
        if test in by_crate.get(crate, set()):
            continue
        needed.setdefault((crate, test), file)

    if "--missing" in sys.argv:
        for (crate, test), file in sorted(needed.items()):
            if (crate, test) not in rows:
                print(f"{crate}\t{file}\t{test}")
        return 0

    errors = []
    for key, file in sorted(needed.items()):
        cells = rows.get(key)
        if cells is None:
            errors.append(f"{key[0]}: upstream test `{key[1]}` ({file}) has no fork test and no row")
            continue
        status = cells[2].strip("`").lower()
        if status == "mapped":
            refs = re.findall(r"`([^`]+)`", cells[3])
            if not refs:
                errors.append(f"{key}: mapped, but names no fork test")
            for ref in refs:
                if ref.rpartition("::")[2] not in every:
                    errors.append(f"{key}: mapped to `{ref}`, which is not a fork test")
        elif status == "excluded":
            if not cells[3].strip():
                errors.append(f"{key}: excluded without a reason")
        elif status == "port":
            errors.append(f"{key}: still to be ported ({cells[3].strip()})")
        else:
            errors.append(f"{key}: status must be `mapped`, `excluded` or `port`, not `{cells[2]}`")
    for key in rows:
        if key not in needed:
            errors.append(f"{PARITY.name}: row {key} is not needed (no such upstream test, or a same-named fork test exists); remove it")

    if errors:
        print("Upstream test parity check failed:\n")
        for e in errors:
            print(f"  {e}")
        return 1
    total = len(upstream_tests())
    print(f"Upstream test parity: {total} upstream tests, {len(needed)} mapped or excluded, all accounted for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
