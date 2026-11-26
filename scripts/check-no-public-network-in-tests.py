#!/usr/bin/env python3
"""No test talks to the public internet.

On train 34 a `rtci-turn` test sent a STUN Binding request to a public server and blocked on the
answer until CI cancelled the macOS job after 90 minutes. A test must not need anything beyond
the machine it runs on: a lost datagram, a missing route, a failed name lookup or a runner without
outbound UDP turns such a test into a hang or a random failure. This script fails when a test
source names a public STUN/TURN server or connects to an address that is not on this machine.

What it reads (the test sources): every ``.rs`` file under a ``tests/`` or ``benches/``
directory, every ``*_test.rs`` / ``test_*.rs`` file, every ``.rs`` file under a crate's ``src/``
(inline ``#[cfg(test)]`` modules and doc-tests live there), and the examples CI runs as programs
(``RUN_EXAMPLES``). The other examples are programs for a person to run against a real network
and are not read. Comments are read too: a doc-test is a comment.

What it flags, line by line (no parsing; deliberately conservative):

* a public STUN/TURN host name (``FORBIDDEN_HOSTS``), anywhere on the line;
* on a line that connects, sends or resolves (``connect(``, ``connect_timeout(``, ``send_to(``,
  ``lookup_host(``, ``to_socket_addrs``), a string literal ``"host:port"`` (or a tuple
  ``("host", port)``) whose host is not on this machine: anything but loopback, the unspecified
  address, ``localhost`` and the documentation ranges (RFC 5737, RFC 3849), which no test
  reaches. A host name there means a real DNS lookup.

A line that only parses or formats such a name (no I/O) is allowed by a row of
``scripts/check-no-public-network-in-tests.allow``::

    <path> | <count> | <text the line contains> | <reason>

The row allows exactly ``count`` flagged lines of ``path`` that contain the text; more fails
(a new line slipped in under an old row) and fewer fails (the row is stale). Every row needs a
reason.

Usage: ``python3 scripts/check-no-public-network-in-tests.py [--root DIR]``.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = Path("scripts") / "check-no-public-network-in-tests.allow"

SKIP_DIRS = {"target", ".git", "fuzz", "oss-fuzz", "node_modules", "artifacts", "corpus", "scripts"}

# Examples CI runs as programs (cargo.yml, scripts/test-env/entry.sh): read like tests.
RUN_EXAMPLES = ("examples/custom-runtime/", "examples/stream-driver-loopback/")

# Public STUN/TURN services and other public hosts a test has no business reaching.
FORBIDDEN_HOSTS = re.compile(
    r"\b(?:"
    r"stun[0-9]*\.l\.google\.com"
    r"|google\.com"
    r"|cloudflare\.com"
    r"|twilio\.com"
    r"|metered\.(?:ca|live)"
    r"|openrelay(?:project)?\.[a-z]+"
    r"|xirsys\.com"
    r"|stunprotocol\.org"
    r"|stun\.(?:ekiga|sipgate|voipbuster|nextcloud|schlund|ideasip)\.[a-z]+"
    r")\b",
    re.IGNORECASE,
)

# A line that makes a connection, sends a datagram or resolves a name.
IO_CALL = re.compile(r"\b(?:connect|connect_timeout|send_to|lookup_host)\s*\(|\.to_socket_addrs\b")
HOST_PORT_LITERAL = re.compile(r'"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.\-:]+?):(?P<port>[0-9]{1,5})"')
HOST_PORT_TUPLE = re.compile(r'\(\s*"(?P<host>[^"]+)"\s*,\s*(?P<port>[0-9]{1,5})\s*\)')

LOCAL_NAMES = {"localhost", "0"}
DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    text: str
    why: str


@dataclass
class Row:
    path: str
    count: int
    needle: str
    reason: str
    where: str
    seen: int = 0


def host_is_local(host: str) -> bool:
    """Whether a connection to `host` stays on this machine (or goes to a documentation
    address no test reaches)."""
    host = host.strip("[]")
    if host.lower() in LOCAL_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # a name: a real lookup
    return ip.is_loopback or ip.is_unspecified or any(ip in net for net in DOC_NETS)


def is_test_source(rel: str) -> bool:
    if not rel.endswith(".rs"):
        return False
    parts = rel.split("/")
    name = parts[-1]
    if rel.startswith(RUN_EXAMPLES):
        return True
    if parts[0] == "examples" and "tests" not in parts[:-1]:
        return False
    return (
        "tests" in parts[:-1]
        or "benches" in parts[:-1]
        or "src" in parts[:-1]
        or name.endswith("_test.rs")
        or name.startswith("test_")
    )


def test_sources(root: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            rel = (Path(dirpath) / name).relative_to(root).as_posix()
            if is_test_source(rel):
                out.append(rel)
    return sorted(out)


def scan_line(line: str) -> str | None:
    """Why `line` reaches off the machine, or None."""
    m = FORBIDDEN_HOSTS.search(line)
    if m:
        return f"names the public host {m.group(0)}"
    if IO_CALL.search(line):
        for pattern in (HOST_PORT_LITERAL, HOST_PORT_TUPLE):
            for lit in pattern.finditer(line):
                if not host_is_local(lit.group("host")):
                    return f"connects, sends or resolves to {lit.group('host')}:{lit.group('port')}"
    return None


def scan(root: Path) -> list[Finding]:
    findings = []
    for rel in test_sources(root):
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            why = scan_line(line)
            if why:
                findings.append(Finding(rel, number, line.strip(), why))
    return findings


def read_allowlist(path: Path) -> tuple[list[Row], list[str]]:
    rows, errors = [], []
    if not path.exists():
        return rows, errors
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = f"{path.name}:{number}"
        fields = [f.strip() for f in line.split(" | ", 3)]
        if len(fields) != 4 or not all(fields):
            errors.append(f"{where}: a row is `<path> | <count> | <text> | <reason>`, all four given")
            continue
        file, count, needle, reason = fields
        if not count.isdigit() or int(count) < 1:
            errors.append(f"{where}: the count must be a whole number of at least 1")
            continue
        rows.append(Row(file, int(count), needle, reason, where))
    return rows, errors


def check(root: Path) -> list[str]:
    rows, errors = read_allowlist(root / ALLOWLIST)
    for finding in scan(root):
        row = next((r for r in rows if r.path == finding.path and r.needle in finding.text), None)
        if row is None:
            errors.append(f"{finding.path}:{finding.line}: {finding.why}: {finding.text}")
        else:
            row.seen += 1
    for row in rows:
        if row.seen > row.count:
            errors.append(
                f"{row.where}: {row.path} has {row.seen} flagged lines containing "
                f"`{row.needle}`, the row allows {row.count}"
            )
        elif row.seen < row.count:
            errors.append(
                f"{row.where}: stale row: {row.path} has {row.seen} flagged lines containing "
                f"`{row.needle}`, the row says {row.count}"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = check(args.root)
    if errors:
        print("Test sources that reach off the machine (fix the test: use a server on loopback in")
        print("the same process; or, for a line that does no I/O, add a row with its reason to")
        print(f"{ALLOWLIST.as_posix()}):")
        for error in errors:
            print(f"  {error}")
        return 1
    print("No test source names a public server or connects off the machine.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
