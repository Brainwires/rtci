#!/usr/bin/env python3
"""Unit tests for scripts/check-no-public-network-in-tests.py, on small trees made for each case.

    python3 scripts/test_check_no_public_network_in_tests.py
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "check_no_public_network_in_tests", HERE / "check-no-public-network-in-tests.py"
)
gate = importlib.util.module_from_spec(spec)
# Registered before exec_module: the module declares dataclasses, which look themselves up there.
sys.modules["check_no_public_network_in_tests"] = gate
spec.loader.exec_module(gate)


class Tree:
    """A throwaway repository root with the files a case writes."""

    def __init__(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def write(self, rel: str, text: str) -> "Tree":
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return self

    def allow(self, *rows: str) -> "Tree":
        return self.write(gate.ALLOWLIST.as_posix(), "# allowlist\n" + "".join(r + "\n" for r in rows))

    def errors(self) -> list[str]:
        return gate.check(self.root)

    def close(self) -> None:
        self._dir.cleanup()


class GateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = Tree()

    def tearDown(self) -> None:
        self.tree.close()

    def test_a_public_stun_server_in_a_unit_test_fails(self) -> None:
        self.tree.write(
            "rtci-turn/src/client/client_test.rs",
            'stun_serv_addr: "stun1.l.google.com:19302".to_owned(),\n',
        )
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("rtci-turn/src/client/client_test.rs:1", errors[0])
        self.assertIn("stun1.l.google.com", errors[0])

    def test_each_listed_public_host_fails_in_an_integration_test(self) -> None:
        for host in (
            "stun.l.google.com",
            "stun4.l.google.com",
            "global.stun.twilio.com",
            "stun.cloudflare.com",
            "openrelay.metered.ca",
            "stun.stunprotocol.org",
        ):
            self.tree.write("tests/a.rs", f'urls: vec!["stun:{host}:3478".to_owned()],\n')
            self.assertEqual(len(self.tree.errors()), 1, host)

    def test_a_connection_to_a_public_address_or_a_name_fails(self) -> None:
        for line in (
            'socket.connect("8.8.8.8:80")?;',
            'let s = TcpStream::connect("1.1.1.1:443").await?;',
            'sock.send_to(&buf, "10.1.2.3:3478")?;',
            'let to = lookup_host(true, "turn.example.net:3478")?;',
            'let a = "example.com:80".to_socket_addrs()?;',
            'socket.connect(("8.8.4.4", 53))?;',
            'socket.connect("[2606:4700::1111]:53")?;',
        ):
            self.tree.write("tests/b.rs", line + "\n")
            self.assertEqual(len(self.tree.errors()), 1, line)

    def test_loopback_unspecified_and_documentation_addresses_pass(self) -> None:
        self.tree.write(
            "tests/c.rs",
            "\n".join(
                (
                    'socket.connect("127.0.0.1:3478")?;',
                    'socket.connect("[::1]:3478")?;',
                    'let to = lookup_host(true, "127.0.0.1:9")?;',
                    'let to = lookup_host(true, "localhost:9")?;',
                    'socket.connect("192.0.2.1:9")?;',
                    'socket.send_to(&buf, "198.51.100.7:1")?;',
                    'socket.send_to(&buf, "203.0.113.9:1")?;',
                    'socket.connect("[2001:db8::1]:9")?;',
                    'socket.connect(("0.0.0.0", 0))?;',
                    # An address with no I/O on its line is data, not a connection.
                    'let candidate = "93.184.216.34:50000";',
                )
            )
            + "\n",
        )
        self.assertEqual(self.tree.errors(), [])

    def test_an_example_not_run_as_a_test_is_not_read(self) -> None:
        self.tree.write("examples/reflect/reflect.rs", 'urls: vec!["stun:stun.l.google.com:19302".into()],\n')
        self.tree.write("rtci-stun/examples/stun_client.rs", 'default = "stun.l.google.com:19302"\n')
        self.assertEqual(self.tree.errors(), [])

    def test_an_example_ci_runs_and_an_example_crates_tests_are_read(self) -> None:
        self.tree.write("examples/custom-runtime/src/main.rs", 'socket.connect("8.8.8.8:80")?;\n')
        self.tree.write("examples/stream-driver/tests/t.rs", 'socket.connect("8.8.8.8:80")?;\n')
        self.assertEqual(len(self.tree.errors()), 2)

    def test_doc_comments_and_benches_are_read(self) -> None:
        self.tree.write("rtci-ice/src/lib.rs", '//! let u = Url::parse_url("stun:stun.l.google.com:19302")?;\n')
        self.tree.write("rtci-turn/benches/bench.rs", 'sock.connect("8.8.8.8:80")?;\n')
        self.assertEqual(len(self.tree.errors()), 2)

    def test_an_allowlist_row_allows_exactly_its_count(self) -> None:
        line = 'Url::parse_url("stun:stun.l.google.com:19302")?;\n'
        row = "rtci-ice/src/url/url_test.rs | 2 | stun.l.google.com | parse only"
        self.tree.write("rtci-ice/src/url/url_test.rs", line * 2).allow(row)
        self.assertEqual(self.tree.errors(), [])

        self.tree.write("rtci-ice/src/url/url_test.rs", line * 3)
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("the row allows 2", errors[0])

        self.tree.write("rtci-ice/src/url/url_test.rs", line)
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("stale row", errors[0])

    def test_an_allowlist_row_covers_only_its_file_and_text(self) -> None:
        self.tree.write("tests/d.rs", 'urls: vec!["stun:stun.l.google.com:19302".to_owned()],\n')
        self.tree.write("tests/e.rs", 'urls: vec!["stun:stun.l.google.com:19302".to_owned()],\n')
        self.tree.allow("tests/d.rs | 1 | stun.l.google.com | configuration only")
        errors = self.tree.errors()
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("tests/e.rs:1", errors[0])

    def test_an_allowlist_row_needs_all_four_fields_and_a_count(self) -> None:
        self.tree.write("tests/f.rs", "fn nothing() {}\n")
        self.tree.allow("tests/f.rs | 1 | google.com |")
        self.assertTrue(any("all four given" in e for e in self.tree.errors()))
        self.tree.allow("tests/f.rs | one | google.com | reason")
        self.assertTrue(any("whole number" in e for e in self.tree.errors()))

    def test_build_output_and_fuzz_trees_are_skipped(self) -> None:
        self.tree.write("target/debug/build/x/out/tests/g.rs", 'socket.connect("8.8.8.8:80")?;\n')
        self.tree.write("rtci-stun/fuzz/fuzz_targets/h.rs", 'socket.connect("8.8.8.8:80")?;\n')
        self.assertEqual(self.tree.errors(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
