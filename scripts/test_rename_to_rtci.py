#!/usr/bin/env python3
"""Unit tests for scripts/rename-to-rtci.py: the token rules, file by file type.

    python3 scripts/test_rename_to_rtci.py
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("rename_to_rtci", HERE / "rename-to-rtci.py")
rn = importlib.util.module_from_spec(spec)
# Registered before exec_module: the module declares dataclasses, which look themselves up there.
sys.modules["rename_to_rtci"] = rn
spec.loader.exec_module(rn)


def crate(name, lib=None, manifest=None, kinds=("lib",), publish=True):
    lib = lib or name.replace("-", "_")
    return rn.Crate(
        name=name,
        old=rn.old_of(name),
        new=rn.new_of(name),
        old_lib=rn.old_of(lib),
        new_lib=rn.new_of(lib),
        manifest=manifest or (f"{name}/Cargo.toml" if name != "rtc" else "Cargo.toml"),
        publish=publish,
        kinds=set(kinds),
    )


CRATES = [
    crate("rtc"),
    crate("rtc-dtls"),
    crate("rtc-ice"),
    crate("rtc-interceptor"),
    crate("rtc-interceptor-derive", kinds=("proc-macro",)),
    crate("rtc-ffi", kinds=("cdylib", "staticlib", "lib")),
    crate("rtc-stream-driver", manifest="examples/stream-driver/Cargo.toml", publish=False),
    crate("rtc-crypto"),
    crate("rtc-sframe"),
    crate("rtc-turn"),
    crate("rtc-mdns"),
    crate("rtc-dtls-fuzz", manifest="rtc-dtls/fuzz/Cargo.toml", publish=False),
]
SYMBOLS = {"rtc_pc", "rtc_pc_new", "rtc_last_error", "RTC_OK", "RTC_ERR_", "RTC_FFI_H"}


def renamer(renamed=False):
    return rn.Renamer(CRATES, SYMBOLS, {"rtc.h": "rtci.h"}, renamed)


def rewrite(path, text, renamed=False):
    events, residue = [], []
    out = rn.rewrite_file(renamer(renamed), path, text, events, residue, {c.manifest: c for c in CRATES})
    return out, events, residue


class RustRules(unittest.TestCase):
    def test_paths_of_the_root_crate_and_the_subcrates(self):
        src = "use rtc::peer_connection::RTCPeerConnection;\nuse rtc_ice::agent::Agent;\nlet n = (0..rtc::rtp::MAX + 1);\n"
        out, _, _ = rewrite("tests/a.rs", src)
        self.assertEqual(
            out, "use rtci::peer_connection::RTCPeerConnection;\nuse rtci_ice::agent::Agent;\nlet n = (0..rtci::rtp::MAX + 1);\n"
        )

    def test_w3c_and_ietf_names_and_other_crates_stay(self):
        src = "use webrtc::rtcp::Packet; let rtc_pc = RTCPeerConnection::new(); // rtcp-mux, srtcp, RTCP\nfoo::rtc::bar();\n"
        out, events, _ = rewrite("tests/a.rs", src)
        self.assertEqual(out, src)
        self.assertEqual(events, [])

    def test_doc_links_and_code_spans(self):
        out, _, _ = rewrite("src/lib.rs", "/// See [`rtc::peer_connection`] and the `rtc` crate.\n")
        self.assertEqual(out, "/// See [`rtci::peer_connection`] and the `rtci` crate.\n")

    def test_use_and_extern_crate(self):
        out, _, _ = rewrite("src/a.rs", "extern crate rtc;\nuse rtc as engine;\n")
        self.assertEqual(out, "extern crate rtci;\nuse rtci as engine;\n")

    def test_generated_paths_in_the_derive_crate(self):
        out, _, _ = rewrite("rtc-interceptor-derive/src/lib.rs", "quote! { impl ::rtc_interceptor::Interceptor for #name {} }\n")
        self.assertEqual(out, "quote! { impl ::rtci_interceptor::Interceptor for #name {} }\n")


DATA = "byte-string or C-string data literal"


def renamed_renamer():
    renamed = [crate(c.new, manifest=c.manifest.replace("rtc-", "rtci-"), kinds=tuple(c.kinds), publish=c.publish) for c in CRATES]
    return rn.Renamer(renamed, SYMBOLS, {"rtc.h": "rtci.h"}, True)


class DataLiterals(unittest.TestCase):
    """Data is not a name: byte strings and strings used as bytes keep their text."""

    # Every byte string with an old name on master 4e6de256 (CI found the first three: fixed
    # P-384 / RSASSA-PSS signatures over the message stopped verifying when it was renamed).
    KNOWN = [
        ("rtc-crypto/src/conformance.rs", '        let message = b"rtc-crypto provider conformance";'),
        ("rtc-crypto/src/conformance.rs", '    let message = b"rtc-crypto verification vector";'),
        ("rtc-crypto/src/conformance.rs", '    let message = b"rtc-crypto RSASSA-PSS verification vector";'),
        ("rtc-dtls/examples/dtls_interop.rs", '                        &b"hello from the rtc-dtls client\\n"[..]'),
        ("rtc-dtls/examples/dtls_interop.rs", '                        &b"hello from the rtc-dtls server\\n"[..]'),
        ("rtc-dtls/src/config/config_test.rs", '            .with_psk_identity_hint(Some(b"rtc-dtls-test".to_vec()))'),
        ("rtc-dtls/src/dtls13/psk.rs", 'const TICKET_AAD: &[u8] = b"rtc-dtls dtls13 ticket";'),
        ("rtc-dtls/src/dtls13/psk.rs", 'const DTLS12_TICKET_AAD: &[u8] = b"rtc-dtls dtls12 ticket";'),
        ("rtc-dtls/src/endpoint.rs", '                builder = builder.with_psk_identity_hint(Some(b"rtc-dtls-test".to_vec()));'),
        ("rtc-dtls/src/endpoint.rs", '                .with_psk_identity_hint(Some(b"rtc-dtls-test".to_vec()))'),
        ("rtc-dtls/src/fuzzing.rs", '            builder = builder.with_psk_identity_hint(Some(b"rtc-dtls-fuzz".to_vec()));'),
        ("rtc-sframe/src/context.rs", 'const DECOY_BASE_KEY: &[u8] = b"rtc-sframe decoy";'),
        ("scripts/test-env/peers/layers/tests/dimpl_rtc_dtls.rs", '    p.rtc.write(p.now, p.dimpl_addr, b"from rtc-dtls")?;'),
        ("scripts/test-env/peers/layers/tests/dimpl_rtc_dtls.rs", '    assert_eq!(p.dimpl_data, vec![b"from rtc-dtls".to_vec()]);'),
    ]

    def test_the_fourteen_known_byte_literals_are_unchanged_and_reported_as_data(self):
        self.assertEqual(len(self.KNOWN), 14)
        for path, line in self.KNOWN:
            out, events, residue = rewrite(path, line + "\n")
            self.assertEqual(out, line + "\n", path)
            self.assertEqual(events, [], line)
            in_literal = [r for r in residue if r.token != "rtc"]  # `p.rtc` is a field, not the literal
            self.assertTrue(in_literal and all(r.reason.startswith(DATA) for r in in_literal), (line, residue))

    def test_the_fourteen_are_not_residue_to_rename_after_the_rename(self):
        for path, line in self.KNOWN:
            events, residue = [], []
            new_path = path.replace("rtc-", "rtci-", 1) if path.startswith("rtc-") else path
            rn.rewrite_file(renamed_renamer(), new_path, line + "\n", events, residue, {})
            self.assertEqual(events, [], line)
            self.assertFalse([r for r in residue if r.reason.startswith("UNEXPECTED")], line)

    def test_every_byte_string_form_is_kept(self):
        src = (
            'let a = b"rtc-dtls x";\nlet b = br"rtc-dtls \\x";\nlet c = br#"say "rtc-dtls""#;\n'
            'let d = br##"rtc-sframe "# still"##;\nlet e = c"rtc-ffi";\n'
        )
        out, events, _ = rewrite("rtc-dtls/src/a.rs", src)
        self.assertEqual(out, src)
        self.assertEqual(events, [])

    def test_a_byte_string_over_several_lines_is_kept_to_its_end(self):
        src = 'const V: &[u8] = b"rtc-dtls \\\n    rtc-sframe line two";\nuse rtc_dtls::x;\n'
        out, _, _ = rewrite("rtc-dtls/src/a.rs", src)
        self.assertEqual(out, src.replace("use rtc_dtls::", "use rtci_dtls::"))

    def test_code_next_to_a_byte_string_is_still_renamed(self):
        out, _, _ = rewrite("src/a.rs", 'rtc_dtls::seal(b"rtc-dtls aad", rtc::x); // rtc-dtls\n')
        self.assertEqual(out, 'rtci_dtls::seal(b"rtc-dtls aad", rtci::x); // rtci-dtls\n')

    def test_a_string_used_as_bytes_on_the_spot_is_kept(self):
        src = 'hkdf.expand("rtc-sframe key".as_bytes(), &mut k);\nlet t = Bytes::from_static("rtc-dtls label");\nlet u = String::from("rtc-ice x").into_bytes();\n'
        out, _, residue = rewrite("rtc-sframe/src/a.rs", src)
        self.assertEqual(out, src.replace('String::from("rtc-ice x")', 'String::from("rtci-ice x")'))
        self.assertEqual(sum(r.reason.startswith("string literal used as bytes") for r in residue), 2)

    def test_human_facing_strings_are_renamed(self):
        src = (
            'pub const DEFAULT_SOFTWARE: &str = concat!("rtc-ice ", env!("CARGO_PKG_VERSION"));\n'
            '#[command(about = "An example of mDNS Query using sans-I/O rtc-mdns")]\n'
            'let s: Box<dyn CipherSuite> = f(x).expect("a suite rtc-dtls has");\n'
            'static T: &str = include_str!("../../rtc-dtls/README.md");\n'
        )
        out, _, _ = rewrite("rtc-ice/src/agent/mod.rs", src)
        self.assertEqual(out, src.replace('"rtc-ice ', '"rtci-ice ').replace("sans-I/O rtc-mdns", "sans-I/O rtci-mdns").replace("suite rtc-dtls", "suite rtci-dtls").replace("../rtc-dtls/", "../rtci-dtls/"))

    def test_the_software_attribute_is_renamed_even_when_used_as_bytes(self):
        # DATA_LITERALS lists it "rename": the product name, not data.
        src = 'let software = "rtc-turn ".as_bytes();\n'
        out, _, _ = rewrite("rtc-turn/src/client/mod.rs", src)
        self.assertEqual(out, 'let software = "rtci-turn ".as_bytes();\n')
        out, _, _ = rewrite("rtc-turn/src/other.rs", src)
        self.assertEqual(out, src)

    def test_a_listed_keep_literal_stays_and_is_reported_with_its_reason(self):
        entry = ("rtc-dtls/src/k.rs", r'^"rtc-dtls exporter"$', "keep", "exporter label a peer derives too")
        rn.DATA_LITERALS.append(entry)
        rn._DATA_LITERAL_PATHS.clear()
        try:
            src = 'const LABEL: &str = "rtc-dtls exporter";\nconst NAME: &str = "rtc-dtls engine";\n'
            out, _, residue = rewrite("rtc-dtls/src/k.rs", src)
            self.assertEqual(out, src.replace("rtc-dtls engine", "rtci-dtls engine"))
            self.assertTrue(any("exporter label a peer derives too" in r.reason for r in residue))
            # After the rename the file is under rtci-dtls/; the entry still applies.
            events, residue = [], []
            rn.rewrite_file(renamed_renamer(), "rtci-dtls/src/k.rs", 'const LABEL: &str = "rtc-dtls exporter";\n', events, residue, {})
            self.assertEqual(events, [])
            self.assertFalse([r for r in residue if r.reason.startswith("UNEXPECTED")])
        finally:
            rn.DATA_LITERALS.remove(entry)
            rn._DATA_LITERAL_PATHS.clear()

    def test_check_still_finds_an_old_name_in_a_human_facing_string(self):
        events, residue = [], []
        rn.rewrite_file(renamed_renamer(), "rtci-ice/src/a.rs", 'let m = "rtc-ice selected no pair";\n', events, residue, {})
        self.assertTrue(events or any(r.reason.startswith("UNEXPECTED") for r in residue))

    def test_lexer_quotes_in_chars_lifetimes_comments_and_raw_strings(self):
        src = (
            "let q = '\"'; fn f<'a>(x: &'a str) {}\n"
            "let s = \"rtc-dtls x\"; // a \" in a comment, rtc-dtls\n"
            "/* b\" not a literal\n rtc-dtls */ let r = r#\"he said \"rtc-dtls\"\"#; let y = b'\"'; let z = b\"rtc-dtls\";\n"
        )
        out, _, _ = rewrite("src/a.rs", src)
        expected = (
            "let q = '\"'; fn f<'a>(x: &'a str) {}\n"
            "let s = \"rtci-dtls x\"; // a \" in a comment, rtci-dtls\n"
            "/* b\" not a literal\n rtci-dtls */ let r = r#\"he said \"rtci-dtls\"\"#; let y = b'\"'; let z = b\"rtc-dtls\";\n"
        )
        self.assertEqual(out, expected)

    def test_byte_strings_in_rust_code_blocks_in_markdown_are_kept(self):
        src = '```rust\nlet aad = b"rtc-dtls ticket";\nuse rtc_dtls::x;\n```\n'
        out, _, _ = rewrite("docs/x.md", src)
        self.assertEqual(out, src.replace("use rtc_dtls", "use rtci_dtls"))


class CargoToml(unittest.TestCase):
    def test_workspace_manifest(self):
        src = (
            '[workspace]\nmembers = ["rtc-dtls", "rtc-ice"]\n\n[workspace.package]\nversion = "0.22.0+brainwires.6"\n'
            'repository = "https://github.com/webrtc-rs/rtc"\n\n[workspace.dependencies]\n'
            'dtls = { version = "0.22.0", path = "rtc-dtls", package = "rtc-dtls" }\n'
            'stream-driver = { version = "0.22.0", path = "examples/stream-driver", package = "rtc-stream-driver" }\n'
            'webrtc = "0.17.3"\n\n[package]\nname = "rtc"\ndocumentation = "https://docs.rs/rtc"\n'
        )
        out, _, _ = rewrite("Cargo.toml", src)
        self.assertIn('members = ["rtci-dtls", "rtci-ice"]', out)
        self.assertIn('version = "0.1.0"\nrepository = "https://github.com/Brainwires/rtci"', out)
        self.assertIn('dtls = { version = "0.1.0", path = "rtci-dtls", package = "rtci-dtls" }', out)
        self.assertIn('package = "rtci-stream-driver"', out)
        self.assertIn('webrtc = "0.17.3"', out)
        self.assertIn('name = "rtci"\ndocumentation = "https://docs.rs/rtci"', out)

    def test_dependency_on_the_root_crate_by_path(self):
        src = '[dependencies]\nrtc = { path = "..", version = "0.22.0" }\n\n[features]\nx = ["rtc/pem", "dep:rtc"]\n'
        out, _, _ = rewrite("rtc-ffi/Cargo.toml", src)
        self.assertEqual(out, '[dependencies]\nrtci = { path = "..", version = "0.1.0" }\n\n[features]\nx = ["rtci/pem", "dep:rtci"]\n')

    def test_dotted_dependency_table_and_fuzz_crate(self):
        src = '[package]\nname = "rtc-dtls-fuzz"\nversion = "0.0.0"\npublish = false\n\n[dependencies.rtc-dtls]\npath = ".."\n\n[dependencies.rtc]\npath = "../.."\n'
        out, _, _ = rewrite("rtc-dtls/fuzz/Cargo.toml", src)
        self.assertIn('name = "rtci-dtls-fuzz"\nversion = "0.0.0"', out)
        self.assertIn("[dependencies.rtci-dtls]", out)
        self.assertIn("[dependencies.rtci]", out)

    def test_per_package_profile_tables(self):
        src = '[profile.dev.package.rtc-dtls]\nopt-level = 3\n\n[profile.release.package."rtc"]\nopt-level = 3\n\n[profile.dev.package.ring]\nopt-level = 3\n'
        out, events, _ = rewrite("Cargo.toml", src)
        self.assertEqual(out, src.replace("package.rtc-dtls]", "package.rtci-dtls]").replace('package."rtc"]', 'package."rtci"]'))
        self.assertEqual(sorted(e.category for e in events if e.category == "cargo-profile-package"), ["cargo-profile-package"] * 2)

    def test_a_registry_dependency_named_rtc_is_upstream_and_stays(self):
        src = '[dev-dependencies]\nrtc = "0.21"\n'
        out, _, _ = rewrite("x/Cargo.toml", src)
        self.assertEqual(out, src)

    def test_patch_and_replace(self):
        src = '[patch.crates-io]\nrtc-dtls = { path = "rtc-dtls" }\n\n[replace]\n"rtc-ice:0.22.0" = { path = "rtc-ice" }\n'
        out, _, _ = rewrite("Cargo.toml", src)
        self.assertEqual(out, '[patch.crates-io]\nrtci-dtls = { path = "rtci-dtls" }\n\n[replace]\n"rtci-ice:0.22.0" = { path = "rtci-ice" }\n')


class Workflows(unittest.TestCase):
    def test_flags_names_and_job_ids(self):
        src = (
            "  rtc_crypto_provider_matrix:\n    name: rtc-dtls (${{ matrix.name }})\n"
            "    run: cargo test --features rtc/${{ matrix.backend }} -p rtc-dtls\n"
            "    run: cargo publish -p rtc --token x\n"
        )
        out, _, _ = rewrite(".github/workflows/cargo.yml", src.replace("rtc_crypto", "rtc_dtls"))
        self.assertIn("rtci_dtls_provider_matrix:", out)
        self.assertIn("name: rtci-dtls (", out)
        self.assertIn("--features rtci/${{ matrix.backend }} -p rtci-dtls", out)
        self.assertIn("cargo publish -p rtci --token", out)

    def test_runner_plan_key_stays(self):
        src = """      include: '[{"crate":"rtc","key":"rtc"}]'\n      jobs: dtls=linux-x64 rtc=linux-x64\n"""
        out, _, residue = rewrite(".github/workflows/fuzz.yml", src)
        self.assertEqual(out, """      include: '[{"crate":"rtci","key":"rtc"}]'\n      jobs: dtls=linux-x64 rtc=linux-x64\n""")
        self.assertTrue(all(r.reason.startswith("runner-plan key") for r in residue))

    def test_comment_prose(self):
        out, _, _ = rewrite(".github/workflows/fuzz.yml", "# The `rtc` crate's fuzz crate; the rtc workspace.\n")
        self.assertEqual(out, "# The `rtci` crate's fuzz crate; the rtc workspace.\n")


class Shell(unittest.TestCase):
    def test_array_and_comparison(self):
        src = 'CRATES=(\n    rtc-dtls\n    rtc\n)\nif [ "$CRATE" = rtc ]; then\nrealm=rtc.test IMAGE=rtc-testenv\n'
        out, _, _ = rewrite("oss-fuzz/build.sh", src)
        self.assertEqual(out, 'CRATES=(\n    rtci-dtls\n    rtci\n)\nif [ "$CRATE" = rtci ]; then\nrealm=rtc.test IMAGE=rtc-testenv\n')

    def test_repository_name(self):
        out, _, _ = rewrite("oss-fuzz/Dockerfile", "COPY . $SRC/webrtc-rs-rtc\n# see https://github.com/Brainwires/webrtc-rs-rtc/issues\n")
        self.assertEqual(out, "COPY . $SRC/rtci\n# see https://github.com/Brainwires/rtci/issues\n")


class Markdown(unittest.TestCase):
    def test_shell_code_blocks_rename_a_bare_crate_word(self):
        src = "```sh\nfor p in rtc-dtls rtc; do cargo publish -p $p; done  # rtc last\n```\n\nThe rtc word in prose stays.\n"
        out, events, _ = rewrite("docs/releasing.md", src)
        self.assertEqual(out, "```sh\nfor p in rtci-dtls rtci; do cargo publish -p $p; done  # rtc last\n```\n\nThe rtc word in prose stays.\n")
        self.assertIn("shell-word", {e.category for e in events})

    def test_a_bare_word_in_a_text_code_block_stays(self):
        src = "```text\nrtc peer <-> browser\n```\n"
        out, _, _ = rewrite("docs/x.md", src)
        self.assertEqual(out, src)

    def test_upstream_urls_and_statements_stay(self):
        src = (
            "[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc/tree/master/rtc-dtls) and "
            "https://crates.io/crates/rtc-ice; upstream's `rtc-interceptor-derive` was deleted. "
            "Ours: `rtc-dtls/src/lib.rs`, `rtc_ice::Agent`, `cargo test -p rtc`.\n"
        )
        out, _, _ = rewrite("docs/x.md", src)
        self.assertEqual(
            out,
            src.replace("Ours: `rtc-dtls/", "Ours: `rtci-dtls/").replace("`rtc_ice::", "`rtci_ice::").replace("-p rtc`", "-p rtci`"),
        )

    def test_toml_snippet(self):
        out, _, _ = rewrite("README.md", '```toml\n[dependencies]\nrtc = "0.21"\nrtc-dtls = { version = "0.21" }\n```\n')
        self.assertEqual(out, '```toml\n[dependencies]\nrtci = "0.1"\nrtci-dtls = { version = "0.1" }\n```\n')

    def test_changelog_only_the_unreleased_section(self):
        src = "# Changelog\n\n## [Unreleased]\n\n- `rtc-dtls`: x\n\n## [0.22.0+brainwires.6] - 2026-11-23\n\n- `rtc-dtls`: y\n"
        out, _, residue = rewrite("CHANGELOG.md", src)
        self.assertIn("- `rtci-dtls`: x", out)
        self.assertIn("- `rtc-dtls`: y", out)
        self.assertTrue(any(r.reason.startswith("released CHANGELOG") for r in residue))

    def test_fork_upstream_table_keeps_its_upstream_columns(self):
        src = (
            "### Upstream changes not taken (reverted inside the merge)\n\n| Upstream commit | What it removed | What the fork does |\n|---|---|---|\n"
            "| `14d89bb2` | Deleted `rtc-interceptor-derive` | Keeps `rtc-interceptor-derive/` |\n"
        )
        out, _, _ = rewrite("FORK.md", src)
        self.assertIn("| Deleted `rtc-interceptor-derive` | Keeps `rtci-interceptor-derive/` |", out)

    def test_parity_table_rows_keep_upstream_keys(self):
        src = "Crate `.` is the top-level `rtc` crate.\n\n| Crate | Upstream test |\n|---|---|\n| `rtc-ice` | `test_x` |\n"
        out, _, _ = rewrite("docs/upstream-test-parity.md", src)
        self.assertEqual(out, src.replace("top-level `rtc`", "top-level `rtci`"))

    def test_marked_lineage_block_is_left(self):
        src = "<!-- rtci-lineage:start -->\nrenamed from `rtc-*` and `rtc`\n<!-- rtci-lineage:end -->\n"
        out, events, _ = rewrite("README.md", src)
        self.assertEqual(out, src)
        self.assertEqual(events, [])


class Ffi(unittest.TestCase):
    def test_exported_names_header_and_library(self):
        src = '#include "rtc.h"\nint32_t s = rtc_pc_new(&pc); if (s != RTC_OK) rtc_last_error(); // RTC_ERR_*, rtc_pc_* RTCPeerConnection RTCConfiguration\n'
        out, _, _ = rewrite("rtc-ffi/tests/c/loopback.c", src)
        self.assertEqual(
            out,
            '#include "rtci.h"\nint32_t s = rtci_pc_new(&pc); if (s != RTCI_OK) rtci_last_error(); // RTCI_ERR_*, rtci_pc_* RTCPeerConnection RTCConfiguration\n',
        )

    def test_library_files_and_env_names(self):
        src = "lib=target/release/librtc_ffi.so; RTC_FFI_LIB=x rtc-ffi-release RTC_TESTENV_TURN_USER\n"
        out, _, _ = rewrite("rtc-ffi/README.md", src)
        self.assertEqual(out, "lib=target/release/librtci_ffi.so; RTCI_FFI_LIB=x rtci-ffi-release RTC_TESTENV_TURN_USER\n")

    def test_header_continuation_lines_follow_the_longer_name(self):
        src = "int32_t rtc_pc_new(const char *json,\n                   struct rtc_pc **out);\n"
        out, _, _ = rewrite("rtc-ffi/include/rtc.h", src)
        self.assertEqual(out, "int32_t rtci_pc_new(const char *json,\n                    struct rtci_pc **out);\n")

    def test_header_continuation_of_a_function_pointer_typedef(self):
        src = "typedef void (*rtc_pc)(void *user,\n                       size_t len);\n"
        out, _, _ = rewrite("rtc-ffi/include/rtc.h", src)
        self.assertEqual(out, "typedef void (*rtci_pc)(void *user,\n                        size_t len);\n")

    def test_local_variables_outside_the_ffi_scope_stay(self):
        out, _, _ = rewrite("tests/a.rs", "let mut rtc_pc = pc; rtc_pc.close();\n")
        self.assertEqual(out, "let mut rtc_pc = pc; rtc_pc.close();\n")


class Idempotence(unittest.TestCase):
    def test_renamed_text_has_nothing_left_to_rename(self):
        samples = [
            ("tests/a.rs", "use rtci::peer_connection::X;\nuse rtci_ice::Agent;\n"),
            ("Cargo.toml", '[package]\nname = "rtci"\n[dependencies]\ndtls = { version = "0.1.0", path = "rtci-dtls", package = "rtci-dtls" }\n'),
            ("oss-fuzz/build.sh", "    rtci\n    rtci-dtls\n"),
        ]
        renamed = [
            crate(c.new, manifest=c.manifest.replace("rtc-", "rtci-"), kinds=tuple(c.kinds), publish=c.publish) for c in CRATES
        ]
        r = rn.Renamer(renamed, SYMBOLS, {"rtc.h": "rtci.h"}, True)
        for path, text in samples:
            events, residue = [], []
            out = rn.rewrite_file(r, path, text, events, residue, {})
            self.assertEqual(out, text, path)
            self.assertEqual(events, [], path)


class Publication(unittest.TestCase):
    def test_dependency_order(self):
        a = crate("rtc-shared")
        b = crate("rtc-dtls")
        b.deps = [{"name": "rtc-shared", "kind": None, "path": "/x", "req": "^0.1.0"}]
        c = crate("rtc")
        c.deps = [
            {"name": "rtc-dtls", "kind": None, "path": "/x", "req": "^0.1.0"},
            {"name": "rtc-stream-driver", "kind": "dev", "path": "/x", "req": "^0.1.0"},
        ]
        d = crate("rtc-stream-driver", manifest="examples/stream-driver/Cargo.toml", publish=False)
        order, notes = rn.publish_order([c, b, a, d])
        self.assertEqual(order, ["rtci-shared", "rtci-dtls", "rtci"])
        self.assertTrue(any("rtci-stream-driver" in n for n in notes))


if __name__ == "__main__":
    unittest.main()
