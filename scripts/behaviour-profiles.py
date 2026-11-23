#!/usr/bin/env python3
"""Renders docs/behaviour-profiles.md from the tables of
src/peer_connection/configuration/behaviour_profile.rs.

    python3 scripts/behaviour-profiles.py          # write the doc
    python3 scripts/behaviour-profiles.py --check  # fail when the doc is not what the code says

Also checks, as the crate's `every_setting_is_governed_or_listed_as_left_alone` test does,
that every setting of the setting engine, the media engine and the default interceptor options
is either governed by the profiles or listed as left alone, and that both lists name only
settings that exist.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "src/peer_connection/configuration"
SOURCE = CONFIG / "behaviour_profile.rs"
DOC = ROOT / "docs/behaviour-profiles.md"

STRING = r'"((?:[^"\\]|\\.)*)"'


def unescape(text):
    return re.sub(r"\\(.)", r"\1", text)


def field(block, key, value=STRING):
    match = re.search(r"^\s*" + key + r":\s*" + value + r",?\s*$", block, re.M)
    if not match:
        raise SystemExit(f"behaviour-profiles: no `{key}` in\n{block}")
    return unescape(match.group(1))


def strip_comments(code):
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    return "\n".join("" if line.lstrip().startswith("//") else line for line in code.split("\n"))


def governed(source):
    start = source.index("governed_behaviours! {\n")
    body = source[start:]
    body = body[: body.index("\n}\n")]
    rows = []
    for block in re.split(r"\n    \{\n", body)[1:]:
        hook = re.search(r"^\s*apply_(setting|media|interceptors):", block, re.M)
        if not hook:
            raise SystemExit(f"behaviour-profiles: no apply_* hook in\n{block}")
        rows.append(
            {
                "id": field(block, "id"),
                "setting": field(block, "setting"),
                "clause": field(block, "clause"),
                "rfc": field(block, "rfc", r".*?=>\s*" + STRING),
                "chrome": field(block, "chrome", r".*?=>\s*" + STRING),
                "strict_rfc": field(block, "strict_rfc", r".*?=>\s*" + STRING),
                "source": field(block, "chrome_source"),
                "evidence": field(block, "evidence", r"(\w+)"),
                "target": hook.group(1),
            }
        )
    return rows


def entries(source, static, struct, keys):
    start = source.index(f"pub(crate) static {static}: &[{struct}] = &[")
    body = source[start:]
    body = body[: body.index("\n];\n")]
    out = []
    for block in body.split(f"{struct} {{")[1:]:
        entry = {}
        for key in keys:
            if key == "class":
                entry[key] = field(block, key, r"NotGovernedClass::(\w+)")
            else:
                entry[key] = field(block, key)
        out.append(entry)
    return out


def declared(path, owner, prefixes):
    code = strip_comments(path.read_text())
    names = set()
    for prefix in prefixes:
        for name in re.findall(r"^\s*pub fn (" + prefix + r"\w*)", code, re.M):
            names.add(f"{owner}::{name}")
    return names


def struct_fields(path, owner):
    code = strip_comments(path.read_text())
    start = code.index(f"pub struct {owner} {{")
    body = code[start:]
    body = body[: body.index("\n}")]
    return {f"{owner}::{name}" for name in re.findall(r"^\s*pub (\w+):", body, re.M)}


def check_completeness(rows, not_governed):
    settings = declared(CONFIG / "setting_engine.rs", "SettingEngineBuilder", ["with_", "without_"])
    settings |= declared(CONFIG / "media_engine.rs", "MediaEngine", ["set_"])
    settings |= struct_fields(CONFIG / "interceptor_registry.rs", "DefaultInterceptorOptions")
    governed_names = {row["setting"] for row in rows}
    left_alone = [entry["setting"] for entry in not_governed]
    errors = []
    if len(set(left_alone)) != len(left_alone):
        errors.append("a setting is listed twice in NOT_GOVERNED")
    both = governed_names & set(left_alone)
    if both:
        errors.append(f"governed and left alone: {sorted(both)}")
    missing = sorted(settings - governed_names - set(left_alone))
    if missing:
        errors.append(
            "settings with no profile entry (add a GOVERNED or NOT_GOVERNED entry to "
            f"behaviour_profile.rs): {missing}"
        )
    stale = sorted((governed_names | set(left_alone)) - settings)
    if stale:
        errors.append(f"profile entries naming no setting: {stale}")
    ids = [row["id"] for row in rows]
    if len(set(ids)) != len(ids):
        errors.append("an id is used twice")
    for row in rows:
        if row["rfc"] == row["chrome"] == row["strict_rfc"]:
            errors.append(f"{row['id']} is the same in every profile (move it to NOT_GOVERNED)")
        if row["evidence"] not in ("Observed", "Unverified"):
            errors.append(f"{row['id']}: evidence {row['evidence']}")
    return errors, len(settings)


def cell(text):
    return text.replace("|", "\\|").replace("\n", " ")


def code(text):
    return f"`{cell(text)}`"


CLASS_TITLES = {
    "EngineOnly": "Engine-only capabilities: the same in every profile",
    "Same": "Examined: the default is libwebrtc's too, or already the RFC's",
    "Input": "Application input: no default to choose",
    "Deprecated": "Deprecated, not read by the engine",
}


def render(rows, not_governed, not_expressible):
    observed = sum(1 for row in rows if row["evidence"] == "Observed")
    unverified = len(rows) - observed
    differs = sum(1 for row in rows if row["chrome"] != row["rfc"])
    strict = sum(1 for row in rows if row["strict_rfc"] != row["rfc"])
    out = []
    w = out.append
    w("# Behaviour profiles")
    w("")
    w("<!-- Generated by scripts/behaviour-profiles.py from")
    w("     src/peer_connection/configuration/behaviour_profile.rs. Do not edit by hand. -->")
    w("")
    w("A `BehaviourProfile` sets, in one call, every default where the engine and an RFC, or the")
    w("engine and libwebrtc (Chrome), choose differently:")
    w("")
    w("- **`Rfc`**: the engine's defaults, unchanged. The RFCs' behaviour, and the interoperable")
    w("  form where a named browser or deployed peer cannot take the RFC's (the audit's `setting`")
    w("  verdict, `docs/conformance/audit/RULES.md`).")
    w("- **`Chrome`**: libwebrtc's choice wherever the engine and libwebrtc both do a thing and")
    w("  choose differently (a timer, an order, a form on the wire, a lenient or strict acceptance")
    w("  rule). It never turns off a capability the engine has and Chrome lacks: those are the same")
    w("  in every profile (section 2), so the `Chrome` profile's offers are a **superset** of")
    w("  Chrome's (extra header extensions, `a=rtcp-fb` types, `a=tls-id`, formats).")
    w("- **`StrictRfc`**: the RFC form even where the default is the interoperable one. For")
    w("  conformance testing only: **it does not interoperate with browsers** (Chromium, Firefox")
    w("  and WebKit refuse an answer whose bundled sections lack `a=rtcp-mux`; a data-only")
    w("  association without `use_srtp` cannot gain media with a browser).")
    w("")
    w("```rust")
    w("let profile = BehaviourProfile::Chrome;")
    w("let setting_engine = SettingEngineBuilder::new().with_behaviour_profile(profile).build();")
    w("let mut media_engine = MediaEngine::for_profile(profile);")
    w("media_engine.register_default_codecs()?;")
    w("// Reads the media engine's profile:")
    w("let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;")
    w("```")
    w("")
    w("A setting given after `with_behaviour_profile` keeps its own value. The connection's")
    w("automatic RTCP session (a registry without one) follows the setting engine's profile.")
    w("")
    w("## The `chrome-defaults` cargo feature")
    w("")
    w("With the `chrome-defaults` feature of the `rtc` crate, `BehaviourProfile::default()` is")
    w("`Chrome`, and so is every `SettingEngine::default()`, `SettingEngineBuilder::new()`,")
    w("`MediaEngine::default()` and `DefaultInterceptorOptions::default()`.")
    w("")
    w("**Cargo unifies features across a dependency graph: one crate of a build that enables")
    w("`chrome-defaults` changes the defaults of every user of `rtc` in that build**, libraries")
    w("that never asked for it included. Prefer the explicit `with_behaviour_profile` call;")
    w("`BehaviourProfile::compiled_default()` tells which default a build has.")
    w("")
    w(f"## 1. Defaults that differ: governed by the profile ({len(rows)})")
    w("")
    w(f"{len(rows)} governed behaviours: the `Chrome` value differs from `Rfc` in {differs}, the")
    w(f"`StrictRfc` value in {strict}. Chrome values: {observed} observed, {unverified} unverified.")
    w("")
    w("A value is what `{:?}` of the setting writes; the crate's tests compare each with the")
    w("setting a profile leaves, and the `Rfc` column with the engine's defaults before any")
    w("profile. **Observed** Chrome values come from the recorded Chromium descriptions")
    w("(`tests/fixtures/browser-sdp/chromium--*.sdp`, from the test environment of conformance")
    w("train 9, round 3: Playwright 1.64.1's Chromium) or a cell of the browser matrix.")
    w("**Unverified** ones rest on knowledge of libwebrtc's source and have not been observed here.")
    w("")
    w("| Behaviour | Setting | Clause | `Rfc` | `Chrome` | `StrictRfc` | Source of the Chrome value |")
    w("|---|---|---|---|---|---|---|")
    for row in rows:
        source = ("observed: " if row["evidence"] == "Observed" else "**unverified**: ") + row["source"]
        w(
            f"| {code(row['id'])} | {code(row['setting'])} | {cell(row['clause'])} | "
            f"{code(row['rfc'])} | {code(row['chrome'])} | {code(row['strict_rfc'])} | {cell(source)} |"
        )
    w("")
    for klass in ["EngineOnly", "Same", "Input", "Deprecated"]:
        entries = [entry for entry in not_governed if entry["class"] == klass]
        number = "2. " if klass == "EngineOnly" else ""
        w(f"## {number}{CLASS_TITLES[klass]} ({len(entries)})")
        w("")
        if klass == "EngineOnly":
            w("A capability the engine has and Chrome lacks stays on under `Chrome`: it negotiates")
            w("down with a Chrome peer, or a Chrome peer does not notice it. Further engine-only")
            w("capabilities with no setting: DTLS 1.3 offered with DTLS 1.2 fallback, the")
            w("post-quantum hybrid key share where the crypto backend has it, RFC 7728 pause /")
            w("resume, SFrame, Cryptex negotiation, receive simulcast with `a=imageattr`, several")
            w("transports and BUNDLE groups, RTCP extended reports, and the statistics the engine")
            w("reports beyond Chrome's.")
            w("")
        w("| Setting | Note |")
        w("|---|---|")
        for entry in entries:
            w(f"| {code(entry['setting'])} | {cell(entry['note'])} |")
        w("")
    w(f"## 3. Not expressible ({len(not_expressible)})")
    w("")
    w("What Chrome does that no setting of the engine can express, and what it would take.")
    w("")
    w("| Behaviour | Chrome | What would be needed |")
    w("|---|---|---|")
    for entry in not_expressible:
        w(f"| {cell(entry['behaviour'])} | {cell(entry['chrome'])} | {cell(entry['needed'])} |")
    w("")
    w("## How it is checked")
    w("")
    w("- `src/peer_connection/configuration/behaviour_profile_test.rs`: every value of every")
    w("  profile, the `Rfc` column against the engine's own defaults, a peer connection built the")
    w("  default way under each profile (its ICE agent configuration included), and that every")
    w("  setting of `SettingEngineBuilder`, `MediaEngine` and `DefaultInterceptorOptions` is in")
    w("  this document (a new setting without a profile entry fails the test and this script).")
    w("- `tests/behaviour_profiles.rs`: under `Chrome`, an offer and an answer compared")
    w("  structurally with the committed Chromium descriptions (the engine's extra attributes are")
    w("  listed there as documented differences); rtc to rtc connections with data and media")
    w("  between profiles, and the `StrictRfc` refusals.")
    w("- `scripts/behaviour-profiles.py --check` (a Python gate of `cargo.yml`): this document is")
    w("  what the code says.")
    w("- The browser matrix runs the core scenarios with the Rust peer under `Chrome`")
    w("  (`examples/interop-peer`, `profile=chrome`).")
    w("")
    return "\n".join(out)


def main():
    source = SOURCE.read_text()
    rows = governed(source)
    not_governed = entries(source, "NOT_GOVERNED", "NotGoverned", ["setting", "class", "note"])
    not_expressible = entries(
        source, "NOT_EXPRESSIBLE", "NotExpressible", ["behaviour", "chrome", "needed"]
    )
    errors, scanned = check_completeness(rows, not_governed)
    if errors:
        for error in errors:
            print(f"behaviour-profiles: {error}", file=sys.stderr)
        return 1
    text = render(rows, not_governed, not_expressible)
    if "--check" in sys.argv[1:]:
        if not DOC.exists() or DOC.read_text() != text:
            print(
                "behaviour-profiles: docs/behaviour-profiles.md is not what the code says; "
                "run python3 scripts/behaviour-profiles.py",
                file=sys.stderr,
            )
            return 1
    else:
        DOC.write_text(text)
    observed = sum(1 for row in rows if row["evidence"] == "Observed")
    print(
        f"behaviour-profiles: {len(rows)} governed ({observed} observed, "
        f"{len(rows) - observed} unverified), {len(not_governed)} left alone, "
        f"{len(not_expressible)} not expressible; {scanned} settings scanned"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
