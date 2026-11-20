#!/usr/bin/env python3
"""Every fuzz target is built and run.

A fuzz target that no job builds is coverage on paper only. For every cargo-fuzz crate in the
repository (`fuzz/` for the `rtc` crate, `<crate>/fuzz/` for the others) this fails when:

* a ``[[bin]]`` entry points at a file that does not exist;
* a file in ``fuzz_targets/`` that defines a target (``fuzz_target!``) has no ``[[bin]]``;
* the crate is missing from ``oss-fuzz/build.sh`` (``FUZZ_CRATES``);
* the crate is missing from ``.github/workflows/fuzz.yml``'s ``targets: all`` matrix, or its
  runner key from the ``pick runners`` job;
* a name in a matrix ``stateful`` list is not a target of that crate.

Usage: ``python3 scripts/check-fuzz-registry.py``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FUZZ_YML = ROOT / ".github" / "workflows" / "fuzz.yml"
OSS_FUZZ = ROOT / "oss-fuzz" / "build.sh"


def fuzz_crates() -> dict[str, Path]:
    """Crate name (as fuzz.yml and build.sh name it) -> its fuzz directory."""
    out = {}
    for manifest in sorted([ROOT / "fuzz" / "Cargo.toml", *ROOT.glob("*/fuzz/Cargo.toml")]):
        if not manifest.exists() or "cargo-fuzz = true" not in manifest.read_text(encoding="utf-8"):
            continue
        fuzz_dir = manifest.parent
        crate = "rtc" if fuzz_dir.parent == ROOT else fuzz_dir.parent.name
        out[crate] = fuzz_dir
    return out


def bins(manifest: Path) -> dict[str, str]:
    """[[bin]] name -> path, from a fuzz crate's Cargo.toml."""
    out = {}
    text = manifest.read_text(encoding="utf-8")
    for block in re.split(r"^\[\[bin\]\]\s*$", text, flags=re.M)[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, flags=re.M)
        path = re.search(r'^path\s*=\s*"([^"]+)"', block, flags=re.M)
        if name and path:
            out[name.group(1)] = path.group(1)
    return out


def matrices(text: str) -> list[list[dict]]:
    """The JSON matrices fuzz.yml's `include:` expression holds (the `all` one and the
    `stateful` one)."""
    return [json.loads(m) for m in re.findall(r"'(\[\{.*?\}\])'", text)]


def main() -> int:
    errors = []
    crates = fuzz_crates()
    fuzz_yml = FUZZ_YML.read_text(encoding="utf-8")
    oss = OSS_FUZZ.read_text(encoding="utf-8")
    oss_crates = set(re.findall(r"^\s+(rtc[a-z-]*)\s*$", oss.split("FUZZ_CRATES=(", 1)[-1].split(")", 1)[0], flags=re.M))
    tables = matrices(fuzz_yml)
    if not tables:
        errors.append("fuzz.yml: no matrix found")
    all_matrix = max(tables, key=len) if tables else []
    picker = re.search(r"jobs: >-\n((?:\s+.*=linux-x64.*\n)+)", fuzz_yml)
    picker_keys = set(re.findall(r"(\w+)=linux-x64", picker.group(1))) if picker else set()

    names: dict[str, set[str]] = {}
    for crate, fuzz_dir in crates.items():
        targets = bins(fuzz_dir / "Cargo.toml")
        names[crate] = set(targets)
        for name, path in targets.items():
            if not (fuzz_dir / path).exists():
                errors.append(f"{crate}: [[bin]] {name} points at {path}, which does not exist")
        listed = {Path(p).name for p in targets.values()}
        for source in sorted((fuzz_dir / "fuzz_targets").glob("*.rs")):
            if "fuzz_target!" in source.read_text(encoding="utf-8") and source.name not in listed:
                errors.append(f"{crate}: {source.relative_to(ROOT)} defines a target but has no [[bin]]")
        if crate not in oss_crates:
            errors.append(f"{crate}: not in oss-fuzz/build.sh FUZZ_CRATES")
        entries = [e for e in all_matrix if e.get("crate") == crate]
        if not entries:
            errors.append(f"{crate}: not in fuzz.yml's `targets: all` matrix")
        for entry in entries:
            if entry.get("key") not in picker_keys:
                errors.append(f"{crate}: runner key {entry.get('key')!r} is not in fuzz.yml's pick-runners jobs")

    for table in tables:
        for entry in table:
            crate = entry.get("crate")
            if crate not in crates:
                errors.append(f"fuzz.yml: matrix names crate {crate!r}, which has no fuzz crate")
                continue
            for target in entry.get("stateful", "").split():
                if target not in names[crate]:
                    errors.append(f"fuzz.yml: {crate} stateful target {target!r} is not a [[bin]]")

    if errors:
        print("Fuzz registry check failed:\n")
        for e in errors:
            print(f"  {e}")
        return 1
    total = sum(len(v) for v in names.values())
    print(f"Fuzz registry: {len(crates)} fuzz crates, {total} targets, all built by OSS-Fuzz and run by fuzz.yml.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
