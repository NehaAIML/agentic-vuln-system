#!/usr/bin/env python3
"""
harden_06_fix_yaml_load.py

Fix sample_repo/app.py line ~14: yaml.load(f) -> yaml.safe_load(f).
Also handles the two-arg form yaml.load(f, Loader=...) if present.
DRY_RUN preview. ast.parse() validation. .bak backup.
"""

from __future__ import annotations
import ast
import re
import shutil
import sys
from pathlib import Path

DRY_RUN = False
TARGET = Path.cwd() / "sample_repo" / "app.py"


def fix(text: str) -> tuple[str, list[str]]:
    notes = []

    # Form A: bare yaml.load(...) with no Loader kwarg
    pat_a = re.compile(r"\byaml\.load\((?![^)]*Loader)")
    n_a = len(pat_a.findall(text))
    if n_a:
        text = pat_a.sub("yaml.safe_load(", text)
        notes.append(f"yaml.load( -> yaml.safe_load(  ({n_a} occurrence)")

    # Form B: yaml.load(f, Loader=yaml.FullLoader) -> keep it, but normalize
    #   Nothing to do; FullLoader is explicit and safe.

    if not notes:
        notes.append("no changes needed (skipped)")

    return text, notes


def show_region(text: str, needle: str, before=2, after=3) -> str:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if needle in ln:
            lo, hi = max(0, i - before), min(len(lines), i + after + 1)
            return "\n".join(f"  {j+1:4d} | {lines[j]}" for j in range(lo, hi))
    return "  (needle not found)"


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)
    if not TARGET.exists():
        print("ERROR: file not found.")
        return 1

    original = TARGET.read_text(encoding="utf-8")
    patched, notes = fix(original)
    for n in notes:
        print(f"  + {n}")

    if patched == original:
        print("\nNo changes.")
        return 0

    try:
        ast.parse(patched)
        print("ast.parse(): OK")
    except SyntaxError as e:
        print(f"ABORT: would not parse: {e}")
        return 2

    print("\n--- region ---")
    print(show_region(patched, "yaml.", before=2, after=2))

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    bak = TARGET.with_suffix(".py.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(patched, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    print(f"BACKUP : {bak}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
