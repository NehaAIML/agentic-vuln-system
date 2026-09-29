#!/usr/bin/env python3
"""
harden_03c_finalize_sandbox_runner.py

Clears the 4 remaining ruff findings in sandbox/sandbox_runner.py:
  * F841   : remove `init = ` (unused assignment)
  * PLW1510 x3 : add explicit `check=False` to subprocess.run call sites

Idempotent. DRY_RUN preview. .bak backup. ast.parse() validation.
Refuses to write if any anchor is missing.
"""

from __future__ import annotations

import ast
import re
import shutil
import sys
from pathlib import Path

# ----------------------------------------------------------------------
DRY_RUN = False
# ----------------------------------------------------------------------

REPO_ROOT = Path.cwd()
TARGET = REPO_ROOT / "sandbox" / "sandbox_runner.py"


def show_region(text: str, needle: str, before: int = 2, after: int = 3) -> str:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if needle in ln:
            lo = max(0, i - before)
            hi = min(len(lines), i + after + 1)
            return "\n".join(f"  {j+1:4d} | {lines[j]}" for j in range(lo, hi))
    return "  (needle not found)"


def apply_patch(text: str) -> tuple[str, list[str]]:
    changes: list[str] = []

    # --- 1. F841: drop `init = ` assignment ---
    if re.search(r"^\s*init\s*=\s*_run\(\[.git., .init.", text, re.MULTILINE):
        text = re.sub(
            r"^(\s*)init\s*=\s*(_run\(\[.git., .init.)",
            r"\1\2",
            text,
            count=1,
            flags=re.MULTILINE,
        )
        changes.append("F841: removed unused `init = ` assignment")
    else:
        changes.append("F841: already clean (skipped)")

    # --- 2. PLW1510 #1: _run() helper (line ~48) ---
    # Pattern: subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    helper_pat = re.compile(
        r"(return\s+subprocess\.run\(\s*cmd,\s*cwd=cwd,\s*capture_output=True,\s*text=True,\s*timeout=timeout)\s*\)"
    )
    if helper_pat.search(text):
        text = helper_pat.sub(r"\1, check=False\n    )", text, count=1)
        changes.append("PLW1510: _run() helper -> added check=False")
    else:
        # maybe already patched
        if "timeout=timeout, check=False" in text:
            changes.append("PLW1510: _run() helper already has check=False (skipped)")
        else:
            changes.append("PLW1510: _run() helper pattern NOT FOUND (manual review)")

    # --- 3. PLW1510 #2: patch_proc subprocess.run (line ~106) ---
    # Pattern block uses multi-line args ending with timeout=10,
    pat_proc = re.compile(
        r'(subprocess\.run\(\s*\["patch", "-p1", "--fuzz=3"\],\s*cwd=sandbox_path,\s*stdin=f,\s*capture_output=True,\s*text=True,\s*timeout=10)(,?\s*\))'
    )
    if pat_proc.search(text):
        text = pat_proc.sub(r"\1, check=False\2", text, count=1)
        changes.append("PLW1510: patch_proc subprocess.run -> added check=False")
    else:
        if re.search(r'"patch", "-p1", "--fuzz=3".*check=False', text, re.DOTALL):
            changes.append("PLW1510: patch_proc already has check=False (skipped)")
        else:
            changes.append("PLW1510: patch_proc pattern NOT FOUND (manual review)")

    # --- 4. PLW1510 #3: py_compile subprocess.run (line ~152) ---
    # Pattern: subprocess.run(["python3", "-m", "py_compile", str(f)], capture_output=True, text=True)
    pyc_pat = re.compile(
        r'(subprocess\.run\(\s*\["python3", "-m", "py_compile", str\(f\)\],\s*capture_output=True,\s*text=True)(,?\s*\))'
    )
    if pyc_pat.search(text):
        text = pyc_pat.sub(r"\1, check=False\2", text, count=1)
        changes.append("PLW1510: py_compile subprocess.run -> added check=False")
    else:
        if re.search(r'"py_compile", str\(f\)\].*check=False', text, re.DOTALL):
            changes.append("PLW1510: py_compile already has check=False (skipped)")
        else:
            changes.append("PLW1510: py_compile pattern NOT FOUND (manual review)")

    return text, changes


def main() -> int:
    print(f"Target    : {TARGET}")
    print(f"DRY_RUN   : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print(f"ERROR: {TARGET} not found. Run from repo root.")
        return 1

    original = TARGET.read_text(encoding="utf-8")
    try:
        patched, changes = apply_patch(original)
    except Exception as e:
        print(f"ABORT: {e}")
        print("Nothing was written.")
        return 2

    print("\nPlanned changes:")
    for c in changes:
        print(f"  + {c}")

    if patched == original:
        print("\nNo changes made — file already clean.")
        return 0

    # --- validation ---
    try:
        ast.parse(patched)
        print("\nast.parse(): OK")
    except SyntaxError as e:
        print(f"\nABORT: patched file would not parse: {e}")
        return 3

    # count check=False occurrences
    n_check = patched.count("check=False")
    print(f"check=False occurrences now: {n_check}  (expected >= 3)")
    if n_check < 3:
        print("ABORT: fewer than 3 check=False found after patch — something didn't apply.")
        return 4

    # regions for eyeballing
    print("\n--- region: _run helper ---")
    print(show_region(patched, "return subprocess.run", before=1, after=2))

    print("\n--- region: git init ---")
    print(show_region(patched, '["git", "init", "-q"]', before=2, after=2))

    print("\n--- region: patch_proc ---")
    print(show_region(patched, '"patch", "-p1"', before=2, after=8))

    print("\n--- region: py_compile ---")
    print(show_region(patched, '"py_compile"', before=2, after=3))

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        print("Set DRY_RUN = False and run again to apply.")
        return 0

    bak = TARGET.with_suffix(".py.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(patched, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    print(f"BACKUP : {bak}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
