#!/usr/bin/env python3
"""
harden_03b_configurable_retry.py

Makes the retry cap in sandbox/sandbox_runner.py configurable via the
MAX_REPAIR_ATTEMPTS environment variable.

Fixes vs harden_03:
  * deterministic import anchor
  * prints the insertion region for visual verification
  * runs ast.parse() before writing (refuses to write invalid Python)
  * verifies helper appears exactly once

DRY_RUN preview + .bak backup. Never overwrites without validating.
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

IMPORT_ANCHOR = "from agent.patch_generator import generate_patch, PatchResult"

HELPER_BLOCK = """

def _default_max_attempts() -> int:
    \"\"\"Retry cap, overridable via MAX_REPAIR_ATTEMPTS env var (default 3).\"\"\"
    raw = os.getenv("MAX_REPAIR_ATTEMPTS", "3")
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"MAX_REPAIR_ATTEMPTS must be an integer, got {raw!r}")
    if value < 1:
        raise ValueError(f"MAX_REPAIR_ATTEMPTS must be >= 1, got {value}")
    return value

"""


def apply_patch(text: str) -> tuple[str, list[str]]:
    changes: list[str] = []

    # ---- 1. import os ----
    if re.search(r"^\s*import os\b", text, re.MULTILINE):
        changes.append("import os: already present (skipped)")
    else:
        new_text, n = re.subn(
            r"^(import shutil\b)",
            r"import os\n\1",
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if n != 1:
            raise RuntimeError("could not find anchor `import shutil` to add `import os`")
        text = new_text
        changes.append("added `import os`")

    # ---- 2. helper function ----
    if "_default_max_attempts" in text:
        changes.append("helper _default_max_attempts: already present (skipped)")
    else:
        if IMPORT_ANCHOR not in text:
            raise RuntimeError(f"anchor import line not found: {IMPORT_ANCHOR!r}")
        text = text.replace(IMPORT_ANCHOR, IMPORT_ANCHOR + HELPER_BLOCK, 1)
        changes.append("inserted _default_max_attempts() helper after agent import")

    # ---- 3. signature defaults ----
    new_text, n = re.subn(
        r"(max_attempts:\s*int\s*=\s*)3\b",
        r"\1_default_max_attempts()",
        text,
    )
    if n == 0:
        raise RuntimeError("no `max_attempts: int = 3` signature found")
    text = new_text
    changes.append(f"replaced {n} signature default(s): 3 -> _default_max_attempts()")

    # ---- 4. argparse default ----
    new_text, n = re.subn(
        r'("--max-attempts"\s*,\s*type=int\s*,\s*default=)3\b',
        r"\1None",
        text,
    )
    if n != 1:
        raise RuntimeError(f"argparse --max-attempts default: expected 1 match, got {n}")
    text = new_text
    changes.append("argparse --max-attempts default 3 -> None")

    # ---- 4b. resolve in main() ----
    if "args.max_attempts = " in text:
        changes.append("main() env fallback: already present (skipped)")
    else:
        anchor = "args = parser.parse_args()"
        if anchor not in text:
            raise RuntimeError("anchor `args = parser.parse_args()` not found")
        text = text.replace(
            anchor,
            anchor
            + "\n\n    if args.max_attempts is None:\n"
            + "        args.max_attempts = _default_max_attempts()",
            1,
        )
        changes.append("main(): resolve args.max_attempts via env when None")

    return text, changes


def region_around(text: str, needle: str, before: int = 3, after: int = 8) -> str:
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if needle in ln:
            lo = max(0, i - before)
            hi = min(len(lines), i + after)
            return "\n".join(f"  {j+1:4d} | {lines[j]}" for j in range(lo, hi))
    return "  (needle not found)"


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
    except RuntimeError as e:
        print(f"ABORT: {e}")
        print("Nothing was written.")
        return 2

    print("\nPlanned changes:")
    for c in changes:
        print(f"  + {c}")

    # sanity 1: valid Python?
    try:
        ast.parse(patched)
        print("\nast.parse(): OK")
    except SyntaxError as e:
        print(f"\nABORT: patched file would not parse: {e}")
        return 3

    # sanity 2: helper appears exactly once?
    count = patched.count("def _default_max_attempts")
    print(f"helper occurrences: {count}")
    if count != 1:
        print("ABORT: expected exactly 1 helper definition.")
        return 4

    # show insertion region
    print("\n--- region: import + helper ---")
    print(region_around(patched, "def _default_max_attempts", before=6, after=10))

    print("\n--- region: argparse default ---")
    print(region_around(patched, "--max-attempts", before=1, after=1))

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
