#!/usr/bin/env python3
"""Adds a tests badge + Tests section to README.md."""
from pathlib import Path
import re, shutil

DRY_RUN = False
TARGET = Path.cwd() / "README.md"

BADGE = "[![Tests](https://img.shields.io/badge/tests-11%20passing-brightgreen)](#tests)"

TESTS_SECTION = """## Tests

Run the test suite:

    pytest -v

**11 tests** currently cover `scanners/prioritization.py` (EPSS scoring
and priority decision), using `responses` to mock the FIRST.org API.
No live network calls.

Reachability filter accuracy is benchmarked separately — see
[`benchmarks/README.md`](benchmarks/README.md).

"""


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print("ERROR: README.md not found."); return 1

    text = TARGET.read_text(encoding="utf-8")
    changes = []

    # 1. Insert badge after the first H1 line
    if BADGE in text:
        changes.append("badge: already present")
    else:
        m = re.search(r"^(#\s+.+)\n", text, re.MULTILINE)
        if not m:
            print("ERROR: no H1 found to anchor badge."); return 2
        h1_end = m.end()
        # ensure a blank line follows
        text = text[:h1_end] + "\n" + BADGE + "\n" + text[h1_end:]
        changes.append("badge: inserted after H1")

    # 2. Append Tests section if missing
    if "\n## Tests\n" in text or text.startswith("## Tests\n"):
        changes.append("Tests section: already present")
    else:
        if not text.endswith("\n"):
            text += "\n"
        text += "\n" + TESTS_SECTION
        changes.append("Tests section: appended")

    print("\nPlanned changes:")
    for c in changes:
        print(f"  + {c}")

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    shutil.copy2(TARGET, TARGET.with_suffix(".md.bak"))
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
