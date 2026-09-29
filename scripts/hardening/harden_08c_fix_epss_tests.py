#!/usr/bin/env python3
"""
harden_08c_fix_epss_tests.py

Replaces the regex URL matching in tests/test_prioritization.py with an
exact-URL helper, so `responses` correctly matches query strings.

Changes:
  1. Remove EPSS_URL_RE constant
  2. Add  _epss_url(cve)  helper that returns the exact URL
  3. Replace each  url=EPSS_URL_RE  with  url=_epss_url("CVE-xxxx")  using
     the same CVE that the test calls get_epss_score() with.

DRY_RUN preview. .bak backup. ast.parse() validation.
"""

from __future__ import annotations

import ast
import re
import shutil
import sys
from pathlib import Path

DRY_RUN = False

TARGET = Path.cwd() / "tests" / "test_prioritization.py"


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print("ERROR: test file not found.")
        return 1

    text = TARGET.read_text(encoding="utf-8")
    original = text
    notes: list[str] = []

    # 1) Replace the constant line with a helper
    old_const = 'EPSS_URL_RE = r"https://api\\.first\\.org/data/v1/epss.*"\n'
    if old_const in text:
        new_helper = (
            "def _epss_url(cve: str) -> str:\n"
            '    """Exact URL that prioritization.get_epss_score() builds."""\n'
            '    return f"https://api.first.org/data/v1/epss?cve={cve}"\n'
        )
        text = text.replace(old_const, new_helper, 1)
        notes.append("replaced EPSS_URL_RE constant with _epss_url() helper")
    elif "_epss_url" in text:
        notes.append("_epss_url helper already present (skipped)")
    else:
        print("  [ABORT] constant anchor not found")
        return 2

    # 2) Replace each `url=EPSS_URL_RE,` with a call using the CVE the test uses.
    #    Strategy: for each occurrence, look forward to find get_epss_score("CVE-...")
    #    in the same test function. Fall back to the first CVE found in the test.
    lines = text.splitlines(keepends=True)
    out_lines: list[str] = []
    replaced = 0
    for i, line in enumerate(lines):
        if "url=EPSS_URL_RE," in line:
            # scan ahead up to 30 lines for a get_epss_score("CVE-...") call
            cve = None
            for j in range(i, min(i + 30, len(lines))):
                m = re.search(r'get_epss_score\(\s*"([^"]+)"', lines[j])
                if m:
                    cve = m.group(1)
                    break
            if cve is None:
                # fall back: look backward
                for j in range(i, max(0, i - 30), -1):
                    m = re.search(r'get_epss_score\(\s*"([^"]+)"', lines[j])
                    if m:
                        cve = m.group(1)
                        break
            if cve is None:
                print(f"  [ABORT] could not determine CVE for line {i+1}")
                return 3
            indent = line[: len(line) - len(line.lstrip())]
            new_line = f'{indent}url=_epss_url("{cve}"),\n'
            out_lines.append(new_line)
            replaced += 1
        else:
            out_lines.append(line)

    text = "".join(out_lines)
    notes.append(f"replaced {replaced} url=EPSS_URL_RE -> url=_epss_url(...)")

    print("\nPlanned changes:")
    for n in notes:
        print(f"  + {n}")

    if text == original:
        print("\nNo changes made.")
        return 0

    try:
        ast.parse(text)
        print("\nast.parse(): OK")
    except SyntaxError as e:
        print(f"\nABORT: patched file would not parse: {e}")
        return 4

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    bak = TARGET.with_suffix(".py.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    print(f"BACKUP : {bak}")
    print("\nNext:")
    print("  pytest tests/test_prioritization.py -v    # expect 11 passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
