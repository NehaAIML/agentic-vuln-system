#!/usr/bin/env python3
"""
harden_08b_fix_epss_tests.py

Fixes 2 test bugs in tests/test_prioritization.py:
  1. happy_path: drop query_param_matcher (too strict); match URL regex only
  2. timeout: responses.Timeout no longer exists -> use requests.exceptions.Timeout

DRY_RUN preview. .bak backup. ast.parse() validation.
"""

from __future__ import annotations

import ast
import shutil
import sys
from pathlib import Path

DRY_RUN = False

TARGET = Path.cwd() / "tests" / "test_prioritization.py"


FIXES = [
    # 1. Drop the query_param_matcher from happy_path test
    {
        "old": """    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        match=[matchers.query_param_matcher({"cve": "CVE-2020-14343"})],
        json={
            "status": "OK",
            "data": [{"cve": "CVE-2020-14343", "epss": "0.973"}],
        },
        status=200,
    )""",
        "new": """    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        json={
            "status": "OK",
            "data": [{"cve": "CVE-2020-14343", "epss": "0.973"}],
        },
        status=200,
    )""",
        "desc": "happy_path: removed query_param_matcher (match URL only)",
    },
    # 2. Remove now-unused matchers import
    {
        "old": "from responses import matchers\n",
        "new": "",
        "desc": "removed unused `from responses import matchers`",
    },
    # 3. Use requests.exceptions.Timeout instead of responses.Timeout
    {
        "old": """        body=responses.Timeout(),""",
        "new": """        body=__import__("requests").exceptions.Timeout("timed out"),""",
        "desc": "timeout test: responses.Timeout -> requests.exceptions.Timeout",
    },
]


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print(f"ERROR: {TARGET} not found.")
        return 1

    text = TARGET.read_text(encoding="utf-8")
    applied: list[str] = []

    for fix in FIXES:
        if fix["new"] and fix["new"] in text:
            applied.append(f"  [skip] {fix['desc']} (already applied)")
            continue
        if fix["old"] not in text:
            print(f"  [ABORT] anchor not found: {fix['desc']}")
            print(f"          expected to find: {fix['old'][:60]!r}")
            return 2
        text = text.replace(fix["old"], fix["new"], 1)
        applied.append(f"  [ok]   {fix['desc']}")

    print("Planned changes:")
    for line in applied:
        print(line)

    try:
        ast.parse(text)
        print("\nast.parse(): OK")
    except SyntaxError as e:
        print(f"\nABORT: patched file would not parse: {e}")
        return 3

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    bak = TARGET.with_suffix(".py.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    print(f"BACKUP : {bak}")
    print("\nNext:")
    print("  pytest tests/test_prioritization.py -v   # expect 11 passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
