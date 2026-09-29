#!/usr/bin/env python3
"""
harden_12_add_alias_map.py

Adds 3 missing PyPI->import aliases to scanners/reachability.py:
    pyopenssl   -> OpenSSL
    pysaml2     -> saml2
    python-jwt  -> python_jwt   (hyphen -> underscore)

DRY_RUN preview. ast.parse() validation. .bak backup. Refuses if anchor missing.
"""
from __future__ import annotations
import ast, shutil, sys
from pathlib import Path

DRY_RUN = False
TARGET = Path.cwd() / "scanners" / "reachability.py"

NEW_ENTRIES = '''    "pyopenssl": "OpenSSL",
    "pysaml2": "saml2",
    "python-jwt": "python_jwt",
'''
ANCHOR = '    "psycopg2-binary": "psycopg2",\n'


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print("ERROR: target not found."); return 1

    text = TARGET.read_text(encoding="utf-8")

    # Idempotency check
    if all(k in text for k in ('"pyopenssl"', '"pysaml2"', '"python-jwt"')):
        print("  [skip] all three aliases already present"); return 0

    if ANCHOR not in text:
        print(f"  [ABORT] anchor not found: {ANCHOR!r}")
        print("          the PYPI_TO_IMPORT_NAME dict may have been reordered.")
        return 2

    text = text.replace(ANCHOR, ANCHOR + NEW_ENTRIES, 1)
    print("  [ok] inserted 3 new alias entries after psycopg2-binary")

    try:
        ast.parse(text)
        print("ast.parse(): OK")
    except SyntaxError as e:
        print(f"ABORT: patched file would not parse: {e}"); return 3

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    bak = TARGET.with_suffix(".py.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    print(f"BACKUP : {bak}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
