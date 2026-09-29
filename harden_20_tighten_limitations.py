#!/usr/bin/env python3
"""Replaces the ## Limitations section with a tighter, mitigation-focused version."""
from pathlib import Path
import re, shutil, sys

DRY_RUN = False
TARGET = Path.cwd() / "README.md"

NEW_SECTION = '''## Limitations

- **Python only.** Reachability analysis runs on Python source. CVEs in
  non-Python dependencies of a Python project are surfaced, not filtered.
- **Static analysis misses dynamic code.** `importlib.import_module()`,
  `__import__`, `getattr()` dispatch, and `eval()` are not tracked. A CVE
  reachable only through these mechanisms may be filtered as dead code.
  *Mitigation:* the benchmark (`benchmarks/README.md`) is a regression
  test for this class of failure; any new false filter reduces recall.
- **Sandbox is not a security boundary.** Patches and tests run in a
  plain temp directory with the host's network and environment inherited.
  Do not run against untrusted repos with production credentials present.
  *Mitigation:* documented in `SECURITY.md`; wrap in a container for
  untrusted input.
- **Cross-CVE test coupling.** Batch mode stacks patches in one sandbox;
  an unrelated failing test can mask a legitimate fix. *Mitigation:*
  single-CVE mode is available; the coupling is documented in
  "Hard-Won Engineering Lessons" above.

'''


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print("ERROR: README.md not found."); return 1

    text = TARGET.read_text(encoding="utf-8")

    # Match "## Limitations\n...up to next ## heading"
    pat = re.compile(r"## Limitations\n.*?(?=\n## )", re.DOTALL)
    m = pat.search(text)
    if not m:
        print("ERROR: '## Limitations' section not found."); return 2

    old_section = m.group(0)
    print(f"Old section: {len(old_section)} chars, {old_section.count(chr(10))} lines")
    print(f"New section: {len(NEW_SECTION)} chars, {NEW_SECTION.count(chr(10))} lines")

    new_text = text[:m.start()] + NEW_SECTION + text[m.end():]

    if new_text == text:
        print("No change."); return 0

    if DRY_RUN:
        print("\n--- NEW SECTION PREVIEW ---")
        for ln in NEW_SECTION.splitlines():
            print(f"  {ln}")
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    shutil.copy2(TARGET, TARGET.with_suffix(".md.bak3"))
    TARGET.write_text(new_text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
