#!/usr/bin/env python3
"""harden_10_readme_limitations.py - Append Limitations section to README.md."""

from __future__ import annotations
import shutil
import sys
from pathlib import Path

DRY_RUN = True
TARGET = Path.cwd() / "README.md"

LIMITATIONS = """## Limitations

- **Python only.** AST-based reachability parses Python sources; other
  languages are not analyzed.
- **Static analysis is incomplete by nature.** Dynamic imports,
  `importlib.import_module()`, `getattr()` dispatches, `eval()`, and
  reflection are not tracked. A CVE in code reachable only through
  these mechanisms may be filtered as "dead code."
- **LLM patches are non-deterministic.** The same CVE may receive a
  different patch on different runs, or between `--backend dry-run`
  and `--backend ollama`.
- **Sandbox is not hardened.** Patches and tests execute in a plain
  temp directory with the host's network and env vars. See
  `SECURITY.md` for the full threat model.
- **EPSS scoring coverage.** `scanners/prioritization.py` has test
  coverage (11 tests). `scanners/reachability.py` and
  `agent/patch_generator.py` HTTP paths do not yet.
- **Cross-CVE coupling.** Batch mode stacks patches into one sandbox;
  an unrelated failing test can mask a legitimate fix. This is
  documented in the "Hard-Won Engineering Lessons" section above.

"""


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)
    if not TARGET.exists():
        print("ERROR: README.md not found.")
        return 1
    text = TARGET.read_text(encoding="utf-8")
    if "## Limitations" in text:
        print("  [skip] Limitations section already present")
        return 0
    inserted = False
    for marker in ("## License\n", "## license\n", "# License\n", "## Citation\n"):
        if marker in text:
            text = text.replace(marker, LIMITATIONS + marker, 1)
            print(f"  [ok] inserted before: {marker.strip()!r}")
            inserted = True
            break
    if not inserted:
        if not text.endswith("\n"):
            text += "\n"
        text += "\n" + LIMITATIONS
        print("  [ok] appended at end (no License heading found)")
    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0
    bak = TARGET.with_suffix(".md.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}\nBACKUP : {bak}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
