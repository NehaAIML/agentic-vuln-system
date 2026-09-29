#!/usr/bin/env python3
"""Adds a '## Benchmark' section to README.md."""
from pathlib import Path
import shutil

DRY_RUN = False
TARGET = Path.cwd() / "README.md"

SECTION = """## Benchmark

Reachability filtering was measured against a purpose-built fixture with
35 documented CVEs. Under strict scoring (direct imports only):

- **Precision: 100%**
- **Recall: 100%**
- **Accuracy: 100%**

Under loose scoring (including transitively-reachable dependencies):
Precision 100%, Recall 83%, Accuracy 89%. The 4 misses are Jinja2,
Werkzeug, certifi, and idna -- reachable only via Flask and requests, and
therefore undetectable by a pure static import scan.

Full methodology, ground truth, and reproduction steps:
**[`benchmarks/README.md`](benchmarks/README.md)**

"""


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)
    if not TARGET.exists():
        print("ERROR: README.md not found."); return 1
    text = TARGET.read_text(encoding="utf-8")
    if "\n## Benchmark\n" in text:
        print("  [skip] Benchmark section already present"); return 0
    if not text.endswith("\n"):
        text += "\n"
    text += "\n" + SECTION
    print("  [ok] appended Benchmark section at end of README")
    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written."); return 0
    shutil.copy2(TARGET, TARGET.with_suffix(".md.bak"))
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
