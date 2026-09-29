#!/usr/bin/env python3
"""harden_11_readme_dashboard.py - Append Dashboard section to README.md."""
from __future__ import annotations
import shutil, sys
from pathlib import Path

DRY_RUN = False
TARGET = Path.cwd() / "README.md"

DASHBOARD = """## Dashboard

A lightweight Streamlit app visualizes the pipeline's output artifacts
from a completed run.

### Prerequisites

~~~bash
pip install -r requirements-dashboard.txt
~~~

### Launch

After running the pipeline, launch the dashboard against the same repo:

~~~bash
streamlit run dashboard/dashboard.py -- --repo-path sample_repo
~~~

The `--repo-path` argument tells the dashboard where to find the run
artifacts. You can also set it interactively from the sidebar.

### What it shows

- Total CVEs detected
- Reachable vs. filtered (dead-code noise reduction)
- Successfully auto-patched count
- Per-CVE attempt counts (from the self-repair loop)
- Mean Time to Remediate (MTTR), derived from attempt durations
  recorded by `sandbox/sandbox_runner.py`

### Input files

The dashboard reads these files from the target repo directory:

| File | Written by | Contents |
|------|-----------|----------|
| `vuln_scan_results.json` | Step 1 (scan or `--mock`) | Raw normalized scan results |
| `reachability_results.json` | Step 1 | Reachable vs. filtered CVEs |
| `code_contexts.json` | Step 2 | AST context bundles |
| `remediation_results.json` | Step 4 | Patch attempts + test outcomes |
| `run_report.json` | Pipeline end | Structured run summary |

"""


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)
    if not TARGET.exists():
        print("ERROR: README.md not found."); return 1
    text = TARGET.read_text(encoding="utf-8")
    if "\n## Dashboard\n" in text or text.startswith("## Dashboard\n"):
        print("  [skip] Dashboard section already present"); return 0
    if not text.endswith("\n"):
        text += "\n"
    text += "\n" + DASHBOARD
    print("  [ok] appended Dashboard at end of README")
    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written."); return 0
    bak = TARGET.with_suffix(".md.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}\nBACKUP : {bak}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
