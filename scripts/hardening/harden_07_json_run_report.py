#!/usr/bin/env python3
"""
harden_07_json_run_report.py

Wires a structured run_report.json into run_pipeline.py.

Adds:
  * `import time` at top
  * `--report <path>` CLI flag (default: <repo>/run_report.json)
  * a small RunReport helper class
  * timing + stage tracking around each existing step
  * final write at the end of main()

Preserves all existing outputs. DRY_RUN preview. ast.parse() validation.
"""

from __future__ import annotations

import ast
import shutil
import sys
from pathlib import Path

DRY_RUN = False

REPO_ROOT = Path.cwd()
TARGET = REPO_ROOT / "run_pipeline.py"

# ---------------------------------------------------------------------------
# Insertions
# ---------------------------------------------------------------------------

IMPORT_ANCHOR = "import argparse\nimport json\nimport sys\nfrom pathlib import Path\n"
NEW_IMPORTS = (
    "import argparse\n"
    "import json\n"
    "import sys\n"
    "import time\n"
    "from datetime import datetime, timezone\n"
    "from pathlib import Path\n"
)

REPORT_HELPER = '''

class RunReport:
    """Collects timing + stage summaries for a single pipeline run."""

    def __init__(self, repo_path: str, backend: str, model: str | None) -> None:
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.t0 = time.monotonic()
        self.data: dict = {
            "started_at": self.started_at,
            "repo_path": repo_path,
            "backend": backend,
            "model": model,
            "stages": {},
            "success": False,
        }

    def stage(self, name: str, **fields: object) -> None:
        """Record a stage outcome. Adds elapsed seconds since run start."""
        self.data["stages"][name] = {
            "elapsed_seconds": round(time.monotonic() - self.t0, 3),
            **fields,
        }

    def finish(self, success: bool) -> dict:
        self.data["success"] = success
        self.data["duration_seconds"] = round(time.monotonic() - self.t0, 3)
        self.data["finished_at"] = datetime.now(timezone.utc).isoformat()
        return self.data

'''

ARG_ANCHOR = '    parser.add_argument("--base-branch", default="main")\n'
NEW_ARG = (
    '    parser.add_argument("--base-branch", default="main")\n'
    "    parser.add_argument(\n"
    '        "--report",\n'
    "        default=None,\n"
    '        help="Path to write the JSON run report (default: <repo>/run_report.json)",\n'
    "    )\n"
)

INIT_ANCHOR = "    repo_path = Path(args.repo_path)\n"
NEW_INIT = (
    "    repo_path = Path(args.repo_path)\n"
    "    report = RunReport(str(repo_path), args.backend, args.model)\n"
)

# Stage 1 instrumentation
S1_ANCHOR = "    reach_result = reachability.filter_vulnerabilities(vulns, str(repo_path))\n"
NEW_S1 = (
    "    reach_result = reachability.filter_vulnerabilities(vulns, str(repo_path))\n"
    "    report.stage(\n"
    '        "reachability",\n'
    "        raw_vulns=len(vulns),\n"
    '        reachable=len(reach_result["reachable"]),\n'
    '        filtered=len(reach_result["filtered"]),\n'
    "    )\n"
)

# Step 1 early-exit hook (no reachable vulns)
EARLY_EXIT_ANCHOR = (
    '        print("\\nNo reachable/actionable vulnerabilities found. Nothing to patch. Exiting.")\n'
    "        return\n"
)
NEW_EARLY_EXIT = (
    '        print("\\nNo reachable/actionable vulnerabilities found. Nothing to patch. Exiting.")\n'
    "        _write_report(report, repo_path, args.report, success=True)\n"
    "        return\n"
)

# Stage 2 instrumentation
S2_ANCHOR = (
    "    contexts = code_graph.build_contexts_for_reachable_vulns(str(repo_path), str(reach_out))\n"
)
NEW_S2 = (
    "    contexts = code_graph.build_contexts_for_reachable_vulns(str(repo_path), str(reach_out))\n"
    '    report.stage("contexts", bundles=len(contexts))\n'
)

# Stage 3+4 instrumentation
S34_ANCHOR = "    print(f\"Batch remediation success: {batch_result['success']}\")\n"
NEW_S34 = (
    "    print(f\"Batch remediation success: {batch_result['success']}\")\n"
    "    report.stage(\n"
    '        "remediation",\n'
    '        patches_applied=sum(1 for p in batch_result["patches"] if p["applied"]),\n'
    '        total_patches=len(batch_result["patches"]),\n'
    '        tests_passed=batch_result["tests_passed"],\n'
    '        batch_success=batch_result["success"],\n'
    "    )\n"
)

# Remediation-failure early exit
REM_FAIL_ANCHOR = (
    "        print(\n"
    '            "\\nBatch remediation did not fully succeed — stopping before PR creation. "\n'
    '            "See remediation_results.json for details (diffs + test output)."\n'
    "        )\n"
    "        return\n"
)
NEW_REM_FAIL = (
    "        print(\n"
    '            "\\nBatch remediation did not fully succeed — stopping before PR creation. "\n'
    '            "See remediation_results.json for details (diffs + test output)."\n'
    "        )\n"
    "        _write_report(report, repo_path, args.report, success=False)\n"
    "        return\n"
)

# Stage 5 instrumentation
S5_ANCHOR = '    print(json.dumps({k: v for k, v in pr_result.items() if k != "body"}, indent=2))\n'
NEW_S5 = (
    '    print(json.dumps({k: v for k, v in pr_result.items() if k != "body"}, indent=2))\n'
    '    report.stage("pr", dry_run=not args.push_pr, ok=bool(pr_result.get("ok", True)))\n'
)

# Final write before the closing "Done" print
FINAL_ANCHOR = '    print("\\nDone. Run the dashboard to view metrics:")\n'
NEW_FINAL = (
    "    _write_report(report, repo_path, args.report, success=True)\n"
    '    print("\\nDone. Run the dashboard to view metrics:")\n'
)

# Helper function to write the report (inserted before `def main()`)
WRITE_HELPER = '''

def _write_report(report: "RunReport", repo_path: Path, report_path: str | None,
                  success: bool) -> None:
    """Write the JSON run report to disk and echo the path."""
    payload = report.finish(success)
    out = Path(report_path) if report_path else (repo_path / "run_report.json")
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\\nRun report written to: {out}")

'''


def apply_patch(text: str) -> tuple[str, list[str]]:
    notes: list[str] = []

    # 1. imports
    if IMPORT_ANCHOR in text:
        text = text.replace(IMPORT_ANCHOR, NEW_IMPORTS, 1)
        notes.append("added `import time`, `datetime`, `timezone`")
    elif "import time\n" in text and "from datetime import datetime, timezone\n" in text:
        notes.append("imports already present (skipped)")
    else:
        raise RuntimeError("import block anchor not found")

    # 2. RunReport class (before def main)
    if "class RunReport" in text:
        notes.append("RunReport class already present (skipped)")
    else:
        anchor = "def main():"
        if anchor not in text:
            raise RuntimeError("`def main():` not found")
        text = text.replace(anchor, REPORT_HELPER.lstrip("\n") + "\n" + anchor, 1)
        notes.append("inserted RunReport class")

    # 3. _write_report helper (after RunReport, before main)
    if "_write_report" in text and "def _write_report" in text:
        notes.append("_write_report helper already present (skipped)")
    else:
        anchor = "def main():"
        text = text.replace(anchor, WRITE_HELPER.strip("\n") + "\n\n\n" + anchor, 1)
        notes.append("inserted _write_report helper")

    # 4. --report arg
    if '"--report"' in text:
        notes.append("--report arg already present (skipped)")
    else:
        if ARG_ANCHOR not in text:
            raise RuntimeError("--base-branch anchor not found")
        text = text.replace(ARG_ANCHOR, NEW_ARG, 1)
        notes.append("added --report CLI flag")

    # 5. init report after repo_path
    if "report = RunReport(" in text:
        notes.append("RunReport instantiation already present (skipped)")
    else:
        if INIT_ANCHOR not in text:
            raise RuntimeError("repo_path = Path(...) anchor not found")
        text = text.replace(INIT_ANCHOR, NEW_INIT, 1)
        notes.append("instantiated RunReport after repo_path")

    # 6. Stage 1
    if 'report.stage(\n        "reachability"' in text or 'report.stage("reachability"' in text:
        notes.append("stage:reachability already recorded (skipped)")
    else:
        if S1_ANCHOR not in text:
            raise RuntimeError("reachability filter anchor not found")
        text = text.replace(S1_ANCHOR, NEW_S1, 1)
        notes.append("recorded stage: reachability")

    # 7. Early exit (no reachable vulns)
    if "_write_report(report, repo_path, args.report, success=True)" in text:
        notes.append("early exit report already wired (skipped)")
    else:
        if EARLY_EXIT_ANCHOR not in text:
            raise RuntimeError("reachability early-exit anchor not found")
        text = text.replace(EARLY_EXIT_ANCHOR, NEW_EARLY_EXIT, 1)
        notes.append("wired early exit (no reachable) to write report")

    # 8. Stage 2
    if 'report.stage("contexts"' in text:
        notes.append("stage:contexts already recorded (skipped)")
    else:
        if S2_ANCHOR not in text:
            raise RuntimeError("contexts build anchor not found")
        text = text.replace(S2_ANCHOR, NEW_S2, 1)
        notes.append("recorded stage: contexts")

    # 9. Stage 3+4
    if 'report.stage(\n        "remediation"' in text or 'report.stage("remediation"' in text:
        notes.append("stage:remediation already recorded (skipped)")
    else:
        if S34_ANCHOR not in text:
            raise RuntimeError("batch remediation anchor not found")
        text = text.replace(S34_ANCHOR, NEW_S34, 1)
        notes.append("recorded stage: remediation")

    # 10. Remediation-failure early exit
    if "_write_report(report, repo_path, args.report, success=False)" in text:
        notes.append("remediation-failure exit report already wired (skipped)")
    else:
        if REM_FAIL_ANCHOR not in text:
            raise RuntimeError("remediation-failure anchor not found")
        text = text.replace(REM_FAIL_ANCHOR, NEW_REM_FAIL, 1)
        notes.append("wired remediation-failure exit to write report")

    # 11. Stage 5
    if 'report.stage("pr"' in text:
        notes.append("stage:pr already recorded (skipped)")
    else:
        if S5_ANCHOR not in text:
            raise RuntimeError("PR result print anchor not found")
        text = text.replace(S5_ANCHOR, NEW_S5, 1)
        notes.append("recorded stage: pr")

    # 12. Final write
    if FINAL_ANCHOR in text:
        text = text.replace(FINAL_ANCHOR, NEW_FINAL, 1)
        notes.append("wired final report write before 'Done' print")
    elif "_write_report(report, repo_path, args.report, success=True)\n" in text:
        notes.append("final report write already present (skipped)")
    else:
        raise RuntimeError("final 'Done' print anchor not found")

    return text, notes


def main() -> int:
    print(f"Target    : {TARGET}")
    print(f"DRY_RUN   : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print(f"ERROR: {TARGET} not found. Run from repo root.")
        return 1

    original = TARGET.read_text(encoding="utf-8")
    try:
        patched, notes = apply_patch(original)
    except RuntimeError as e:
        print(f"ABORT: {e}")
        print("Nothing was written.")
        return 2

    print("\nPlanned changes:")
    for n in notes:
        print(f"  + {n}")

    try:
        ast.parse(patched)
        print("\nast.parse(): OK")
    except SyntaxError as e:
        print(f"\nABORT: patched file would not parse: {e}")
        return 3

    # Sanity: report-related symbols appear the right number of times
    checks = {
        "class RunReport": patched.count("class RunReport"),
        "def _write_report": patched.count("def _write_report"),
        "RunReport(": patched.count("RunReport("),
        "report.stage(": patched.count("report.stage("),
    }
    print("\nSanity counts:")
    for k, v in checks.items():
        print(f"  {k:22} {v}")
    if checks["class RunReport"] != 1 or checks["def _write_report"] != 1:
        print("ABORT: expected exactly 1 RunReport class and 1 _write_report helper.")
        return 4

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        print("Set DRY_RUN = False and run again to apply.")
        return 0

    bak = TARGET.with_suffix(".py.bak")
    shutil.copy2(TARGET, bak)
    TARGET.write_text(patched, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    print(f"BACKUP : {bak}")
    print("\nNext:")
    print(
        "  python run_pipeline.py sample_repo --mock sample_repo/vuln_scan_results.json --backend dry-run"
    )
    print("  cat sample_repo/run_report.json")
    print(
        '  git add -A && git commit -m "feat(pipeline): write structured run_report.json per run"'
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
