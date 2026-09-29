"""
run_pipeline.py
---------------
Orchestrates the full pipeline end-to-end against a target repo:

  Step 1: scan (or --mock) -> reachability filter
  Step 2: AST code-graph context extraction
  Step 3+4: LLM patch generation inside the sandboxed TDD self-repair loop
            (batch mode: one sandbox, all reachable CVEs, one test run)
  Step 5: PR creation (dry-run by default) + Proof-of-Execution report

Usage:
    python3 run_pipeline.py sample_repo --mock sample_repo/vuln_scan_results.json --backend dry-run

This is the "single button" entrypoint; each step's module can also be run
standalone (see README.md) for debugging or partial re-runs.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from scanners import reachability, code_graph
from sandbox import sandbox_runner
from agent import pr_creator


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


def _write_report(
    report: "RunReport", repo_path: Path, report_path: str | None, success: bool
) -> None:
    """Write the JSON run report to disk and echo the path."""
    payload = report.finish(success)
    out = Path(report_path) if report_path else (repo_path / "run_report.json")
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nRun report written to: {out}")


def main():
    parser = argparse.ArgumentParser(
        description="Agentic Vulnerability Triage & Auto-Patching pipeline"
    )
    parser.add_argument("repo_path", help="Path to the target repository")
    parser.add_argument(
        "--mock",
        help="Path to a pre-existing normalized scan results JSON "
        "(use this if osv-scanner isn't installed)",
    )
    parser.add_argument("--backend", default="dry-run", choices=["dry-run", "ollama", "groq"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument(
        "--push-pr",
        action="store_true",
        help="Actually push branch + open PR via `gh`. Default: local dry-run only.",
    )
    parser.add_argument("--base-branch", default="main")
    parser.add_argument(
        "--report",
        default=None,
        help="Path to write the JSON run report (default: <repo>/run_report.json)",
    )
    args = parser.parse_args()

    repo_path = Path(args.repo_path)
    report = RunReport(str(repo_path), args.backend, args.model)

    # ---------- Step 1 ----------
    print("=" * 70)
    print("STEP 1: Vulnerability Ingestion & Reachability Analysis")
    print("=" * 70)
    scan_results_path = args.mock or (repo_path / "vuln_scan_results.json")
    with open(scan_results_path) as f:
        vulns = json.load(f)
    print(f"Loaded {len(vulns)} raw vulnerability record(s) from {scan_results_path}")

    reach_result = reachability.filter_vulnerabilities(vulns, str(repo_path))
    report.stage(
        "reachability",
        raw_vulns=len(vulns),
        reachable=len(reach_result["reachable"]),
        filtered=len(reach_result["filtered"]),
    )
    print(f"Reachable (actionable): {len(reach_result['reachable'])}")
    print(f"Filtered (dead code):   {len(reach_result['filtered'])}")
    reach_out = repo_path / "reachability_results.json"
    with open(reach_out, "w") as f:
        json.dump(reach_result, f, indent=2)

    if not reach_result["reachable"]:
        print("\nNo reachable/actionable vulnerabilities found. Nothing to patch. Exiting.")
        _write_report(report, repo_path, args.report, success=True)
        return

    # ---------- Step 2 ----------
    print("\n" + "=" * 70)
    print("STEP 2: Context-Aware Code Retrieval & AST Mapping")
    print("=" * 70)
    contexts = code_graph.build_contexts_for_reachable_vulns(str(repo_path), str(reach_out))
    report.stage("contexts", bundles=len(contexts))
    print(f"Built {len(contexts)} context bundle(s)")
    contexts_out = repo_path / "code_contexts.json"
    with open(contexts_out, "w") as f:
        json.dump(contexts, f, indent=2)

    # ---------- Step 3 + 4 ----------
    print("\n" + "=" * 70)
    print("STEP 3+4: LLM Patch Generation + Sandboxed TDD Self-Repair Loop")
    print("=" * 70)
    batch_result = sandbox_runner.remediate_batch(
        str(repo_path),
        contexts,
        backend=args.backend,
        model=args.model,
        api_key=args.api_key,
        max_attempts=args.max_attempts,
    )
    for p in batch_result["patches"]:
        print(f"  {p['vuln_id']} ({p['package']}): applied={p['applied']}")
    print(f"Tests passed (full suite, all patches stacked): {batch_result['tests_passed']}")
    print(f"Batch remediation success: {batch_result['success']}")
    report.stage(
        "remediation",
        patches_applied=sum(1 for p in batch_result["patches"] if p["applied"]),
        total_patches=len(batch_result["patches"]),
        tests_passed=batch_result["tests_passed"],
        batch_success=batch_result["success"],
    )
    remediation_out = repo_path / "remediation_results.json"
    with open(remediation_out, "w") as f:
        json.dump(batch_result, f, indent=2)

    if not batch_result["success"]:
        print(
            "\nBatch remediation did not fully succeed — stopping before PR creation. "
            "See remediation_results.json for details (diffs + test output)."
        )
        _write_report(report, repo_path, args.report, success=False)
        return

    # ---------- Step 5 ----------
    print("\n" + "=" * 70)
    print("STEP 5: Automated PR Creation & Proof-of-Execution")
    print("=" * 70)
    pr_result = pr_creator.create_pr_for_batch(
        str(repo_path),
        batch_result,
        base_branch=args.base_branch,
        dry_run=not args.push_pr,
    )
    print(json.dumps({k: v for k, v in pr_result.items() if k != "body"}, indent=2))
    report.stage("pr", dry_run=not args.push_pr, ok=bool(pr_result.get("ok", True)))

    _write_report(report, repo_path, args.report, success=True)
    print("\nDone. Run the dashboard to view metrics:")
    print(f"  streamlit run dashboard/dashboard.py -- --repo-path {repo_path}")


if __name__ == "__main__":
    sys.exit(main())
