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
from pathlib import Path

from scanners import reachability, code_graph
from sandbox import sandbox_runner
from agent import pr_creator


def main():
    parser = argparse.ArgumentParser(description="Agentic Vulnerability Triage & Auto-Patching pipeline")
    parser.add_argument("repo_path", help="Path to the target repository")
    parser.add_argument("--mock", help="Path to a pre-existing normalized scan results JSON "
                                        "(use this if osv-scanner isn't installed)")
    parser.add_argument("--backend", default="dry-run", choices=["dry-run", "ollama", "groq"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--push-pr", action="store_true",
                         help="Actually push branch + open PR via `gh`. Default: local dry-run only.")
    parser.add_argument("--base-branch", default="main")
    args = parser.parse_args()

    repo_path = Path(args.repo_path)

    # ---------- Step 1 ----------
    print("=" * 70)
    print("STEP 1: Vulnerability Ingestion & Reachability Analysis")
    print("=" * 70)
    scan_results_path = args.mock or (repo_path / "vuln_scan_results.json")
    with open(scan_results_path) as f:
        vulns = json.load(f)
    print(f"Loaded {len(vulns)} raw vulnerability record(s) from {scan_results_path}")

    reach_result = reachability.filter_vulnerabilities(vulns, str(repo_path))
    print(f"Reachable (actionable): {len(reach_result['reachable'])}")
    print(f"Filtered (dead code):   {len(reach_result['filtered'])}")
    reach_out = repo_path / "reachability_results.json"
    with open(reach_out, "w") as f:
        json.dump(reach_result, f, indent=2)

    if not reach_result["reachable"]:
        print("\nNo reachable/actionable vulnerabilities found. Nothing to patch. Exiting.")
        return

    # ---------- Step 2 ----------
    print("\n" + "=" * 70)
    print("STEP 2: Context-Aware Code Retrieval & AST Mapping")
    print("=" * 70)
    contexts = code_graph.build_contexts_for_reachable_vulns(str(repo_path), str(reach_out))
    print(f"Built {len(contexts)} context bundle(s)")
    contexts_out = repo_path / "code_contexts.json"
    with open(contexts_out, "w") as f:
        json.dump(contexts, f, indent=2)

    # ---------- Step 3 + 4 ----------
    print("\n" + "=" * 70)
    print("STEP 3+4: LLM Patch Generation + Sandboxed TDD Self-Repair Loop")
    print("=" * 70)
    batch_result = sandbox_runner.remediate_batch(
        str(repo_path), contexts, backend=args.backend, model=args.model,
        api_key=args.api_key, max_attempts=args.max_attempts,
    )
    for p in batch_result["patches"]:
        print(f"  {p['vuln_id']} ({p['package']}): applied={p['applied']}")
    print(f"Tests passed (full suite, all patches stacked): {batch_result['tests_passed']}")
    print(f"Batch remediation success: {batch_result['success']}")
    remediation_out = repo_path / "remediation_results.json"
    with open(remediation_out, "w") as f:
        json.dump(batch_result, f, indent=2)

    if not batch_result["success"]:
        print("\nBatch remediation did not fully succeed — stopping before PR creation. "
              "See remediation_results.json for details (diffs + test output).")
        return

    # ---------- Step 5 ----------
    print("\n" + "=" * 70)
    print("STEP 5: Automated PR Creation & Proof-of-Execution")
    print("=" * 70)
    pr_result = pr_creator.create_pr_for_batch(
        str(repo_path), batch_result, base_branch=args.base_branch, dry_run=not args.push_pr,
    )
    print(json.dumps({k: v for k, v in pr_result.items() if k != "body"}, indent=2))

    print("\nDone. Run the dashboard to view metrics:")
    print(f"  streamlit run dashboard/dashboard.py -- --repo-path {repo_path}")


if __name__ == "__main__":
    sys.exit(main())
