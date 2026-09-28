# Agentic Vulnerability Triage & Automated Patching System

A local, zero-cost pipeline that scans a repo for CVEs, filters out ones that
are never actually reached by your code, generates a minimal fix with an LLM
(local via Ollama, or a free-tier API), verifies the fix in an isolated
sandbox against your real test suite with a self-repair loop, then opens a
PR with a proof-of-execution report — plus a Streamlit dashboard for
metrics.

## Architecture

```
Step 1: Ingestion & Reachability   scanners/run_scan.py, scanners/reachability.py
Step 2: AST Code-Graph Context     scanners/code_graph.py
Step 3: LLM Patch Generation       agent/patch_generator.py
Step 4: Sandboxed TDD Self-Repair  sandbox/sandbox_runner.py
Step 5: PR Creation + Dashboard    agent/pr_creator.py, dashboard/dashboard.py

run_pipeline.py                   orchestrates all 5 steps in one command
```

## Setup

```bash
pip install -r requirements.txt --break-system-packages
```

Optional, for a real scan instead of `--mock`:
```bash
# https://github.com/google/osv-scanner
go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

Optional, for a local LLM backend instead of `--backend dry-run`:
```bash
# https://ollama.com
ollama pull deepseek-coder-v2
ollama serve
```

## Quick start (using the included sample repo)

The sample repo (`sample_repo/`) has two real, reachable CVEs (a PyYAML
unsafe-load and a `requests` header-leak) and one dead-code CVE (Jinja2,
imported but never called) to demonstrate the reachability filter.

```bash
# Full pipeline, one command, no LLM/network required:
python3 run_pipeline.py sample_repo \
    --mock sample_repo/vuln_scan_results.json \
    --backend dry-run

# View the dashboard:
streamlit run dashboard/dashboard.py -- --repo-path sample_repo
```

To actually push the branch and open a PR (requires a real git remote and,
optionally, the `gh` CLI authenticated):

```bash
python3 run_pipeline.py sample_repo --mock sample_repo/vuln_scan_results.json --push-pr
```

## Running against your own repo

```bash
# 1. Real scan with OSV-Scanner (writes <repo>/vuln_scan_results.json)
python3 scanners/run_scan.py /path/to/your/repo

# 2. Everything else, one command
python3 run_pipeline.py /path/to/your/repo --backend ollama --model deepseek-coder-v2
```

Or with a free-tier API:
```bash
python3 run_pipeline.py /path/to/your/repo --backend groq --api-key $GROQ_API_KEY
```

## Running steps individually (debugging / partial re-runs)

```bash
python3 -m scanners.reachability   <repo> <repo>/vuln_scan_results.json
python3 -m scanners.code_graph     <repo> <repo>/reachability_results.json
python3 -m agent.patch_generator   <repo>/code_contexts.json --backend dry-run --repo-root <repo>
python3 -m sandbox.sandbox_runner  <repo> <repo>/code_contexts.json --batch --backend dry-run
python3 -m agent.pr_creator        <repo> <repo>/remediation_results.json        # dry-run by default
python3 -m agent.pr_creator        <repo> <repo>/remediation_results.json --push # actually opens a PR
```

## Design notes / gotchas worth knowing

- **Reachability is a heuristic, not a proof.** It's a fast AST walk that
  checks "is this package imported and referenced anywhere," not a full
  taint/call-graph analysis. It's deliberately biased toward *not* filtering
  when unsure.
- **PyPI package names often differ from their import name**
  (`PyYAML` → `yaml`, `Pillow` → `PIL`). `scanners/reachability.py` has a
  lookup table (`PYPI_TO_IMPORT_NAME`) for the common mismatches; extend it
  if your scan results include a package not in that table.
- **Batch vs. per-CVE remediation.** `sandbox_runner.remediate()` tests each
  CVE's fix in its own isolated sandbox — good for tight verification, but a
  test suite with an unrelated pre-existing failure will make *every*
  isolated CVE fix look "failed," since that sandbox never sees any of the
  other fixes. `sandbox_runner.remediate_batch()` (used by `run_pipeline.py`
  and `--batch`) stacks all the reachable-CVE fixes into one sandbox and
  runs the suite once — closer to how you'd actually ship one PR.
- **Diffs never `.strip()` blindly.** Trailing blank lines inside a unified
  diff can be meaningful hunk context. Sanitizing LLM output (stripping
  markdown fences, leading commentary) only removes lines clearly outside
  the diff body — never touches diff content itself.
- **Nothing here force-pushes, merges, or touches `main`/`master` directly.**
  `pr_creator.py` always creates a new branch and defaults to `dry_run=True`
  (local branch + commit only, no push). You opt into `--push-pr` explicitly.
- **The dry-run LLM backend is deterministic**, built from real file content
  via `difflib`, specifically so Steps 4–5 are fully testable without any
  live model or network access. It only knows fix templates for PyYAML and
  `requests` in this repo — swap in `--backend ollama` or `--backend groq`
  for real coverage of arbitrary CVEs.

## File outputs (written into the target repo directory)

| File | Written by | Contents |
|---|---|---|
| `vuln_scan_results.json` | Step 1 (scan) | Raw normalized CVE list |
| `reachability_results.json` | Step 1 (filter) | Reachable vs. filtered CVEs |
| `code_contexts.json` | Step 2 | Per-CVE function context + call graph |
| `remediation_results.json` | Step 4 | Per-CVE diffs, apply/test results |

## Requirements

See `requirements.txt`. Core: `streamlit` (dashboard). Everything else
(`ast`, `difflib`, `subprocess`, `tempfile`, `urllib`) is Python stdlib —
`GitPython`/`gh` are optional; the code shells out to plain `git` and falls
back gracefully if `gh` isn't installed.
