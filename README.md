<div align="center">

# Enterprise Agentic Vulnerability Triage and Automated Remediation System

### **[ Autonomous Vulnerability Triage & Automated Patching Engine ]**
*AST Reachability | EPSS Threat Intel | Sandboxes | Self-Repair*

</div>

---

A local pipeline that filters unreachable CVEs via AST call-graphs, prioritizes vulnerabilities with live EPSS scores, drafts code fixes, and verifies them inside isolated environments before generating patches. Python/PyPI scope only.

## Core Modules

* **AST Call-Graph Reachability (`scanners/reachability.py`)**: Parses abstract syntax trees to determine if vulnerable third-party dependencies are actively invoked in execution paths, filtering out dead code.
* **Live EPSS Scoring (`scanners/prioritization.py`)**: Queries the official FIRST.org EPSS API in real time for exploit probabilities.
* **Sandbox Execution (`sandbox/sandbox_runner.py`)**: Isolates test execution to verify patches without side effects.
* **Self-Repair Loop**: Captures test error tracebacks upon failure and feeds them back into reflection loops to refine patch logic.

## Quick Start & Setup

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the pipeline:
   ```bash
   python3 run_pipeline.py sample_repo --mock sample_repo/vuln_scan_results.json --backend dry-run
   ```

4. Run unit tests:
   ```bash
   python3 -m pytest tests/ -v
   ```

## Limitations & Scope

* Designed as a single-repo, local developer tool and workflow automation utility.
* Does not replace comprehensive enterprise vulnerability scanners or guarantee full application security.
* Relies on local Python runtimes and temporary-directory sandboxes for verification.
