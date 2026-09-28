<div align=center>

# Enterprise Agentic Vulnerability Triage and Automated Remediation System

### **[ Autonomous Vulnerability Triage & Automated Patching Engine ]**
*AST Reachability | EPSS Threat Intel | Sandboxes | Self-Repair*

</div>

---

## Executive Technical Specification

### Strategic Overview
This system provides an autonomous pipeline designed to mitigate the bottleneck of software vulnerability management. By moving beyond naive static alerts, the architecture combines abstract syntax tree (AST) call-graph reachability analysis with real-time threat intelligence and sandboxed self-repair loops. The objective is to drastically reduce Mean Time to Remediation (MTTR) for Python-based enterprise services while eliminating false positives and deployment regressions.

### Core Architectural Modules
* **AST Call-Graph Reachability Engine (`scanners/reachability.py`)**: Parses abstract syntax trees to build precise call graphs, filtering out vulnerable dependencies that exist in packaging manifests but are never invoked in active execution paths.
* **Live EPSS Threat Scoring (`scanners/prioritization.py`)**: Integrates directly with the official FIRST.org Exploit Prediction Scoring System (EPSS) API in real time to prioritize vulnerabilities based on active exploit probability rather than static CVSS severity alone.
* **Isolated Sandbox Execution (`sandbox/sandbox_runner.py`)**: Executes generated patches within secure, isolated environments to verify code correctness and prevent unintended side effects before human or automated sign-off.
* **Agentic Self-Repair Loop**: Captures test error tracebacks upon failure and feeds them back into iterative reflection loops to automatically refine patch syntax and logic until verification passes.

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

## Technical Notes & Publication Scope

* **Template vs. LLM Backend Status**: The default `--backend dry-run` generates patches from deterministic templates covering PyYAML and requests. While Ollama and Groq backends are fully implemented, live model execution should be verified prior to production LLM-generated patch deployments.
* **Sandbox Architecture**: Patch verification executes within isolated temporary-directory sandboxes (`sandbox/sandbox_runner.py`) rather than Docker containers, providing secure and lightweight isolation without container daemon dependencies.
* **Threat Intel & Scope Boundaries**: Vulnerability prioritization leverages real-time queries to the official FIRST.org EPSS API, combined with AST call-graph reachability (`scanners/reachability.py`) strictly scoped to Python and PyPI ecosystem dependencies.
