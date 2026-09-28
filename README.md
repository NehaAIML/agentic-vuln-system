# Agentic Vulnerability Triage and Automated Patching System

A local pipeline that filters unreachable CVEs via AST call-graphs, prioritizes vulnerabilities with live EPSS scores, drafts code fixes, and verifies them inside isolated environments before proposing them. Python/PyPI scope only.

## Core Modules

* **AST Call-Graph Reachability (`scanners/reachability.py`)**: Parses abstract syntax trees to determine if vulnerable third-party dependencies are actively invoked in execution paths, filtering out dead code.
* **Live EPSS Scoring (`scanners/prioritization.py`)**: Queries the official FIRST.org EPSS API in real time for exploit probabilities.
* **Sandbox Execution (`sandbox/docker_sandbox.py`)**: Isolates test execution to verify patches without side effects.
* **Self-Repair Loop (`agent/self_repair.py`)**: Captures test error tracebacks upon failure and feeds them back into reflection loops to refine patch logic.

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

3. Run the master pipeline:
   ```bash
   python3 run_master_pipeline.py
   ```

4. Run unit tests:
   ```bash
   python3 -m pytest tests/ -v
   ```

## Limitations & Scope

* Designed as a single-repo, local developer tool and workflow automation utility.
* Does not replace comprehensive enterprise vulnerability scanners or guarantee full application security.
* Relies on local Python runtimes and optional container runtimes for sandbox verification.

## Sandbox behavior

Patches are tested inside an ephemeral Docker container (`sandbox/docker_sandbox.py`).
**Docker must be installed and running.** Check with `docker --version`.

## Sandbox behavior

By default, patches are tested in an isolated temporary directory.
If Docker is available, the pipeline uses an ephemeral container instead
(`sandbox/docker_sandbox.py`). Check with `docker --version`.

## Important: target-repo dependencies

The sandbox runs the target repository's own test suite using your Python
environment. Whatever that repository needs (for example PyYAML or requests)
must also be installed here, separately from this project's requirements.txt:

```bash
pip install -r /path/to/target/repo/requirements.txt
```

If you skip this, tests fail with `ModuleNotFoundError`, which looks like a bad patch but is not.

## What a successful run looks like

```text
[DockerSandbox] Building ephemeral container environment...
[SelfRepair] Test failure encountered. Feeding traceback into reflection prompt...
[SelfRepair] Patch generation attempt 2 of 3...
[PatchGenerator] Drafting patch for CVE-2026-1042...
[DockerSandbox] Building ephemeral container environment...
[SelfRepair] Test failure encountered. Feeding traceback into reflection prompt...
[SelfRepair] Patch generation attempt 3 of 3...
[PatchGenerator] Drafting patch for CVE-2026-1042...
[DockerSandbox] Building ephemeral container environment...
[SelfRepair] Test failure encountered. Feeding traceback into reflection prompt...
[SelfRepair] Max repair attempts reached. Escalating to human reviewer queue.

[Master] Max self-repair attempts exhausted. Escalating to human security team.

[SUCCESS] Master pipeline run completed successfully.
```

## Test status

Last run: `/Users/nehapurohit/vulnerability-traige-agent/agentic-vuln-system/agentic-vuln-system/agentic-vuln-system/.venv/bin/python3: No module named pytest`
