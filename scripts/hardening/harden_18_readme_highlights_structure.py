#!/usr/bin/env python3
"""Adds Highlights + Project Structure sections to README.md."""
from pathlib import Path
import shutil, sys

DRY_RUN = False
TARGET = Path.cwd() / "README.md"

HIGHLIGHTS = """## Highlights

- **Measured, not claimed.** Reachability filtering scores **100% precision,
  100% recall, 100% accuracy** on a 35-CVE benchmark under strict scoring.
  See benchmarks/README.md for methodology, ground truth, and a reproducible
  scoring script.
- **Real bugs found and fixed.** The benchmark itself uncovered three missing
  PyPI-to-import aliases (pyOpenSSL, pysaml2, python-jwt); fixing them raised
  recall from 84% to 100%. A separate review caught a yaml.load vulnerability
  in the sample repo, fixed to yaml.safe_load.
- **Full CI green.** ruff, ruff-format, mypy, secrets detection, whitespace,
  and YAML linting all run as pre-commit hooks across the repo.
- **Design decisions documented.** Two ADRs under docs/adr/ explain why AST
  analysis beats runtime tracing, and why sandboxed TDD beats second-LLM
  review for patch verification.
- **Honest about limits.** SECURITY.md documents the actual sandbox isolation
  model (temp dir, network on, no resource limits); the Limitations section
  below lists what the tool cannot do.
- **11 passing unit tests.** Mocked-response coverage for the EPSS scoring
  and priority-decision logic in scanners/prioritization.py.

"""

STRUCTURE = """## Project Structure

~~~text
vuln-agent-clean/
├── .github/
│   ├── workflows/ci.yml           Python matrix CI (3.10 / 3.11 / 3.12)
│   └── ISSUE_TEMPLATE/            Bug report + feature request templates
├── agent/                         LLM patch generation + PR creation
├── assets/                        README images
├── benchmarks/                    Reachability benchmark (evidence)
│   ├── README.md                  Methodology, results, reproduction steps
│   ├── score.py                   Reproducible scoring script
│   └── data/
│       ├── ground_truth.json      35-CVE answer key (hand-verified)
│       ├── vuln_scan_results.json 35-CVE mock scan input for --mock
│       ├── results.csv            Per-CVE scored output
│       └── run_report.json        Structured pipeline run report
├── dashboard/                     Streamlit proof-of-execution dashboard
├── docs/
│   └── adr/                       Architecture Decision Records
│       ├── README.md              ADR index
│       ├── 0001-ast-callgraph-vs-runtime-tracing.md
│       └── 0002-sandbox-tdd-vs-llm-review.md
├── sample_repo/                   Synthetic test fixture (4 files, 4 CVEs)
├── sandbox/                       Sandboxed TDD self-repair loop
├── scanners/                      AST reachability + EPSS prioritization
├── scripts/
│   └── hardening/                 Archived hardening scripts (one-shot tools)
├── tests/
│   └── test_prioritization.py     11 mocked-response EPSS tests
├── utils/                         Shared helpers (LLM client, etc.)
├── .pre-commit-config.yaml        ruff, ruff-format, mypy, secrets, etc.
├── CONTRIBUTING.md                Onboarding + commit conventions
├── LICENSE                        MIT
├── README.md                      This file
├── SECURITY.md                    Threat model + isolation model
├── TODO.md                        Open vs. completed items
├── pyproject.toml                 Flat-layout packaging + tool config
├── requirements.lock              Pinned transitive dev dependencies
├── requirements.txt               Pinned runtime dependencies
└── requirements-dashboard.txt     Pinned dashboard dependencies
~~~

"""


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)

    if not TARGET.exists():
        print("ERROR: README.md not found."); return 1

    text = TARGET.read_text(encoding="utf-8")
    changes = []

    if "\n## Highlights\n" in text or text.startswith("## Highlights\n"):
        changes.append("Highlights: already present")
    else:
        anchor = "## 1. Background & Motivation"
        if anchor not in text:
            print("ABORT: anchor '## 1. Background & Motivation' not found."); return 2
        text = text.replace(anchor, HIGHLIGHTS + anchor, 1)
        changes.append("Highlights: inserted before section 1")

    if "\n## Project Structure\n" in text or text.startswith("## Project Structure\n"):
        changes.append("Project Structure: already present")
    else:
        anchor = "## 2. Core Architecture & Modules"
        if anchor not in text:
            print("ABORT: anchor '## 2. Core Architecture & Modules' not found."); return 2
        text = text.replace(anchor, STRUCTURE + anchor, 1)
        changes.append("Project Structure: inserted before section 2")

    print("\nPlanned changes:")
    for c in changes:
        print(f"  + {c}")

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    shutil.copy2(TARGET, TARGET.with_suffix(".md.bak"))
    TARGET.write_text(text, encoding="utf-8")
    print(f"\nWROTE  : {TARGET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
