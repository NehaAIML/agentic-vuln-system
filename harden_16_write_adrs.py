#!/usr/bin/env python3
"""Writes docs/adr/0001 and 0002 ADRs + a docs/adr/README.md index."""
from pathlib import Path

DRY_RUN = False

ADR_0001 = '''# ADR 0001: AST Call-Graph Reachability vs. Runtime Tracing

- **Status:** Accepted
- **Date:** 2026-09-29
- **Context:** `scanners/reachability.py`

## Problem

Dependency scanners report every CVE in every installed package. Most of
those packages are never actually used by the target codebase, so their
CVEs are not exploitable. To filter that noise, we need to know which
dependencies the code actually imports and calls.

Two approaches exist:

1. **Static analysis** — parse the source, build a call graph, see which
   imports are referenced.
2. **Dynamic analysis** — instrument the code, run it (or its test suite),
   trace which imports actually execute.

## Decision

Use **static AST analysis**, not runtime tracing.

## Rationale

- **Safety.** Static analysis executes nothing. It is safe to run against
  arbitrary, untrusted code with no sandbox required.
- **Speed.** No test suite to invoke, no app to start. A scan completes in
  seconds per repository.
- **Determinism.** Same input, same output, every time.
- **Coverage.** Runtime tracing only sees code paths the test suite
  happens to exercise. Static analysis sees all code, including branches
  that tests don't cover.

## Consequences

**Accept we cannot detect:**
- Dynamic imports (`importlib.import_module`, `__import__`)
- Attribute-based dispatch (`getattr(obj, name)` where `name` is a variable)
- `eval`-based code paths
- Transitively reachable dependencies (e.g. Jinja2 via Flask) — tracking
  these would require resolving each imported package's own imports
- Module-name aliases unless explicitly listed (`pyOpenSSL` imports as
  `OpenSSL`; we maintain a lookup table)

**Require ongoing maintenance:**
- The `PYPI_TO_IMPORT_NAME` alias table in `scanners/reachability.py` is
  the load-bearing piece for correctness. Its gaps are exactly the gap
  found by the benchmark (see `benchmarks/README.md`).

**Known failure mode:** false negatives on aliasing are *dangerous*
(a real vuln filtered as dead code). To bound this, the benchmark in
`benchmarks/` serves as a regression test — any alias regression shows
up as reduced recall.

## Related

- Benchmark results: `benchmarks/README.md`
- Code: `scanners/reachability.py`
'''

ADR_0002 = '''# ADR 0002: Sandboxed TDD Verification vs. Second-LLM Review

- **Status:** Accepted
- **Date:** 2026-09-29
- **Context:** `sandbox/sandbox_runner.py`

## Problem

When an LLM generates a patch for a CVE, we need to know if the patch is
actually correct — not just plausible-looking. Two verification approaches:

1. **Second-LLM review.** Ask another model to read the diff and judge
   whether it fixes the vulnerability without breaking anything.
2. **Sandboxed TDD.** Apply the patch to a copy of the repo in isolation,
   run the actual test suite, and use the result as ground truth.

## Decision

Use **sandboxed TDD**, with the real test-suite output fed back into the
next generation attempt on failure.

## Rationale

- **Ground truth.** Tests pass or they don't. No LLM opinion enters the
  correctness decision.
- **Actionable feedback.** When a patch fails, the exact test error
  (assertion diff, stack trace, timeout) is the most useful possible
  input for the next attempt. "The reviewer didn't like it" is not.
- **Empirically converges.** Up to `MAX_REPAIR_ATTEMPTS` (default 3) is
  enough for the model to correct most straightforward patches.
- **Anti-hallucination.** LLMs are known to confidently approve broken
  code. Removing the LLM from the verification path removes that failure
  mode.

## Consequences

**Requires:**
- A working test suite in the target repository. If none is detected, we
  fall back to a `py_compile` syntax check only — weaker guarantee.
- Isolated filesystem state per attempt, so a failed patch does not
  poison the next attempt. Implemented via `tempfile.mkdtemp()` per run.
- Real wall-clock cost per attempt (test suite runtime, times up to three).

**Does not provide:**
- OS-level sandboxing. Patches execute with the host network stack and
  inherited environment variables. See `SECURITY.md` for the full threat
  model. This is a development aid, not a production isolation boundary.
- Protection from a patch that passes tests but is still wrong (e.g.
  tests with insufficient coverage).

## Alternatives considered

- **Second-LLM review only.** Rejected — no ground truth, adds a second
  hallucination surface, and provides no actionable failure signal.
- **Both (LLM review *and* TDD).** Rejected as cost without benefit; the
  TDD result already dominates the LLM review signal.

## Related

- Threat model: `SECURITY.md`
- Code: `sandbox/sandbox_runner.py`
'''

INDEX = '''# Architecture Decision Records

Short documents capturing the load-bearing design decisions in this
repository and the reasoning behind them.

Each ADR follows the standard format: Context, Decision, Rationale,
Consequences.

| # | Title | Status |
|---|---|---|
| [0001](0001-ast-callgraph-vs-runtime-tracing.md) | AST Call-Graph vs. Runtime Tracing | Accepted |
| [0002](0002-sandbox-tdd-vs-llm-review.md) | Sandboxed TDD vs. Second-LLM Review | Accepted |
'''


def main() -> int:
    base = Path("docs/adr")
    print(f"Target dir : {base.resolve()}")
    print(f"DRY_RUN    : {DRY_RUN}")
    print("=" * 60)

    files = {
        base / "0001-ast-callgraph-vs-runtime-tracing.md": ADR_0001,
        base / "0002-sandbox-tdd-vs-llm-review.md": ADR_0002,
        base / "README.md": INDEX,
    }

    for path, content in files.items():
        status = "EXISTS" if path.exists() else "new"
        print(f"  [{status}] {path}  ({content.count(chr(10))} lines)")

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        return 0

    base.mkdir(parents=True, exist_ok=True)
    for path, content in files.items():
        path.write_text(content, encoding="utf-8")
        print(f"WROTE : {path}")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
