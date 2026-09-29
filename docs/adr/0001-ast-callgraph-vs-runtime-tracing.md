# ADR 0001: AST Call-Graph Reachability vs. Runtime Tracing

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
