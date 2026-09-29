# ADR 0002: Sandboxed TDD Verification vs. Second-LLM Review

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
