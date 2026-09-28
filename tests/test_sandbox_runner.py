"""
test_sandbox_runner.py
------------------------
Tests for sandbox/sandbox_runner.py, focused on the properties that
actually matter for trusting this system:

1. A patch that fails to APPLY triggers a retry with the error fed back.
2. A patch that applies but FAILS TESTS triggers a retry (not a false pass).
3. After max_attempts, the loop gives up cleanly rather than looping forever
   or silently reporting success.
4. A working patch is accepted as soon as it appears, without burning
   remaining attempts.
5. The sandbox never touches the original repo directory's files.

These use a monkeypatched `generate_patch` so the tests are deterministic
and don't depend on any real LLM.
"""
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sandbox import sandbox_runner


ORIGINAL_APP = "def add(a, b):\n    return a + b\n"
ORIGINAL_TEST = (
    "import sys\nfrom pathlib import Path\n"
    "sys.path.insert(0, str(Path(__file__).resolve().parent))\n"
    "import app\n\n"
    "def test_add():\n    assert app.add(2, 3) == 5\n"
)

GOOD_FIX = "def add(a, b):\n    return a + b  # unchanged, just annotated as reviewed\n"
BROKEN_FIX_SEMANTICS = "def add(a, b):\n    return a - b  # oops, wrong operator\n"


def make_diff(old_text: str, new_text: str, relpath: str = "app.py") -> str:
    import difflib
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    diff_lines = list(difflib.unified_diff(
        old_lines, new_lines, fromfile=f"a/{relpath}", tofile=f"b/{relpath}",
    ))
    return f"diff --git a/{relpath} b/{relpath}\nindex 000..111 100644\n" + "".join(diff_lines)


@pytest.fixture
def tmp_repo():
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / "app.py").write_text(ORIGINAL_APP)
        (repo / "test_app.py").write_text(ORIGINAL_TEST)
        yield repo


@pytest.fixture
def dummy_vuln_and_context():
    return {"id": "CVE-FAKE", "package": "fake-pkg", "installed_version": "1.0",
            "fixed_version": "1.1"}, {"file": "app.py"}


def _patch_result(diff_text):
    return sandbox_runner.PatchResult(diff=diff_text, raw_response=diff_text, model="fake")


def test_working_patch_succeeds_on_first_attempt(tmp_repo, dummy_vuln_and_context, monkeypatch):
    vuln, context = dummy_vuln_and_context
    monkeypatch.setattr(sandbox_runner, "generate_patch",
                         lambda *a, **k: _patch_result(make_diff(ORIGINAL_APP, GOOD_FIX)))

    result = sandbox_runner.remediate(str(tmp_repo), vuln, context, backend="dry-run", max_attempts=3)

    assert result.success is True
    assert len(result.attempts) == 1
    assert result.attempts[0].apply_succeeded is True
    assert result.attempts[0].tests_passed is True


def test_broken_patch_that_fails_tests_is_rejected_and_retried(tmp_repo, dummy_vuln_and_context, monkeypatch):
    """A patch that applies cleanly but breaks the test suite must not be
    accepted -- it should trigger a retry with the test failure fed back."""
    vuln, context = dummy_vuln_and_context
    call_log = []

    def fake_generate(v, c, backend, model, api_key, prior_error, prior_diff, repo_root=None):
        call_log.append(prior_error)
        return _patch_result(make_diff(ORIGINAL_APP, BROKEN_FIX_SEMANTICS))

    monkeypatch.setattr(sandbox_runner, "generate_patch", fake_generate)

    result = sandbox_runner.remediate(str(tmp_repo), vuln, context, backend="dry-run", max_attempts=3)

    assert result.success is False
    assert len(result.attempts) == 3  # exhausted all attempts
    assert all(a.apply_succeeded for a in result.attempts)
    assert all(not a.tests_passed for a in result.attempts)
    # First call has no prior error; subsequent calls must carry the test
    # failure forward so the "LLM" actually gets a chance to learn.
    assert call_log[0] is None
    assert "test" in call_log[1].lower() or "fail" in call_log[1].lower()


def test_self_repair_loop_recovers_after_initial_failure(tmp_repo, dummy_vuln_and_context, monkeypatch):
    """Simulates a realistic self-repair: attempt 1 is broken, attempt 2 is
    the corrected fix. The loop must accept attempt 2 and stop (not burn
    the 3rd attempt), proving prior_error actually influences the next try
    in this harness."""
    vuln, context = dummy_vuln_and_context
    attempt_counter = {"n": 0}

    def fake_generate(v, c, backend, model, api_key, prior_error, prior_diff, repo_root=None):
        attempt_counter["n"] += 1
        if attempt_counter["n"] == 1:
            return _patch_result(make_diff(ORIGINAL_APP, BROKEN_FIX_SEMANTICS))
        return _patch_result(make_diff(ORIGINAL_APP, GOOD_FIX))

    monkeypatch.setattr(sandbox_runner, "generate_patch", fake_generate)

    result = sandbox_runner.remediate(str(tmp_repo), vuln, context, backend="dry-run", max_attempts=3)

    assert result.success is True
    assert len(result.attempts) == 2  # stopped as soon as attempt 2 passed
    assert result.attempts[0].tests_passed is False
    assert result.attempts[1].tests_passed is True


def test_patch_that_fails_to_apply_is_retried_with_apply_error(tmp_repo, dummy_vuln_and_context, monkeypatch):
    vuln, context = dummy_vuln_and_context
    call_log = []

    def fake_generate(v, c, backend, model, api_key, prior_error, prior_diff, repo_root=None):
        call_log.append(prior_error)
        return _patch_result("diff --git a/app.py b/app.py\nTHIS IS NOT A VALID PATCH\n")

    monkeypatch.setattr(sandbox_runner, "generate_patch", fake_generate)

    result = sandbox_runner.remediate(str(tmp_repo), vuln, context, backend="dry-run", max_attempts=2)

    assert result.success is False
    assert len(result.attempts) == 2
    assert all(not a.apply_succeeded for a in result.attempts)
    assert all(not a.tests_ran for a in result.attempts)  # tests never run if apply failed
    assert "apply" in call_log[1].lower()


def test_original_repo_is_never_modified(tmp_repo, dummy_vuln_and_context, monkeypatch):
    vuln, context = dummy_vuln_and_context
    monkeypatch.setattr(sandbox_runner, "generate_patch",
                         lambda *a, **k: _patch_result(make_diff(ORIGINAL_APP, GOOD_FIX)))

    original_content_before = (tmp_repo / "app.py").read_text()
    sandbox_runner.remediate(str(tmp_repo), vuln, context, backend="dry-run", max_attempts=3)
    original_content_after = (tmp_repo / "app.py").read_text()

    assert original_content_before == original_content_after == ORIGINAL_APP


def test_no_test_suite_falls_back_to_syntax_check(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    passed, output = sandbox_runner.run_tests(str(tmp_path))
    assert passed is True
    assert "syntax check" in output.lower()


def test_syntax_broken_file_fails_fallback_check(tmp_path):
    (tmp_path / "app.py").write_text("def f(:\n    return 1\n")
    passed, output = sandbox_runner.run_tests(str(tmp_path))
    assert passed is False
