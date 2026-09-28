import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, List, Dict, Any

from agent.patch_generator import generate_patch, PatchResult


@dataclass
class AttemptRecord:
    attempt_number: int
    diff: str
    apply_succeeded: bool
    apply_output: str
    tests_ran: bool
    tests_passed: bool
    test_output: str
    duration_seconds: float


@dataclass
class RemediationResult:
    vuln_id: str
    package: str
    success: bool
    final_diff: Optional[str]
    attempts: List[AttemptRecord] = field(default_factory=list)
    sandbox_path: Optional[str] = None


def _run(cmd: List[str], cwd: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )


def make_sandbox(repo_path: str) -> str:
    """Copy the repo into a fresh temp dir. Returns the sandbox path."""
    sandbox = tempfile.mkdtemp(prefix="vuln_patch_sandbox_")
    # Copy contents (not the dir itself) so sandbox root== repo root
    shutil.copytree(repo_path, sandbox, dirs_exist_ok=True,
                     ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc",
                                                    ".venv", "venv", "node_modules"))
    return sandbox


def apply_diff(sandbox_path: str, diff_text: str) -> tuple[bool, str]:
    """
    Try `git apply` first (handles most unified diffs cleanly).
    Falls back to the classic `patch` utility with a 10-second timeout
    to prevent hanging on malformed diffs.
    """
    patch_file = Path(sandbox_path) / "_agent_patch.diff"
    patch_file.write_text(diff_text)

    is_git_repo = (Path(sandbox_path) / ".git").exists()
    if not is_git_repo:
        # Initialize a throwaway git repo so `git apply` has something to
        # check the patch against
        init = _run(["git", "init", "-q"], cwd=sandbox_path)
        _run(["git", "add", "-A"], cwd=sandbox_path)
        _run(["git", "-c", "user.email=agent@local", "-c", "user.name=agent",
              "commit", "-q", "-m", "baseline"], cwd=sandbox_path)

    result = _run(
        ["git", "apply", "--whitespace=fix", str(patch_file.name)],
        cwd=sandbox_path,
    )
    if result.returncode == 0:
        return True, result.stdout + result.stderr

    # Fall back to `patch -p1` with timeout to prevent hanging
    try:
        with open(patch_file) as f:
            patch_proc = subprocess.run(
                ["patch", "-p1", "--fuzz=3"],
                cwd=sandbox_path,
                stdin=f,
                capture_output=True,
                text=True,
                timeout=10,
            )
        if patch_proc.returncode == 0:
            return True, patch_proc.stdout + patch_proc.stderr
        patch_error = patch_proc.stdout + patch_proc.stderr
    except subprocess.TimeoutExpired:
        patch_error = "patch command timed out after 10 seconds"

    combined_error = (
        f"git apply failed:\n{result.stdout}\n{result.stderr}\n\n"
        f"patch -p1 fallback also failed:\n{patch_error}"
    )
    return False, combined_error


def run_tests(sandbox_path: str, test_command: Optional[List[str]] = None,
              timeout: int = 180) -> tuple[bool, str]:
    """
    Run the regression suite inside the sandbox. Auto-detects pytest vs
    npm test if no explicit command is given.
    """
    if test_command is None:
        if (Path(sandbox_path) / "pytest.ini").exists() or \
           any(Path(sandbox_path).glob("test_*.py")) or \
           any(Path(sandbox_path).glob("**/test_*.py")):
            test_command = ["python3", "-m", "pytest", "-q"]
        elif (Path(sandbox_path) / "package.json").exists():
            test_command = ["npm", "test", "--silent"]
        else:
            # No detectable test suite: fall back to a syntax-only sanity
            # check so we still catch outright broken patches.
            test_command = None

    if test_command is None:
        py_files = list(Path(sandbox_path).rglob("*.py"))
        errors = []
        for f in py_files:
            r = subprocess.run(["python3", "-m", "py_compile", str(f)],
                                capture_output=True, text=True)
            if r.returncode != 0:
                errors.append(r.stderr)
        if errors:
            return False, "\n".join(errors)
        return True, "No test suite detected; syntax check passed on all .py files."

    try:
        result = _run(test_command, cwd=sandbox_path, timeout=timeout)
        passed = result.returncode == 0
        return passed, result.stdout + "\n" + result.stderr
    except subprocess.TimeoutExpired as e:
        return False, f"Test command timed out after {timeout}s: {e}"
    except FileNotFoundError as e:
        return False, f"Test command not found ({' '.join(test_command)}): {e}"


def remediate(repo_path: str, vuln: Dict[str, Any], context: Dict[str, Any],
              backend: str = "dry-run", model: Optional[str] = None,
              api_key: Optional[str] = None, max_attempts: int = 3,
              test_command: Optional[List[str]] = None,
              keep_sandbox: bool = True) -> RemediationResult:
    """
    Full Step 4 loop for a single vulnerability:
    generate -> sandbox -> apply -> test -> (repair loop) -> result.
    """
    sandbox_path = make_sandbox(repo_path)
    attempts: List[AttemptRecord] = []
    prior_error, prior_diff = None, None
    success = False
    final_diff = None

    for attempt_num in range(1, max_attempts + 1):
        start = time.time()

        patch_result: PatchResult = generate_patch(
            vuln, context, backend=backend, model=model, api_key=api_key,
            prior_error=prior_error, prior_diff=prior_diff, repo_root=repo_path,
        )
        diff_text = patch_result.diff

        applied, apply_output = apply_diff(sandbox_path, diff_text)

        tests_ran, tests_passed, test_output = False, False, ""
        if applied:
            tests_ran = True
            tests_passed, test_output = run_tests(sandbox_path, test_command)

        duration = time.time() - start
        attempts.append(AttemptRecord(
            attempt_number=attempt_num,
            diff=diff_text,
            apply_succeeded=applied,
            apply_output=apply_output,
            tests_ran=tests_ran,
            tests_passed=tests_passed,
            test_output=test_output,
            duration_seconds=round(duration, 2),
        ))

        if applied and tests_passed:
            success = True
            final_diff = diff_text
            break

        # Prepare feedback for the next self-repair iteration
        if not applied:
            prior_error = f"Patch failed to apply:\n{apply_output}"
        else:
            prior_error = f"Patch applied but tests failed:\n{test_output}"
        prior_diff = diff_text

        # Reset sandbox to baseline before next attempt so failed partial
        # applies don't compound.
        _run(["git", "checkout", "--", "."], cwd=sandbox_path)
        _run(["git", "clean", "-fd"], cwd=sandbox_path)

    result = RemediationResult(
        vuln_id=vuln["id"],
        package=vuln["package"],
        success=success,
        final_diff=final_diff,
        attempts=attempts,
        sandbox_path=sandbox_path if keep_sandbox else None,
    )

    if not keep_sandbox:
        shutil.rmtree(sandbox_path, ignore_errors=True)

    return result


def remediate_batch(repo_path: str, vulns_and_contexts: List[Dict[str, Any]],
                     backend: str = "dry-run", model: Optional[str] = None,
                     api_key: Optional[str] = None, max_attempts: int = 3,
                     test_command: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Batch mode: apply the generated fix for every given vulnerability into
    ONE shared sandbox, then run the test suite once against the combined
    result.
    """
    sandbox_path = make_sandbox(repo_path)
    per_vuln_results = []

    for entry in vulns_and_contexts:
        vuln, context = entry["vuln"], entry["context"]
        prior_error, prior_diff = None, None
        applied_ok, final_diff = False, None
        attempts = []

        for attempt_num in range(1, max_attempts + 1):
            patch_result = generate_patch(
                vuln, context, backend=backend, model=model, api_key=api_key,
                prior_error=prior_error, prior_diff=prior_diff, repo_root=repo_path,
            )
            applied, apply_output = apply_diff(sandbox_path, patch_result.diff)
            attempts.append({"attempt": attempt_num, "applied": applied, "output": apply_output})
            if applied:
                applied_ok, final_diff = True, patch_result.diff
                break
            prior_error, prior_diff = f"Patch failed to apply:\n{apply_output}", patch_result.diff

        per_vuln_results.append({
            "vuln_id": vuln["id"], "package": vuln["package"],
            "applied": applied_ok, "diff": final_diff, "apply_attempts": attempts,
        })

    tests_passed, test_output = run_tests(sandbox_path, test_command)

    return {
        "sandbox_path": sandbox_path,
        "patches": per_vuln_results,
        "all_applied": all(p["applied"] for p in per_vuln_results),
        "tests_passed": tests_passed,
        "test_output": test_output,
        "success": all(p["applied"] for p in per_vuln_results) and tests_passed,
    }


def main():
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("repo_path")
    parser.add_argument("code_contexts_json")
    parser.add_argument("--backend", default="dry-run", choices=["dry-run", "ollama", "groq"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--batch", action="store_true",
                         help="Apply all patches into one sandbox, test once (realistic single-PR flow)")
    args = parser.parse_args()

    with open(args.code_contexts_json) as f:
        contexts = json.load(f)

    if args.batch:
        result = remediate_batch(
            args.repo_path, contexts, backend=args.backend, model=args.model,
            api_key=args.api_key, max_attempts=args.max_attempts,
        )
        print(f"\n=== Batch remediation ({len(contexts)} CVE(s)) ===")
        for p in result["patches"]:
            print(f"  {p['vuln_id']} ({p['package']}): applied={p['applied']}")
        print(f"Tests passed: {result['tests_passed']}")
        print(f"Overall success: {result['success']}")
        out_path = Path(args.repo_path) / "remediation_results.json"
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nWritten batch remediation report to {out_path}")
        return

    all_results = []
    for c in contexts:
        vuln, ctx = c["vuln"], c["context"]
        print(f"\n=== Remediating {vuln['id']} ({vuln['package']}) ===")
        result = remediate(
            args.repo_path, vuln, ctx,
            backend=args.backend, model=args.model, api_key=args.api_key,
            max_attempts=args.max_attempts,
        )
        status = "SUCCESS" if result.success else "FAILED"
        print(f"Result: {status} after {len(result.attempts)} attempt(s)")
        for a in result.attempts:
            print(f"  attempt {a.attempt_number}: applied={a.apply_succeeded} "
                  f"tests_passed={a.tests_passed} ({a.duration_seconds}s)")
        all_results.append(asdict(result))

    out_path = Path(args.repo_path) / "remediation_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nWritten remediation report to {out_path}")


if __name__ == "__main__":
    main()
