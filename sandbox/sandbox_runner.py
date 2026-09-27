import subprocess
from pathlib import Path

def run_sandbox_tests(repo_dir: str) -> dict:
    """Runs pytest inside an isolated sandbox environment."""
    print(f"[Sandbox] Running regression tests in {repo_dir}...")
    result = subprocess.run(["pytest"], cwd=repo_dir, capture_output=True, text=True)
    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr
    }
