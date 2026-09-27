import sys
import subprocess
from pathlib import Path

def run_sandbox_tests(repo_dir: str) -> dict:
    """Runs pytest inside an isolated sandbox environment using the current virtual environment interpreter."""
    print(f"[Sandbox] Running regression tests in {repo_dir}...")
    result = subprocess.run([sys.executable, "-m", "pytest"], cwd=repo_dir, capture_output=True, text=True)
    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr
    }
