import sys
import subprocess

def test_sandbox_pytest():
    res = subprocess.run([sys.executable, "-m", "pytest", "--version"], capture_output=True, text=True)
    assert res.returncode == 0
