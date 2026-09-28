#!/usr/bin/env bash
# setup.sh
# ---------
# Automates every step in SETUP.md steps 3-8. Run this from INSIDE the
# unzipped vuln-triage-agent directory (the same folder this file is in).
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# What it does, in order:
#   1. Checks python3/pip3 are available (fails loudly with instructions if not)
#   2. Creates a virtual environment in ./.venv
#   3. Installs requirements.txt into it
#   4. Runs the unit test suite (tests/)
#   5. Runs the simulation test (simulate.py)
#   6. Runs the pipeline against the included sample_repo (dry-run, no LLM needed)
#
# It does NOT install Ollama, osv-scanner, or gh (those are optional and
# covered in SETUP.md steps 10-12), and does NOT push/open any real PR.

set -e  # exit immediately if any command fails

echo "=== Step 0: checking for python3 ==="
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found."
    echo "Install it first:"
    echo "  macOS:          brew install python3"
    echo "  Ubuntu/Debian:  sudo apt update && sudo apt install -y python3 python3-pip"
    echo "  Windows:        https://www.python.org/downloads/"
    exit 1
fi
python3 --version

echo ""
echo "=== Step 1: creating virtual environment in ./.venv ==="
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "Created .venv"
else
    echo ".venv already exists, skipping creation"
fi

echo ""
echo "=== Step 2: activating virtual environment ==="
# shellcheck disable=SC1091
source .venv/bin/activate
echo "Activated. Using: $(which python3)"

echo ""
echo "=== Step 3: installing dependencies ==="
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "Installed: $(pip show streamlit 2>/dev/null | grep Version) (streamlit), $(pip show pytest 2>/dev/null | grep Version) (pytest)"

echo ""
echo "=== Step 3b: installing the SAMPLE REPO's own dependencies ==="
echo "(The sandboxed test step runs sample_repo's tests using this same"
echo " Python environment, so sample_repo's own deps -- PyYAML, requests --"
echo " must be installed here too, separately from the pipeline's own"
echo " requirements.txt above. When you point this at YOUR OWN repo later,"
echo " you must likewise install THAT repo's dependencies into this venv"
echo " first, e.g.: pip install -r /path/to/your/repo/requirements.txt)"
pip install -r sample_repo/requirements.txt --quiet
echo "Installed sample_repo's dependencies."

echo ""
echo "=== Step 4: running unit test suite (tests/) ==="
python3 -m pytest tests/ -v

echo ""
echo "=== Step 5: running simulation test (simulate.py) ==="
python3 simulate.py

echo ""
echo "=== Step 6: running full pipeline against sample_repo (dry-run, no LLM/network needed) ==="
python3 run_pipeline.py sample_repo --mock sample_repo/vuln_scan_results.json --backend dry-run

echo ""
echo "=================================================================="
echo "Setup complete. Everything ran successfully."
echo ""
echo "Next steps:"
echo "  - View the dashboard:"
echo "      streamlit run dashboard/dashboard.py -- --repo-path sample_repo"
echo "  - Run against your own repo (see SETUP.md steps 10-12 for real"
echo "    LLM / real scanner / real PR setup):"
echo "      python3 scanners/run_scan.py /path/to/your/repo"
echo "      python3 run_pipeline.py /path/to/your/repo --backend ollama --model deepseek-coder-v2"
echo ""
echo "Remember: next time you open a new terminal, reactivate the venv first:"
echo "      source .venv/bin/activate"
echo "=================================================================="
