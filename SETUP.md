# SETUP.md — Complete, Zero-Assumptions Setup Guide

This guide assumes **nothing** is already set up. Every command below is
meant to be typed exactly as shown, in order, into a terminal (macOS/Linux)
or WSL/Git Bash on Windows. If a step doesn't apply to you (e.g. you
already have Python), skip it and move to the next.

---

## 0. Check what you already have

Open a terminal and run these one at a time:

```bash
python3 --version
```
You need **Python 3.9 or newer**. If this command fails ("command not
found") or shows a version older than 3.9, install Python first:
- macOS: `brew install python3` (install Homebrew first from https://brew.sh if you don't have it)
- Ubuntu/Debian: `sudo apt update && sudo apt install -y python3 python3-pip`
- Windows: download the installer from https://www.python.org/downloads/ and check "Add Python to PATH" during install

```bash
git --version
```
If this fails, install git:
- macOS: `brew install git`
- Ubuntu/Debian: `sudo apt install -y git`
- Windows: download from https://git-scm.com/download/win

```bash
pip3 --version
```
If this fails but Python worked, install pip:
```bash
python3 -m ensurepip --upgrade
```

---

## 1. Create a working directory

Pick where you want this project to live. Example: your home directory.

```bash
cd ~
```
(This moves you to your home directory. `~` is a shortcut for it.)

```bash
mkdir -p vuln-triage-agent
```
`mkdir` = "make directory". `-p` means "don't error if it already exists,
and create any missing parent folders too."

```bash
cd vuln-triage-agent
```
This moves you *into* the folder you just created. From here on, every
command assumes you are inside this folder. Run `pwd` (print working
directory) at any point to double check where you are.

---

## 2. Unzip the delivered package into this directory

If you downloaded `vuln-triage-agent.zip` from this chat, move it into the
folder you just made, then unzip it:

```bash
# adjust this path to wherever your browser/app saved the downloaded file
mv ~/Downloads/vuln-triage-agent.zip ~/vuln-triage-agent/
```

```bash
cd ~/vuln-triage-agent
```

```bash
unzip vuln-triage-agent.zip
```
If `unzip` isn't installed:
- macOS: it's built in.
- Ubuntu/Debian: `sudo apt install -y unzip`
- Windows: right-click the `.zip` file in File Explorer → "Extract All"

After this, confirm the files are there:
```bash
ls -la
```
You should see folders named `agent`, `scanners`, `sandbox`, `dashboard`,
`tests`, `sample_repo`, plus files like `run_pipeline.py`, `README.md`,
`requirements.txt`, `simulate.py`, `perf_test.py`.

---

## 3. Create a Python virtual environment (recommended, keeps dependencies isolated)

Still inside `~/vuln-triage-agent`:

```bash
python3 -m venv .venv
```
This creates a new hidden folder `.venv` inside your project directory
containing an isolated Python install.

Activate it:
```bash
source .venv/bin/activate
```
(On Windows Git Bash: `source .venv/Scripts/activate`. On Windows
PowerShell: `.venv\Scripts\Activate.ps1`)

Your terminal prompt should now show `(.venv)` at the start of the line.
**Every command from here on should be run with this venv activated** —
if you close and reopen your terminal, re-run the `source` command above
before continuing.

---

## 4. Install dependencies

```bash
pip install --upgrade pip
```

```bash
pip install -r requirements.txt
```

If you're on a system where `pip` refuses to install outside a venv (some
Linux distros), and you skipped step 3, use:
```bash
pip install -r requirements.txt --break-system-packages
```

This installs `streamlit` (for the dashboard) and `pytest` (for the test
suite). Everything else the project uses (`ast`, `difflib`, `subprocess`,
`tempfile`, `json`, `urllib`) is part of Python itself — nothing else to
install for the core pipeline.

**Important — also install the TARGET repo's own dependencies:**
The sandboxed test step (Step 4 of the pipeline) runs the target repo's
own test suite using this same Python environment. That means whatever
packages the target repo needs (e.g. `sample_repo` needs PyYAML and
`requests`) must ALSO be installed here — separately from this project's
own `requirements.txt` above. For the included sample repo:
```bash
pip install -r sample_repo/requirements.txt
```
When you later point this at your own real repo, install *that* repo's
dependencies the same way before running the pipeline against it:
```bash
pip install -r /path/to/your/repo/requirements.txt
```
If you skip this, Step 4 will correctly report test failures — but they'll
be `ModuleNotFoundError`s having nothing to do with the actual patch, which
is confusing to debug if you don't know to look for it.

---

## 5. Verify the install worked — run the test suite

```bash
python3 -m pytest tests/ -v
```
You should see 38 lines ending in `PASSED`, and a final line saying
`38 passed`. If anything fails here, stop and check your Python version
(step 0) before going further.

---

## 6. Run the simulation test (proves the pipeline's logic against known-correct answers)

```bash
python3 simulate.py
```
Expected output: `SIMULATION PASSED: pipeline output matches known ground
truth on a synthetic 4-CVE, 4-file, transitive-call repo.`

---

## 7. Run the performance benchmark (optional, takes ~10-30 seconds)

```bash
python3 perf_test.py
```
This prints a table showing how each pipeline stage scales as repo size
grows (10 → 500 synthetic files). No setup needed beyond step 4.

---

## 8. Run the full pipeline against the included sample repo

```bash
python3 run_pipeline.py sample_repo --mock sample_repo/vuln_scan_results.json --backend dry-run
```
This runs all 5 steps (scan → reachability → context → patch → sandboxed
test loop → PR branch creation) using the included sample vulnerable app,
with no LLM or network access required (`--backend dry-run`).

Expected: it prints progress through Steps 1–5 and ends with a message
about a branch named `fix/cve-...` being created locally.

---

## 9. View the dashboard

```bash
streamlit run dashboard/dashboard.py -- --repo-path sample_repo
```
This starts a local web server (usually at `http://localhost:8501`) and
should automatically open it in your browser. If it doesn't open
automatically, copy the "Local URL" printed in the terminal into your
browser manually.

Press `Ctrl+C` in the terminal to stop the dashboard server when you're done.

---

## 10. (Optional) Run against a real local LLM instead of dry-run

Install Ollama (a free, local LLM runner):
```bash
curl -fsSL https://ollama.com/install.sh | sh
```
(Windows/macOS: download the installer from https://ollama.com instead.)

Start the Ollama service (usually starts automatically after install; if
not, run this in its own terminal window and leave it running):
```bash
ollama serve
```

In a **new terminal window**, pull a coding model (this downloads several
GB, may take a while):
```bash
ollama pull deepseek-coder-v2
```

Back in your original terminal (with `.venv` activated, inside
`~/vuln-triage-agent`), run the pipeline with the real model:
```bash
python3 run_pipeline.py sample_repo --mock sample_repo/vuln_scan_results.json --backend ollama --model deepseek-coder-v2
```

---

## 11. (Optional) Run a real OSV-Scanner scan instead of `--mock`

Install Go if you don't have it (needed to install osv-scanner):
- macOS: `brew install go`
- Ubuntu/Debian: `sudo apt install -y golang-go`
- Windows: https://go.dev/dl/

Install osv-scanner:
```bash
go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

Make sure Go's install location is on your PATH (usually `~/go/bin`):
```bash
export PATH="$PATH:$HOME/go/bin"
```
(Add that line to your `~/.bashrc` or `~/.zshrc` to make it permanent.)

Scan any real repo:
```bash
python3 scanners/run_scan.py /path/to/your/real/repo
```
This writes `/path/to/your/real/repo/vuln_scan_results.json`, which you
then feed into the full pipeline without `--mock`:
```bash
python3 run_pipeline.py /path/to/your/real/repo --backend ollama --model deepseek-coder-v2
```

---

## 12. (Optional) Actually push a branch and open a PR

This requires a real repo with a real git remote (e.g. hosted on GitHub),
and the GitHub CLI installed and authenticated:

```bash
# Install gh (GitHub CLI)
# macOS: brew install gh
# Ubuntu/Debian: sudo apt install -y gh
# Windows: winget install --id GitHub.cli

gh auth login
```
Follow the interactive prompts to log in.

Then run the pipeline with `--push-pr`:
```bash
python3 run_pipeline.py /path/to/your/real/repo --push-pr
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'streamlit'` | You forgot step 3 (activate venv) or step 4 (install deps). Run both again. |
| `ModuleNotFoundError: No module named 'yaml'` (or `requests`, or any other package) showing up **inside the pipeline's test output**, not from a command you ran directly | You forgot to install the *target repo's* own dependencies into this venv (see the callout in step 4). Run `pip install -r <target repo>/requirements.txt`. |
| `pip: command not found` | Use `pip3` instead of `pip`, or revisit step 0. |
| `git apply failed` when running the pipeline | This is expected/handled — the self-repair loop retries automatically up to 3 times. Check `remediation_results.json` in your target repo for details. |
| Dashboard shows "No pipeline output found" | You need to run step 8 (`run_pipeline.py`) against that repo path first — the dashboard only reads files the pipeline already produced. |
| `ollama: command not found` after install | Restart your terminal, or re-run the `curl` install command from step 10. |
| Permission denied errors on Linux when installing packages | Add `--break-system-packages` to any `pip install` command, or use the venv from step 3 instead (preferred). |

## Deactivating the virtual environment

When you're done working in this project:
```bash
deactivate
```
This returns your terminal to normal (no more `(.venv)` prefix).
