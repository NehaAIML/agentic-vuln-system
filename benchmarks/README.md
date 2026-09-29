# Benchmark: Reachability Filter Accuracy

**Claim under test:** the tool "filters dead-code vulnerabilities" without
mislabeling reachable code as dead.

**Method:** run `scanners/reachability.py` against a purpose-built fixture
with 35 documented CVEs, then compare its reachable/filtered split to a
hand-verified ground truth.

## Target

- **Fixture:** [`sambitsahugithub/Vulnerability-Management`](https://github.com/sambitsahugithub/Vulnerability-Management)
- **Source files scanned:** 8 `.py` files
- **CVEs in fixture:** 35 (10 CRITICAL, 11 HIGH, 8 MEDIUM, 6 LOW)

### Known caveat about the fixture

The fixture's `requirements.txt` and its `README.md` disagree on package
versions (e.g. README says PyYAML 3.13, `requirements.txt` says PyYAML 6.0.3).
We use the **README's documented CVE list** as ground truth, since the
fixture's stated purpose is to exercise known CVEs.

## Ground truth

Determined by scanning the fixture's 8 source files for explicit imports.
Each CVE is classified as:

| Class | Meaning | Count |
|---|---|---|
| DIRECT | Package is explicitly imported in source | 19 |
| TRANSITIVE | Package is imported by an explicitly-imported package | 4 |
| dead | Package is in `requirements.txt` but never imported | 12 |
| **Total** | | **35** |

## Results

Scored two ways — strict (only DIRECT counts as "should be reachable")
and loose (DIRECT + TRANSITIVE both count).

### STRICT scoring

| Metric | Value |
|---|---|
| True Positives | 19 |
| False Positives | 0 |
| False Negatives | 0 |
| True Negatives | 16 |
| **Precision** | **100%** |
| **Recall** | **100%** |
| **Accuracy** | **100%** |

### LOOSE scoring

| Metric | Value |
|---|---|
| True Positives | 19 |
| False Positives | 0 |
| False Negatives | 4 |
| True Negatives | 12 |
| **Precision** | **100%** |
| **Recall** | **83%** |
| **Accuracy** | **89%** |

The 4 loose-scoring misses are Jinja2, Werkzeug, certifi, and idna.
All four are reachable only transitively (via Flask and requests). A pure
static import scan cannot detect them without resolving package internals —
a fundamental limitation, not a bug.

## What we fixed during this benchmark

The initial run scored **84% strict recall** with 3 false negatives:
pyOpenSSL, pysaml2, python-jwt.

`scanners/reachability.py`'s `PYPI_TO_IMPORT_NAME` alias table was missing:

| Package | Module name in source | Alias entry added |
|---|---|---|
| pyOpenSSL | OpenSSL | `"pyopenssl": "OpenSSL"` |
| pysaml2 | saml2 | `"pysaml2": "saml2"` |
| python-jwt | python_jwt | `"python-jwt": "python_jwt"` |

Adding these three lines raised strict recall from 84% -> 100% and
strict accuracy from 91% -> 100%.

## Reproduce

    cd ~/vuln-agent-clean
    source .venv/bin/activate

    mkdir -p ~/benchmark-targets
    cd ~/benchmark-targets
    curl -L https://github.com/sambitsahugithub/Vulnerability-Management/archive/refs/heads/main.tar.gz -o vm.tar.gz
    tar xzf vm.tar.gz && mv Vulnerability-Management-main Vulnerability-Management
    cd Vulnerability-Management

    python ~/vuln-agent-clean/run_pipeline.py . --mock ~/vuln-agent-clean/benchmarks/data/vuln_scan_results.json --backend dry-run --report ~/vuln-agent-clean/benchmarks/data/run_report.json

    # score
    cd ~/vuln-agent-clean
    python benchmarks/score.py

## Artifacts

- `data/ground_truth.json` — hand-verified answer key (35 packages)
- `data/vuln_scan_results.json` — 35-CVE mock scan input for `--mock`
- `data/results.csv` — per-CVE scored output
- `data/run_report.json` — structured pipeline run report
- `score.py` — the scoring script

## Limitations of this benchmark

- **One fixture.** 35 CVEs on a single repo. Larger multi-repo validation
  would strengthen the claim.
- **Hand-verified ground truth.** Determined by reading the source, not by
  an independent third-party scanner. Reproducible but not adversarial.
- **Transitive reachability not modeled.** The 4 loose-scoring misses
  reflect this.
- **Fixture version-mismatch caveat.** See "Known caveat" above.
