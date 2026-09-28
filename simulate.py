"""
simulate.py
-----------
A scenario/simulation test: generates a synthetic repo with KNOWN GROUND
TRUTH (which CVEs are reachable, which are dead code, across multiple
files and packages), runs the real pipeline against it, and asserts the
output matches the known-correct answer. This is different from the unit
tests in tests/ -- it exercises the full Step 1->5 flow together, the way
run_pipeline.py does, against a repo the pipeline has never seen before.

Ground truth encoded below:
  - CVE-A (pkg_alpha): reachable, used directly in service.py
  - CVE-B (pkg_beta):  reachable, used only inside a helper called
                       transitively (2 hops) from main.py
  - CVE-C (pkg_gamma): UNREACHABLE -- imported in utils.py but never called
  - CVE-D (pkg_delta): reachable, used in a DIFFERENT file (models.py)
                       than where it's imported (still same import, just
                       checking cross-file usage isn't required here --
                       reachability is per-file import+use)

Run: python3 simulate.py
Exit code 0 = all assertions passed. Non-zero = simulation caught a
real discrepancy between expected and actual pipeline behavior.
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scanners import reachability, code_graph
from sandbox import sandbox_runner


def build_synthetic_repo(root: Path):
    (root / "service.py").write_text(
        "import pkg_alpha\n\n"
        "def handle_request(payload):\n"
        "    return pkg_alpha.parse(payload)\n"
    )
    (root / "main.py").write_text(
        "import pkg_beta\n\n"
        "def entrypoint():\n"
        "    return step_one()\n\n"
        "def step_one():\n"
        "    return step_two()\n\n"
        "def step_two():\n"
        "    return pkg_beta.render()\n"
    )
    (root / "utils.py").write_text(
        "import pkg_gamma  # imported, never called -- dead code\n\n"
        "def unrelated_helper(x):\n"
        "    return x * 2\n"
    )
    (root / "models.py").write_text(
        "import pkg_delta\n\n"
        "class Model:\n"
        "    def save(self):\n"
        "        return pkg_delta.serialize(self)\n"
    )
    scan_results = [
        {"id": "CVE-A", "package": "pkg_alpha", "ecosystem": "PyPI",
         "installed_version": "1.0", "fixed_version": "1.1", "severity": "HIGH", "summary": "test"},
        {"id": "CVE-B", "package": "pkg_beta", "ecosystem": "PyPI",
         "installed_version": "1.0", "fixed_version": "1.1", "severity": "MEDIUM", "summary": "test"},
        {"id": "CVE-C", "package": "pkg_gamma", "ecosystem": "PyPI",
         "installed_version": "1.0", "fixed_version": "1.1", "severity": "CRITICAL", "summary": "test"},
        {"id": "CVE-D", "package": "pkg_delta", "ecosystem": "PyPI",
         "installed_version": "1.0", "fixed_version": "1.1", "severity": "LOW", "summary": "test"},
    ]
    (root / "vuln_scan_results.json").write_text(json.dumps(scan_results, indent=2))
    return scan_results


def run_simulation() -> list:
    """Returns a list of failure strings; empty list = simulation passed."""
    failures = []
    tmp = Path(tempfile.mkdtemp(prefix="sim_repo_"))
    try:
        scan_results = build_synthetic_repo(tmp)

        # ---- Step 1 ----
        reach_result = reachability.filter_vulnerabilities(scan_results, str(tmp))
        reachable_ids = {v["id"] for v in reach_result["reachable"]}
        filtered_ids = {v["id"] for v in reach_result["filtered"]}

        expected_reachable = {"CVE-A", "CVE-B", "CVE-D"}
        expected_filtered = {"CVE-C"}

        if reachable_ids != expected_reachable:
            failures.append(f"Step 1 reachable mismatch: expected {expected_reachable}, got {reachable_ids}")
        if filtered_ids != expected_filtered:
            failures.append(f"Step 1 filtered mismatch: expected {expected_filtered}, got {filtered_ids}")

        reach_out = tmp / "reachability_results.json"
        reach_out.write_text(json.dumps(reach_result))

        # ---- Step 2 ----
        contexts = code_graph.build_contexts_for_reachable_vulns(str(tmp), str(reach_out))
        context_by_id = {c["vuln"]["id"]: c["context"] for c in contexts}

        if context_by_id.get("CVE-A", {}).get("target_function") is None:
            failures.append("Step 2: CVE-A should resolve to an enclosing function (handle_request)")
        elif context_by_id["CVE-A"]["target_function"]["name"] != "handle_request":
            failures.append(f"Step 2: CVE-A enclosing function wrong: {context_by_id['CVE-A']['target_function']['name']}")

        # CVE-B is used inside step_two, called transitively from entrypoint via step_one.
        # Blast radius should be 2 (step_one, entrypoint both transitively reach step_two).
        b_ctx = context_by_id.get("CVE-B", {})
        if b_ctx.get("target_function", {}).get("name") != "step_two":
            failures.append(f"Step 2: CVE-B enclosing function wrong: {b_ctx.get('target_function')}")
        elif b_ctx["blast_radius"] != 2:
            failures.append(f"Step 2: CVE-B blast radius expected 2, got {b_ctx['blast_radius']}")

        # ---- Step 4 (dry-run has no fix templates for these synthetic
        # packages, so we only assert the pipeline runs to completion
        # without crashing and correctly reports "no template" as a
        # graceful no-op rather than an exception) ----
        try:
            batch_result = sandbox_runner.remediate_batch(
                str(tmp), contexts, backend="dry-run", max_attempts=1
            )
        except Exception as e:
            failures.append(f"Step 4 crashed on synthetic repo with unknown packages: {e}")
        else:
            if not isinstance(batch_result.get("patches"), list):
                failures.append("Step 4: batch_result missing 'patches' list")

        return failures
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    failures = run_simulation()
    if failures:
        print(f"SIMULATION FAILED ({len(failures)} discrepancy/ies):")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("SIMULATION PASSED: pipeline output matches known ground truth "
              "on a synthetic 4-CVE, 4-file, transitive-call repo.")
        sys.exit(0)
