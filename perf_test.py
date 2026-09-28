"""
perf_test.py
------------
Answers: "where does this pipeline get slow, and at what scale?"

Generates synthetic repos of increasing size and times:
  1. Reachability scan (AST walk cost vs. file count)
  2. Code-graph context building (per-CVE cost)
  3. Sandbox creation (shutil.copytree cost vs. repo size)
  4. Full batch remediation loop, dry-run backend (apply + test cost)

Dry-run backend has ~0 latency by design (no network), so this measures
the pipeline's OWN overhead, not an LLM's. When switching to a real
backend (Ollama/Groq), add that model's per-call latency (typically
1-15s local, 0.5-3s API) x number of reachable CVEs x up to max_attempts
retries as the dominant cost on top of these numbers.

Run: python3 perf_test.py
"""
import json
import random
import shutil
import string
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scanners import reachability, code_graph
from sandbox import sandbox_runner


def gen_file(vulnerable_packages: list, seed: int, reachable: bool) -> str:
    """Generates one synthetic .py file, some reachable, some dead code, plus
    filler functions/imports to simulate a realistic non-trivial file."""
    rng = random.Random(seed)
    pkg = rng.choice(vulnerable_packages)
    lines = [f"import {pkg}", "import os", "import json", ""]
    for i in range(rng.randint(3, 8)):
        lines.append(f"def helper_{seed}_{i}(x):")
        lines.append(f"    return x + {i}")
        lines.append("")
    if reachable:
        lines.append(f"def use_it_{seed}():")
        lines.append(f"    return {pkg}.do_something()")
    else:
        lines.append(f"def unrelated_{seed}():")
        lines.append(f"    return os.path.join('a', 'b')")
    return "\n".join(lines) + "\n"


def build_synthetic_repo(root: Path, num_files: int, num_packages: int) -> list:
    packages = [f"pkg_{i}" for i in range(num_packages)]
    vulns = []
    for i, pkg in enumerate(packages):
        vulns.append({
            "id": f"CVE-SIM-{i}", "package": pkg, "ecosystem": "PyPI",
            "installed_version": "1.0", "fixed_version": "1.1",
            "severity": "HIGH", "summary": "synthetic",
        })
    for i in range(num_files):
        reachable = (i % 3 != 0)  # ~2/3 of files actually use their import
        content = gen_file(packages, seed=i, reachable=reachable)
        (root / f"module_{i}.py").write_text(content)
    return vulns


def time_it(label, fn, *args, **kwargs):
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - start
    print(f"  {label:.<55} {elapsed:>8.3f}s")
    return result, elapsed


def run_benchmark(num_files: int, num_packages: int):
    print(f"\n=== Benchmark: {num_files} files, {num_packages} vulnerable packages ===")
    tmp = Path(tempfile.mkdtemp(prefix="perf_repo_"))
    try:
        vulns = build_synthetic_repo(tmp, num_files, num_packages)

        # Step 1: reachability scan
        reach_result, t1 = time_it(
            "Step 1: reachability scan", reachability.filter_vulnerabilities, vulns, str(tmp)
        )
        reach_out = tmp / "reachability_results.json"
        reach_out.write_text(json.dumps(reach_result))
        print(f"    -> {len(reach_result['reachable'])} reachable, {len(reach_result['filtered'])} filtered")

        # Step 2: code-graph context building
        contexts, t2 = time_it(
            "Step 2: code-graph context extraction",
            code_graph.build_contexts_for_reachable_vulns, str(tmp), str(reach_out)
        )

        # Step 4 building block: sandbox creation cost alone (copytree)
        _, t3 = time_it("   -> sandbox creation (copytree) alone", sandbox_runner.make_sandbox, str(tmp))

        # Full batch remediation (dry-run: near-zero LLM cost, measures our overhead)
        batch_result, t4 = time_it(
            "Step 3+4: batch remediate (dry-run backend)",
            sandbox_runner.remediate_batch, str(tmp), contexts, backend="dry-run", max_attempts=1
        )

        total = t1 + t2 + t3 + t4
        print(f"  {'TOTAL':.<55} {total:>8.3f}s")
        return {
            "num_files": num_files, "num_packages": num_packages,
            "reachable_count": len(reach_result["reachable"]),
            "t_reachability": t1, "t_code_graph": t2,
            "t_sandbox_copy": t3, "t_batch_remediate": t4, "t_total": total,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("Performance test: pipeline overhead at increasing repo scale.")
    print("(dry-run backend = ~0 LLM latency; this isolates the pipeline's own cost)")

    results = []
    for num_files, num_packages in [(10, 3), (50, 5), (200, 10), (500, 15)]:
        results.append(run_benchmark(num_files, num_packages))

    print("\n=== Summary ===")
    print(f"{'files':>6} {'pkgs':>5} {'reachable':>10} {'reach(s)':>10} {'graph(s)':>10} "
          f"{'sbox(s)':>9} {'batch(s)':>9} {'total(s)':>9}")
    for r in results:
        print(f"{r['num_files']:>6} {r['num_packages']:>5} {r['reachable_count']:>10} "
              f"{r['t_reachability']:>10.3f} {r['t_code_graph']:>10.3f} "
              f"{r['t_sandbox_copy']:>9.3f} {r['t_batch_remediate']:>9.3f} {r['t_total']:>9.3f}")

    print("\nNote on real-backend latency (not simulated here):")
    print("  Real per-CVE cost = t_batch_remediate (this pipeline's overhead)")
    print("                    + (LLM call latency x reachable_count x avg attempts)")
    print("  e.g. 10 reachable CVEs x 8s/call (local Ollama) x 1.3 avg attempts ~= 104s added")
    print("  This is almost always the dominant term once you leave --backend dry-run.")


if __name__ == "__main__":
    main()
