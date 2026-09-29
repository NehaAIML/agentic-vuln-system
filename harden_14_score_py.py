#!/usr/bin/env python3
"""Writes benchmarks/score.py - the scoring script."""
from pathlib import Path

CONTENT = '''#!/usr/bin/env python3
"""
benchmarks/score.py

Scores the pipeline's reachability output against the hand-verified
ground truth in benchmarks/data/ground_truth.json.

Usage:
    cd ~/vuln-agent-clean
    source .venv/bin/activate
    python benchmarks/score.py

Assumes the target fixture was already scanned and wrote:
    ~/benchmark-targets/Vulnerability-Management/reachability_results.json
"""
import csv
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GT_PATH = REPO / "benchmarks" / "data" / "ground_truth.json"
PIPE_PATH = Path.home() / "benchmark-targets" / "Vulnerability-Management" / "reachability_results.json"
CSV_PATH = REPO / "benchmarks" / "data" / "results.csv"


def main() -> int:
    if not GT_PATH.exists():
        print(f"ERROR: {GT_PATH} not found.")
        return 1
    if not PIPE_PATH.exists():
        print(f"ERROR: {PIPE_PATH} not found. Run the pipeline first.")
        return 1

    gt = json.loads(GT_PATH.read_text())
    gt_status = {info["cve"]: (pkg, info["status"]) for pkg, info in gt["packages"].items()}
    gt_reachable = {cve for cve, (_, s) in gt_status.items() if s in ("DIRECT", "TRANSITIVE")}
    gt_direct = {cve for cve, (_, s) in gt_status.items() if s == "DIRECT"}

    pipe = json.loads(PIPE_PATH.read_text())
    pipe_reachable = {v["id"] for v in pipe.get("reachable", [])}
    pipe_filtered = {v["id"] for v in pipe.get("filtered", [])}

    rows = []
    for cve, (pkg, truth) in gt_status.items():
        in_pipe_reach = cve in pipe_reachable
        in_pipe_filt = cve in pipe_filtered
        pipe_says = "REACHABLE" if in_pipe_reach else ("FILTERED" if in_pipe_filt else "MISSING")
        truth_strict = "REACHABLE" if truth == "DIRECT" else "FILTERED"
        truth_loose = "REACHABLE" if truth in ("DIRECT", "TRANSITIVE") else "FILTERED"
        rows.append({
            "cve": cve, "pkg": pkg, "truth": truth, "pipe": pipe_says,
            "match_strict": pipe_says == truth_strict,
            "match_loose": pipe_says == truth_loose,
        })

    print(f"{'CVE':18} {'PACKAGE':14} {'TRUTH':11} {'PIPELINE':11} {'STRICT':7} {'LOOSE':6}")
    print("-" * 80)
    for r in sorted(rows, key=lambda x: x["pkg"]):
        print(f"{r['cve']:18} {r['pkg']:14} {r['truth']:11} {r['pipe']:11} "
              f"{'✓' if r['match_strict'] else '✗':7} {'✓' if r['match_loose'] else '✗':6}")

    print()
    print("=" * 80)
    print("METRICS vs GROUND TRUTH")
    print("=" * 80)
    for label, truth_set in [("STRICT (direct only)", gt_direct),
                             ("LOOSE (direct + transitive)", gt_reachable)]:
        tp = fp = fn = tn = 0
        for r in rows:
            pipe_says_reach = r["pipe"] == "REACHABLE"
            truth_reach_ = r["cve"] in truth_set
            if pipe_says_reach and truth_reach_: tp += 1
            elif pipe_says_reach and not truth_reach_: fp += 1
            elif not pipe_says_reach and truth_reach_: fn += 1
            else: tn += 1
        prec = tp / (tp + fp) if (tp + fp) else 0
        rec = tp / (tp + fn) if (tp + fn) else 0
        acc = (tp + tn) / len(rows)
        print(f"\\n{label}")
        print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
        print(f"  Precision : {prec:.0%}")
        print(f"  Recall    : {rec:.0%}")
        print(f"  Accuracy  : {acc:.0%}")

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CSV_PATH.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["cve", "pkg", "truth", "pipe", "match_strict", "match_loose"])
        w.writeheader()
        for r in sorted(rows, key=lambda x: x["cve"]):
            w.writerow(r)
    print(f"\\nWrote {CSV_PATH}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
'''

target = Path("benchmarks/score.py")
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(CONTENT, encoding="utf-8")
print(f"WROTE : {target}")
print(f"LINES : {CONTENT.count(chr(10))}")
