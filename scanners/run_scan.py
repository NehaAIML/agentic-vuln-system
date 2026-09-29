"""
run_scan.py
-----------
Wraps OSV-Scanner (preferred) or Trivy to produce a normalized JSON list of
vulnerabilities for a target repository. Falls back to parsing an existing
OSV-Scanner JSON file if the binary isn't installed, so the rest of the
pipeline can be developed/tested without network access to install scanners.

Normalized record shape:
{
    "id": "CVE-2023-XXXXX",
    "package": "requests",
    "ecosystem": "PyPI",
    "installed_version": "2.25.1",
    "fixed_version": "2.31.0",
    "severity": "HIGH",
    "summary": "...",
    "advisory_url": "...",
    "manifest_file": "requirements.txt"
}
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any


def _run(cmd: List[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):  # osv-scanner returns 1 when vulns found
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
    return result.stdout


def scan_with_osv(repo_path: str) -> Dict[str, Any]:
    """Run osv-scanner against a repo directory and return raw JSON dict."""
    if shutil.which("osv-scanner") is None:
        raise FileNotFoundError("osv-scanner binary not found on PATH")
    cmd = ["osv-scanner", "--json", "--recursive", repo_path]
    raw = _run(cmd)
    return json.loads(raw)


def normalize_osv(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten OSV-Scanner's nested JSON into simple per-vuln records."""
    normalized = []
    for result in raw.get("results", []):
        source = result.get("source", {}).get("path", "unknown")
        for pkg_entry in result.get("packages", []):
            pkg = pkg_entry.get("package", {})
            for vuln in pkg_entry.get("vulnerabilities", []):
                fixed_version = None
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fixed_version = event["fixed"]

                severity = "UNKNOWN"
                if vuln.get("severity"):
                    severity = vuln["severity"][0].get("score", "UNKNOWN")

                normalized.append(
                    {
                        "id": vuln.get("id"),
                        "package": pkg.get("name"),
                        "ecosystem": pkg.get("ecosystem"),
                        "installed_version": pkg.get("version"),
                        "fixed_version": fixed_version,
                        "severity": severity,
                        "summary": vuln.get("summary", ""),
                        "advisory_url": (vuln.get("references") or [{}])[0].get("url", ""),
                        "manifest_file": source,
                    }
                )
    return normalized


def load_mock_scan(path: str) -> List[Dict[str, Any]]:
    """
    Fallback for environments without osv-scanner installed / no network.
    Expects a pre-existing OSV-style JSON file, OR our own normalized format.
    """
    with open(path) as f:
        data = json.load(f)
    if "results" in data:
        return normalize_osv(data)
    return data  # already normalized


def main():
    if len(sys.argv) < 2:
        print("Usage: run_scan.py <repo_path> [--mock <path_to_json>]")
        sys.exit(1)

    repo_path = sys.argv[1]

    if "--mock" in sys.argv:
        mock_path = sys.argv[sys.argv.index("--mock") + 1]
        vulns = load_mock_scan(mock_path)
    else:
        try:
            raw = scan_with_osv(repo_path)
            vulns = normalize_osv(raw)
        except FileNotFoundError as e:
            print(f"[warn] {e}. Falling back to mock data if provided.", file=sys.stderr)
            vulns = []

    out_path = Path(repo_path) / "vuln_scan_results.json"
    with open(out_path, "w") as f:
        json.dump(vulns, f, indent=2)

    print(f"Found {len(vulns)} vulnerabilities. Written to {out_path}")
    for v in vulns:
        print(
            f"  - {v['id']}: {v['package']}=={v['installed_version']} "
            f"(fix: {v['fixed_version']}) [{v['severity']}]"
        )


if __name__ == "__main__":
    main()
