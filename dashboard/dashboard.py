"""
dashboard.py
------------
Step 5: Proof-of-Execution Dashboard.

Lightweight Streamlit app that visualizes the pipeline's output artifacts:
  - vuln_scan_results.json        (Step 1: raw scan)
  - reachability_results.json     (Step 1: reachable vs filtered)
  - code_contexts.json            (Step 2: context bundles)
  - remediation_results.json      (Step 4: batch remediation outcome)

Run with:
    streamlit run dashboard/dashboard.py -- --repo-path sample_repo

Metrics shown: total CVEs detected, reachable vs filtered (noise reduction),
successfully auto-patched count, per-CVE attempt counts, and a simple
Mean Time to Remediate (MTTR) estimate derived from attempt durations
recorded by the sandbox runner.
"""
import json
import sys
import time
from pathlib import Path

import streamlit as st


def load_json(path: Path):
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def get_repo_path() -> Path:
    # Streamlit passes app args after `--`; support both that and a
    # plain query param / sidebar override for convenience.
    args = sys.argv[1:]
    if "--repo-path" in args:
        return Path(args[args.index("--repo-path") + 1])
    return Path(st.sidebar.text_input("Repo path", value="sample_repo"))


def main():
    st.set_page_config(page_title="Vuln Triage & Auto-Patch Dashboard", layout="wide")
    st.title("🛡️ Agentic Vulnerability Triage & Auto-Patching")
    st.caption("Live metrics from the local pipeline — scan → reachability → context → "
               "LLM patch → sandboxed TDD loop → PR")

    repo_path = get_repo_path()

    scan_results = load_json(repo_path / "vuln_scan_results.json")
    reachability = load_json(repo_path / "reachability_results.json")
    remediation = load_json(repo_path / "remediation_results.json")

    if scan_results is None and reachability is None and remediation is None:
        st.warning(
            f"No pipeline output found in `{repo_path}`. Run the pipeline first:\n\n"
            f"```\npython3 -m scanners.reachability {repo_path} {repo_path}/vuln_scan_results.json\n"
            f"python3 -m scanners.code_graph {repo_path} {repo_path}/reachability_results.json\n"
            f"python3 -m sandbox.sandbox_runner {repo_path} {repo_path}/code_contexts.json --batch\n```"
        )
        return

    total_detected = len(scan_results) if scan_results else (
        len(reachability["reachable"]) + len(reachability["filtered"]) if reachability else 0
    )
    reachable_count = len(reachability["reachable"]) if reachability else None
    filtered_count = len(reachability["filtered"]) if reachability else None

    # remediation.json can be either the single-CVE list shape (each item a
    # RemediationResult) or the batch shape (one dict with a "patches" key).
    if remediation is not None and isinstance(remediation, dict) and "patches" in remediation:
        patched_count = sum(1 for p in remediation["patches"] if p["applied"]) if remediation["tests_passed"] else 0
        total_patch_targets = len(remediation["patches"])
        all_attempt_durations = []  # batch mode doesn't track per-attempt timing granularly
    elif remediation is not None and isinstance(remediation, list):
        patched_count = sum(1 for r in remediation if r["success"])
        total_patch_targets = len(remediation)
        all_attempt_durations = [
            a["duration_seconds"] for r in remediation for a in r["attempts"]
        ]
    else:
        patched_count, total_patch_targets, all_attempt_durations = 0, 0, []

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total CVEs detected", total_detected)
    col2.metric("Reachable (actionable)", reachable_count if reachable_count is not None else "—")
    col3.metric("Filtered (dead code)", filtered_count if filtered_count is not None else "—")
    col4.metric("Auto-patched successfully", f"{patched_count}/{total_patch_targets}"
                if total_patch_targets else "—")

    if all_attempt_durations:
        mttr = sum(all_attempt_durations) / max(1, total_patch_targets)
        st.metric("Mean Time to Remediate (MTTR, sandbox wall-clock)", f"{mttr:.2f}s")

    st.divider()

    tab1, tab2, tab3 = st.tabs(["📋 Vulnerabilities", "🔍 Reachability Triage", "🩹 Remediation Results"])

    with tab1:
        if scan_results:
            st.dataframe(
                [{"CVE": v["id"], "Package": v["package"], "Installed": v["installed_version"],
                  "Fixed in": v.get("fixed_version"), "Severity": v.get("severity")}
                 for v in scan_results],
                use_container_width=True,
            )
        else:
            st.info("No raw scan results file found.")

    with tab2:
        if reachability:
            st.subheader("✅ Reachable — real, actionable vulnerabilities")
            for v in reachability["reachable"]:
                usages = v.get("_reachability", {}).get("usages", [])
                loc = usages[0] if usages else {}
                st.write(f"**{v['id']}** ({v['package']}) — used at "
                         f"`{loc.get('file', '?')}:{loc.get('line', '?')}` "
                         f"in `{loc.get('function', '?')}()`")
            st.subheader("🗑️ Filtered — dead code, deprioritized")
            for v in reachability["filtered"]:
                st.write(f"~~{v['id']} ({v['package']})~~ — never imported/called")
        else:
            st.info("No reachability results file found.")

    with tab3:
        if remediation is None:
            st.info("No remediation results file found.")
        elif isinstance(remediation, dict) and "patches" in remediation:
            st.write(f"**Overall success:** {'✅ Yes' if remediation['success'] else '❌ No'}")
            for p in remediation["patches"]:
                with st.expander(f"{p['vuln_id']} ({p['package']}) — "
                                  f"{'✅ applied' if p['applied'] else '❌ failed to apply'}"):
                    st.code(p.get("diff") or "(no diff)", language="diff")
            st.text_area("Test output", remediation.get("test_output", ""), height=200)
        else:
            for r in remediation:
                with st.expander(f"{r['vuln_id']} ({r['package']}) — "
                                  f"{'✅ SUCCESS' if r['success'] else '❌ FAILED'} "
                                  f"after {len(r['attempts'])} attempt(s)"):
                    for a in r["attempts"]:
                        st.write(f"Attempt {a['attempt_number']}: applied={a['apply_succeeded']}, "
                                 f"tests_passed={a['tests_passed']}, {a['duration_seconds']}s")
                        st.code(a["diff"], language="diff")


if __name__ == "__main__":
    main()
