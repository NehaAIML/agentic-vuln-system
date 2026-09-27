import json
from pathlib import Path
from utils.banner import print_banner
from scanners.reachability import check_reachability
from scanners.prioritization import evaluate_vulnerability_priority
from agent.patch_generator import generate_patch
from agent.self_repair import self_repair_loop
from sandbox.docker_sandbox import run_in_docker
from agent.pr_creator import create_pull_request

def master_run():
    print_banner()
    print("🚀 Initializing Master Agentic Vulnerability & Patching Pipeline...\n")
    
    cve_id = "CVE-2026-1042"
    vuln_info = {"package": "requests", "cve": cve_id}
    
    is_reachable = check_reachability(".", vuln_info)
    priority = evaluate_vulnerability_priority(cve_id, is_reachable)
    print(f"[Master] Evaluated Priority Level: {priority}\n")
    
    if "FILTERED_OUT" in priority:
        print("[Master] Vulnerability is in dead code or unreachable. Skipping patch generation.")
        return

    print("[Master] Initiating Self-Repair Patch Generation Loop...")
    
    def test_runner():
        return run_in_docker(".")

    success = self_repair_loop(
        patch_generator_func=lambda ctx: generate_patch(vuln_info, ctx),
        test_runner_func=test_runner,
        initial_context="vulnerable function code snippet here",
        max_attempts=3
    )
    
    if success:
        print("\n[Master] Patch verified successfully in Docker sandbox. Creating Pull Request...")
        patch_diff = "diff --git a/app.py b/app.py\n+ secure_fix()"
        create_pull_request(f"fix/{cve_id.lower()}", patch_diff, "Containerized pytest passed all assertions.")
        status_state = "PATCH_VERIFIED_AND_PR_OPENED"
    else:
        print("\n[Master] Max self-repair attempts exhausted. Escalating to human security team.")
        status_state = "ESCALATED_TO_HUMAN"

    report = [{
        "cve": cve_id,
        "reachable": is_reachable,
        "priority": priority,
        "status": status_state,
        "sandbox": "Docker Ephemeral Container"
    }]
    Path("master_execution_report.json").write_text(json.dumps(report, indent=2))
    print("\n[SUCCESS] Master pipeline run completed successfully.")

if __name__ == "__main__":
    master_run()
