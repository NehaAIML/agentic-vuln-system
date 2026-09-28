"""
test_pr_creator.py
--------------------
The one property that matters most here: pr_creator must REFUSE to create
a PR when the batch remediation didn't fully succeed. Everything else
(branch naming, report formatting) is secondary to this safety gate.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent.pr_creator import create_pr_for_batch, build_proof_of_execution_report


def test_refuses_to_open_pr_when_tests_failed(tmp_path):
    batch_result = {
        "success": False,
        "all_applied": True,
        "tests_passed": False,
        "patches": [{"vuln_id": "CVE-1", "package": "x", "applied": True, "diff": "..."}],
        "test_output": "1 failed",
    }
    result = create_pr_for_batch(str(tmp_path), batch_result)
    assert result["pr_created"] is False
    assert "did not fully succeed" in result["reason"]


def test_refuses_to_open_pr_when_a_patch_failed_to_apply(tmp_path):
    batch_result = {
        "success": False,
        "all_applied": False,
        "tests_passed": True,
        "patches": [{"vuln_id": "CVE-1", "package": "x", "applied": False, "diff": None}],
        "test_output": "n/a",
    }
    result = create_pr_for_batch(str(tmp_path), batch_result)
    assert result["pr_created"] is False


def test_report_includes_all_cve_ids_and_pass_fail_status():
    batch_result = {
        "success": True,
        "patches": [
            {"vuln_id": "CVE-2020-1", "package": "pkgA", "applied": True, "apply_attempts": [1]},
            {"vuln_id": "CVE-2020-2", "package": "pkgB", "applied": True, "apply_attempts": [1, 2]},
        ],
        "tests_passed": True,
        "test_output": "3 passed",
    }
    report = build_proof_of_execution_report(batch_result)
    assert "CVE-2020-1" in report
    assert "CVE-2020-2" in report
    assert "PASSED" in report
