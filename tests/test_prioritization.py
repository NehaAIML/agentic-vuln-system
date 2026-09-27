from scanners.prioritization import evaluate_vulnerability_priority

def test_prioritization_unreachable():
    # If not reachable, should always filter out regardless of EPSS score
    result = evaluate_vulnerability_priority("CVE-2026-0000", is_reachable=False)
    assert "FILTERED_OUT" in result
