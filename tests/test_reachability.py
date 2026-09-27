from scanners.reachability import check_reachability

def test_reachability_basic():
    res = check_reachability(".", {"package": "requests", "cve": "CVE-2026-001"})
    assert res is True
