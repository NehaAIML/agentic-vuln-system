import requests

def get_epss_score(cve_id: str) -> float:
    """Queries the official FIRST.org EPSS API for live exploit prediction probability."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        if data.get("status") == "OK" and data.get("data"):
            return float(data["data"][0].get("epss", 0.0))
    except Exception:
        pass
    return 0.0

def evaluate_vulnerability_priority(cve_id: str, is_reachable: bool) -> str:
    """Calculates composite priority based on live EPSS score and AST reachability."""
    epss_score = get_epss_score(cve_id)
    print(f"[Prioritization] CVE: {cve_id} | EPSS Score: {epss_score:.4f} | Reachable: {is_reachable}")
    
    if not is_reachable:
        return "FILTERED_OUT (Dead Code / Unreachable)"
    elif epss_score > 0.05:
        return "CRITICAL_IMMEDIATE_PATCH"
    else:
        return "LOW_PRIORITY_BACKLOG"
