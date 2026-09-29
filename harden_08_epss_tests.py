#!/usr/bin/env python3
"""
harden_08_epss_tests.py

Creates tests/test_prioritization.py covering scanners/prioritization.py.

Tests:
  get_epss_score:
    * happy path returns float
    * status != OK returns 0.0
    * empty data list returns 0.0
    * malformed JSON returns 0.0
    * network exception returns 0.0
    * timeout exception returns 0.0
  evaluate_vulnerability_priority:
    * not reachable -> FILTERED_OUT
    * reachable + epss > 0.05 -> CRITICAL
    * reachable + epss == 0.05 (boundary) -> LOW (not > 0.05)
    * reachable + epss < 0.05 -> LOW

DRY_RUN preview. Backs up any existing tests/test_prioritization.py.
Does NOT touch scanners/prioritization.py.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

DRY_RUN = False

REPO_ROOT = Path.cwd()
TESTS_DIR = REPO_ROOT / "tests"
TARGET = TESTS_DIR / "test_prioritization.py"

TEST_CONTENT = '''"""
tests/test_prioritization.py

Coverage for scanners/prioritization.py (EPSS scoring + priority decision).
Uses `responses` to mock the FIRST.org EPSS API — no live network calls.
"""

from __future__ import annotations

import pytest
import responses
from responses import matchers

from scanners import prioritization


EPSS_URL_RE = r"https://api\\.first\\.org/data/v1/epss.*"


# ---------------------------------------------------------------------------
# get_epss_score
# ---------------------------------------------------------------------------

@responses.activate
def test_get_epss_score_happy_path() -> None:
    """A well-formed OK response returns the epss float."""
    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        match=[matchers.query_param_matcher({"cve": "CVE-2020-14343"})],
        json={
            "status": "OK",
            "data": [{"cve": "CVE-2020-14343", "epss": "0.973"}],
        },
        status=200,
    )
    assert prioritization.get_epss_score("CVE-2020-14343") == pytest.approx(0.973)


@responses.activate
def test_get_epss_score_status_not_ok_returns_zero() -> None:
    """status != OK -> 0.0, no crash."""
    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        json={"status": "ERROR", "data": []},
        status=200,
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_empty_data_returns_zero() -> None:
    """status OK but empty data list -> 0.0."""
    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        json={"status": "OK", "data": []},
        status=200,
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_missing_epss_key_returns_zero() -> None:
    """data present but no `epss` key -> 0.0 (uses .get default)."""
    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        json={"status": "OK", "data": [{"cve": "CVE-xxxx"}]},
        status=200,
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_malformed_json_returns_zero() -> None:
    """Non-JSON body -> exception caught -> 0.0."""
    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        body="not json at all",
        status=200,
        content_type="text/plain",
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_connection_error_returns_zero() -> None:
    """requests.ConnectionError -> 0.0, no raise."""
    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        body=responses.ConnectionError("boom"),
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_timeout_returns_zero() -> None:
    """requests.Timeout -> 0.0, no raise."""
    responses.add(
        responses.GET,
        url=EPSS_URL_RE,
        body=responses.Timeout(),
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


# ---------------------------------------------------------------------------
# evaluate_vulnerability_priority
# ---------------------------------------------------------------------------

def test_priority_not_reachable_is_filtered(monkeypatch) -> None:
    """Unreachable CVE -> FILTERED_OUT regardless of EPSS."""
    monkeypatch.setattr(prioritization, "get_epss_score", lambda _cid: 0.99)
    result = prioritization.evaluate_vulnerability_priority("CVE-xxxx", is_reachable=False)
    assert result == "FILTERED_OUT (Dead Code / Unreachable)"


def test_priority_reachable_high_epss_is_critical(monkeypatch) -> None:
    """Reachable + epss > 0.05 -> CRITICAL."""
    monkeypatch.setattr(prioritization, "get_epss_score", lambda _cid: 0.5)
    result = prioritization.evaluate_vulnerability_priority("CVE-xxxx", is_reachable=True)
    assert result == "CRITICAL_IMMEDIATE_PATCH"


def test_priority_reachable_at_threshold_is_low(monkeypatch) -> None:
    """Boundary: epss == 0.05 is NOT > 0.05 -> LOW."""
    monkeypatch.setattr(prioritization, "get_epss_score", lambda _cid: 0.05)
    result = prioritization.evaluate_vulnerability_priority("CVE-xxxx", is_reachable=True)
    assert result == "LOW_PRIORITY_BACKLOG"


def test_priority_reachable_low_epss_is_low(monkeypatch) -> None:
    """Reachable + epss < 0.05 -> LOW."""
    monkeypatch.setattr(prioritization, "get_epss_score", lambda _cid: 0.01)
    result = prioritization.evaluate_vulnerability_priority("CVE-xxxx", is_reachable=True)
    assert result == "LOW_PRIORITY_BACKLOG"
'''


def main() -> int:
    print(f"Target  : {TARGET}")
    print(f"DRY_RUN : {DRY_RUN}")
    print("=" * 60)

    if not TESTS_DIR.exists():
        print(f"ERROR: {TESTS_DIR} not found. Run from repo root.")
        return 1

    if TARGET.exists():
        print(f"[note] {TARGET.name} already exists")
        print("       a .bak will be created before overwriting")
    else:
        print(f"[new]  {TARGET.name} will be created")

    test_count = TEST_CONTENT.count("def test_")
    print(f"\nTest functions in file: {test_count}")

    if DRY_RUN:
        print("\nDRY_RUN is ON - nothing was written.")
        print("Set DRY_RUN = False and run again to apply.")
        print("\nThen:  pytest tests/test_prioritization.py -v")
        return 0

    if TARGET.exists():
        bak = TARGET.with_suffix(".py.bak")
        shutil.copy2(TARGET, bak)
        print(f"BACKUP : {bak}")

    TARGET.write_text(TEST_CONTENT, encoding="utf-8")
    print(f"WROTE  : {TARGET}")
    print("\nNext:")
    print("  pytest tests/test_prioritization.py -v")
    print(
        '  git add -A && git commit -m "test(scanners): cover EPSS scoring and priority decision"'
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
