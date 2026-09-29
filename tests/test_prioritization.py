"""
tests/test_prioritization.py

Coverage for scanners/prioritization.py (EPSS scoring + priority decision).
Uses `responses` to mock the FIRST.org EPSS API — no live network calls.
"""

from __future__ import annotations

import pytest
import responses

from scanners import prioritization


def _epss_url(cve: str) -> str:
    """Exact URL that prioritization.get_epss_score() builds."""
    return f"https://api.first.org/data/v1/epss?cve={cve}"


# ---------------------------------------------------------------------------
# get_epss_score
# ---------------------------------------------------------------------------


@responses.activate
def test_get_epss_score_happy_path() -> None:
    """A well-formed OK response returns the epss float."""
    responses.add(
        responses.GET,
        url=_epss_url("CVE-2020-14343"),
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
        url=_epss_url("CVE-xxxx"),
        json={"status": "ERROR", "data": []},
        status=200,
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_empty_data_returns_zero() -> None:
    """status OK but empty data list -> 0.0."""
    responses.add(
        responses.GET,
        url=_epss_url("CVE-xxxx"),
        json={"status": "OK", "data": []},
        status=200,
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_missing_epss_key_returns_zero() -> None:
    """data present but no `epss` key -> 0.0 (uses .get default)."""
    responses.add(
        responses.GET,
        url=_epss_url("CVE-xxxx"),
        json={"status": "OK", "data": [{"cve": "CVE-xxxx"}]},
        status=200,
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_malformed_json_returns_zero() -> None:
    """Non-JSON body -> exception caught -> 0.0."""
    responses.add(
        responses.GET,
        url=_epss_url("CVE-xxxx"),
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
        url=_epss_url("CVE-xxxx"),
        body=responses.ConnectionError("boom"),
    )
    assert prioritization.get_epss_score("CVE-xxxx") == 0.0


@responses.activate
def test_get_epss_score_timeout_returns_zero() -> None:
    """requests.Timeout -> 0.0, no raise."""
    responses.add(
        responses.GET,
        url=_epss_url("CVE-xxxx"),
        body=__import__("requests").exceptions.Timeout("timed out"),
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
