"""
API tests for Cyber Situation Room.

Run from the backend folder:

    pip install -r requirements-dev.txt
    python -m pytest
"""

import pytest

from conftest import ALLOWED_ORIGIN


LIST_ROUTES = [
    "/",
    "/health",
    "/cves",
    "/vulnerabilities/prioritized",
    "/vulnerabilities/risk-summary",
    "/vulnerabilities/timeline",
    "/threat-intelligence",
    "/threat-intelligence/summary",
    "/intelligence-analysis",
    "/mitre-attack/analysis",
    "/correlations/graph",
]


# ------------------------------------------------------------
# Fresh install: every route must work before any data is loaded
# ------------------------------------------------------------

@pytest.mark.parametrize("path", LIST_ROUTES)
def test_routes_return_200_on_empty_database(client, empty_db, path):
    response = client.get(path)
    assert response.status_code == 200, response.text


def test_risk_summary_is_all_zero_on_empty_database(client, empty_db):
    summary = client.get("/vulnerabilities/risk-summary").json()
    assert summary["total"] == 0
    assert summary["critical"] == 0
    assert summary["known_exploited"] == 0


# ------------------------------------------------------------
# Data correctness on a known dataset
# ------------------------------------------------------------

@pytest.mark.parametrize("path", LIST_ROUTES)
def test_routes_return_200_with_data(client, seeded_db, path):
    response = client.get(path)
    assert response.status_code == 200, response.text


def test_risk_summary_counts_match_seeded_data(client, seeded_db):
    summary = client.get("/vulnerabilities/risk-summary").json()
    assert summary["total"] == 3
    assert summary["nvd_critical"] == 1
    assert summary["nvd_medium"] == 1
    assert summary["nvd_low"] == 1
    assert summary["known_exploited"] == 1


def test_prioritized_puts_known_exploited_critical_first(client, seeded_db):
    prioritized = client.get("/vulnerabilities/prioritized?limit=10").json()
    assert [item["cve_id"] for item in prioritized][0] == "CVE-2026-0001"
    scores = [item["risk_score"] for item in prioritized]
    assert scores == sorted(scores, reverse=True)


def test_risk_debug_components_add_up(client, seeded_db):
    detail = client.get("/vulnerabilities/risk-debug/CVE-2026-0001").json()
    total = (
        detail["cvss_component"]
        + detail["kev_component"]
        + detail["recency_component"]
    )
    assert detail["kev_component"] == 30
    assert detail["risk_score"] == pytest.approx(total, abs=0.2)


def test_advisory_is_correlated_to_the_cve_it_mentions(
    client, advisory_id
):
    data = client.get(
        f"/threat-intelligence/{advisory_id}/correlations"
    ).json()
    assert "CVE-2026-0001" in data["cve_ids"]


def test_advisory_is_mapped_to_mitre_techniques(client, advisory_id):
    data = client.get(
        f"/threat-intelligence/{advisory_id}/mitre-attack"
    ).json()
    mapped = {mapping["attack_id"] for mapping in data["mappings"]}
    assert "T1566" in mapped


def test_timeline_respects_requested_window(client, seeded_db):
    week = client.get("/vulnerabilities/timeline?days=7").json()
    quarter = client.get("/vulnerabilities/timeline?days=90").json()
    assert sum(day["count"] for day in week) == 2
    assert sum(day["count"] for day in quarter) == 3


# ------------------------------------------------------------
# Missing records return 404, not 200 with an error body
# ------------------------------------------------------------

def test_unknown_cve_returns_404(client, seeded_db):
    response = client.get("/vulnerabilities/risk-debug/CVE-1999-0000")
    assert response.status_code == 404


def test_unknown_event_correlations_return_404(client, seeded_db):
    response = client.get("/threat-intelligence/999999/correlations")
    assert response.status_code == 404


def test_unknown_event_mitre_mappings_return_404(client, seeded_db):
    response = client.get("/threat-intelligence/999999/mitre-attack")
    assert response.status_code == 404


# ------------------------------------------------------------
# Hostile input
# ------------------------------------------------------------

@pytest.mark.parametrize(
    "cve_id",
    [
        "CVE-2026-0001' OR '1'='1",
        "CVE-2026-0001\"; DROP TABLE cves; --",
        "..%2F..%2Fetc%2Fpasswd",
        "<script>alert(1)</script>",
    ],
)
def test_injection_attempts_in_cve_id_are_not_found(
    client, seeded_db, cve_id
):
    response = client.get(f"/vulnerabilities/risk-debug/{cve_id}")
    assert response.status_code == 404
    # The table must still be intact afterwards.
    summary = client.get("/vulnerabilities/risk-summary").json()
    assert summary["total"] == 3


def test_non_numeric_event_id_is_rejected(client, seeded_db):
    response = client.get("/threat-intelligence/abc/correlations")
    assert response.status_code == 422


@pytest.mark.parametrize("limit", ["abc", "1.5", ""])
def test_non_integer_limit_is_rejected(client, empty_db, limit):
    response = client.get(f"/cves?limit={limit}")
    assert response.status_code == 422


@pytest.mark.parametrize(
    "path, maximum",
    [
        ("/cves?limit=999999", 2000),
        ("/vulnerabilities/prioritized?limit=999999", 100),
        ("/threat-intelligence?limit=999999", 100),
    ],
)
def test_oversized_limits_are_clamped(client, seeded_db, path, maximum):
    response = client.get(path)
    assert response.status_code == 200
    assert len(response.json()) <= maximum


def test_negative_limit_is_clamped_to_one(client, seeded_db):
    response = client.get("/cves?limit=-5")
    assert response.status_code == 200
    assert len(response.json()) == 1


# ------------------------------------------------------------
# CORS: only the local frontend may read responses in a browser
# ------------------------------------------------------------

def test_cors_allows_the_frontend_origin(client, empty_db):
    response = client.get("/health", headers={"Origin": ALLOWED_ORIGIN})
    assert response.headers.get("access-control-allow-origin") == ALLOWED_ORIGIN


def test_cors_does_not_allow_other_origins(client, empty_db):
    response = client.get(
        "/health", headers={"Origin": "https://attacker.example"}
    )
    assert "access-control-allow-origin" not in response.headers
