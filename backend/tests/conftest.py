"""
Shared fixtures for the API test suite.

The tests run against a throwaway SQLite file, never the real
cyber_situation_room.db. DATABASE_URL must be set before database.py
is imported, which is why it happens at the top of this file.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest
from sqlalchemy import text

_TMP_DIR = tempfile.mkdtemp(prefix="csr-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_TMP_DIR) / 'test.db'}"

# Make the backend modules importable when pytest runs from backend/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import models  # noqa: E402
from database import SessionLocal, engine  # noqa: E402


ALLOWED_ORIGIN = "http://localhost:5173"


def _reset_caches():
    main._risk_cache["created_at"] = None
    main._risk_cache["prioritized"] = None
    main._risk_cache["summary"] = None
    main._mitre_analysis_cache["created_at"] = None
    main._mitre_analysis_cache["result"] = None


def _clear_tables():
    with engine.begin() as connection:
        for table in ("cves", "threat_events", "sources", "attack_techniques"):
            connection.execute(text(f"DELETE FROM {table}"))


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def empty_db():
    _clear_tables()
    _reset_caches()
    yield
    _clear_tables()
    _reset_caches()


@pytest.fixture
def seeded_db(empty_db):
    """
    Small, fully synthetic dataset. Dates are fixed so results do not
    depend on when the tests are run, except for recency scoring, which
    the tests deliberately avoid asserting exact values for.
    """
    db = SessionLocal()
    try:
        db.add_all(
            [
                models.CVE(
                    cve_id="CVE-2026-0001",
                    description="Test remote code execution",
                    cvss_score=9.8,
                    severity="CRITICAL",
                    published_date="2026-10-30T10:00:00.000",
                    last_modified="2026-10-30",
                    known_exploited=1,
                    kev_date_added="2026-10-31",
                ),
                models.CVE(
                    cve_id="CVE-2026-0002",
                    description="Test cross-site scripting",
                    cvss_score=6.1,
                    severity="MEDIUM",
                    published_date="2026-10-28T10:00:00.000",
                    last_modified="2026-10-28",
                    known_exploited=0,
                ),
                models.CVE(
                    cve_id="CVE-2026-0003",
                    description="Test information disclosure",
                    cvss_score=3.1,
                    severity="LOW",
                    published_date="2026-10-20T10:00:00.000",
                    last_modified="2026-10-20",
                    known_exploited=0,
                ),
                models.ThreatEvent(
                    title="Test advisory: phishing campaign exploits CVE-2026-0001",
                    description=(
                        "Actors send phishing emails and exploit "
                        "CVE-2026-0001 to gain access over SSH."
                    ),
                    event_type="Advisory",
                    severity="HIGH",
                    event_date="2026-10-31",
                    source_name="CISA",
                    source_url="https://www.cisa.gov/",
                    external_id="test-advisory-1",
                    advisory_type="Cybersecurity Advisory",
                ),
                models.AttackTechnique(
                    attack_id="T1566",
                    name="Phishing",
                    tactics="initial-access",
                    url="https://attack.mitre.org/techniques/T1566/",
                ),
                models.AttackTechnique(
                    attack_id="T1021.004",
                    name="SSH",
                    tactics="lateral-movement",
                    url="https://attack.mitre.org/techniques/T1021/004/",
                    is_subtechnique=1,
                ),
            ]
        )
        db.commit()
    finally:
        db.close()

    _reset_caches()
    yield


@pytest.fixture
def advisory_id(seeded_db):
    db = SessionLocal()
    try:
        return (
            db.query(models.ThreatEvent.id)
            .filter(models.ThreatEvent.external_id == "test-advisory-1")
            .scalar()
        )
    finally:
        db.close()
