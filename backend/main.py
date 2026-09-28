from datetime import datetime, timezone
import re

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text, bindparam

from database import engine, Base, SessionLocal
import models


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

_mitre_analysis_cache = {
    "created_at": None,
    "result": None,
}


app = FastAPI(
    title="Cyber Situation Room",
    description=(
        "Cyber threat intelligence and "
        "situational awareness platform"
    ),
    version="0.3.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE SESSION
# ============================================================

def get_db():
    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "project": "Cyber Situation Room",
        "status": "online",
        "version": "0.3.0"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ============================================================
# GET ALL CVEs
# ============================================================

@app.get("/cves")
def get_cves(
    limit: int = 500,
    db: Session = Depends(get_db)
):
    """
    Return a bounded recent CVE dataset for the dashboard.

    The database can contain tens of thousands of CVEs, so the
    frontend should not download the entire table on every load.
    Use a limit between 1 and 2000.
    """
    limit = max(1, min(limit, 2000))

    cves = (
        db.query(models.CVE)
        .order_by(
            models.CVE.published_date.desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "cvss_score": cve.cvss_score,
            "severity": cve.severity,
            "published_date": cve.published_date,
            "last_modified": cve.last_modified,
            "known_exploited": cve.known_exploited,
            "kev_date_added": cve.kev_date_added,
            "kev_due_date": cve.kev_due_date
        }
        for cve in cves
    ]


# ============================================================
# PARSE NVD DATE
# ============================================================

def parse_nvd_date(date_value):
    """
    Convert an NVD ISO-8601 timestamp into
    a timezone-aware UTC datetime.
    """

    if not date_value:
        return None

    try:

        value = str(
            date_value
        ).strip()

        if value.endswith("Z"):
            value = (
                value[:-1]
                + "+00:00"
            )

        parsed = datetime.fromisoformat(
            value
        )

        if parsed.tzinfo is None:

            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    except (
        ValueError,
        TypeError
    ):

        return None


# ============================================================
# RECENCY SCORE
# ============================================================

def calculate_recency_score(
    published_date
):

    published = parse_nvd_date(
        published_date
    )

    if published is None:

        return {
            "recency_score": 0,
            "age_days": None
        }

    now = datetime.now(
        timezone.utc
    )

    age_seconds = (
        now - published
    ).total_seconds()

    age_days = max(
        0,
        age_seconds / 86400
    )

    if age_days <= 7:

        recency_score = 10

    elif age_days <= 30:

        recency_score = 7

    elif age_days <= 60:

        recency_score = 4

    elif age_days <= 90:

        recency_score = 2

    else:

        recency_score = 0

    return {
        "recency_score": recency_score,
        "age_days": round(
            age_days,
            2
        )
    }


# ============================================================
# RISK SCORE COMPONENTS
# ============================================================

def calculate_risk_components(cve):
    """
    Cyber Situation Room derived risk score.

    CVSS:
        Maximum 60 points

    KEV:
        Maximum 30 points

    Recency:
        Maximum 10 points

    Total:
        Maximum 100 points

    This is NOT an official NVD or CISA score.
    """

    # --------------------------------------------------------
    # CVSS
    # --------------------------------------------------------

    cvss_component = 0.0

    if cve.cvss_score is not None:

        cvss_score = float(
            cve.cvss_score
        )

        cvss_component = (
            cvss_score / 10
        ) * 60

    # --------------------------------------------------------
    # KEV
    # --------------------------------------------------------

    kev_component = 0

    if cve.known_exploited == 1:

        kev_component = 30

    # --------------------------------------------------------
    # RECENCY
    # --------------------------------------------------------

    recency = calculate_recency_score(
        cve.published_date
    )

    recency_component = recency[
        "recency_score"
    ]

    age_days = recency[
        "age_days"
    ]

    # --------------------------------------------------------
    # TOTAL
    # --------------------------------------------------------

    total = (
        cvss_component
        + kev_component
        + recency_component
    )

    total = min(
        total,
        100
    )

    return {
        "cvss_component": round(
            cvss_component,
            1
        ),
        "kev_component": kev_component,
        "recency_component": recency_component,
        "age_days": age_days,
        "risk_score": round(
            total,
            1
        )
    }


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(cve):

    components = calculate_risk_components(
        cve
    )

    return components[
        "risk_score"
    ]


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 85:

        return "CRITICAL"

    if score >= 70:

        return "HIGH"

    if score >= 40:

        return "MEDIUM"

    return "LOW"


# ============================================================
# DASHBOARD RISK CACHE
# ============================================================

# Risk calculations are derived from the full CVE dataset.
# Cache them briefly so the dashboard does not recalculate
# ~30,000 CVEs separately for every endpoint request.
RISK_CACHE_TTL_SECONDS = 30

_risk_cache = {
    "created_at": None,
    "prioritized": None,
    "summary": None
}


def build_risk_cache(db: Session):
    now = datetime.now(timezone.utc)

    cached_at = _risk_cache["created_at"]

    if (
        cached_at is not None
        and _risk_cache["prioritized"] is not None
        and _risk_cache["summary"] is not None
    ):
        age = (now - cached_at).total_seconds()

        if age < RISK_CACHE_TTL_SECONDS:
            return (
                _risk_cache["prioritized"],
                _risk_cache["summary"]
            )

    cves = (
        db.query(models.CVE)
        .order_by(models.CVE.published_date.desc())
        .all()
    )

    prioritized = []

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "known_exploited": 0,
        "total": len(cves),
        "nvd_critical": 0,
        "nvd_high": 0,
        "nvd_medium": 0,
        "nvd_low": 0,
        "priority_risks": 0
    }

    for cve in cves:
        components = calculate_risk_components(cve)

        risk_score = components["risk_score"]
        risk_level = get_risk_level(risk_score)

        if risk_level == "CRITICAL":
            summary["critical"] += 1
        elif risk_level == "HIGH":
            summary["high"] += 1
        elif risk_level == "MEDIUM":
            summary["medium"] += 1
        else:
            summary["low"] += 1

        nvd_severity = (cve.severity or "").upper()
        if nvd_severity == "CRITICAL":
            summary["nvd_critical"] += 1
        elif nvd_severity == "HIGH":
            summary["nvd_high"] += 1
        elif nvd_severity == "MEDIUM":
            summary["nvd_medium"] += 1
        elif nvd_severity == "LOW":
            summary["nvd_low"] += 1

        if cve.known_exploited == 1:
            summary["known_exploited"] += 1

        prioritized.append(
            {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_score": cve.cvss_score,
                "severity": cve.severity,
                "published_date": cve.published_date,
                "last_modified": cve.last_modified,
                "known_exploited": cve.known_exploited,
                "kev_date_added": cve.kev_date_added,
                "kev_due_date": cve.kev_due_date,
                "cvss_component": components["cvss_component"],
                "kev_component": components["kev_component"],
                "recency_component": components["recency_component"],
                "age_days": components["age_days"],
                "risk_score": risk_score,
                "risk_level": risk_level
            }
        )

    prioritized.sort(
        key=lambda item: (
            item["risk_score"],
            item["known_exploited"],
            item["cvss_score"] or 0
        ),
        reverse=True
    )

    summary["priority_risks"] = (
        summary["critical"] + summary["high"]
    )

    _risk_cache["created_at"] = now
    _risk_cache["prioritized"] = prioritized
    _risk_cache["summary"] = summary

    return prioritized, summary


# ============================================================
# PRIORITIZED VULNERABILITIES
# ============================================================

@app.get(
    "/vulnerabilities/prioritized"
)
def get_prioritized_vulnerabilities(
    limit: int = 25,
    db: Session = Depends(get_db)
):
    """
    Return vulnerabilities ranked by the derived risk score.

    Full-dataset calculation is cached briefly to avoid repeated
    scans when the dashboard loads multiple endpoints.
    """
    limit = max(1, min(limit, 100))

    prioritized, _summary = build_risk_cache(db)

    return prioritized[:limit]


# ============================================================
# RISK SUMMARY
# ============================================================

@app.get(
    "/vulnerabilities/risk-summary"
)
def get_risk_summary(
    db: Session = Depends(get_db)
):
    """
    Return cached derived vulnerability risk counts.
    """
    _prioritized, summary = build_risk_cache(db)
    return summary


# ============================================================
# VULNERABILITY TIMELINE
# ============================================================

@app.get("/vulnerabilities/timeline")
def get_vulnerability_timeline(
    days: int = 90,
    db: Session = Depends(get_db)
):
    """
    Return daily CVE publication counts for the requested period.

    This avoids sending thousands of CVE rows to the browser just
    to construct the timeline chart.
    """
    days = max(1, min(days, 365))

    # Anchor the requested window to the newest CVE date available in the
    # local dataset rather than the machine's current calendar date. This
    # keeps 7D/30D/90D meaningful when the dashboard database is not live.
    latest_date = db.execute(
        text(
            """
            SELECT MAX(date(substr(published_date, 1, 10)))
            FROM cves
            WHERE published_date IS NOT NULL
              AND published_date != ''
              AND date(substr(published_date, 1, 10)) IS NOT NULL
            """
        )
    ).scalar()

    if not latest_date:
        return []

    rows = db.execute(
        text(
            """
            SELECT
                substr(published_date, 1, 10) AS date,
                COUNT(*) AS count
            FROM cves
            WHERE published_date IS NOT NULL
              AND published_date != ''
              AND date(substr(published_date, 1, 10))
                  >= date(:latest_date, :days)
              AND date(substr(published_date, 1, 10))
                  <= date(:latest_date)
            GROUP BY substr(published_date, 1, 10)
            ORDER BY date ASC
            """
        ),
        {"latest_date": latest_date, "days": f"-{days - 1} days"}
    ).fetchall()

    return [
        {
            "date": row[0],
            "count": row[1]
        }
        for row in rows
    ]


# ============================================================
# RISK DEBUG / EXPLAINABILITY
# ============================================================

@app.get(
    "/vulnerabilities/risk-debug/{cve_id}"
)
def get_risk_debug(
    cve_id: str,
    db: Session = Depends(get_db)
):

    cve = (
        db.query(models.CVE)
        .filter(
            models.CVE.cve_id
            == cve_id
        )
        .first()
    )

    if not cve:

        return {
            "error": "CVE not found"
        }

    components = (
        calculate_risk_components(
            cve
        )
    )

    return {
        "cve_id": cve.cve_id,

        "published_date": (
            cve.published_date
        ),

        "cvss_score": (
            cve.cvss_score
        ),

        "known_exploited": (
            cve.known_exploited
        ),

        "age_days": components[
            "age_days"
        ],

        "cvss_component": components[
            "cvss_component"
        ],

        "kev_component": components[
            "kev_component"
        ],

        "recency_component": components[
            "recency_component"
        ],

        "risk_score": components[
            "risk_score"
        ],

        "risk_level": get_risk_level(
            components[
                "risk_score"
            ]
        )
    }


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

@app.get(
    "/threat-intelligence"
)
def get_threat_intelligence(
    limit: int = 30,
    db: Session = Depends(get_db)
):

    limit = max(
        1,
        min(
            limit,
            100
        )
    )

    events = (
        db.query(
            models.ThreatEvent
        )
        .order_by(
            models.ThreatEvent.id.desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "id": event.id,
            "title": event.title,
            "description": event.description,
            "event_type": event.event_type,
            "severity": event.severity,
            "event_date": event.event_date,
            "source_name": event.source_name,
            "source_url": event.source_url,
            "external_id": event.external_id,
            "advisory_type": event.advisory_type
        }

        for event in events
    ]


# ============================================================
# THREAT INTELLIGENCE / CVE CORRELATION
# ============================================================

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@app.get("/threat-intelligence/{event_id}/correlations")
def get_threat_correlations(
    event_id: int,
    db: Session = Depends(get_db)
):
    """
    Correlate a threat-intelligence advisory with CVEs mentioned
    in its title/description and enrich matching CVEs with NVD,
    KEV, and Cyber Situation Room derived risk information.
    """

    event = (
        db.query(models.ThreatEvent)
        .filter(models.ThreatEvent.id == event_id)
        .first()
    )

    if not event:
        return {
            "event_id": event_id,
            "cve_ids": [],
            "correlations": []
        }

    text_blob = f"{event.title or ''} {event.description or ''}"

    cve_ids = sorted(
        {match.upper() for match in CVE_PATTERN.findall(text_blob)}
    )

    correlations = []

    for cve_id in cve_ids:
        cve = (
            db.query(models.CVE)
            .filter(models.CVE.cve_id == cve_id)
            .first()
        )

        if not cve:
            correlations.append({
                "cve_id": cve_id,
                "found_in_database": False
            })
            continue

        components = calculate_risk_components(cve)
        risk_score = components["risk_score"]

        correlations.append({
            "cve_id": cve.cve_id,
            "found_in_database": True,
            "cvss_score": cve.cvss_score,
            "nvd_severity": cve.severity,
            "known_exploited": cve.known_exploited == 1,
            "kev_date_added": cve.kev_date_added,
            "kev_due_date": cve.kev_due_date,
            "published_date": cve.published_date,
            "risk_score": risk_score,
            "risk_level": get_risk_level(risk_score)
        })

    return {
        "event_id": event_id,
        "cve_ids": cve_ids,
        "correlations": correlations
    }



# ============================================================
# INTELLIGENCE ANALYSIS
# ============================================================

@app.get("/intelligence-analysis")
def get_intelligence_analysis(
    db: Session = Depends(get_db)
):
    """
    Derived intelligence analysis based only on explicit CVE
    identifiers found in CISA threat-intelligence records.
    """

    events = (
        db.query(models.ThreatEvent)
        .all()
    )

    total_advisories = len(events)
    advisories_with_cves = 0
    total_cve_mentions = 0

    cve_reference_counts = {}

    matched_cves = {}
    unmatched_cves = set()

    for event in events:

        text_blob = (
            f"{event.title or ''} "
            f"{event.description or ''}"
        )

        cve_ids = sorted(
            {
                match.upper()
                for match in CVE_PATTERN.findall(text_blob)
            }
        )

        if not cve_ids:
            continue

        advisories_with_cves += 1
        total_cve_mentions += len(cve_ids)

        for cve_id in cve_ids:

            cve_reference_counts[cve_id] = (
                cve_reference_counts.get(cve_id, 0) + 1
            )

            cve = (
                db.query(models.CVE)
                .filter(
                    models.CVE.cve_id == cve_id
                )
                .first()
            )

            if not cve:
                unmatched_cves.add(cve_id)
                continue

            components = calculate_risk_components(cve)
            risk_score = components["risk_score"]
            risk_level = get_risk_level(risk_score)

            matched_cves[cve_id] = {
                "cve_id": cve.cve_id,
                "reference_count": cve_reference_counts[cve_id],
                "cvss_score": cve.cvss_score,
                "nvd_severity": cve.severity,
                "known_exploited": cve.known_exploited == 1,
                "risk_score": risk_score,
                "risk_level": risk_level
            }

    nvd_matched = len(matched_cves)
    unmatched_count = len(unmatched_cves)

    kev_correlated = sum(
        1
        for item in matched_cves.values()
        if item["known_exploited"]
    )

    high_critical_correlated = sum(
        1
        for item in matched_cves.values()
        if item["risk_level"] in {
            "HIGH",
            "CRITICAL"
        }
    )

    risk_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for item in matched_cves.values():

        level = (
            item["risk_level"]
            or "LOW"
        ).lower()

        if level in risk_distribution:
            risk_distribution[level] += 1

    top_referenced = sorted(
        [
            {
                "cve_id": cve_id,
                "reference_count": count,
                "nvd_match": cve_id in matched_cves
            }
            for cve_id, count
            in cve_reference_counts.items()
        ],
        key=lambda item: (
            -item["reference_count"],
            item["cve_id"]
        )
    )[:10]

    highest_risk = sorted(
        matched_cves.values(),
        key=lambda item: (
            -item["risk_score"],
            -item["reference_count"]
        )
    )[:10]

    return {
        "analysis_scope": {
            "source": "CISA",
            "correlation_method": "explicit_cve_identifier",
            "total_advisories": total_advisories
        },

        "correlation_metrics": {
            "advisories_with_cves": advisories_with_cves,
            "total_cve_mentions": total_cve_mentions,
            "unique_cve_references": len(
                cve_reference_counts
            ),
            "nvd_matched": nvd_matched,
            "nvd_unmatched": unmatched_count,
            "kev_correlated": kev_correlated,
            "high_critical_correlated": high_critical_correlated
        },

        "risk_distribution": risk_distribution,

        "top_referenced_cves": top_referenced,

        "highest_risk_correlations": highest_risk,

        "unmatched_cves": sorted(
            unmatched_cves
        )[:25]
    }





# ============================================================
# MITRE ATT&CK ANALYSIS
# ============================================================


def normalize_attack_text(value):
    value = value or ""
    return re.sub(r"\s+", " ", value).strip()


def phrase_pattern(phrase):
    escaped = re.escape((phrase or "").strip())
    escaped = escaped.replace(r"\ ", r"\s+")
    return re.compile(
        r"(?<![A-Za-z0-9])" + escaped + r"(?![A-Za-z0-9])",
        re.I,
    )


def extract_attack_evidence(text_blob, technique_name):
    if not text_blob or not technique_name:
        return None

    match = phrase_pattern(technique_name).search(text_blob)
    if not match:
        return None

    start = max(0, match.start() - 100)
    end = min(len(text_blob), match.end() + 140)
    evidence = normalize_attack_text(text_blob[start:end])

    if start > 0:
        evidence = "..." + evidence
    if end < len(text_blob):
        evidence += "..."

    return evidence


# Generic ATT&CK names that occur naturally in vulnerability advisories.
# These are excluded because a literal word/phrase is not meaningful
# evidence of the corresponding ATT&CK behavior.
BLOCKED_GENERIC_ATTACK_NAMES = {
    "at",
    "software",
    "server",
    "tool",
    "domains",
    "credentials",
    "hardware",
    "files",
    "process",
    "data",
    "network",
    "account",
    "accounts",
    "system",
    "service",
    "services",
    "application",
    "applications",
    "user",
    "users",
    "web",
    "email",
    "command",
    "vulnerabilities",
    "firmware",
    "dll",
}


# Context rules are deliberately behavior-oriented rather than merely
# checking whether a common word appears somewhere in an advisory.
BEHAVIOR_RULES = {
    "phishing": [
        r"\bphishing campaign\b",
        r"\bphishing attack\b",
        r"\bphishing attacks\b",
        r"\bphishing email campaign\b",
        r"\bphishing emails?\s+(?:sent|used|delivered|targeted|distributed)\b",
        r"\bspearphishing\b",
        r"\bspear[- ]phishing\b",
    ],
    "social engineering": [
        r"\bsocial engineering campaign\b",
        r"\bsocial engineering attack\b",
        r"\bsocial engineering attacks\b",
        r"\bsocial engineering scheme\b",
        r"\bsocial engineering operation\b",
        r"\bsocial engineering technique\b",
    ],
    "impersonation": [
        r"\bimpersonat(?:e|es|ed|ing|ion)\b",
        r"\bpretend(?:s|ed|ing)? to be\b",
        r"\bmasquerad(?:e|es|ed|ing)\b",
        r"\bimpersonat(?:e|ion)\s+(?:a|an|the)\b",
    ],
    "ssh": [
        r"\bSSH\s+(?:access|connection|connections|server|servers|service|services|session|sessions|login|logins|key|keys|credentials)\b",
        r"\bremote\s+SSH\b",
        r"\bvia\s+SSH\b",
        r"\bover\s+SSH\b",
        r"\bSSH[- ]based\b",
    ],
    "proxy": [
        r"\bproxy\s+(?:server|servers|network|networks|connection|connections)\b",
        r"\bvia\s+(?:a\s+)?proxy\b",
        r"\bproxy\s+command\b",
        r"\bproxy\s+traffic\b",
        r"\bproxy\s+chains?\b",
    ],
    "acquire infrastructure": [
        r"\bacquir(?:e|es|ed|ing)\s+(?:infrastructure|servers?|domains?|cloud infrastructure)\b",
        r"\b(?:purchase|rent|lease|obtain)\s+(?:infrastructure|servers?|domains?)\b",
        r"\bestablish(?:es|ed|ing)?\s+(?:infrastructure|servers?)\b",
    ],
    "network devices": [
        r"\bnetwork devices?\s+(?:for|used for)\s+(?:reconnaissance|scanning|enumeration|discovery)\b",
        r"\bdiscover(?:ing|y)?\s+(?:network devices?|routers?|switches?)\b",
        r"\bscan(?:ning)?\s+(?:network devices?|routers?|switches?)\b",
        r"\benumerat(?:e|es|ed|ing|ion)\s+(?:network devices?|routers?|switches?)\b",
    ],
    "artificial intelligence": [
        r"\bAI\s+(?:models?|systems?|services?|platforms?)\b",
        r"\bartificial intelligence\s+(?:models?|systems?|services?|platforms?)\b",
        r"\bAI\s+(?:distillation|training|inference|model extraction)\b",
        r"\bmodel\s+(?:distillation|extraction)\b",
    ],
}


# Phrases commonly inserted by CISA as generic defensive guidance.
# A technique should not be attributed merely because it occurs inside
# these boilerplate recommendations.
BOILERPLATE_CONTEXTS = [
    re.compile(
        r"Avoiding Social Engineering and Phishing Attacks",
        re.I,
    ),
    re.compile(
        r"protect themselves from social engineering attacks",
        re.I,
    ),
    re.compile(
        r"Do not click web links or open attachments in unsolicited email messages",
        re.I,
    ),
    re.compile(
        r"avoiding email scams",
        re.I,
    ),
]


def is_boilerplate_match(text, match):
    if not match:
        return False

    start = max(0, match.start() - 220)
    end = min(len(text), match.end() + 220)
    window = text[start:end]

    return any(pattern.search(window) for pattern in BOILERPLATE_CONTEXTS)


def has_behavior_context(technique_name, text):
    name = normalize_attack_text(technique_name)
    name_lower = name.lower()

    rules = BEHAVIOR_RULES.get(name_lower)

    if not rules:
        return True

    for rule in rules:
        match = re.search(rule, text, re.I)
        if match and not is_boilerplate_match(text, match):
            return True

    return False



def _v5_normalized(text):
    return normalize_attack_text(text or "")


# V5 is intentionally conservative. A literal ATT&CK technique name is
# NOT sufficient evidence. A candidate must also have behavior-oriented
# evidence in the advisory. These are derived candidate mappings, not
# official MITRE/CISA attribution.

V5_REJECTED_GENERIC_NAMES = {
    "at", "software", "server", "tool", "domains", "credentials",
    "hardware", "files", "process", "data", "network", "account",
    "accounts", "system", "service", "services", "application",
    "applications", "user", "users", "web", "email", "command",
    "vulnerabilities", "firmware", "dll", "ip addresses",
}

V5_CROSS_FRAMEWORK_PATTERNS = [
    re.compile(r"\bMITRE\s+ATLAS\b", re.I),
    re.compile(r"\bATLAS\s+Mappings?\b", re.I),
    re.compile(r"\bAML\.[A-Z0-9.-]+\b", re.I),
]

V5_DEFENSIVE_PATTERNS = [
    re.compile(r"\brecommend(?:s|ed|ing)?\b", re.I),
    re.compile(r"\bshould\s+(?:restrict|block|disable|remove|limit)\b", re.I),
    re.compile(r"\brestrict(?:ing|ed)?\s+(?:the\s+)?(?:IP addresses?|access)\b", re.I),
    re.compile(r"\bmitigat(?:e|es|ed|ing|ion)\b", re.I),
    re.compile(r"\bprotect(?:s|ed|ing)?\s+(?:users?|organizations?|customers?)\b", re.I),
    re.compile(r"\bapply\s+(?:the\s+)?(?:update|patch|mitigation)\b", re.I),
]

V5_BOILERPLATE_PATTERNS = [
    re.compile(r"Avoiding Social Engineering and Phishing Attacks", re.I),
    re.compile(r"protect themselves from social engineering attacks", re.I),
    re.compile(
        r"Do not click web links or open attachments in unsolicited email messages",
        re.I,
    ),
    re.compile(r"avoiding email scams", re.I),
]

V5_BEHAVIOR_RULES = {
    "impersonation": [
        r"\b(?:attacker|adversary|threat actor|actor|campaign|operation|group|criminals?)\b.{0,180}\bimpersonat(?:e|es|ed|ing|ion)\b",
        r"\bimpersonat(?:e|es|ed|ing)\b.{0,180}\b(?:victim|user|administrator|employee|organization|vendor|company|service)\b",
        r"\b(?:pretend|masquerad(?:e|es|ed|ing))\b.{0,120}\b(?:as|to be)\b",
    ],
    "ssh": [
        r"\b(?:attacker|adversary|threat actor|actor|group)\b.{0,180}\b(?:use|uses|used|using|access|accessed|connect|connected|connects|login|logged in)\b.{0,120}\bSSH\b",
        r"\b(?:SSH|secure shell)\b.{0,120}\b(?:attacker|adversary|threat actor|actor)\b",
        r"\b(?:remote access|remote connection)\b.{0,100}\bvia\s+SSH\b",
    ],
    "proxy": [
        r"\b(?:attacker|adversary|threat actor|actor|campaign|operation)\b.{0,180}\b(?:use|uses|used|using|route|routes|routed|routing)\b.{0,120}\bproxy\b",
        r"\bproxy\b.{0,150}\b(?:conceal|conceals|concealed|hide|hides|hidden|obfuscate|obfuscates|obfuscated)\b.{0,100}\b(?:traffic|connection|source|origin)\b",
        r"\bproxy\s+chains?\b.{0,120}\b(?:attacker|adversary|threat actor|actor)\b",
    ],
    "acquire infrastructure": [
        r"\b(?:attacker|adversary|threat actor|actor|group|campaign|operation)\b.{0,180}\b(?:acquir(?:e|es|ed|ing)|purchase|purchased|rent|rented|lease|leased|obtain|obtained|establish|established|maintain|maintained)\b.{0,120}\b(?:infrastructure|servers?|domains?|cloud infrastructure)\b",
        r"\b(?:acquir(?:e|es|ed|ing)|purchase|purchased|rent|rented|lease|leased|obtain|obtained|establish|established)\b.{0,120}\b(?:infrastructure|servers?|domains?)\b.{0,120}\b(?:attacker|adversary|threat actor|actor|group)\b",
    ],
    "network devices": [
        r"\b(?:attacker|adversary|threat actor|actor|group)\b.{0,180}\b(?:discover|discovers|discovered|discovering|scan|scans|scanned|scanning|enumerate|enumerates|enumerated|enumerating)\b.{0,120}\b(?:network devices?|routers?|switches?)\b",
        r"\b(?:network devices?|routers?|switches?)\b.{0,150}\b(?:attacker|adversary|threat actor|actor)\b.{0,120}\b(?:discover|scan|enumerat)\w*\b",
    ],
    "artificial intelligence": [
        r"\b(?:attacker|adversary|threat actor|actor|group)\b.{0,180}\b(?:obtain|obtains|obtained|acquire|acquires|acquired|use|uses|used|using)\b.{0,120}\b(?:AI|artificial intelligence)\b",
        r"\b(?:AI|artificial intelligence)\b.{0,150}\b(?:capabilit(?:y|ies)|models?|services?)\b.{0,120}\b(?:attacker|adversary|threat actor|actor)\b",
    ],
}

def _v5_is_cross_framework(text):
    return any(p.search(text or "") for p in V5_CROSS_FRAMEWORK_PATTERNS)

def _v5_is_boilerplate(text):
    return any(p.search(text or "") for p in V5_BOILERPLATE_PATTERNS)

def _v5_behavior_match(technique_name, text):
    name = _v5_normalized(technique_name).lower()
    rules = V5_BEHAVIOR_RULES.get(name)

    # No behavior rule means there is no safe basis for a derived mapping.
    if not rules:
        return None

    for rule in rules:
        match = re.search(rule, text or "", re.I | re.S)
        if not match:
            continue

        start = max(0, match.start() - 260)
        end = min(len(text or ""), match.end() + 260)
        window = (text or "")[start:end]

        if _v5_is_boilerplate(window):
            continue
        if _v5_is_cross_framework(window):
            continue
        if any(p.search(window) for p in V5_DEFENSIVE_PATTERNS):
            continue

        return match

    return None


def quality_filter_attack_mappings(event, mappings):
    # V5.1: balanced context validation.
    # Exact technique-name matching is retained, but rigid attacker/action
    # regexes are replaced by broader local behavioral context checks.
    # These are derived candidate mappings, not official MITRE attribution.

    import re

    title = normalize_attack_text(getattr(event, "title", ""))
    description = normalize_attack_text(getattr(event, "description", ""))
    full_text = f"{title} {description}".strip()

    blocked = {
        "at", "software", "server", "tool", "domains", "credentials",
        "hardware", "files", "process", "data", "network", "account",
        "accounts", "system", "service", "services", "application",
        "applications", "user", "users", "web", "email", "command",
        "vulnerabilities", "firmware", "dll", "ip addresses",
    }

    context_rules = {
        "impersonation": [
            r"\bimpersonat\w*\b", r"\bmasquerad\w*\b",
            r"\bpretend(?:s|ed|ing)?\s+to\s+be\b",
            r"\bpose(?:s|d)?\s+as\b", r"\bspoof(?:ed|ing|s)?\b",
        ],
        "ssh": [
            r"\bSSH\b", r"\bSecure Shell\b", r"\bremote\s+SSH\b",
            r"\bSSH[- ]based\b",
        ],
        "proxy": [
            r"\bproxy\s+(?:network|server|traffic|chain)\b",
            r"\bvia\s+(?:a\s+)?proxy\b",
            r"\bproxy\b",
        ],
        "acquire infrastructure": [
            r"\bacquir\w*\b", r"\bpurchas\w*\b", r"\brent\w*\b",
            r"\bleas\w*\b", r"\bobtain\w*\b", r"\bestablish\w*\b",
            r"\binfrastructure\b",
        ],
        "network devices": [
            r"\bnetwork\s+devices?\b", r"\brouters?\b", r"\bswitches?\b",
            r"\bscan\w*\b", r"\benumerat\w*\b", r"\bdiscover\w*\b",
        ],
        "artificial intelligence": [
            r"\bartificial\s+intelligence\b", r"\bAI\b",
            r"\bAI\s+models?\b", r"\bmodel\s+(?:distillation|extraction)\b",
        ],
        "phishing": [
            r"\bphishing\b", r"\bspearphishing\b",
        ],
        "social engineering": [
            r"\bsocial\s+engineering\b",
        ],
    }

    adversarial = [
        r"\battacker\w*\b", r"\badversar\w*\b",
        r"\bthreat\s+actor\w*\b", r"\bmalicious\w*\b",
        r"\bexploit\w*\b", r"\battack\w*\b", r"\bcampaign\w*\b",
        r"\boperation\w*\b", r"\bcompromis\w*\b", r"\babus\w*\b",
        r"\bfraudulent\w*\b", r"\bcriminal\w*\b", r"\btarget\w*\b",
        r"\bimpersonat\w*\b", r"\bphishing\b", r"\bspearphishing\b",
        r"\bsocial\s+engineering\b", r"\bmalware\b", r"\bransomware\b",
    ]

    boilerplate = [
        r"Avoiding Social Engineering and Phishing Attacks",
        r"protect themselves from social engineering attacks",
        r"Do not click web links or open attachments in unsolicited email messages",
        r"avoiding email scams",
    ]

    cross_framework = [
        r"\bMITRE\s+ATLAS\b",
        r"\bATLAS\s+Mappings?\b",
        r"\bMITRE\s+ATLAS\s+Mappings?\b",
        r"\bAML\.[A-Z0-9.-]+\b",
    ]

    defensive = [
        r"\bCISA\s+recommends\b",
        r"\bmitigat(?:e|es|ed|ing|ion)\b",
        r"\b(?:restrict|block|disable|limit)\b.{0,100}\b(?:access|IP\s+addresses?|connections?)\b",
        r"\bapply\s+(?:the\s+)?(?:update|patch|mitigation)\b",
        r"\binstall\s+(?:the\s+)?(?:update|patch)\b",
    ]

    def any_match(patterns, text):
        return any(re.search(p, text or "", re.I | re.S) for p in patterns)

    def window(text, match, radius=420):
        a = max(0, match.start() - radius)
        b = min(len(text), match.end() + radius)
        return text[a:b]

    filtered = []
    seen = set()

    for mapping in mappings:
        name = normalize_attack_text(mapping.get("technique_name", ""))
        key_name = name.lower()

        if not name or key_name in blocked:
            continue

        title_match = phrase_pattern(name).search(title)
        body_match = phrase_pattern(name).search(description)
        if not title_match and not body_match:
            continue

        anchor = title_match or body_match
        evidence_window = window(full_text, anchor)

        # Never use another framework's mapping table as Enterprise ATT&CK
        # evidence.
        if any_match(cross_framework, evidence_window):
            continue

        rules = context_rules.get(key_name)
        if not rules or not any_match(rules, evidence_window):
            continue

        # Remove clearly defensive-only context. If there is also an
        # adversarial signal nearby, keep it for further validation.
        if any_match(defensive, evidence_window) and not any_match(adversarial, evidence_window):
            continue

        # Technique-specific safeguards.
        if key_name == "impersonation":
            if not any_match([
                r"\b(?:attacker|adversar\w*|threat\s+actor|actor)\b.{0,220}\bimpersonat\w*\b",
                r"\bimpersonat\w*\b.{0,220}\b(?:user|administrator|employee|organization|vendor|company|victim)\b",
                r"\b(?:pretend|masquerad|pose|spoof)\w*\b",
            ], evidence_window):
                continue

        if key_name == "proxy":
            if not any_match([
                r"\bproxy\s+(?:network|server|traffic|chain)\b",
                r"\bvia\s+(?:a\s+)?proxy\b",
                r"\bproxy\b.{0,160}\b(?:malicious|fraudulent|attack|actor|adversar\w*|conceal|hide|route)\w*\b",
            ], evidence_window):
                continue

        if key_name == "acquire infrastructure":
            if not any_match([
                r"\bacquir\w*\b", r"\bpurchas\w*\b", r"\brent\w*\b",
                r"\bleas\w*\b", r"\bobtain\w*\b", r"\bestablish\w*\b",
            ], evidence_window):
                continue

        if key_name == "network devices":
            if not any_match([
                r"\bscan\w*\b", r"\benumerat\w*\b",
                r"\bdiscover\w*\b", r"\breconnaissance\b",
            ], evidence_window):
                continue

        if key_name == "artificial intelligence":
            # AI as a topic is insufficient. Require an adversarial context.
            if not any_match(adversarial, evidence_window):
                continue

        if any_match(boilerplate, evidence_window):
            # Boilerplate alone must never create a mapping.
            if not any_match(adversarial, evidence_window):
                continue

        evidence = extract_attack_evidence(full_text, name)
        if not evidence:
            continue

        # HIGH means the title itself contains both the technique and a
        # meaningful adversarial signal. Otherwise use MEDIUM.
        confidence = "HIGH" if (
            title_match and any_match(adversarial, title)
        ) else "MEDIUM"

        mapping["confidence"] = confidence
        mapping["evidence"] = evidence
        mapping["match_type"] = "derived_context_validated_candidate_v5_1"

        key = (mapping.get("event_id"), mapping.get("attack_id"))
        if key in seen:
            continue

        seen.add(key)
        filtered.append(mapping)

    return filtered


@app.get("/threat-intelligence/{event_id}/mitre-attack")
def get_threat_attack_mappings(
    event_id: int,
    db: Session = Depends(get_db)
):
    event = (
        db.query(models.ThreatEvent)
        .filter(models.ThreatEvent.id == event_id)
        .first()
    )

    if not event:
        return {"event_id": event_id, "mappings": []}

    text_blob = normalize_attack_text(
        f"{event.title or ''} {event.description or ''}"
    )
    title_blob = normalize_attack_text(event.title or "")

    rows = db.execute(
        text(
            "SELECT attack_id, name, tactics, url "
            "FROM attack_techniques "
            "ORDER BY LENGTH(name) DESC"
        )
    ).fetchall()

    mappings = []

    for row in rows:
        evidence = extract_attack_evidence(text_blob, row[1])

        if not evidence:
            continue

        title_evidence = extract_attack_evidence(title_blob, row[1])

        mappings.append({
            "attack_id": row[0],
            "technique_name": row[1],
            "tactics": row[2] or "",
            "url": row[3] or "",
            "evidence": title_evidence or evidence,
            "confidence": "HIGH" if title_evidence else "MEDIUM",
            "match_type": "derived_context_validated_candidate_v5_1",
        })

    mappings = quality_filter_attack_mappings(event, mappings)

    return {
        "event_id": event_id,
        "mapping_method": (
            "derived_context_validated_candidate_v5_1"
        ),
        "mappings": mappings,
    }


@app.get("/mitre-attack/analysis")
def get_mitre_attack_analysis(
    db: Session = Depends(get_db)
):
    # Cache the derived analysis because the dashboard requests it on load.
    # The underlying CISA/ATT&CK data changes only when ingestion runs.
    global _mitre_analysis_cache

    now = datetime.now(timezone.utc)
    cached = _mitre_analysis_cache.get("result")
    cached_at = _mitre_analysis_cache.get("created_at")

    if cached is not None and cached_at is not None:
        if (now - cached_at).total_seconds() < 300:
            return cached

    events = db.query(models.ThreatEvent).all()

    # The existing V5.1 quality filter only permits these exact technique
    # names to survive validation. Restricting the catalog query to those
    # candidates avoids scanning the entire ATT&CK catalog for every advisory
    # while preserving the existing mapping and output logic.
    candidate_names = tuple(BEHAVIOR_RULES.keys())
    technique_rows = db.execute(
        text(
            "SELECT attack_id, name, tactics, url "
            "FROM attack_techniques "
            "WHERE LOWER(name) IN :candidate_names "
            "ORDER BY LENGTH(name) DESC"
        ).bindparams(bindparam("candidate_names", expanding=True)),
        {"candidate_names": candidate_names},
    ).fetchall()

    total_mappings = 0
    events_with_mappings = 0
    high_confidence = 0
    medium_confidence = 0
    technique_counts = {}
    tactic_counts = {}
    mappings = []

    for event in events:
        text_blob = normalize_attack_text(
            f"{event.title or ''} {event.description or ''}"
        )
        title_blob = normalize_attack_text(event.title or "")
        event_mappings = []

        for row in technique_rows:
            evidence = extract_attack_evidence(text_blob, row[1])

            if not evidence:
                continue

            title_evidence = extract_attack_evidence(title_blob, row[1])

            event_mappings.append({
                "event_id": event.id,
                "event_title": event.title,
                "attack_id": row[0],
                "technique_name": row[1],
                "tactics": row[2] or "",
                "confidence": "HIGH" if title_evidence else "MEDIUM",
                "evidence": title_evidence or evidence,
                "url": row[3] or "",
            })

        event_mappings = quality_filter_attack_mappings(
            event,
            event_mappings,
        )

        if event_mappings:
            events_with_mappings += 1

        for mapping in event_mappings:
            total_mappings += 1

            if mapping["confidence"] == "HIGH":
                high_confidence += 1
            else:
                medium_confidence += 1

            technique_key = (
                mapping["attack_id"],
                mapping["technique_name"],
            )

            technique_counts[technique_key] = (
                technique_counts.get(technique_key, 0) + 1
            )

            for tactic in [
                item.strip()
                for item in mapping["tactics"].split(",")
                if item.strip()
            ]:
                tactic_counts[tactic] = (
                    tactic_counts.get(tactic, 0) + 1
                )

        mappings.extend(event_mappings)

    top_techniques = [
        {
            "attack_id": key[0],
            "technique_name": key[1],
            "event_count": count,
        }
        for key, count in sorted(
            technique_counts.items(),
            key=lambda item: (-item[1], item[0][0]),
        )[:10]
    ]

    top_tactics = [
        {
            "tactic": tactic,
            "event_count": count,
        }
        for tactic, count in sorted(
            tactic_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:10]
    ]

    result = {
        "analysis_scope": {
            "source": "CISA",
            "attack_domain": "Enterprise",
            "mapping_method": (
                "derived_context_validated_candidate_v5_1"
            ),
            "total_advisories": len(events),
        },
        "metrics": {
            "events_with_mappings": events_with_mappings,
            "total_mappings": total_mappings,
            "high_confidence": high_confidence,
            "medium_confidence": medium_confidence,
            "unmapped_events": len(events) - events_with_mappings,
        },
        "top_techniques": top_techniques,
        "top_tactics": top_tactics,
        "mappings": mappings[:100],
    }

    _mitre_analysis_cache["created_at"] = now
    _mitre_analysis_cache["result"] = result

    return result


@app.get("/correlations/graph")
def get_correlation_graph(
    limit: int = 12,
    db: Session = Depends(get_db)
):
    """
    Build a derived CISA -> CVE correlation graph.

    Correlations are created only when an explicit CVE identifier
    is present in the CISA advisory title or description.

    No keyword-based or heuristic CVE correlations are used.
    """

    limit = max(1, min(limit, 50))

    events = (
        db.query(models.ThreatEvent)
        .order_by(
            models.ThreatEvent.event_date.desc(),
            models.ThreatEvent.id.desc()
        )
        .all()
    )

    nodes = []
    edges = []

    advisory_count = 0
    cve_count = 0
    kev_count = 0

    seen_advisories = set()
    seen_cves = set()
    seen_edges = set()

    for event in events:
        text_blob = (
            f"{event.title or ''} "
            f"{event.description or ''}"
        )

        cve_ids = sorted(
            {
                match.upper()
                for match in CVE_PATTERN.findall(text_blob)
            }
        )

        if not cve_ids:
            continue

        if advisory_count >= limit:
            break

        advisory_node_id = f"advisory-{event.id}"

        if event.id not in seen_advisories:
            nodes.append({
                "id": advisory_node_id,
                "type": "advisory",
                "label": event.title,
                "event_id": event.id,
                "event_date": event.event_date,
                "source": event.source_name,
                "source_url": event.source_url
            })

            seen_advisories.add(event.id)
            advisory_count += 1

        for cve_id in cve_ids:
            cve = (
                db.query(models.CVE)
                .filter(models.CVE.cve_id == cve_id)
                .first()
            )

            if not cve:
                continue

            components = calculate_risk_components(cve)
            risk_score = components["risk_score"]
            risk_level = get_risk_level(risk_score)

            cve_node_id = f"cve-{cve.cve_id}"

            if cve.cve_id not in seen_cves:
                nodes.append({
                    "id": cve_node_id,
                    "type": "cve",
                    "label": cve.cve_id,
                    "cvss_score": cve.cvss_score,
                    "severity": cve.severity,
                    "known_exploited": cve.known_exploited == 1,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "published_date": cve.published_date
                })

                seen_cves.add(cve.cve_id)
                cve_count += 1

                if cve.known_exploited == 1:
                    kev_count += 1

            edge_key = (
                f"{advisory_node_id}"
                f"->{cve_node_id}"
            )

            if edge_key not in seen_edges:
                edges.append({
                    "id": edge_key,
                    "source": advisory_node_id,
                    "target": cve_node_id,
                    "relationship": "explicit_cve_reference"
                })

                seen_edges.add(edge_key)

    return {
        "analysis_scope": {
            "source": "CISA",
            "correlation_method": "explicit_cve_identifier",
            "limit": limit
        },
        "metrics": {
            "advisories": advisory_count,
            "unique_cves": cve_count,
            "kev_cves": kev_count,
            "relationships": len(edges)
        },
        "nodes": nodes,
        "edges": edges
    }


# ============================================================
# THREAT INTELLIGENCE SUMMARY
# ============================================================

@app.get(
    "/threat-intelligence/summary"
)
def get_threat_intelligence_summary(
    db: Session = Depends(get_db)
):

    events = (
        db.query(
            models.ThreatEvent
        )
        .all()
    )

    summary = {
        "total": len(events),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "event_types": {},
        "sources": {}
    }

    for event in events:

        severity = (
            event.severity
            or "UNKNOWN"
        ).upper()

        if severity == "CRITICAL":

            summary[
                "critical"
            ] += 1

        elif severity == "HIGH":

            summary[
                "high"
            ] += 1

        elif severity == "MEDIUM":

            summary[
                "medium"
            ] += 1

        elif severity == "LOW":

            summary[
                "low"
            ] += 1

        event_type = (
            event.event_type
            or "Unknown"
        )

        if event_type not in summary[
            "event_types"
        ]:

            summary[
                "event_types"
            ][event_type] = 0

        summary[
            "event_types"
        ][event_type] += 1

        source = (
            event.source_name
            or "Unknown"
        )

        if source not in summary[
            "sources"
        ]:

            summary[
                "sources"
            ][source] = 0

        summary[
            "sources"
        ][source] += 1

    return summary
