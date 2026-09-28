import hashlib
import html
import re
import requests
import xml.etree.ElementTree as ET

from database import SessionLocal
import models


CISA_FEED_URL = (
    "https://www.cisa.gov/"
    "cybersecurity-advisories/all.xml"
)

SOURCE_NAME = "CISA"


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(value):
    if not value:
        return ""

    value = html.unescape(value)
    value = re.sub(r"<[^>]+>", " ", value)
    value = re.sub(r"\s+", " ", value)

    return value.strip()


# ============================================================
# DEDUPLICATION
# ============================================================

def generate_external_id(title, link):
    value = f"{title}|{link}"

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


# ============================================================
# ADVISORY TYPE
#
# Based primarily on the CISA advisory title.
# ============================================================

def get_advisory_type(title):
    title_upper = title.upper()

    if "ICS MEDICAL ADVISORY" in title_upper:
        return "ICS Medical Advisory"

    if "ICS ADVISORY" in title_upper:
        return "ICS Advisory"

    if "STOPRANSOMWARE" in title_upper:
        return "Ransomware Advisory"

    if "CYBERSECURITY ADVISORY" in title_upper:
        return "Cybersecurity Advisory"

    if "ALERT" in title_upper:
        return "Alert"

    if "ANALYSIS" in title_upper:
        return "Analysis Report"

    return "Cybersecurity Advisory"


# ============================================================
# PRODUCT / VULNERABILITY DETECTION
#
# Used to identify product and ICS vulnerability advisories.
# ============================================================

def is_product_vulnerability(title, text):
    title_upper = title.upper()

    # Explicit vulnerability terminology
    vulnerability_terms = [
        "vulnerability",
        "vulnerabilities",
        "cve-",
        "security flaw",
        "security flaws",
        "security vulnerability",
        "security vulnerabilities",
        "remote code execution",
        "command injection",
        "code injection",
        "privilege escalation",
        "denial of service",
        "denial-of-service",
        "buffer overflow",
        "path traversal",
        "sql injection",
        "cross-site scripting",
    ]

    if any(
        term in text
        for term in vulnerability_terms
    ):
        return True

    # Common product / ICS vendors and advisory indicators
    product_indicators = [
        "ICS ADVISORY",
        "ICS MEDICAL ADVISORY",
        "ROCKWELL AUTOMATION",
        "SCHNEIDER ELECTRIC",
        "MITSUBISHI ELECTRIC",
        "SIEMENS",
        "HONEYWELL",
        "HITACHI",
        "EMERSON",
        "PHOENIX CONTACT",
        "ADVANTECH",
        "FORTINET",
        "IVANTI",
        "PALO ALTO",
        "CISCO",
        "MICROSOFT",
        "ORACLE",
        "VMWARE",
        "F5 ",
    ]

    if any(
        indicator in title_upper
        for indicator in product_indicators
    ):
        return True

    return False


# ============================================================
# EVENT TYPE
#
# THIS IS A CYBER SITUATION ROOM DERIVED CLASSIFICATION.
#
# The order is important:
#
# 1. Explicit threat-intelligence/campaign titles
# 2. Product/ICS vulnerabilities
# 3. Ransomware
# 4. Phishing
# 5. Malware
# 6. Threat actor
# 7. Cyber attack
# 8. Generic cybersecurity advisory
# ============================================================

def get_event_type(title, description):
    title_upper = title.upper()
    text = f"{title} {description}".lower()

    # --------------------------------------------------------
    # 1. Explicit threat-intelligence / campaign titles
    #
    # This is checked BEFORE vulnerability detection because
    # campaign descriptions may contain CVE/security terms.
    # --------------------------------------------------------

    threat_title_indicators = [
        "CONDUCTING",
        "CAMPAIGN",
        "THREAT ACTOR",
        "THREAT ACTORS",
        "STATE-SPONSORED",
        "STATE SPONSORED",
        "NATION-STATE",
        "ADVANCED PERSISTENT THREAT",
        "APT",
    ]

    if any(
        indicator in title_upper
        for indicator in threat_title_indicators
    ):
        return "Threat Actor"

    # --------------------------------------------------------
    # 2. Product / ICS vulnerability
    # --------------------------------------------------------

    if is_product_vulnerability(title, text):
        return "Vulnerability"

    # --------------------------------------------------------
    # 3. Ransomware
    # --------------------------------------------------------

    ransomware_indicators = [
        "stopransomware",
        "ransomware campaign",
        "ransomware attack",
        "ransomware group",
        "ransomware operation",
    ]

    if any(
        term in text
        for term in ransomware_indicators
    ):
        return "Ransomware"

    # --------------------------------------------------------
    # 4. Explicit phishing activity
    #
    # Deliberately strict to prevent false positives.
    # --------------------------------------------------------

    phishing_indicators = [
        "phishing campaign",
        "phishing attack",
        "phishing emails",
        "phishing email campaign",
        "credential phishing",
        "phishing infrastructure",
    ]

    if any(
        term in text
        for term in phishing_indicators
    ):
        return "Phishing"

    # --------------------------------------------------------
    # 5. Malware
    # --------------------------------------------------------

    malware_indicators = [
        "malware campaign",
        "malware infection",
        "malware family",
        "malware variant",
        "remote access trojan",
        "backdoor malware",
        "botnet campaign",
    ]

    if any(
        term in text
        for term in malware_indicators
    ):
        return "Malware"

    # --------------------------------------------------------
    # 6. Threat actor / campaign intelligence in description
    # --------------------------------------------------------

    threat_actor_indicators = [
        "threat actor",
        "threat actors",
        "state-sponsored",
        "state sponsored",
        "nation-state actor",
        "nation state actor",
        "advanced persistent threat",
        "apt group",
        "apt actor",
        "campaign against",
        "campaign targeting",
    ]

    if any(
        term in text
        for term in threat_actor_indicators
    ):
        return "Threat Actor"

    # --------------------------------------------------------
    # 7. Generic cyber attack
    # --------------------------------------------------------

    attack_indicators = [
        "cyber attack campaign",
        "cyberattack campaign",
        "intrusion campaign",
        "attack campaign",
        "successful intrusion",
        "network intrusion",
        "compromise campaign",
    ]

    if any(
        term in text
        for term in attack_indicators
    ):
        return "Cyber Attack"

    # --------------------------------------------------------
    # 8. Default
    # --------------------------------------------------------

    return "Cybersecurity Advisory"


# ============================================================
# DERIVED SEVERITY
#
# IMPORTANT:
# This is NOT an official CISA severity rating.
# It is a Cyber Situation Room analytical classification.
# ============================================================

def get_severity(title, description):
    text = f"{title} {description}".lower()

    # --------------------------------------------------------
    # CRITICAL
    #
    # Only strong indicators.
    # --------------------------------------------------------

    critical_indicators = [
        "actively exploited",
        "active exploitation",
        "widespread exploitation",
        "ransomware attack",
        "ransomware campaign",
        "remote code execution",
    ]

    if any(
        term in text
        for term in critical_indicators
    ):
        return "CRITICAL"

    # --------------------------------------------------------
    # HIGH
    # --------------------------------------------------------

    high_indicators = [
        "threat actor",
        "threat actors",
        "state-sponsored",
        "state sponsored",
        "nation-state",
        "advanced persistent threat",
        "apt group",
        "malware campaign",
        "phishing campaign",
        "successful intrusion",
        "exploitation campaign",
    ]

    if any(
        term in text
        for term in high_indicators
    ):
        return "HIGH"

    # --------------------------------------------------------
    # DEFAULT
    # --------------------------------------------------------

    return "MEDIUM"


# ============================================================
# DOWNLOAD CISA FEED
# ============================================================

def parse_feed():
    print("Downloading CISA advisory feed...")

    response = requests.get(
        CISA_FEED_URL,
        timeout=30,
        headers={
            "User-Agent":
                "Cyber-Situation-Room/0.1"
        },
    )

    response.raise_for_status()

    print(
        f"Received {len(response.content):,} bytes."
    )

    root = ET.fromstring(
        response.content
    )

    items = root.findall(".//item")

    print(
        f"Found {len(items)} advisory items."
    )

    return items


# ============================================================
# INGEST CISA
# ============================================================

def ingest_cisa():
    items = parse_feed()

    db = SessionLocal()

    added = 0
    skipped = 0

    try:

        for item in items:

            title_element = item.find("title")
            link_element = item.find("link")
            description_element = item.find(
                "description"
            )
            date_element = item.find(
                "pubDate"
            )

            if (
                title_element is None
                or link_element is None
            ):
                continue

            # ------------------------------------------------
            # Source data
            # ------------------------------------------------

            title = clean_text(
                title_element.text
            )

            link = clean_text(
                link_element.text
            )

            description = ""

            if description_element is not None:
                description = clean_text(
                    description_element.text
                )

            event_date = ""

            if date_element is not None:
                event_date = clean_text(
                    date_element.text
                )

            # ------------------------------------------------
            # Stable external ID
            # ------------------------------------------------

            external_id = generate_external_id(
                title,
                link
            )

            # ------------------------------------------------
            # Duplicate check
            # ------------------------------------------------

            existing = (
                db.query(
                    models.ThreatEvent
                )
                .filter(
                    models.ThreatEvent.external_id
                    == external_id
                )
                .first()
            )

            if existing:
                skipped += 1
                continue

            # ------------------------------------------------
            # Derived classifications
            # ------------------------------------------------

            advisory_type = get_advisory_type(
                title
            )

            event_type = get_event_type(
                title,
                description
            )

            severity = get_severity(
                title,
                description
            )

            # ------------------------------------------------
            # Create database record
            # ------------------------------------------------

            threat_event = models.ThreatEvent(
                title=title,
                description=description,
                event_type=event_type,
                severity=severity,
                event_date=event_date,
                source_name=SOURCE_NAME,
                source_url=link,
                external_id=external_id,
                advisory_type=advisory_type,
            )

            db.add(threat_event)

            added += 1

        db.commit()

        print()
        print(
            "========== CISA INGESTION COMPLETE =========="
        )
        print(
            f"Feed items: {len(items)}"
        )
        print(
            f"Added: {added}"
        )
        print(
            f"Skipped duplicates: {skipped}"
        )
        print(
            "=============================================="
        )

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    ingest_cisa()