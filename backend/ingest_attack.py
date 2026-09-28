from datetime import datetime, timezone
import json
import requests

from sqlalchemy import text

from database import engine


MITRE_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)


def extract_attack_id(obj):
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            external_id = reference.get("external_id")
            if external_id:
                return external_id

    return None


def extract_attack_url(obj):
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("url") or ""

    return ""


def normalize_tactics(obj):
    tactics = []

    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") != "mitre-attack":
            continue

        phase_name = phase.get("phase_name", "").strip()
        if phase_name and phase_name not in tactics:
            tactics.append(phase_name)

    return ", ".join(tactics)


def main():
    print("Downloading official MITRE Enterprise ATT&CK STIX 2.1 data...")
    response = requests.get(
        MITRE_ENTERPRISE_URL,
        timeout=60,
        headers={"User-Agent": "Cyber-Situation-Room/1.0"},
    )
    response.raise_for_status()

    bundle = response.json()
    objects = bundle.get("objects", [])

    attack_patterns = [
        obj
        for obj in objects
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]

    print(f"ATT&CK objects received: {len(objects)}")
    print(f"Active attack techniques: {len(attack_patterns)}")

    now = datetime.now(timezone.utc).isoformat()

    rows = []

    for obj in attack_patterns:
        attack_id = extract_attack_id(obj)

        if not attack_id or not attack_id.startswith("T"):
            continue

        name = (obj.get("name") or "").strip()
        if not name:
            continue

        rows.append(
            {
                "attack_id": attack_id,
                "name": name,
                "description": obj.get("description") or "",
                "tactics": normalize_tactics(obj),
                "url": extract_attack_url(obj),
                "version": obj.get("x_mitre_version") or "",
                "source_updated": obj.get("modified") or now,
                "is_subtechnique": 1 if obj.get("x_mitre_is_subtechnique") else 0,
            }
        )

    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS attack_techniques (
                    id INTEGER PRIMARY KEY,
                    attack_id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    description TEXT,
                    tactics TEXT,
                    url TEXT,
                    version TEXT,
                    source_updated TEXT,
                    is_subtechnique INTEGER DEFAULT 0
                )
                """
            )
        )

        connection.execute(text("DELETE FROM attack_techniques"))

        connection.execute(
            text(
                """
                INSERT INTO attack_techniques (
                    attack_id,
                    name,
                    description,
                    tactics,
                    url,
                    version,
                    source_updated,
                    is_subtechnique
                )
                VALUES (
                    :attack_id,
                    :name,
                    :description,
                    :tactics,
                    :url,
                    :version,
                    :source_updated,
                    :is_subtechnique
                )
                """
            ),
            rows,
        )

    print(f"Inserted techniques: {len(rows)}")
    print("MITRE Enterprise ATT&CK catalog ingestion complete.")


if __name__ == "__main__":
    main()
