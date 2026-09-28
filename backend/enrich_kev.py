import requests

from database import SessionLocal
import models


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def enrich_kev():
    print("Downloading CISA KEV catalog...")

    response = requests.get(
        KEV_URL,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    print(f"Received {len(vulnerabilities)} KEV records.")

    db = SessionLocal()

    try:
        matched = 0

        for item in vulnerabilities:
            cve_id = item.get("cveID")

            if not cve_id:
                continue

            cve = (
                db.query(models.CVE)
                .filter(models.CVE.cve_id == cve_id)
                .first()
            )

            if not cve:
                continue

            cve.known_exploited = 1
            cve.kev_date_added = item.get("dateAdded")
            cve.kev_due_date = item.get("dueDate")

            matched += 1

        db.commit()

        print(f"Matched with our database: {matched}")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    enrich_kev()