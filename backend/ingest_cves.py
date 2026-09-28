import time
from datetime import datetime, timedelta, timezone

import requests

from database import SessionLocal
import models


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Number of days of vulnerability history to maintain
DAYS_BACK = 90

# NVD supports up to 2,000 records per request
RESULTS_PER_PAGE = 2000

# Small delay between requests to avoid hitting the API too aggressively
REQUEST_DELAY = 0.7


def get_date_range():
    """
    Calculate the rolling 90-day NVD publication window.
    """

    end_date = datetime.now(timezone.utc)

    start_date = end_date - timedelta(days=DAYS_BACK)

    start_date_str = (
        start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    )

    end_date_str = (
        end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    )

    return start_date_str, end_date_str


def ingest_cves():
    print("Connecting to NVD...")

    start_date, end_date = get_date_range()

    print(
        f"Fetching CVEs from {start_date} "
        f"to {end_date}"
    )

    headers = {
        "User-Agent": "Cyber-Situation-Room/0.1"
    }

    db = SessionLocal()

    total_received = 0
    total_added = 0
    total_skipped = 0

    start_index = 0
    nvd_total_results = None

    try:
        while True:

            print(
                f"Requesting NVD records "
                f"starting at index {start_index}..."
            )

            params = {
                "pubStartDate": start_date,
                "pubEndDate": end_date,
                "startIndex": start_index,
                "resultsPerPage": RESULTS_PER_PAGE,
            }

            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=60,
            )

            response.raise_for_status()

            data = response.json()

            vulnerabilities = data.get(
                "vulnerabilities",
                []
            )

            nvd_total_results = data.get(
                "totalResults",
                0
            )

            page_count = len(vulnerabilities)

            print(
                f"Received {page_count} CVEs "
                f"(NVD total: {nvd_total_results})"
            )

            if page_count == 0:
                break

            total_received += page_count

            for item in vulnerabilities:

                cve_data = item.get("cve", {})

                cve_id = cve_data.get("id")

                if not cve_id:
                    continue

                existing = (
                    db.query(models.CVE)
                    .filter(
                        models.CVE.cve_id
                        == cve_id
                    )
                    .first()
                )

                if existing:
                    total_skipped += 1
                    continue

                description = ""

                descriptions = cve_data.get(
                    "descriptions",
                    []
                )

                for desc in descriptions:
                    if (
                        desc.get("lang")
                        == "en"
                    ):
                        description = desc.get(
                            "value",
                            ""
                        )
                        break

                metrics = cve_data.get(
                    "metrics",
                    {}
                )

                cvss_score = None
                severity = None

                # Prefer CVSS v3.1
                if metrics.get("cvssMetricV31"):

                    metric = metrics[
                        "cvssMetricV31"
                    ][0]

                    cvss_data = metric.get(
                        "cvssData",
                        {}
                    )

                    cvss_score = cvss_data.get(
                        "baseScore"
                    )

                    severity = cvss_data.get(
                        "baseSeverity"
                    )

                # Fall back to CVSS v3.0
                elif metrics.get(
                    "cvssMetricV30"
                ):

                    metric = metrics[
                        "cvssMetricV30"
                    ][0]

                    cvss_data = metric.get(
                        "cvssData",
                        {}
                    )

                    cvss_score = cvss_data.get(
                        "baseScore"
                    )

                    severity = cvss_data.get(
                        "baseSeverity"
                    )

                # Fall back to CVSS v2
                elif metrics.get(
                    "cvssMetricV2"
                ):

                    metric = metrics[
                        "cvssMetricV2"
                    ][0]

                    cvss_data = metric.get(
                        "cvssData",
                        {}
                    )

                    cvss_score = cvss_data.get(
                        "baseScore"
                    )

                    severity = metric.get(
                        "baseSeverity"
                    )

                published_date = cve_data.get(
                    "published"
                )

                last_modified = cve_data.get(
                    "lastModified"
                )

                new_cve = models.CVE(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    published_date=published_date,
                    last_modified=last_modified,
                    known_exploited=0,
                    kev_date_added=None,
                    kev_due_date=None,
                )

                db.add(new_cve)

                total_added += 1

            db.commit()

            start_index += page_count

            if (
                start_index
                >= nvd_total_results
            ):
                break

            time.sleep(REQUEST_DELAY)

        print()
        print(
            "========== NVD INGESTION COMPLETE =========="
        )
        print(
            f"Total received: {total_received}"
        )
        print(
            f"Added: {total_added}"
        )
        print(
            f"Skipped duplicates: {total_skipped}"
        )
        print(
            f"Database should now contain "
            f"approximately {total_added + total_skipped} "
            f"processed records from this run."
        )
        print(
            "============================================"
        )

    except requests.exceptions.RequestException as error:

        db.rollback()

        print()
        print(
            "NVD API request failed:"
        )
        print(error)

        raise

    except Exception as error:

        db.rollback()

        print()
        print(
            "NVD ingestion failed:"
        )
        print(error)

        raise

    finally:

        db.close()


if __name__ == "__main__":
    ingest_cves()