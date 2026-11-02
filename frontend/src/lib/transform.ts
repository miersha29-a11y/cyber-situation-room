import type { CVE, TimelineData, SeverityData, RiskSummary } from "../types";

/* ==========================================================
   DATA SHAPING HELPERS
   ========================================================== */

const KNOWN_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function buildSeverityData(cves: CVE[]): SeverityData[] {
  const count = (severity: string) =>
    cves.filter((cve) => cve.severity === severity).length;

  return [
    { name: "Critical", value: count("CRITICAL") },
    { name: "High", value: count("HIGH") },
    { name: "Medium", value: count("MEDIUM") },
    { name: "Low", value: count("LOW") },
    {
      name: "Unknown",
      value: cves.filter(
        (cve) => !cve.severity || !KNOWN_SEVERITIES.includes(cve.severity)
      ).length,
    },
  ];
}

export function normalizeRiskSummary(data: Partial<RiskSummary> | undefined): RiskSummary {
  return {
    critical: Number(data?.critical ?? 0),
    high: Number(data?.high ?? 0),
    medium: Number(data?.medium ?? 0),
    low: Number(data?.low ?? 0),
    known_exploited: Number(data?.known_exploited ?? 0),
    total: Number(data?.total ?? 0),
    nvd_critical: Number(data?.nvd_critical ?? 0),
    nvd_high: Number(data?.nvd_high ?? 0),
    nvd_medium: Number(data?.nvd_medium ?? 0),
    nvd_low: Number(data?.nvd_low ?? 0),
    priority_risks: Number(data?.priority_risks ?? 0),
  };
}

// The backend returns only dates that contain CVEs. Build a contiguous
// calendar series so each range represents the requested number of
// calendar days instead of collapsing to active dates only.
export function buildTimeline(
  data: { date: string; count: number }[],
  range: number
): TimelineData[] {
  const countsByDate = new Map(
    data.map((item) => [item.date, Number(item.count) || 0])
  );

  const validDates = data
    .map((item) => item.date)
    .filter(Boolean)
    .sort();

  if (validDates.length === 0) {
    return [];
  }

  const end = new Date(`${validDates[validDates.length - 1]}T00:00:00`);
  const timeline: TimelineData[] = [];

  for (let offset = range - 1; offset >= 0; offset -= 1) {
    const date = new Date(end);
    date.setDate(end.getDate() - offset);

    const isoDate = [
      date.getFullYear(),
      String(date.getMonth() + 1).padStart(2, "0"),
      String(date.getDate()).padStart(2, "0"),
    ].join("-");

    const count = countsByDate.get(isoDate) ?? 0;
    const recentCounts = timeline
      .slice(Math.max(0, timeline.length - 6))
      .map((item) => item.count);
    const movingValues = [...recentCounts, count];
    const movingAverage =
      movingValues.reduce((sum, value) => sum + value, 0) /
      movingValues.length;

    timeline.push({
      date: isoDate,
      count,
      movingAverage: Number(movingAverage.toFixed(1)),
    });
  }

  return timeline;
}
