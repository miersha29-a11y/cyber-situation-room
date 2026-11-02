import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { API_BASE_URL, fetchJson } from "../api";
import { buildSeverityData, normalizeRiskSummary, buildTimeline } from "../lib/transform";
import type { CVE, SeverityData, RangeOption, PrioritizedVulnerability, RiskSummary, CorrelationGraphNode, CorrelationGraphResponse, RiskDebug, ThreatEvent, ThreatSummary, ThreatCorrelation, MitreAttackAnalysis, IntelligenceAnalysis, ConnectionStatus } from "../types";

/*
 * All dashboard state, server data and event handlers.
 * Components receive only the slice they use (see Dashboard type).
 */
export function useDashboard() {
  const scrollToSection = (id: string) => {
    const headingMap: Record<string, string> = {
      overview: "Global Threat Overview",
      "threat-intelligence": "Threat Intelligence",
      "vulnerability-intelligence": "Vulnerability Intelligence",
      "mitre-attack": "MITRE ATT&CK Mapping",
      "correlation-intelligence": "Correlation Intelligence",
      "intelligence-analysis": "Intelligence Analysis",
      "latest-intelligence": "Latest Intelligence",
    };

    const targetText = headingMap[id];

    if (!targetText) {
      return;
    }

    const headings = Array.from(
      document.querySelectorAll("h1, h2")
    );

    const target = headings.find(
      (heading) =>
        heading.textContent?.trim() === targetText
    );

    if (!target) {
      return;
    }

    const section =
      target.closest(".panel") ||
      target.closest("section") ||
      target;

    section.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  };

  /* ==========================================================
     UI STATE
     ========================================================== */

  const [selectedRange, setSelectedRange] =
    useState<RangeOption>(30);

  const [selectedCVE, setSelectedCVE] =
    useState<PrioritizedVulnerability | null>(null);

  const [riskDebug, setRiskDebug] =
    useState<RiskDebug | null>(null);

  const [detailLoading, setDetailLoading] =
    useState(false);

  const [threatSeverityFilter, setThreatSeverityFilter] =
    useState("ALL");

  const [selectedThreat, setSelectedThreat] =
    useState<ThreatEvent | null>(null);

  const [threatCorrelations, setThreatCorrelations] =
    useState<ThreatCorrelation[]>([]);

  const [correlationLoading, setCorrelationLoading] =
    useState(false);

  const [threatTypeFilter, setThreatTypeFilter] =
    useState("ALL");

  /* ==========================================================
     SERVER DATA (TanStack React Query)
     Each query is cached, de-duplicated and retried by React
     Query, so no component state is set inside effects.
     ========================================================== */

  const cvesQuery = useQuery({
    queryKey: ["cves", 500],
    queryFn: ({ signal }) =>
      fetchJson<CVE[]>("/cves?limit=500", signal),
  });

  // The browser receives only a bounded recent dataset.
  // Global KPI values come from /vulnerabilities/risk-summary.
  const severityData = useMemo<SeverityData[]>(
    () => (cvesQuery.data ? buildSeverityData(cvesQuery.data) : []),
    [cvesQuery.data]
  );

  const prioritizedQuery = useQuery({
    queryKey: ["vulnerabilities", "prioritized", 10],
    queryFn: ({ signal }) =>
      fetchJson<PrioritizedVulnerability[]>(
        "/vulnerabilities/prioritized?limit=10",
        signal
      ),
  });

  const prioritizedVulnerabilities = useMemo(
    () => prioritizedQuery.data ?? [],
    [prioritizedQuery.data]
  );

  const vulnerabilityLoading = prioritizedQuery.isLoading;

  const riskSummaryQuery = useQuery({
    queryKey: ["vulnerabilities", "risk-summary"],
    queryFn: ({ signal }) =>
      fetchJson<RiskSummary>("/vulnerabilities/risk-summary", signal),
  });

  // Always show what the API actually returned. An empty database
  // shows zeros, never a stored snapshot.
  const riskSummary = useMemo<RiskSummary>(
    () => normalizeRiskSummary(riskSummaryQuery.data),
    [riskSummaryQuery.data]
  );

  const correlationGraphQuery = useQuery({
    queryKey: ["correlations", "graph", 12],
    queryFn: ({ signal }) =>
      fetchJson<CorrelationGraphResponse>(
        "/correlations/graph?limit=12",
        signal
      ),
  });

  const correlationGraph = correlationGraphQuery.data ?? null;
  const correlationGraphLoading = correlationGraphQuery.isLoading;
  const correlationGraphError = correlationGraphQuery.error
    ? correlationGraphQuery.error.message
    : null;

  /* ==========================================================
     THREAT INTELLIGENCE DATA
     ========================================================== */

  const threatEventsQuery = useQuery({
    queryKey: ["threat-intelligence", 30],
    queryFn: ({ signal }) =>
      fetchJson<ThreatEvent[]>("/threat-intelligence?limit=30", signal),
  });

  const threatSummaryQuery = useQuery({
    queryKey: ["threat-intelligence", "summary"],
    queryFn: ({ signal }) =>
      fetchJson<ThreatSummary>("/threat-intelligence/summary", signal),
  });

  const threatEvents = useMemo(
    () => threatEventsQuery.data ?? [],
    [threatEventsQuery.data]
  );

  const threatSummary = useMemo<ThreatSummary>(
    () =>
      threatSummaryQuery.data ?? {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        event_types: {},
        sources: {},
      },
    [threatSummaryQuery.data]
  );

  const threatLoading =
    threatEventsQuery.isLoading || threatSummaryQuery.isLoading;

  const intelligenceAnalysisQuery = useQuery({
    queryKey: ["intelligence-analysis"],
    queryFn: ({ signal }) =>
      fetchJson<IntelligenceAnalysis>("/intelligence-analysis", signal),
  });

  const intelligenceAnalysis = intelligenceAnalysisQuery.data ?? null;
  const intelligenceAnalysisLoading = intelligenceAnalysisQuery.isLoading;

  const mitreAttackQuery = useQuery({
    queryKey: ["mitre-attack", "analysis"],
    queryFn: ({ signal }) =>
      fetchJson<MitreAttackAnalysis>("/mitre-attack/analysis", signal),
  });

  const mitreAttackAnalysis = mitreAttackQuery.data ?? null;
  const mitreAttackLoading = mitreAttackQuery.isLoading;

  /* ==========================================================
     API STATUS
     First failed query, shown in a banner so a dead backend is
     visible instead of looking like an empty dashboard.
     ========================================================== */

  const apiError =
    [
      cvesQuery,
      prioritizedQuery,
      riskSummaryQuery,
      correlationGraphQuery,
      threatEventsQuery,
      threatSummaryQuery,
      intelligenceAnalysisQuery,
      mitreAttackQuery,
    ].find((query) => query.isError)?.error ?? null;

  const databaseEmpty =
    riskSummaryQuery.isSuccess && riskSummary.total === 0;


  /* ==========================================================
     OPEN THREAT DETAIL + CVE CORRELATION
     ========================================================== */

  const openThreat = async (event: ThreatEvent) => {
    setSelectedThreat(event);
    setThreatCorrelations([]);
    setCorrelationLoading(true);

    try {
      const response = await fetch(
        `${API_BASE_URL}/threat-intelligence/${event.id}/correlations`
      );

      if (!response.ok) {
        throw new Error(
          `Threat correlation HTTP ${response.status}`
        );
      }

      const data = (await response.json()) as {
        correlations?: ThreatCorrelation[];
      };

      setThreatCorrelations(
        Array.isArray(data.correlations)
          ? data.correlations
          : []
      );
    } catch (error) {
      console.error(
        "Failed to fetch threat correlations:",
        error
      );
      setThreatCorrelations([]);
    } finally {
      setCorrelationLoading(false);
    }
  };


  /* ==========================================================
     OPEN CVE DETAIL
     ========================================================== */

  const openCVE = (
    vulnerability: PrioritizedVulnerability
  ) => {

    setSelectedCVE(
      vulnerability
    );

    setRiskDebug(null);

    setDetailLoading(true);


    fetch(
      `${API_BASE_URL}/vulnerabilities/risk-debug/${encodeURIComponent(vulnerability.cve_id)}`
    )
      .then((response) => {

        if (!response.ok) {

          throw new Error(
            "Failed to fetch risk details"
          );
        }

        return response.json();
      })

      .then((data: RiskDebug) => {

        setRiskDebug(data);
      })

      .catch((error) => {

        console.error(
          "Failed to fetch risk details:",
          error
        );
      })

      .finally(() => {

        setDetailLoading(
          false
        );
      });
  };


  /* ==========================================================
     OPEN CORRELATED CVE DETAIL
     ========================================================== */

  const openCorrelatedCVE = async (
  cve: CorrelationGraphNode
) => {
  const risk = Number(cve.risk_score ?? 0);
  const riskLevel = cve.risk_level || "UNKNOWN";
  const cvssScore =
    cve.cvss_score !== null &&
    cve.cvss_score !== undefined
      ? Number(cve.cvss_score)
      : null;

  const fallback: PrioritizedVulnerability = {
    cve_id: cve.label,
    description: "Loading NVD description...",
    cvss_score: cvssScore,
    severity: cve.severity ?? null,
    published_date: cve.published_date || "",
    last_modified: "",
    known_exploited: cve.known_exploited ? 1 : 0,
    kev_date_added: null,
    kev_due_date: null,

    cvss_component:
      cvssScore !== null
        ? Number(((cvssScore / 10) * 60).toFixed(1))
        : 0,

    kev_component: cve.known_exploited ? 30 : 0,

    recency_component: Math.max(
      0,
      Number(
        (
          risk -
          (cvssScore !== null
            ? (cvssScore / 10) * 60
            : 0) -
          (cve.known_exploited ? 30 : 0)
        ).toFixed(1)
      )
    ),

    age_days: null,
    risk_score: risk,
    risk_level: riskLevel,
  };

  // Open the detail panel immediately.
  setSelectedCVE(fallback);
  setRiskDebug(null);
  setDetailLoading(true);

  const cveId = encodeURIComponent(cve.label);

  const riskRequest = fetch(
    `${API_BASE_URL}/vulnerabilities/risk-debug/${cveId}`
  ).then((response) => {
    if (!response.ok) {
      throw new Error(`Risk debug HTTP ${response.status}`);
    }

    return response.json() as Promise<RiskDebug>;
  });

  const nvdRequest = fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`
  ).then((response) => {
    if (!response.ok) {
      throw new Error(`NVD HTTP ${response.status}`);
    }

    return response.json() as Promise<{
      vulnerabilities?: Array<{
        cve?: {
          descriptions?: Array<{
            lang?: string;
            value?: string;
          }>;
          lastModified?: string;
        };
      }>;
    }>;
  });

  const [riskResult, nvdResult] =
    await Promise.allSettled([
      riskRequest,
      nvdRequest,
    ]);

  /*
   * RISK DEBUG
   */
  if (riskResult.status === "fulfilled") {
    setRiskDebug(riskResult.value);

    /*
     * If the backend has the CVE, use its authoritative
     * risk information in the detail panel.
     */
    setSelectedCVE((current) =>
      current
        ? {
            ...current,
            risk_score:
              riskResult.value.risk_score ??
              current.risk_score,
            risk_level:
              riskResult.value.risk_level ||
              current.risk_level,
            cvss_score:
              riskResult.value.cvss_score ??
              current.cvss_score,
            known_exploited:
              riskResult.value.known_exploited ??
              current.known_exploited,
          }
        : current
    );
  } else {
    console.error(
      "Risk-debug fallback used for correlated CVE:",
      riskResult.reason
    );

    setRiskDebug({
      cve_id: fallback.cve_id,
      published_date: fallback.published_date,
      cvss_score: fallback.cvss_score,
      known_exploited: fallback.known_exploited,
      age_days: fallback.age_days,
      cvss_component: fallback.cvss_component,
      kev_component: fallback.kev_component,
      recency_component: fallback.recency_component,
      risk_score: fallback.risk_score,
      risk_level: fallback.risk_level,
    });
  }

  /*
   * NVD DESCRIPTION
   */
  if (nvdResult.status === "fulfilled") {
    const nvdCVE =
      nvdResult.value.vulnerabilities?.[0]?.cve;

    const description =
      nvdCVE?.descriptions?.find(
        (item) =>
          item.lang?.toLowerCase() === "en"
      )?.value ||
      nvdCVE?.descriptions?.[0]?.value;

    setSelectedCVE((current) =>
      current
        ? {
            ...current,
            description:
              description ||
              "No NVD description available.",
            last_modified:
              nvdCVE?.lastModified ||
              current.last_modified,
          }
        : current
    );
  } else {
    console.error(
      "Unable to load NVD description for correlated CVE:",
      nvdResult.reason
    );

    setSelectedCVE((current) =>
      current
        ? {
            ...current,
            description:
              "NVD description could not be retrieved at this time.",
          }
        : current
    );
  }

  setDetailLoading(false);
};

  /* ==========================================================
     CLOSE CVE DETAIL
     ========================================================== */

  const closeCVE = () => {

    setSelectedCVE(null);

    setRiskDebug(null);
  };


  /* ==========================================================
     TIMELINE
     ========================================================== */

  const timelineQuery = useQuery({
    queryKey: ["vulnerabilities", "timeline", selectedRange],
    queryFn: ({ signal }) =>
      fetchJson<{ date: string; count: number }[]>(
        `/vulnerabilities/timeline?days=${selectedRange}`,
        signal
      ),
  });

  const timelineData = useMemo(
    () => buildTimeline(timelineQuery.data ?? [], selectedRange),
    [timelineQuery.data, selectedRange]
  );


  /* ==========================================================
     AVAILABLE DAYS
     ========================================================== */

  const availableDays = timelineData.length;


  const threatEventTypes = useMemo(() => {
    const types = new Set(
      threatEvents
        .map((event) => event.event_type)
        .filter((type): type is string => Boolean(type))
    );

    return Array.from(types).sort();
  }, [threatEvents]);

  const filteredThreatEvents = useMemo(() => {
    return threatEvents.filter((event) => {
      const severityMatches =
        threatSeverityFilter === "ALL" ||
        (event.severity || "MEDIUM") === threatSeverityFilter;

      const typeMatches =
        threatTypeFilter === "ALL" ||
        (event.event_type || "Cybersecurity Advisory") === threatTypeFilter;

      return severityMatches && typeMatches;
    });
  }, [threatEvents, threatSeverityFilter, threatTypeFilter]);

  const topThreatTypes = useMemo(() => {
    return Object.entries(threatSummary.event_types)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 4);
  }, [threatSummary.event_types]);

  /* ==========================================================
     CONNECTION STATUS
     Drives the sidebar and topbar indicators so they reflect
     the API's real state instead of always showing green.
     ========================================================== */

  const anyLoading = [
    cvesQuery,
    prioritizedQuery,
    riskSummaryQuery,
    correlationGraphQuery,
    threatEventsQuery,
    threatSummaryQuery,
    intelligenceAnalysisQuery,
    mitreAttackQuery,
  ].some((query) => query.isLoading);

  const connectionStatus: ConnectionStatus = apiError
    ? "offline"
    : anyLoading
      ? "connecting"
      : databaseEmpty
        ? "empty"
        : "online";

  return {
    scrollToSection,
    cvesQuery,
    severityData,
    prioritizedQuery,
    prioritizedVulnerabilities,
    vulnerabilityLoading,
    riskSummaryQuery,
    riskSummary,
    correlationGraphQuery,
    correlationGraph,
    correlationGraphLoading,
    correlationGraphError,
    threatEventsQuery,
    threatSummaryQuery,
    threatEvents,
    threatSummary,
    threatLoading,
    intelligenceAnalysisQuery,
    intelligenceAnalysis,
    intelligenceAnalysisLoading,
    mitreAttackQuery,
    mitreAttackAnalysis,
    mitreAttackLoading,
    apiError,
    databaseEmpty,
    openThreat,
    openCVE,
    openCorrelatedCVE,
    closeCVE,
    timelineQuery,
    timelineData,
    availableDays,
    threatEventTypes,
    filteredThreatEvents,
    topThreatTypes,
    selectedRange,
    setSelectedRange,
    selectedCVE,
    setSelectedCVE,
    riskDebug,
    setRiskDebug,
    detailLoading,
    setDetailLoading,
    threatSeverityFilter,
    setThreatSeverityFilter,
    selectedThreat,
    setSelectedThreat,
    threatCorrelations,
    setThreatCorrelations,
    correlationLoading,
    setCorrelationLoading,
    threatTypeFilter,
    setThreatTypeFilter,
    connectionStatus,
  };
}

export type Dashboard = ReturnType<typeof useDashboard>;
