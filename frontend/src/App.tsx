import { useEffect, useMemo, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

type CVE = {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  severity: string | null;
  published_date: string;
  last_modified: string;
  known_exploited: number;
  kev_date_added: string | null;
  kev_due_date: string | null;
};

type TimelineData = {
  date: string;
  count: number;
  movingAverage: number;
};

type SeverityData = {
  name: string;
  value: number;
};

type RangeOption = 7 | 30 | 90;

type PrioritizedVulnerability = {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  severity: string | null;
  published_date: string;
  last_modified: string;
  known_exploited: number;
  kev_date_added: string | null;
  kev_due_date: string | null;
  cvss_component: number;
  kev_component: number;
  recency_component: number;
  age_days: number | null;
  risk_score: number;
  risk_level: string;
};

type RiskSummary = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  known_exploited: number;
  total: number;
  nvd_critical?: number;
  nvd_high?: number;
  nvd_medium?: number;
  nvd_low?: number;
  priority_risks?: number;
};

type CorrelationGraphNode = {
  id: string;
  type: "advisory" | "cve";
  label: string;
  event_id?: number;
  event_date?: string;
  source?: string;
  source_url?: string;
  cvss_score?: number | null;
  severity?: string | null;
  known_exploited?: boolean;
  risk_score?: number;
  risk_level?: string;
  published_date?: string;
};

type CorrelationGraphEdge = {
  id: string;
  source: string;
  target: string;
  relationship: string;
};

type CorrelationGraphResponse = {
  analysis_scope: {
    source: string;
    correlation_method: string;
    limit: number;
  };
  metrics: {
    advisories: number;
    unique_cves: number;
    kev_cves: number;
    relationships: number;
  };
  nodes: CorrelationGraphNode[];
  edges: CorrelationGraphEdge[];
};





type RiskDebug = {
  cve_id: string;
  published_date: string;
  cvss_score: number | null;
  known_exploited: number;
  age_days: number | null;
  cvss_component: number;
  kev_component: number;
  recency_component: number;
  risk_score: number;
  risk_level: string;
};

/* ============================================================
   THREAT INTELLIGENCE TYPES
   ============================================================ */

type ThreatEvent = {
  id: number;
  title: string;
  description: string;
  event_type: string | null;
  severity: string | null;
  event_date: string | null;
  source_name: string | null;
  source_url: string | null;
  external_id: string | null;
  advisory_type: string | null;
};

type ThreatSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  event_types: Record<string, number>;
  sources: Record<string, number>;
};

type ThreatCorrelation = {
  cve_id: string;
  found_in_database: boolean;
  cvss_score?: number | null;
  nvd_severity?: string | null;
  known_exploited?: boolean;
  kev_date_added?: string | null;
  kev_due_date?: string | null;
  published_date?: string | null;
  risk_score?: number;
  risk_level?: string;
};

type MitreAttackMapping = {
  event_id?: number;
  event_title?: string;
  attack_id: string;
  technique_name: string;
  tactics: string;
  confidence: string;
  evidence: string;
  url: string;
};

type MitreAttackAnalysis = {
  analysis_scope: {
    source: string;
    attack_domain: string;
    mapping_method: string;
    total_advisories: number;
  };
  metrics: {
    events_with_mappings: number;
    total_mappings: number;
    high_confidence: number;
    medium_confidence: number;
    unmapped_events: number;
  };
  top_techniques: Array<{
    attack_id: string;
    technique_name: string;
    event_count: number;
  }>;
  top_tactics: Array<{
    tactic: string;
    event_count: number;
  }>;
  mappings: MitreAttackMapping[];
};

type IntelligenceAnalysis = {
  analysis_scope: {
    source: string;
    correlation_method: string;
    total_advisories: number;
  };
  correlation_metrics: {
    advisories_with_cves: number;
    total_cve_mentions: number;
    unique_cve_references: number;
    nvd_matched: number;
    nvd_unmatched: number;
    kev_correlated: number;
    high_critical_correlated: number;
  };
  risk_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  top_referenced_cves: Array<{
    cve_id: string;
    reference_count: number;
    nvd_match: boolean;
  }>;
  highest_risk_correlations: Array<{
    cve_id: string;
    reference_count: number;
    cvss_score: number | null;
    nvd_severity: string | null;
    known_exploited: boolean;
    risk_score: number;
    risk_level: string;
  }>;
  unmatched_cves: string[];
};


const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e",
  Unknown: "#64748b",
};


function formatDate(dateString: string) {
  if (!dateString) {
    return "Unknown";
  }

  const date = new Date(
    `${dateString}T00:00:00`
  );

  if (Number.isNaN(date.getTime())) {
    return dateString;
  }

  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "2-digit",
  });
}


function formatFullDate(dateString: string) {
  if (!dateString) {
    return "Unknown";
  }

  const date = new Date(dateString);

  if (Number.isNaN(date.getTime())) {
    return dateString;
  }

  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "2-digit",
    year: "numeric",
  });
}


function formatThreatDate(dateString: string | null) {
  if (!dateString) {
    return "Unknown";
  }

  const date = new Date(dateString);

  if (Number.isNaN(date.getTime())) {
    return dateString;
  }

  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "2-digit",
    year: "numeric",
  });
}




function App() {
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

  const [severityData, setSeverityData] =
    useState<SeverityData[]>([]);


  const [selectedRange, setSelectedRange] =
    useState<RangeOption>(30);


  const [
    prioritizedVulnerabilities,
    setPrioritizedVulnerabilities,
  ] =
    useState<PrioritizedVulnerability[]>(
      []
    );


  const [riskSummary, setRiskSummary] =
    useState<RiskSummary>({
      critical: 35,
      high: 13,
      medium: 19934,
      low: 10295,
      known_exploited: 51,
      total: 30277,
      nvd_critical: 3869,
      nvd_high: 12100,
      nvd_medium: 10208,
      nvd_low: 1054,
      priority_risks: 48,
    });


  const [
    vulnerabilityLoading,
    setVulnerabilityLoading,
  ] = useState(true);


  const [selectedCVE, setSelectedCVE] =
    useState<PrioritizedVulnerability | null>(
      null
    );


  const [riskDebug, setRiskDebug] =
    useState<RiskDebug | null>(null);


  const [detailLoading, setDetailLoading] =
    useState(false);


  const [correlationGraph, setCorrelationGraph] =
    useState<CorrelationGraphResponse | null>(null);

  const [correlationGraphLoading, setCorrelationGraphLoading] =
    useState(true);

  const [correlationGraphError, setCorrelationGraphError] =
    useState<string | null>(null);

  /* ==========================================================
     THREAT INTELLIGENCE STATE
     ========================================================== */

  const [
    threatEvents,
    setThreatEvents,
  ] = useState<ThreatEvent[]>([]);


  const [
    threatSummary,
    setThreatSummary,
  ] = useState<ThreatSummary>({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    event_types: {},
    sources: {},
  });


  const [
    threatLoading,
    setThreatLoading,
  ] = useState(true);

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

  const [intelligenceAnalysis, setIntelligenceAnalysis] =
    useState<IntelligenceAnalysis | null>(null);

  const [intelligenceAnalysisLoading, setIntelligenceAnalysisLoading] =
    useState(true);

  const [mitreAttackAnalysis, setMitreAttackAnalysis] =
    useState<MitreAttackAnalysis | null>(null);

  const [mitreAttackLoading, setMitreAttackLoading] =
    useState(true);


  /* ==========================================================
     FETCH CVE DATA
     ========================================================== */

  useEffect(() => {

    fetch(
      "http://127.0.0.1:8000/cves?limit=500"
    )
      .then((response) => {

        if (!response.ok) {
          throw new Error(
            "Failed to fetch CVE data"
          );
        }

        return response.json();
      })

      .then((data: CVE[]) => {

        // The browser receives only a bounded recent dataset.
        // Global KPI values come from /vulnerabilities/risk-summary.
        // Keep the calculations below for the recent-dataset chart.


        const severityCounts = {

          CRITICAL:
            data.filter(
              (cve) =>
                cve.severity ===
                "CRITICAL"
            ).length,

          HIGH:
            data.filter(
              (cve) =>
                cve.severity ===
                "HIGH"
            ).length,

          MEDIUM:
            data.filter(
              (cve) =>
                cve.severity ===
                "MEDIUM"
            ).length,

          LOW:
            data.filter(
              (cve) =>
                cve.severity ===
                "LOW"
            ).length,

          UNKNOWN:
            data.filter(
              (cve) =>
                !cve.severity ||
                ![
                  "CRITICAL",
                  "HIGH",
                  "MEDIUM",
                  "LOW",
                ].includes(
                  cve.severity
                )
            ).length,
        };


        setSeverityData([
          {
            name: "Critical",
            value:
              severityCounts.CRITICAL,
          },
          {
            name: "High",
            value:
              severityCounts.HIGH,
          },
          {
            name: "Medium",
            value:
              severityCounts.MEDIUM,
          },
          {
            name: "Low",
            value:
              severityCounts.LOW,
          },
          {
            name: "Unknown",
            value:
              severityCounts.UNKNOWN,
          },
        ]);
      })

      .catch((error) => {

        console.error(
          "Failed to fetch CVEs:",
          error
        );
      });

  }, []);


  /* ==========================================================
     FETCH PRIORITIZED VULNERABILITIES
     ========================================================== */

  useEffect(() => {

    setVulnerabilityLoading(
      true
    );


    fetch(
      "http://127.0.0.1:8000/vulnerabilities/prioritized?limit=10"
    )
      .then((response) => {

        if (!response.ok) {

          throw new Error(
            "Failed to fetch prioritized vulnerabilities"
          );
        }

        return response.json();
      })

      .then(
        (
          data: PrioritizedVulnerability[]
        ) => {

          setPrioritizedVulnerabilities(
            data
          );
        }
      )

      .catch((error) => {

        console.error(
          "Failed to fetch prioritized vulnerabilities:",
          error
        );
      })

      .finally(() => {

        setVulnerabilityLoading(
          false
        );
      });

  }, []);


  /* ==========================================================
     FETCH RISK SUMMARY
     ========================================================== */

  useEffect(() => {

    fetch(
      "http://127.0.0.1:8000/vulnerabilities/risk-summary"
    )
      .then((response) => {

        if (!response.ok) {

          throw new Error(
            "Failed to fetch risk summary"
          );
        }

        return response.json();
      })

      .then((data: RiskSummary) => {
        const normalized: RiskSummary = {
          critical: Number(data.critical ?? 0),
          high: Number(data.high ?? 0),
          medium: Number(data.medium ?? 0),
          low: Number(data.low ?? 0),
          known_exploited: Number(data.known_exploited ?? 0),
          total: Number(data.total ?? 0),
          nvd_critical: Number(data.nvd_critical ?? 0),
          nvd_high: Number(data.nvd_high ?? 0),
          nvd_medium: Number(data.nvd_medium ?? 0),
          nvd_low: Number(data.nvd_low ?? 0),
          priority_risks: Number(data.priority_risks ?? 0),
        };

        // Keep the current database snapshot visible if the API returns an empty
        // payload during backend startup; a non-empty API response always wins.
        if (normalized.total > 0) {
          setRiskSummary(normalized);
        }
      })

      .catch((error) => {

        console.error(
          "Failed to fetch risk summary:",
          error
        );
      });

  }, []);


  /* ==========================================================
     FETCH CORRELATION GRAPH
     ========================================================== */

  useEffect(() => {
    setCorrelationGraphLoading(true);
    setCorrelationGraphError(null);

    fetch(
      "http://127.0.0.1:8000/correlations/graph?limit=12"
    )
      .then((response) => {
        if (!response.ok) {
          throw new Error(
            `Correlation graph HTTP ${response.status}`
          );
        }

        return response.json();
      })
      .then((data: CorrelationGraphResponse) => {
        setCorrelationGraph(data);
      })
      .catch((error) => {
        console.error(
          "Failed to fetch correlation graph:",
          error
        );
        setCorrelationGraphError(
          error instanceof Error
            ? error.message
            : "Unable to load correlation intelligence."
        );
      })
      .finally(() => {
        setCorrelationGraphLoading(false);
      });
  }, []);


  /* ==========================================================
     FETCH THREAT INTELLIGENCE
     ========================================================== */

  useEffect(() => {

    setThreatLoading(true);


    Promise.all([

      fetch(
        "http://127.0.0.1:8000/threat-intelligence?limit=30"
      ).then((response) => {

        if (!response.ok) {

          throw new Error(
            "Failed to fetch threat intelligence"
          );
        }

        return response.json();
      }),


      fetch(
        "http://127.0.0.1:8000/threat-intelligence/summary"
      ).then((response) => {

        if (!response.ok) {

          throw new Error(
            "Failed to fetch threat intelligence summary"
          );
        }

        return response.json();
      }),

    ])

      .then(
        ([events, summary]) => {

          setThreatEvents(
            events
          );

          setThreatSummary(
            summary
          );
        }
      )

      .catch((error) => {

        console.error(
          "Failed to fetch threat intelligence:",
          error
        );
      })

      .finally(() => {

        setThreatLoading(
          false
        );
      });

  }, []);


  /* ==========================================================
     FETCH INTELLIGENCE ANALYSIS
     ========================================================== */

  useEffect(() => {

    setIntelligenceAnalysisLoading(true);

    fetch(
      "http://127.0.0.1:8000/intelligence-analysis"
    )
      .then((response) => {

        if (!response.ok) {
          throw new Error(
            "Failed to fetch intelligence analysis"
          );
        }

        return response.json();
      })
      .then((data: IntelligenceAnalysis) => {
        setIntelligenceAnalysis(data);
      })
      .catch((error) => {
        console.error(
          "Failed to fetch intelligence analysis:",
          error
        );
      })
      .finally(() => {
        setIntelligenceAnalysisLoading(false);
      });

  }, []);


  /* ==========================================================
     FETCH MITRE ATT&CK ANALYSIS
     ========================================================== */

  useEffect(() => {

    setMitreAttackLoading(true);

    fetch(
      "http://127.0.0.1:8000/mitre-attack/analysis"
    )
      .then((response) => {
        if (!response.ok) {
          throw new Error(
            "Failed to fetch MITRE ATT&CK analysis"
          );
        }
        return response.json();
      })
      .then((data: MitreAttackAnalysis) => {
        setMitreAttackAnalysis(data);
      })
      .catch((error) => {
        console.error(
          "Failed to fetch MITRE ATT&CK analysis:",
          error
        );
      })
      .finally(() => {
        setMitreAttackLoading(false);
      });

  }, []);


  /* ==========================================================
     OPEN THREAT DETAIL + CVE CORRELATION
     ========================================================== */

  const openThreat = async (event: ThreatEvent) => {
    setSelectedThreat(event);
    setThreatCorrelations([]);
    setCorrelationLoading(true);

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/threat-intelligence/${event.id}/correlations`
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
      `http://127.0.0.1:8000/vulnerabilities/risk-debug/${vulnerability.cve_id}`
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
    `http://127.0.0.1:8000/vulnerabilities/risk-debug/${cveId}`
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

  const [timelineData, setTimelineData] =
    useState<TimelineData[]>([]);


  useEffect(() => {

    fetch(
      `http://127.0.0.1:8000/vulnerabilities/timeline?days=${selectedRange}`
    )
      .then((response) => {

        if (!response.ok) {
          throw new Error(
            "Failed to fetch vulnerability timeline"
          );
        }

        return response.json();
      })
      .then((data: { date: string; count: number }[]) => {

        // The backend returns only dates that contain CVEs. Build a contiguous
        // calendar series so each range represents the requested number of
        // calendar days instead of collapsing to active dates only.
        const countsByDate = new Map(
          data.map((item) => [item.date, Number(item.count) || 0])
        );

        const validDates = data
          .map((item) => item.date)
          .filter(Boolean)
          .sort();

        if (validDates.length === 0) {
          setTimelineData([]);
          return;
        }

        const end = new Date(
          `${validDates[validDates.length - 1]}T00:00:00`
        );
        const timeline: TimelineData[] = [];

        for (let offset = selectedRange - 1; offset >= 0; offset -= 1) {
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

        setTimelineData(timeline);
      })
      .catch((error) => {
        console.error(
          "Failed to fetch vulnerability timeline:",
          error
        );
        setTimelineData([]);
      });

  }, [selectedRange]);


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

  return (

    <div className="app">

      {/* =====================================================
          SIDEBAR
          ===================================================== */}

      <aside className="sidebar">

        <div className="logo">

          <span>🛡</span>

          <div>

            <strong>
              CYBER
            </strong>

            <small>
              SITUATION ROOM
            </small>

          </div>

        </div>


        <nav>

          <p className="nav-title">
            COMMAND
          </p>

          <a className="active" href="#overview" onClick={(event) => { event.preventDefault(); scrollToSection("overview"); }}>Overview</a>

          <a href="#threat-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("threat-intelligence"); }}>Threat Intelligence</a>

          <a href="#vulnerability-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("vulnerability-intelligence"); }}>Vulnerabilities</a>

          <a href="#threat-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("threat-intelligence"); }}>Threat Campaigns</a>

          <a href="#mitre-attack" onClick={(event) => { event.preventDefault(); scrollToSection("mitre-attack"); }}>MITRE ATT&CK</a>


          <p className="nav-title">
            ANALYSIS
          </p>

          <a href="#correlation-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("correlation-intelligence"); }}>Threat Map</a>

          <a href="#intelligence-analysis" onClick={(event) => { event.preventDefault(); scrollToSection("intelligence-analysis"); }}>Analytics</a>

          <a href="#latest-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("latest-intelligence"); }}>Data Sources</a>

        </nav>


        <div className="system-status">

          <span className="status-dot"></span>

          SYSTEM ONLINE

        </div>

      </aside>


      {/* =====================================================
          MAIN
          ===================================================== */}

      <main className="main" id="overview">

        <header className="topbar">

          <div>

            <h1>
              Global Threat Overview
            </h1>

            <p>
              Cybersecurity situational
              awareness dashboard
            </p>

          </div>


          <div className="topbar-right">

            <span>
              LIVE INTELLIGENCE
            </span>

            <span className="live-dot"></span>

          </div>

        </header>


        {/* ===================================================
            KPI CARDS
            =================================================== */}

        <section className="cards">

          <div className="card">

            <p>
              Total CVEs
            </p>

            <h2>
              {riskSummary.total.toLocaleString()}
            </h2>

            <span>
              Full CVE database
            </span>

          </div>


          <div className="card">

            <p>
              Critical CVEs
            </p>

            <h2>
              {(riskSummary.nvd_critical ?? 0).toLocaleString()}
            </h2>

            <span>
              Full database · NVD severity: CRITICAL
            </span>

          </div>


          <div className="card">

            <p>
              Known Exploited
            </p>

            <h2>
              {riskSummary.known_exploited}
            </h2>

            <span>
              Full database · CISA KEV matches
            </span>

          </div>


          <div className="card">

            <p>
              Priority Risks
            </p>

            <h2>
              {(riskSummary.priority_risks ?? 0).toLocaleString()}
            </h2>

            <span>
              Full database · derived CRITICAL + HIGH
            </span>

          </div>

        </section>


        {/* ===================================================
            CHARTS
            =================================================== */}

        <section className="dashboard-grid">

          <div className="panel large">

            <div className="panel-header">

              <div>

                <h2>
                  Threat Activity
                </h2>

                <div className="chart-subtitle">
                  CVE publication activity
                </div>

              </div>


              <div className="chart-controls">

                <span className="chart-source">
                  NVD
                </span>


                <div className="range-selector">

                  {[7, 30, 90].map(
                    (range) => (

                      <button
                        key={range}
                        className={
                          selectedRange === range
                            ? "range-button active"
                            : "range-button"
                        }
                        onClick={() =>
                          setSelectedRange(
                            range as RangeOption
                          )
                        }
                      >
                        {range}D
                      </button>

                    )
                  )}

                </div>

              </div>

            </div>


            <div className="chart-meta">

              <span>
                Daily publications
              </span>

              <span>
                7-day moving average
              </span>


              {selectedRange === 90 &&
                availableDays < 90 && (

                  <span className="data-warning">
                    {availableDays}D DATA
                    AVAILABLE
                  </span>

                )}

            </div>


            <div
              style={{
                width: "100%",
                height: 300,
              }}
            >

              <ResponsiveContainer>

                <LineChart
                  data={timelineData}
                  margin={{
                    top: 10,
                    right: 12,
                    left: 0,
                    bottom: 5,
                  }}
                >

                  <CartesianGrid
                    strokeDasharray="2 6"
                    stroke="#1a2230"
                    vertical={false}
                  />

                  <XAxis
                    dataKey="date"
                    tick={{
                      fontSize: 10,
                      fill: "#657189",
                    }}
                    tickFormatter={
                      formatDate
                    }
                    tickLine={false}
                    axisLine={{
                      stroke:
                        "#202735",
                    }}
                  />

                  <YAxis
                    allowDecimals={false}
                    tick={{
                      fontSize: 10,
                      fill: "#657189",
                    }}
                    tickLine={false}
                    axisLine={false}
                  />

                  <Tooltip
                    content={({
                      active,
                      payload,
                      label,
                    }) => {

                      if (
                        !active ||
                        !payload ||
                        payload.length === 0
                      ) {
                        return null;
                      }


                      const data =
                        payload[0]
                          ?.payload as TimelineData;


                      if (!data) {
                        return null;
                      }


                      return (

                        <div className="custom-tooltip">

                          <div className="tooltip-date">

                            {formatDate(
                              String(label ?? "")
                            )}

                          </div>


                          <div className="tooltip-row">

                            <span>
                              CVEs published
                            </span>

                            <strong>
                              {data.count}
                            </strong>

                          </div>


                          <div className="tooltip-row">

                            <span>
                              7-day average
                            </span>

                            <strong>
                              {
                                data.movingAverage
                              }
                            </strong>

                          </div>

                        </div>

                      );
                    }}
                  />


                  <Line
                    type="monotone"
                    dataKey="count"
                    name="Published CVEs"
                    stroke="#38bdf8"
                    strokeWidth={2}
                    dot={{
                      r: 2.5,
                      fill: "#38bdf8",
                    }}
                    activeDot={{
                      r: 5,
                    }}
                  />


                  <Line
                    type="monotone"
                    dataKey="movingAverage"
                    name="7-day average"
                    stroke="#a78bfa"
                    strokeWidth={2}
                    strokeDasharray="6 4"
                    dot={false}
                  />

                </LineChart>

              </ResponsiveContainer>

            </div>

          </div>


          <div className="panel">

            <div className="panel-header">

              <h2>
                Severity Distribution
              </h2>

            </div>


            <div
              style={{
                width: "100%",
                height: 300,
              }}
            >

              <ResponsiveContainer>

                <PieChart>

                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="43%"
                    innerRadius={48}
                    outerRadius={88}
                    paddingAngle={2}
                  >

                    {severityData.map(
                      (
                        entry,
                        index
                      ) => (

                        <Cell
                          key={`cell-${index}`}
                          fill={
                            SEVERITY_COLORS[
                              entry.name
                            ]
                          }
                        />

                      )
                    )}

                  </Pie>


                  <Tooltip
                    contentStyle={{
                      backgroundColor:
                        "#0d111a",
                      border:
                        "1px solid #202735",
                      borderRadius:
                        "6px",
                      color:
                        "#ffffff",
                    }}
                    formatter={(
                      value,
                      name
                    ) => [
                      `${value} CVEs`,
                      name,
                    ]}
                  />


                  <Legend
                    verticalAlign="bottom"
                    height={55}
                    formatter={(value) => {

                      const item =
                        severityData.find(
                          (entry) =>
                            entry.name ===
                            String(value ?? "")
                        );


                      const label = String(value ?? "");

                      return `${label}: ${
                        item?.value ?? 0
                      }`;

                    }}
                  />

                </PieChart>

              </ResponsiveContainer>

            </div>

          </div>

        </section>


        {/* ===================================================
            VULNERABILITY INTELLIGENCE
            =================================================== */}

        <section className="vulnerability-section">

          <div className="panel vulnerability-panel">

            <div className="panel-header vulnerability-header">

              <div>

                <h2>
                  Vulnerability Intelligence
                </h2>

                <div className="chart-subtitle">
                  Prioritized by Cyber Situation
                  Room risk scoring
                </div>

              </div>


              <span>
                DERIVED ANALYSIS
              </span>

            </div>


            {/* RISK SUMMARY */}

            <div className="risk-summary">

              <div className="risk-summary-item critical-risk">

                <span className="risk-summary-label">
                  CRITICAL
                </span>

                <strong>
                  {riskSummary.critical.toLocaleString()}
                </strong>

              </div>


              <div className="risk-summary-item high-risk">

                <span className="risk-summary-label">
                  HIGH
                </span>

                <strong>
                  {riskSummary.high.toLocaleString()}
                </strong>

              </div>


              <div className="risk-summary-item medium-risk">

                <span className="risk-summary-label">
                  MEDIUM
                </span>

                <strong>
                  {riskSummary.medium.toLocaleString()}
                </strong>

              </div>


              <div className="risk-summary-item low-risk">

                <span className="risk-summary-label">
                  LOW
                </span>

                <strong>
                  {riskSummary.low.toLocaleString()}
                </strong>

              </div>


              <div className="risk-summary-item kev-risk">

                <span className="risk-summary-label">
                  KEV
                </span>

                <strong>
                  {riskSummary.known_exploited}
                </strong>

              </div>

            </div>


            {/* TABLE */}

            <div className="table-wrapper">

              {vulnerabilityLoading ? (

                <div className="table-loading">
                  Loading vulnerability
                  intelligence...
                </div>

              ) : (

                <table className="vulnerability-table">

                  <thead>

                    <tr>

                      <th>
                        CVE
                      </th>

                      <th>
                        CVSS
                      </th>

                      <th>
                        SEVERITY
                      </th>

                      <th>
                        KEV
                      </th>

                      <th>
                        PUBLISHED
                      </th>

                      <th>
                        RISK
                      </th>

                    </tr>

                  </thead>


                  <tbody>

                    {prioritizedVulnerabilities.map(
                      (vulnerability) => (

                        <tr
                          key={
                            vulnerability.cve_id
                          }
                          className="clickable-row"
                          onClick={() =>
                            openCVE(
                              vulnerability
                            )
                          }
                          title="Open vulnerability intelligence"
                        >

                          <td>

                            <div className="cve-cell">

                              <strong>
                                {
                                  vulnerability.cve_id
                                }
                              </strong>

                              <span>

                                {
                                  vulnerability.description?.slice(
                                    0,
                                    90
                                  ) ||
                                  "No description available"
                                }

                                {
                                  vulnerability
                                    .description
                                    ?.length >
                                    90
                                    ? "..."
                                    : ""
                                }

                              </span>

                            </div>

                          </td>


                          <td>

                            <span className="cvss-value">

                              {
                                vulnerability.cvss_score !==
                                null
                                  ? vulnerability.cvss_score.toFixed(
                                      1
                                    )
                                  : "N/A"
                              }

                            </span>

                          </td>


                          <td>

                            <span
                              className={`table-severity ${
                                vulnerability.severity?.toLowerCase() ||
                                "unknown"
                              }`}
                            >

                              {
                                vulnerability.severity ||
                                "UNKNOWN"
                              }

                            </span>

                          </td>


                          <td>

                            {
                              vulnerability.known_exploited ===
                              1 ? (

                                <span className="kev-badge">
                                  KEV
                                </span>

                              ) : (

                                <span className="no-kev" style={{ fontSize: "11px", fontWeight: 400, color: "#64748b" }}>
                                  NO
                                </span>

                              )
                            }

                          </td>


                          <td>

                            <span className="published-date">

                              {formatFullDate(
                                vulnerability.published_date
                              )}

                            </span>

                          </td>


                          <td>

                            <div className="risk-cell">

                              <strong
                                className={`risk-score ${vulnerability.risk_level.toLowerCase()}`}
                              >

                                {
                                  vulnerability.risk_score
                                }

                              </strong>


                              <span
                                className={`risk-level ${vulnerability.risk_level.toLowerCase()}`}
                              >

                                {
                                  vulnerability.risk_level
                                }

                              </span>

                            </div>

                          </td>

                        </tr>

                      )
                    )}

                  </tbody>

                </table>

              )}

            </div>


            <div className="analysis-note">

              Risk score is a Cyber Situation Room
              derived analytical metric based on
              CVSS, CISA KEV status, and vulnerability
              recency. It is not an official NVD or
              CISA score.


              <span className="click-hint">

                Click a vulnerability to view
                score details.

              </span>

            </div>

          </div>

        </section>


        {/* ===================================================
            CORRELATION VISUALIZATION
            =================================================== */}

        <section className="vulnerability-section">
          <div className="panel vulnerability-panel">
            <div className="panel-header vulnerability-header">
              <div>
                <h2>Correlation Intelligence</h2>
                <div className="chart-subtitle">
                  CISA advisory → CVE → KEV → derived risk
                </div>
              </div>

              <span className="cti-source-label">
                EXPLICIT CVE LINKS • DERIVED
              </span>
            </div>

            {correlationGraphLoading ? (
              <div className="table-loading">
                Loading correlation intelligence...
              </div>
            ) : correlationGraphError ? (
              <div className="table-loading">
                Unable to load correlation intelligence: {correlationGraphError}
              </div>
            ) : !correlationGraph ? (
              <div className="table-loading">
                No correlation intelligence available.
              </div>
            ) : (
              <>
                <div className="risk-summary">
                  <div className="risk-summary-item">
                    <span className="risk-summary-label">ADVISORIES</span>
                    <strong>{correlationGraph.metrics.advisories}</strong>
                  </div>

                  <div className="risk-summary-item">
                    <span className="risk-summary-label">UNIQUE CVEs</span>
                    <strong>{correlationGraph.metrics.unique_cves}</strong>
                  </div>

                  <div className="risk-summary-item kev-risk">
                    <span className="risk-summary-label">KEV CVEs</span>
                    <strong>{correlationGraph.metrics.kev_cves}</strong>
                  </div>

                  <div className="risk-summary-item">
                    <span className="risk-summary-label">RELATIONSHIPS</span>
                    <strong>{correlationGraph.metrics.relationships}</strong>
                  </div>
                </div>

                <div
                  style={{
                    marginTop: "20px",
                    display: "grid",
                    gap: "12px",
                  }}
                >
                  {correlationGraph.nodes
                    .filter((node) => node.type === "advisory")
                    .map((advisory) => {
                      const connectedCveIds = correlationGraph.edges
                        .filter((edge) => edge.source === advisory.id)
                        .map((edge) => edge.target);

                      const connectedCves = correlationGraph.nodes.filter(
                        (node) =>
                          node.type === "cve" &&
                          connectedCveIds.includes(node.id)
                      );

                      return (
                        <div
                          key={advisory.id}
                          style={{
                            border:
                              "1px solid rgba(148, 163, 184, 0.16)",
                            borderRadius: "14px",
                            padding: "16px",
                            background:
                              "rgba(15, 23, 42, 0.35)",
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "flex-start",
                              gap: "16px",
                              marginBottom: "14px",
                            }}
                          >
                            <div style={{ minWidth: 0 }}>
                              <div
                                style={{
                                  fontSize: "10px",
                                  letterSpacing: "0.12em",
                                  opacity: 0.55,
                                  marginBottom: "5px",
                                }}
                              >
                                CISA ADVISORY #{advisory.event_id}
                              </div>

                              <strong
                                style={{
                                  display: "block",
                                  fontSize: "14px",
                                  lineHeight: 1.45,
                                }}
                              >
                                {advisory.label}
                              </strong>

                              {advisory.event_date && (
                                <div
                                  style={{
                                    marginTop: "6px",
                                    fontSize: "10px",
                                    opacity: 0.45,
                                  }}
                                >
                                  {formatThreatDate(advisory.event_date)}
                                </div>
                              )}
                            </div>

                            <div
                              style={{
                                flexShrink: 0,
                                textAlign: "right",
                              }}
                            >
                              <div
                                style={{
                                  fontSize: "9px",
                                  letterSpacing: "0.1em",
                                  opacity: 0.45,
                                }}
                              >
                                LINKS
                              </div>
                              <strong
                                style={{
                                  fontFamily: "monospace",
                                  fontSize: "18px",
                                }}
                              >
                                {connectedCves.length}
                              </strong>
                            </div>
                          </div>

                          {connectedCves.length === 0 ? (
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: "14px",
                              }}
                            >
                              <div
                                style={{
                                  minWidth: "150px",
                                  padding: "10px 12px",
                                  border:
                                    "1px solid rgba(56, 189, 248, 0.20)",
                                  borderRadius: "9px",
                                  background:
                                    "rgba(56, 189, 248, 0.05)",
                                }}
                              >
                                <div
                                  style={{
                                    fontSize: "9px",
                                    letterSpacing: "0.1em",
                                    opacity: 0.5,
                                    marginBottom: "4px",
                                  }}
                                >
                                  SOURCE
                                </div>
                                <strong style={{ fontSize: "11px" }}>
                                  CISA
                                </strong>
                              </div>

                              <span style={{ opacity: 0.3 }}>→</span>

                              <span
                                style={{
                                  fontSize: "11px",
                                  opacity: 0.38,
                                }}
                              >
                                No local NVD CVE match
                              </span>
                            </div>
                          ) : (
                            <div
                              style={{
                                display: "grid",
                                gridTemplateColumns:
                                  "150px 40px minmax(0, 1fr)",
                                gap: "12px",
                                alignItems: "center",
                              }}
                            >
                              <div
                                style={{
                                  padding: "10px 12px",
                                  border:
                                    "1px solid rgba(56, 189, 248, 0.20)",
                                  borderRadius: "9px",
                                  background:
                                    "rgba(56, 189, 248, 0.05)",
                                }}
                              >
                                <div
                                  style={{
                                    fontSize: "9px",
                                    letterSpacing: "0.1em",
                                    opacity: 0.5,
                                    marginBottom: "4px",
                                  }}
                                >
                                  SOURCE
                                </div>
                                <strong style={{ fontSize: "11px" }}>
                                  CISA
                                </strong>
                              </div>

                              <div
                                style={{
                                  textAlign: "center",
                                  fontSize: "20px",
                                  opacity: 0.35,
                                }}
                              >
                                →
                              </div>

                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns:
                                    "repeat(auto-fit, minmax(230px, 1fr))",
                                  gap: "10px",
                                }}
                              >
                                {connectedCves.map((cve) => {
                                  const risk = cve.risk_score ?? 0;
                                  const riskLevel =
                                    cve.risk_level || "UNKNOWN";

                                  return (
                                    <button
                                      key={cve.id}
                                      type="button"
                                      onClick={() =>
                                        openCorrelatedCVE(cve)
                                      }
                                      title="Open full vulnerability intelligence"
                                      style={{
                                        minWidth: 0,
                                        width: "100%",
                                        padding: "12px",
                                        textAlign: "left",
                                        border:
                                          "1px solid rgba(148, 163, 184, 0.16)",
                                        borderRadius: "9px",
                                        background:
                                          "rgba(30, 41, 59, 0.62)",
                                        color: "inherit",
                                        cursor: "pointer",
                                        transition:
                                          "border-color 0.15s ease, transform 0.15s ease",
                                      }}
                                      onMouseEnter={(event) => {
                                        event.currentTarget.style.borderColor =
                                          "rgba(56, 189, 248, 0.55)";
                                        event.currentTarget.style.transform =
                                          "translateY(-1px)";
                                      }}
                                      onMouseLeave={(event) => {
                                        event.currentTarget.style.borderColor =
                                          "rgba(148, 163, 184, 0.16)";
                                        event.currentTarget.style.transform =
                                          "translateY(0)";
                                      }}
                                    >
                                      <div
                                        style={{
                                          display: "flex",
                                          alignItems: "center",
                                          justifyContent: "space-between",
                                          gap: "8px",
                                        }}
                                      >
                                        <strong
                                          style={{
                                            fontFamily: "monospace",
                                            fontSize: "10px",
                                          }}
                                        >
                                          {cve.label}
                                        </strong>

                                        {cve.known_exploited && (
                                          <span className="kev-badge">
                                            KEV
                                          </span>
                                        )}
                                      </div>

                                      <div
                                        style={{
                                          display: "flex",
                                          alignItems: "center",
                                          gap: "8px",
                                          marginTop: "7px",
                                          fontSize: "9px",
                                          opacity: 0.75,
                                        }}
                                      >
                                        <span>
                                          CVSS{" "}
                                          {cve.cvss_score !== null &&
                                          cve.cvss_score !== undefined
                                            ? cve.cvss_score.toFixed(1)
                                            : "N/A"}
                                        </span>

                                        <span>•</span>

                                        <span>
                                          Risk{" "}
                                          <strong
                                            style={{
                                              fontFamily: "monospace",
                                            }}
                                          >
                                            {risk.toFixed(1)}
                                          </strong>
                                        </span>

                                        <span
                                          className={`risk-level ${riskLevel.toLowerCase()}`}
                                          style={{
                                            marginLeft: "auto",
                                          }}
                                        >
                                          {riskLevel}
                                        </span>
                                      </div>

                                      <div
                                        style={{
                                          marginTop: "8px",
                                          fontSize: "8px",
                                          letterSpacing: "0.08em",
                                          opacity: 0.38,
                                        }}
                                      >
                                        CLICK TO VIEW NVD DESCRIPTION +
                                        RISK BREAKDOWN
                                      </div>
                                    </button>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                </div>

                <div className="analysis-note">
                  Correlation source:{" "}
                  {correlationGraph.analysis_scope.source}. Method:{" "}
                  {correlationGraph.analysis_scope.correlation_method}.
                  Relationships are created only from explicit CVE
                  identifiers in CISA advisory text. CVSS and KEV are source
                  data; risk is a Cyber Situation Room derived metric. No
                  keyword-only correlation is used.
                </div>
              </>
            )}
          </div>
        </section>




        {/* ===================================================
            THREAT INTELLIGENCE
            =================================================== */}

        <section className="vulnerability-section">

          <div className="panel vulnerability-panel">

            <div className="panel-header vulnerability-header">

              <div>

                <h2>
                  Threat Intelligence
                </h2>

                <div className="chart-subtitle">
                  Latest public cybersecurity advisories
                  from CISA
                </div>

              </div>


              <span className="cti-source-label">
                CISA • LIVE FEED
              </span>

            </div>


            {/* CTI SUMMARY */}

            <div className="risk-summary">

              <div className="risk-summary-item">

                <span className="risk-summary-label">
                  TOTAL
                </span>

                <strong>
                  {threatSummary.total}
                </strong>

              </div>


              <div className="risk-summary-item critical-risk">

                <span className="risk-summary-label">
                  CRITICAL
                </span>

                <strong>
                  {threatSummary.critical}
                </strong>

              </div>


              <div className="risk-summary-item high-risk">

                <span className="risk-summary-label">
                  HIGH
                </span>

                <strong>
                  {threatSummary.high}
                </strong>

              </div>


              <div className="risk-summary-item medium-risk">

                <span className="risk-summary-label">
                  MEDIUM
                </span>

                <strong>
                  {threatSummary.medium}
                </strong>

              </div>


              <div className="risk-summary-item">

                <span className="risk-summary-label">
                  SOURCE
                </span>

                <strong>
                  CISA
                </strong>

              </div>

            </div>


            {/* CTI ANALYTICS */}

            {!threatLoading && threatSummary.total > 0 && (

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns:
                    "minmax(0, 1fr) minmax(0, 1fr)",
                  gap: "12px",
                  marginBottom: "18px",
                }}
              >

                <div
                  style={{
                    border: "1px solid #202735",
                    borderRadius: "8px",
                    padding: "14px",
                    background: "#0b1018",
                  }}
                >

                  <div
                    style={{
                      fontSize: "10px",
                      letterSpacing: "0.12em",
                      color: "#657189",
                      marginBottom: "10px",
                    }}
                  >
                    EVENT TYPE BREAKDOWN
                  </div>

                  <div
                    style={{
                      display: "flex",
                      flexWrap: "wrap",
                      gap: "8px",
                    }}
                  >

                    {topThreatTypes.map(
                      ([type, count]) => (

                        <span
                          key={type}
                          style={{
                            border: "1px solid #202735",
                            borderRadius: "999px",
                            padding: "6px 9px",
                            fontSize: "11px",
                            color: "#cbd5e1",
                          }}
                        >
                          {type} · {count}
                        </span>

                      )
                    )}

                  </div>

                </div>


                <div
                  style={{
                    border: "1px solid #202735",
                    borderRadius: "8px",
                    padding: "14px",
                    background: "#0b1018",
                  }}
                >

                  <div
                    style={{
                      fontSize: "10px",
                      letterSpacing: "0.12em",
                      color: "#657189",
                      marginBottom: "10px",
                    }}
                  >
                    INTELLIGENCE SCOPE
                  </div>

                  <div
                    style={{
                      display: "flex",
                      gap: "18px",
                      alignItems: "center",
                    }}
                  >

                    <div>
                      <strong
                        style={{
                          fontSize: "20px",
                          color: "#e5e7eb",
                        }}
                      >
                        {threatEventTypes.length}
                      </strong>

                      <div
                        style={{
                          fontSize: "10px",
                          color: "#657189",
                        }}
                      >
                        derived event types
                      </div>
                    </div>

                    <div>
                      <strong
                        style={{
                          fontSize: "20px",
                          color: "#e5e7eb",
                        }}
                      >
                        {Object.keys(
                          threatSummary.sources
                        ).length}
                      </strong>

                      <div
                        style={{
                          fontSize: "10px",
                          color: "#657189",
                        }}
                      >
                        source(s)
                      </div>
                    </div>

                  </div>

                </div>

              </div>

            )}


            {/* CTI FILTERS */}

            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: "10px",
                alignItems: "center",
                marginBottom: "14px",
              }}
            >

              <span
                style={{
                  fontSize: "10px",
                  letterSpacing: "0.1em",
                  color: "#657189",
                }}
              >
                FILTER
              </span>

              <select
                value={threatSeverityFilter}
                onChange={(event) =>
                  setThreatSeverityFilter(
                    event.target.value
                  )
                }
                style={{
                  background: "#0b1018",
                  color: "#cbd5e1",
                  border: "1px solid #202735",
                  borderRadius: "6px",
                  padding: "7px 10px",
                  fontSize: "11px",
                }}
              >
                <option value="ALL">
                  ALL SEVERITIES
                </option>
                <option value="CRITICAL">
                  CRITICAL
                </option>
                <option value="HIGH">
                  HIGH
                </option>
                <option value="MEDIUM">
                  MEDIUM
                </option>
                <option value="LOW">
                  LOW
                </option>
              </select>


              <select
                value={threatTypeFilter}
                onChange={(event) =>
                  setThreatTypeFilter(
                    event.target.value
                  )
                }
                style={{
                  background: "#0b1018",
                  color: "#cbd5e1",
                  border: "1px solid #202735",
                  borderRadius: "6px",
                  padding: "7px 10px",
                  fontSize: "11px",
                }}
              >
                <option value="ALL">
                  ALL EVENT TYPES
                </option>

                {threatEventTypes.map(
                  (type) => (
                    <option
                      key={type}
                      value={type}
                    >
                      {type.toUpperCase()}
                    </option>
                  )
                )}

              </select>


              <span
                style={{
                  fontSize: "10px",
                  color: "#657189",
                  marginLeft: "auto",
                }}
              >
                {filteredThreatEvents.length}
                {" "}of{" "}
                {threatEvents.length} records
              </span>

            </div>


            {/* CTI FEED */}

            <div className="cti-feed">

              {threatLoading ? (

                <div className="table-loading">
                  Loading threat intelligence...
                </div>

              ) : threatEvents.length === 0 ? (

                <div className="table-loading">
                  No threat intelligence records
                  available.
                </div>

              ) : (

                filteredThreatEvents.map(
                  (event) => (

                    <div
                      className="cti-event"
                      key={event.id}
                      onClick={() => openThreat(event)}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(keyboardEvent) => {
                        if (
                          keyboardEvent.key === "Enter" ||
                          keyboardEvent.key === " "
                        ) {
                          keyboardEvent.preventDefault();
                          openThreat(event);
                        }
                      }}
                      style={{ cursor: "pointer" }}
                    >

                      <div className="cti-event-indicator">

                        <span
                          className={`cti-severity-dot ${
                            (
                              event.severity ||
                              "MEDIUM"
                            ).toLowerCase()
                          }`}
                        />

                      </div>


                      <div className="cti-event-content">

                        <div className="cti-event-top">

                          <span
                            className={`table-severity ${
                              (
                                event.severity ||
                                "MEDIUM"
                              ).toLowerCase()
                            }`}
                          >

                            {
                              event.severity ||
                              "MEDIUM"
                            }

                          </span>


                          <span className="cti-event-type">

                            {
                              event.advisory_type ||
                              "Cybersecurity Advisory"
                            }

                          </span>

                          <span
                            style={{
                              fontSize: "9px",
                              letterSpacing: "0.08em",
                              color: "#64748b",
                              border: "1px solid #202735",
                              borderRadius: "4px",
                              padding: "3px 6px",
                            }}
                          >
                            DERIVED
                          </span>

                        </div>


                        <strong className="cti-event-title">

                          {event.title}

                        </strong>


                        <p className="cti-event-description">

                          {
                            event.description ||
                            "No description available."
                          }

                        </p>


                        <div className="cti-event-meta">

                          <span>

                            {event.source_name ||
                              "CISA"}

                          </span>


                          <span>
                            •
                          </span>


                          <span>

                            {formatThreatDate(
                              event.event_date
                            )}

                          </span>


                          {event.event_type && (

                            <>
                              <span>
                                •
                              </span>

                              <span>

                                {event.event_type}

                              </span>
                            </>

                          )}

                        </div>

                      </div>


                      {event.source_url && (

                        <a
                          className="cti-open-link"
                          href={
                            event.source_url
                          }
                          target="_blank"
                          rel="noreferrer"
                          onClick={(e) =>
                            e.stopPropagation()
                          }
                        >

                          VIEW CISA
                          <span>
                            ↗
                          </span>

                        </a>

                      )}

                    </div>

                  )
                )

              )}

            </div>


            <div className="analysis-note">

              Source data is retrieved from the
              official CISA advisory feed. Event type
              and severity shown above are Cyber
              Situation Room derived classifications
              and should not be interpreted as official
              CISA severity ratings.

            </div>

          </div>

        </section>


        {/* ===================================================
            INTELLIGENCE ANALYSIS
            =================================================== */}

        <section className="vulnerability-section">

          <div className="panel vulnerability-panel">

            <div className="panel-header vulnerability-header">
              <div>
                <h2>
                  Intelligence Analysis
                </h2>

                <div className="chart-subtitle">
                  Cross-source analysis derived from explicit CVE references
                </div>
              </div>

              <span className="cti-source-label">
                CISA + NVD + KEV • DERIVED
              </span>
            </div>

            {intelligenceAnalysisLoading ? (
              <div className="detail-loading">
                Loading intelligence analysis...
              </div>
            ) : intelligenceAnalysis ? (
              <>

                <div className="risk-summary">
                  <div className="risk-summary-item">
                    <span className="risk-summary-label">
                      CISA ADVISORIES
                    </span>
                    <strong>
                      {intelligenceAnalysis.analysis_scope.total_advisories}
                    </strong>
                  </div>

                  <div className="risk-summary-item">
                    <span className="risk-summary-label">
                      CVE REFERENCES
                    </span>
                    <strong>
                      {intelligenceAnalysis.correlation_metrics.unique_cve_references}
                    </strong>
                  </div>

                  <div className="risk-summary-item high-risk">
                    <span className="risk-summary-label">
                      NVD MATCHED
                    </span>
                    <strong>
                      {intelligenceAnalysis.correlation_metrics.nvd_matched}
                    </strong>
                  </div>

                  <div className="risk-summary-item critical-risk">
                    <span className="risk-summary-label">
                      KEV CORRELATED
                    </span>
                    <strong>
                      {intelligenceAnalysis.correlation_metrics.kev_correlated}
                    </strong>
                  </div>
                </div>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)",
                    gap: "12px",
                    marginBottom: "18px",
                  }}
                >

                  <div
                    style={{
                      border: "1px solid #202735",
                      borderRadius: "8px",
                      padding: "16px",
                      background: "#0b1018",
                    }}
                  >
                    <div style={{ fontSize: "10px", letterSpacing: "0.12em", color: "#657189", marginBottom: "14px" }}>
                      CORRELATION COVERAGE
                    </div>

                    <div style={{ display: "grid", gap: "11px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: "12px" }}>
                        <span style={{ fontSize: "12px" }}>Advisories with CVEs</span>
<strong style={{ fontSize: "14px" }}>{intelligenceAnalysis.correlation_metrics.advisories_with_cves}</strong>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: "12px" }}>
                        <span style={{ fontSize: "12px" }}>Explicit CVE references</span>
<strong style={{ fontSize: "14px" }}>{intelligenceAnalysis.correlation_metrics.total_cve_mentions}</strong>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: "12px" }}>
                        <span style={{ fontSize: "12px" }}>NVD matched</span>
<strong style={{ fontSize: "14px" }}>{intelligenceAnalysis.correlation_metrics.nvd_matched}</strong>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: "12px" }}>
                        <span style={{ fontSize: "12px" }}>NVD unmatched</span>
<strong style={{ fontSize: "14px" }}>{intelligenceAnalysis.correlation_metrics.nvd_unmatched}</strong>
                      </div>
                    </div>
                  </div>

                  <div
                    style={{
                      border: "1px solid #202735",
                      borderRadius: "8px",
                      padding: "16px",
                      background: "#0b1018",
                    }}
                  >
                    <div style={{ fontSize: "10px", letterSpacing: "0.12em", color: "#657189", marginBottom: "14px" }}>
                      CORRELATED RISK
                    </div>

                    <div style={{ display: "grid", gap: "11px" }}>
                      {([
                        ["CRITICAL", intelligenceAnalysis.risk_distribution.critical],
                        ["HIGH", intelligenceAnalysis.risk_distribution.high],
                        ["MEDIUM", intelligenceAnalysis.risk_distribution.medium],
                        ["LOW", intelligenceAnalysis.risk_distribution.low],
                      ] as const).map(([label, count]) => (
                        <div key={label} style={{ display: "flex", justifyContent: "space-between", gap: "12px" }}>
                          <span style={{ fontSize: "12px" }}>{label}</span>
<strong style={{ fontSize: "14px" }}>{count}</strong>
                        </div>
                      ))}
                    </div>
                  </div>

                </div>

                <div className="detail-section" style={{ marginBottom: "18px" }}>
                  <div className="detail-section-title">
                    HIGHEST-RISK CORRELATED VULNERABILITIES
                  </div>

                  <div style={{ overflowX: "auto", border: "1px solid #202735", borderRadius: "7px" }}>
                    <table
                      className="cve-table"
                      style={{ minWidth: "760px", margin: 0 }}
                    >
                      <thead>
                        <tr>
                          <th style={{ minWidth: "190px", padding: "12px 14px", textAlign: "left" }}>CVE</th>
                          <th style={{ minWidth: "75px", padding: "12px 14px", textAlign: "center" }}>CVSS</th>
                          <th style={{ minWidth: "110px", padding: "12px 14px" }}>NVD SEVERITY</th>
                          <th style={{ minWidth: "85px", padding: "12px 14px", textAlign: "center" }}>KEV</th>
                          <th style={{ minWidth: "120px", padding: "12px 14px", textAlign: "center" }}>DERIVED RISK</th>
                          <th style={{ minWidth: "105px", padding: "12px 14px" }}>RISK LEVEL</th>
                          <th style={{ minWidth: "90px", padding: "12px 14px", textAlign: "center" }}>REFERENCES</th>
                        </tr>
                      </thead>
                      <tbody>
                        {intelligenceAnalysis.highest_risk_correlations.map((item) => (
                          <tr key={item.cve_id}>
                            <td style={{ padding: "13px 14px", textAlign: "left" }}>
  <button
    type="button"
    onClick={() =>
      openCorrelatedCVE({
        id: item.cve_id,
        type: "cve",
        label: item.cve_id,
        cvss_score: item.cvss_score ?? null,
        severity: item.nvd_severity ?? null,
        known_exploited: item.known_exploited ?? false,
        risk_score: item.risk_score ?? 0,
        risk_level: item.risk_level || "UNKNOWN",
        published_date: "",
      })
    }
    title="Open full vulnerability intelligence"
    style={{
      border: "none",
      padding: 0,
      margin: 0,
      background: "transparent",
      color: "#e5e7eb",
      fontFamily: "monospace",
      fontSize: "12px",
      fontWeight: 700,
      cursor: "pointer",
      textAlign: "left",
    }}
  >
    {item.cve_id}
  </button>
</td>

                            <td style={{ padding: "13px 14px", textAlign: "center" }}>
                              <strong style={{ fontSize: "13px" }}>
                                {item.cvss_score !== null ? item.cvss_score.toFixed(1) : "N/A"}
                              </strong>
                            </td>

                            <td style={{ padding: "13px 14px" }}>
                              <span
                                className={`table-severity ${(item.nvd_severity || "UNKNOWN").toLowerCase()}`}
                              >
                                {item.nvd_severity || "UNKNOWN"}
                              </span>
                            </td>

                            <td style={{ padding: "13px 14px", textAlign: "center" }}>
                              {item.known_exploited ? (
                                <span className="kev-badge">KEV</span>
                              ) : (
                                <span className="no-kev" style={{ fontSize: "11px", fontWeight: 400, color: "#64748b" }}>NO</span>
                              )}
                            </td>

                            <td style={{ padding: "13px 14px", textAlign: "center" }}>
                              <strong
                                className={`risk-score ${item.risk_level.toLowerCase()}`}
                                style={{ fontSize: "15px" }}
                              >
                                {item.risk_score.toFixed(1)}
                              </strong>
                            </td>

                            <td style={{ padding: "13px 14px" }}>
                              <span className={`risk-level ${item.risk_level.toLowerCase()}`}>
                                {item.risk_level}
                              </span>
                            </td>

                            <td style={{ padding: "13px 14px", textAlign: "center" }}>
                              <span
                                style={{
                                  display: "inline-flex",
                                  minWidth: "24px",
                                  justifyContent: "center",
                                  padding: "3px 7px",
                                  border: "1px solid #2a3445",
                                  borderRadius: "4px",
                                  fontSize: "11px",
                                  color: "#aeb8c9",
                                }}
                              >
                                {item.reference_count}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="detail-section">
                  <div className="detail-section-title">
                    UNMATCHED CVE REFERENCES
                  </div>

                  <p style={{ marginTop: "8px", color: "#8b96aa", fontSize: "12px", lineHeight: 1.6 }}>
                    These CVE identifiers were explicitly referenced by CISA but are not present in the current local NVD dataset. They are retained as intelligence evidence rather than discarded.
                  </p>

                  <div style={{ display: "flex", flexWrap: "wrap", gap: "7px", marginTop: "12px" }}>
                    {intelligenceAnalysis.unmatched_cves.map((cveId) => (
                      <span
                        key={cveId}
                        style={{
                          border: "1px solid #202735",
                          borderRadius: "5px",
                          padding: "6px 8px",
                          fontSize: "10px",
                          color: "#aeb8c9",
                          background: "#0b1018",
                        }}
                      >
                        {cveId}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="analysis-note">
                  Analysis is derived from explicit CVE identifiers found in CISA advisories. NVD and KEV values are source data; risk levels are Cyber Situation Room derived metrics. No keyword-only correlations are created.
                </div>

              </>
            ) : (
              <div className="detail-error">
                Unable to load intelligence analysis.
              </div>
            )}

          </div>

        </section>


        {/* ===================================================
            MITRE ATT&CK
            =================================================== */}

        <section className="vulnerability-section">

          <div className="panel vulnerability-panel">

            <div className="panel-header vulnerability-header">
              <div>
                <h2>
                  MITRE ATT&CK Mapping
                </h2>

                <div className="chart-subtitle">
                  Enterprise technique mapping derived from behavioral evidence validation
                </div>
              </div>

              <span className="cti-source-label">
                CISA + MITRE ATT&CK • DERIVED
              </span>
            </div>

            {mitreAttackLoading ? (
              <div className="detail-loading">
                Loading MITRE ATT&CK analysis...
              </div>
            ) : mitreAttackAnalysis ? (
              <>

                <div className="risk-summary">
                  <div className="risk-summary-item">
                    <span className="risk-summary-label">
                      CISA ADVISORIES
                    </span>
                    <strong>
                      {mitreAttackAnalysis.analysis_scope.total_advisories}
                    </strong>
                  </div>

                  <div className="risk-summary-item high-risk">
                    <span className="risk-summary-label">
                      VALIDATED MAPPINGS
                    </span>
                    <strong>
                      {mitreAttackAnalysis.metrics.total_mappings}
                    </strong>
                  </div>

                  <div className="risk-summary-item critical-risk">
                    <span className="risk-summary-label">
                      HIGH CONFIDENCE
                    </span>
                    <strong>
                      {mitreAttackAnalysis.metrics.high_confidence}
                    </strong>
                  </div>

                  <div className="risk-summary-item">
                    <span className="risk-summary-label">
                      UNMAPPED
                    </span>
                    <strong>
                      {mitreAttackAnalysis.metrics.unmapped_events}
                    </strong>
                  </div>
                </div>

                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1fr)",
                    gap: "12px",
                    marginBottom: "18px",
                  }}
                >

                  <div
                    style={{
                      border: "1px solid #202735",
                      borderRadius: "8px",
                      padding: "16px",
                      background: "#0b1018",
                    }}
                  >
                    <div style={{
                      fontSize: "10px",
                      letterSpacing: "0.12em",
                      color: "#657189",
                      marginBottom: "14px",
                    }}>
                      TOP TECHNIQUES
                    </div>

                    <div style={{ display: "grid", gap: "10px" }}>
                      {mitreAttackAnalysis.top_techniques.length === 0 ? (
                        <span style={{ color: "#64748b", fontSize: "12px" }}>
                          No explicit technique-name matches found.
                        </span>
                      ) : (
                        mitreAttackAnalysis.top_techniques.map((item) => (
                          <div
                            key={item.attack_id}
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              gap: "12px",
                              alignItems: "center",
                            }}
                          >
                            <div>
                              <strong style={{ fontFamily: "monospace", fontSize: "11px" }}>
                                {item.attack_id}
                              </strong>
                              <span style={{ marginLeft: "8px", fontSize: "12px" }}>
                                {item.technique_name}
                              </span>
                            </div>
                            <strong style={{ fontSize: "14px" }}>{item.event_count}</strong>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div
                    style={{
                      border: "1px solid #202735",
                      borderRadius: "8px",
                      padding: "16px",
                      background: "#0b1018",
                    }}
                  >
                    <div style={{
                      fontSize: "10px",
                      letterSpacing: "0.12em",
                      color: "#657189",
                      marginBottom: "14px",
                    }}>
                      TOP TACTICS
                    </div>

                    <div style={{ display: "grid", gap: "10px" }}>
                      {mitreAttackAnalysis.top_tactics.length === 0 ? (
                        <span style={{ color: "#64748b", fontSize: "12px" }}>
                          No mapped tactics yet.
                        </span>
                      ) : (
                        mitreAttackAnalysis.top_tactics.map((item) => (
                          <div
                            key={item.tactic}
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              gap: "12px",
                            }}
                          >
                            <span style={{ fontSize: "12px" }}>
  {item.tactic.charAt(0).toUpperCase() + item.tactic.slice(1)}
</span>
                            <strong style={{ fontSize: "14px" }}>{item.event_count}</strong>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                </div>

                <div className="detail-section">
                  <div className="detail-section-title">
                    TECHNIQUE EVIDENCE
                  </div>

                  {mitreAttackAnalysis.mappings.length === 0 ? (
                    <div style={{
                      marginTop: "10px",
                      color: "#64748b",
                      fontSize: "12px",
                    }}>
                      No explicit MITRE ATT&CK technique names were found in the current CISA advisory set.
                    </div>
                  ) : (
                    <div style={{
                      display: "grid",
                      gap: "8px",
                      marginTop: "10px",
                    }}>
                      {mitreAttackAnalysis.mappings.slice(0, 12).map((mapping, index) => (
                        <a
                          key={`${mapping.event_id}-${mapping.attack_id}-${index}`}
                          href={mapping.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{
                            display: "block",
                            color: "inherit",
                            textDecoration: "none",
                            border: "1px solid #202735",
                            borderRadius: "7px",
                            padding: "11px 12px",
                            background: "#0b1018",
                            cursor: "pointer",
                          }}
                          title={`Open ${mapping.attack_id} in MITRE ATT&CK`}
                        >
                          <div style={{
                            display: "flex",
                            justifyContent: "space-between",
                            gap: "12px",
                            flexWrap: "wrap",
                            alignItems: "center",
                          }}>
                            <div>
                              <strong style={{ fontFamily: "monospace", fontSize: "11px" }}>
                                {mapping.attack_id}
                              </strong>
                              <span style={{ marginLeft: "8px", fontSize: "12px" }}>
                                {mapping.technique_name}
                              </span>
                            </div>

                            <span style={{
                              fontSize: "9px",
                              letterSpacing: "0.08em",
                              color: mapping.confidence === "HIGH" ? "#86efac" : "#fbbf24",
                              border: "1px solid #202735",
                              borderRadius: "4px",
                              padding: "4px 7px",
                            }}>
                              {mapping.confidence}
                            </span>
                          </div>

                          <div style={{
                            marginTop: "7px",
                            color: "#7f8ba0",
                            fontSize: "10px",
                          }}>
                            {mapping.event_title || `CISA event #${mapping.event_id}`}
                          </div>

                          <div style={{
                            marginTop: "7px",
                            color: "#aeb8c9",
                            fontSize: "11px",
                            lineHeight: 1.5,
                          }}>
                            Evidence: {mapping.evidence}
                          </div>
                        </a>
                      ))}
                    </div>
                  )}
                </div>

                <div className="analysis-note">
                  ATT&CK mappings are created only after behavioral evidence is validated against the Enterprise ATT&CK catalog. Security terms appearing in advisory text are treated as context unless they provide sufficient adversarial-behavior evidence. These are Cyber Situation Room derived mappings, not official MITRE attribution.
                </div>

              </>
            ) : (
              <div className="detail-error">
                Unable to load MITRE ATT&CK analysis.
              </div>
            )}

          </div>

        </section>


        {/* ===================================================
            LATEST INTELLIGENCE
            =================================================== */}

        <section className="panel intelligence">

          <div className="panel-header">

            <h2>
              Latest Intelligence
            </h2>

            <span>
              PUBLIC SOURCES
            </span>

          </div>


          <div className="intel-row">

            <span className="severity critical">
              CRITICAL
            </span>


            <div>

              <strong>
                CISA Threat Intelligence
              </strong>

              <p>
                {threatSummary.total} public
                cybersecurity advisories are currently
                available from the CISA feed.
              </p>

            </div>

          </div>


          <div className="intel-row">

            <span className="severity high">
              HIGH
            </span>


            <div>

              <strong>
                Vulnerability intelligence
              </strong>

              <p>
                Prioritized CVE intelligence is
                available above.
              </p>

            </div>

          </div>

        </section>

      </main>


      {/* =====================================================
          THREAT INTELLIGENCE DETAIL OVERLAY
          ===================================================== */}

      {selectedThreat && (
        <div
          className="cve-overlay"
          onClick={() => {
            setSelectedThreat(null);
            setThreatCorrelations([]);
            setCorrelationLoading(false);
          }}
        >
          <div
            className="cve-detail-panel"
            onClick={(event) => event.stopPropagation()}
            style={{ maxWidth: "820px" }}
          >
            <div className="detail-header">
              <div>
                <div className="detail-eyebrow">
                  THREAT INTELLIGENCE
                </div>

                <h2>
                  {selectedThreat.title}
                </h2>

                <p>
                  {selectedThreat.source_name || "CISA"} advisory
                </p>
              </div>

              <button
                className="close-button"
                onClick={() => {
                setSelectedThreat(null);
                setThreatCorrelations([]);
                setCorrelationLoading(false);
              }}
                aria-label="Close threat intelligence details"
              >
                ×
              </button>
            </div>

            <div
              className="detail-status-grid"
              style={{ marginBottom: "20px" }}
            >
              <div className="detail-status-card">
                <span>DERIVED SEVERITY</span>

                <strong className="detail-severity">
                  {selectedThreat.severity || "UNKNOWN"}
                </strong>

                <small>
                  Cyber Situation Room classification
                </small>
              </div>

              <div className="detail-status-card">
                <span>EVENT TYPE</span>

                <strong
                  style={{
                    fontSize: "16px",
                    lineHeight: 1.3,
                  }}
                >
                  {selectedThreat.event_type || "UNKNOWN"}
                </strong>

                <small>
                  Derived classification
                </small>
              </div>

              <div className="detail-status-card">
                <span>ADVISORY TYPE</span>

                <strong
                  style={{
                    fontSize: "16px",
                    lineHeight: 1.3,
                  }}
                >
                  {selectedThreat.advisory_type ||
                    "Cybersecurity Advisory"}
                </strong>

                <small>
                  Feed metadata
                </small>
              </div>
            </div>

            <div
              style={{
                border: "1px solid #202735",
                borderRadius: "8px",
                padding: "18px",
                background: "#0b1018",
                marginBottom: "16px",
              }}
            >
              <div
                style={{
                  fontSize: "10px",
                  letterSpacing: "0.12em",
                  color: "#657189",
                  marginBottom: "10px",
                }}
              >
                ADVISORY DESCRIPTION
              </div>

              <p
                style={{
                  margin: 0,
                  color: "#cbd5e1",
                  fontSize: "14px",
                  lineHeight: 1.8,
                  whiteSpace: "pre-wrap",
                }}
              >
                {selectedThreat.description ||
                  "No description available."}
              </p>
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns:
                  "repeat(auto-fit, minmax(180px, 1fr))",
                gap: "10px",
                marginBottom: "18px",
              }}
            >
              <div className="detail-status-card">
                <span>SOURCE</span>
                <strong style={{ fontSize: "14px" }}>
                  {selectedThreat.source_name || "CISA"}
                </strong>
              </div>

              <div className="detail-status-card">
                <span>PUBLISHED</span>
                <strong style={{ fontSize: "14px" }}>
                  {formatThreatDate(
                    selectedThreat.event_date
                  )}
                </strong>
              </div>

              <div className="detail-status-card">
                <span>RECORD ID</span>
                <strong
                  style={{
                    fontSize: "12px",
                    wordBreak: "break-all",
                  }}
                >
                  {selectedThreat.external_id || "N/A"}
                </strong>
              </div>
            </div>

            <div
              style={{
                border: "1px solid #202735",
                borderRadius: "8px",
                padding: "18px",
                background: "#0b1018",
                marginBottom: "16px",
              }}
            >
              <div
                style={{
                  fontSize: "10px",
                  letterSpacing: "0.12em",
                  color: "#657189",
                  marginBottom: "12px",
                }}
              >
                CORRELATED VULNERABILITIES
              </div>

              {correlationLoading ? (
                <div style={{ color: "#64748b", fontSize: "13px" }}>
                  Correlating advisory with CVE database...
                </div>
              ) : threatCorrelations.length === 0 ? (
                <div style={{ color: "#64748b", fontSize: "13px" }}>
                  No CVE identifiers were found in this advisory.
                </div>
              ) : (
                <div style={{ display: "grid", gap: "10px" }}>
                  {threatCorrelations.map((correlation) => (
                    <div
                      key={correlation.cve_id}
                      style={{
                        border: "1px solid #202735",
                        borderRadius: "6px",
                        padding: "12px",
                        background: "#0d131d",
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          gap: "12px",
                          flexWrap: "wrap",
                          alignItems: "center",
                        }}
                      >
                        <button
  type="button"
  onClick={() =>
    openCorrelatedCVE({
      id: correlation.cve_id,
      type: "cve",
      label: correlation.cve_id,
      cvss_score: correlation.cvss_score ?? null,
      severity: correlation.nvd_severity ?? null,
      known_exploited: correlation.known_exploited ?? false,
      risk_score: correlation.risk_score ?? 0,
      risk_level: correlation.risk_level || "UNKNOWN",
      published_date: correlation.published_date || "",
    })
  }
  title="Open full vulnerability intelligence"
  style={{
    border: "none",
    padding: 0,
    margin: 0,
    background: "transparent",
    color: "#e5e7eb",
    fontSize: "14px",
    fontWeight: 700,
    cursor: "pointer",
    textAlign: "left",
  }}
>
  {correlation.cve_id}
</button>

                        <span
                          style={{
                            fontSize: "9px",
                            letterSpacing: "0.08em",
                            color: correlation.found_in_database ? "#86efac" : "#fbbf24",
                            border: "1px solid #202735",
                            borderRadius: "4px",
                            padding: "4px 7px",
                          }}
                        >
                          {correlation.found_in_database ? "NVD MATCH" : "NOT IN DATABASE"}
                        </span>
                      </div>

                      {correlation.found_in_database && (
                        <div
                          style={{
                            display: "flex",
                            flexWrap: "wrap",
                            gap: "14px",
                            marginTop: "10px",
                            color: "#94a3b8",
                            fontSize: "11px",
                          }}
                        >
                          <span>CVSS: <strong style={{ color: "#e5e7eb" }}>{correlation.cvss_score ?? "N/A"}</strong></span>
                          <span>NVD: <strong style={{ color: "#e5e7eb" }}>{correlation.nvd_severity || "N/A"}</strong></span>
                          <span>Derived risk: <strong style={{ color: "#e5e7eb" }}>{correlation.risk_score ?? "N/A"}</strong></span>
                          <span>Risk level: <strong style={{ color: "#e5e7eb" }}>{correlation.risk_level || "N/A"}</strong></span>
                          <span>KEV: <strong style={{ color: "#e5e7eb" }}>{correlation.known_exploited ? "YES" : "NO"}</strong></span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="analysis-note">
              Severity and event type are derived by Cyber
              Situation Room and are not official CISA severity
              ratings.
            </div>

            {selectedThreat.source_url && (
              <div
                style={{
                  marginTop: "18px",
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <a
                  className="cti-open-link"
                  href={selectedThreat.source_url}
                  target="_blank"
                  rel="noreferrer"
                >
                  OPEN ORIGINAL CISA ADVISORY
                  <span>↗</span>
                </a>
              </div>
            )}
          </div>
        </div>
      )}


      {/* =====================================================
          CVE DETAIL OVERLAY
          ===================================================== */}

      {selectedCVE && (

        <div
          className="cve-overlay"
          onClick={closeCVE}
        >

          <div
            className="cve-detail-panel"
            onClick={(event) =>
              event.stopPropagation()
            }
          >

            <div className="detail-header">

              <div>

                <div className="detail-eyebrow">
                  VULNERABILITY INTELLIGENCE
                </div>

                <h2>
                  {selectedCVE.cve_id}
                </h2>

                <p>
                  Explainable risk assessment
                </p>

              </div>


              <button
                className="close-button"
                onClick={closeCVE}
                aria-label="Close vulnerability details"
              >
                ×
              </button>

            </div>


            {/* STATUS */}

            <div className="detail-status-grid">

              <div className="detail-status-card">

                <span>
                  RISK SCORE
                </span>

                <strong
                  className={`detail-risk-score ${
                    selectedCVE.risk_level.toLowerCase()
                  }`}
                >

                  {selectedCVE.risk_score}

                </strong>

                <small>
                  {selectedCVE.risk_level}
                </small>

              </div>


              <div className="detail-status-card">

                <span>
                  CVSS
                </span>

                <strong>

                  {selectedCVE.cvss_score !== null &&
selectedCVE.cvss_score !== undefined
  ? selectedCVE.cvss_score.toFixed(1)
  : "N/A"}

                </strong>

                <small>
                  NVD severity
                </small>

              </div>


              <div className="detail-status-card">

                <span>
                  SEVERITY
                </span>

                <strong className="detail-severity">

                  {selectedCVE.severity ||
                    "UNKNOWN"}

                </strong>

                <small>
                  NVD classification
                </small>

              </div>


              <div className="detail-status-card">

                <span>
                  KEV
                </span>

                <strong
                  className={
                    selectedCVE.known_exploited ===
                    1
                      ? "detail-kev yes"
                      : "detail-kev no"
                  }
                >

                  {selectedCVE.known_exploited ===
                  1
                    ? "YES"
                    : "NO"}

                </strong>

                <small>
                  CISA known exploited
                </small>

              </div>

            </div>


            {/* DESCRIPTION */}

            <div className="detail-section">

              <div className="detail-section-title">
                DESCRIPTION
              </div>

              <p className="detail-description">

                {selectedCVE.description ||
                  "No description available."}

              </p>

            </div>


            {/* RISK BREAKDOWN */}

            <div className="detail-section">

              <div className="detail-section-title">
                RISK SCORE BREAKDOWN
              </div>


              {detailLoading ? (

                <div className="detail-loading">
                  Calculating risk components...
                </div>

              ) : riskDebug ? (

                <div className="risk-breakdown">

                  <div className="risk-breakdown-row">

                    <div>

                      <strong>
                        CVSS contribution
                      </strong>

                      <span>

                        {riskDebug.cvss_score !== null &&
riskDebug.cvss_score !== undefined
  ? `CVSS ${riskDebug.cvss_score.toFixed(
      1
    )} × 60%`
  : "No CVSS score"}

                      </span>

                    </div>


                    <strong className="breakdown-value">

                      +
                      {
                        riskDebug.cvss_component
                      }

                    </strong>

                  </div>


                  <div className="risk-breakdown-row">

                    <div>

                      <strong>
                        KEV contribution
                      </strong>

                      <span>

                        {riskDebug.known_exploited ===
                        1
                          ? "Known exploited vulnerability"
                          : "Not listed in CISA KEV"}

                      </span>

                    </div>


                    <strong className="breakdown-value">

                      +
                      {
                        riskDebug.kev_component
                      }

                    </strong>

                  </div>


                  <div className="risk-breakdown-row">

                    <div>

                      <strong>
                        Recency contribution
                      </strong>

                      <span>

                        {riskDebug.age_days !==
                        null
                          ? `${riskDebug.age_days} days old`
                          : "Publication date unavailable"}

                      </span>

                    </div>


                    <strong className="breakdown-value">

                      +
                      {
                        riskDebug.recency_component
                      }

                    </strong>

                  </div>


                  <div className="risk-total-row">

                    <span>
                      CYBER SITUATION ROOM
                      RISK SCORE
                    </span>

                    <strong>
                      {
                        riskDebug.risk_score
                      }
                    </strong>

                  </div>

                </div>

              ) : (

                <div className="detail-error">
                  Unable to load risk breakdown.
                </div>

              )}

            </div>


            {/* TIMELINE INFORMATION */}

            <div className="detail-section">

              <div className="detail-section-title">
                VULNERABILITY TIMELINE
              </div>


              <div className="detail-info-grid">

                <div>

                  <span>
                    Published
                  </span>

                  <strong>

                    {formatFullDate(
                      selectedCVE.published_date
                    )}

                  </strong>

                </div>


                <div>

                  <span>
                    Last Modified
                  </span>

                  <strong>

                    {formatFullDate(
                      selectedCVE.last_modified
                    )}

                  </strong>

                </div>


                <div>

                  <span>
                    KEV Added
                  </span>

                  <strong>

                    {selectedCVE.kev_date_added
                      ? formatFullDate(
                          selectedCVE.kev_date_added
                        )
                      : "Not listed"}

                  </strong>

                </div>


                <div>

                  <span>
                    KEV Due Date
                  </span>

                  <strong>

                    {selectedCVE.kev_due_date
                      ? formatFullDate(
                          selectedCVE.kev_due_date
                        )
                      : "Not listed"}

                  </strong>

                </div>

              </div>

            </div>


            {/* FOOTER */}

            <div className="detail-footer">

              <span>
                SOURCE: NVD + CISA KEV
              </span>

              <span>
                ANALYSIS: CYBER SITUATION ROOM
              </span>

            </div>

          </div>

        </div>

      )}

    </div>
  );
}


export default App;



