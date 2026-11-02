/* Shared API response and UI types. */

export type CVE = {
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

export type TimelineData = {
  date: string;
  count: number;
  movingAverage: number;
};

export type SeverityData = {
  name: string;
  value: number;
};

export type RangeOption = 7 | 30 | 90;

export type PrioritizedVulnerability = {
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

export type RiskSummary = {
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

export type CorrelationGraphNode = {
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

export type CorrelationGraphEdge = {
  id: string;
  source: string;
  target: string;
  relationship: string;
};

export type CorrelationGraphResponse = {
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





export type RiskDebug = {
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

export type ThreatEvent = {
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

export type ThreatSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  event_types: Record<string, number>;
  sources: Record<string, number>;
};

export type ThreatCorrelation = {
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

export type MitreAttackMapping = {
  event_id?: number;
  event_title?: string;
  attack_id: string;
  technique_name: string;
  tactics: string;
  confidence: string;
  evidence: string;
  url: string;
};

export type MitreAttackAnalysis = {
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

export type IntelligenceAnalysis = {
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

export type ConnectionStatus =
  | "connecting"
  | "online"
  | "empty"
  | "degraded"
  | "offline";
