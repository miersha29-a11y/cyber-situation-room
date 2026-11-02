import { formatThreatDate } from "../lib/format";
import type { Dashboard } from "../hooks/useDashboard";

type ThreatDetailDrawerProps = Pick<
  Dashboard,
  | "openCorrelatedCVE"
  | "selectedThreat"
  | "setSelectedThreat"
  | "threatCorrelations"
  | "setThreatCorrelations"
  | "correlationLoading"
  | "setCorrelationLoading"
>;

export function ThreatDetailDrawer({
  openCorrelatedCVE,
  selectedThreat,
  setSelectedThreat,
  threatCorrelations,
  setThreatCorrelations,
  correlationLoading,
  setCorrelationLoading,
}: ThreatDetailDrawerProps) {
  if (!selectedThreat) {
    return null;
  }

  return (
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
  );
}
