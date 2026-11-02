import type { Dashboard } from "../hooks/useDashboard";

type IntelligenceAnalysisProps = Pick<
  Dashboard,
  | "intelligenceAnalysis"
  | "intelligenceAnalysisLoading"
  | "openCorrelatedCVE"
>;

export function IntelligenceAnalysis({
  intelligenceAnalysis,
  intelligenceAnalysisLoading,
  openCorrelatedCVE,
}: IntelligenceAnalysisProps) {
  return (
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
  );
}
