import { formatThreatDate } from "../lib/format";
import type { Dashboard } from "../hooks/useDashboard";

type CorrelationIntelligenceProps = Pick<
  Dashboard,
  | "correlationGraph"
  | "correlationGraphLoading"
  | "correlationGraphError"
  | "openCorrelatedCVE"
>;

export function CorrelationIntelligence({
  correlationGraph,
  correlationGraphLoading,
  correlationGraphError,
  openCorrelatedCVE,
}: CorrelationIntelligenceProps) {
  return (
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
  );
}
