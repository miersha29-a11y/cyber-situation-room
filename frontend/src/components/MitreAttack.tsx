import type { Dashboard } from "../hooks/useDashboard";

type MitreAttackProps = Pick<
  Dashboard,
  | "mitreAttackAnalysis"
  | "mitreAttackLoading"
>;

export function MitreAttack({
  mitreAttackAnalysis,
  mitreAttackLoading,
}: MitreAttackProps) {
  return (
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
  );
}
