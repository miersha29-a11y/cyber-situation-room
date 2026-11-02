import { formatFullDate } from "../lib/format";
import type { Dashboard } from "../hooks/useDashboard";

type CveDetailDrawerProps = Pick<
  Dashboard,
  | "closeCVE"
  | "selectedCVE"
  | "riskDebug"
  | "detailLoading"
>;

export function CveDetailDrawer({
  closeCVE,
  selectedCVE,
  riskDebug,
  detailLoading,
}: CveDetailDrawerProps) {
  if (!selectedCVE) {
    return null;
  }

  return (

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

  );
}
