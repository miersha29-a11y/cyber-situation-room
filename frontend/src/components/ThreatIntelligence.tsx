import { formatThreatDate } from "../lib/format";
import type { Dashboard } from "../hooks/useDashboard";

type ThreatIntelligenceProps = Pick<
  Dashboard,
  | "threatEvents"
  | "threatSummary"
  | "threatLoading"
  | "openThreat"
  | "threatEventTypes"
  | "filteredThreatEvents"
  | "topThreatTypes"
  | "threatSeverityFilter"
  | "setThreatSeverityFilter"
  | "threatTypeFilter"
  | "setThreatTypeFilter"
>;

export function ThreatIntelligence({
  threatEvents,
  threatSummary,
  threatLoading,
  openThreat,
  threatEventTypes,
  filteredThreatEvents,
  topThreatTypes,
  threatSeverityFilter,
  setThreatSeverityFilter,
  threatTypeFilter,
  setThreatTypeFilter,
}: ThreatIntelligenceProps) {
  return (
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
  );
}
