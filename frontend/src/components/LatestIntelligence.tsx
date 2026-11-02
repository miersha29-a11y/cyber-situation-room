import type { Dashboard } from "../hooks/useDashboard";

type LatestIntelligenceProps = Pick<
  Dashboard,
  | "threatSummary"
>;

export function LatestIntelligence({
  threatSummary,
}: LatestIntelligenceProps) {
  return (
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
  );
}
