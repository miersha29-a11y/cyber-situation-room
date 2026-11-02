import type { Dashboard } from "../hooks/useDashboard";

type KpiCardsProps = Pick<
  Dashboard,
  | "riskSummary"
>;

export function KpiCards({
  riskSummary,
}: KpiCardsProps) {
  return (
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
  );
}
