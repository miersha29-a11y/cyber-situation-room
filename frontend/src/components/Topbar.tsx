import type { Dashboard } from "../hooks/useDashboard";
import { CONNECTION_LABELS } from "../lib/status";

type TopbarProps = Pick<
  Dashboard,
  | "connectionStatus"
>;

export function Topbar({
  connectionStatus,
}: TopbarProps) {
  return (
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


      <div className="topbar-right" role="status">

        <span>
          {CONNECTION_LABELS[connectionStatus]}
        </span>

        <span className={`live-dot is-${connectionStatus}`}></span>

      </div>

    </header>
  );
}
