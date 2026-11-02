import type { Dashboard } from "../hooks/useDashboard";
import { CONNECTION_LABELS } from "../lib/status";

type SidebarProps = Pick<
  Dashboard,
  | "scrollToSection"
  | "connectionStatus"
>;

export function Sidebar({
  scrollToSection,
  connectionStatus,
}: SidebarProps) {
  return (
    <aside className="sidebar">

      <div className="logo">

        <span>🛡</span>

        <div>

          <strong>
            CYBER
          </strong>

          <small>
            SITUATION ROOM
          </small>

        </div>

      </div>


      <nav>

        <p className="nav-title">
          COMMAND
        </p>

        <a className="active" href="#overview" onClick={(event) => { event.preventDefault(); scrollToSection("overview"); }}>Overview</a>

        <a href="#threat-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("threat-intelligence"); }}>Threat Intelligence</a>

        <a href="#vulnerability-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("vulnerability-intelligence"); }}>Vulnerabilities</a>

        <a href="#threat-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("threat-intelligence"); }}>Threat Campaigns</a>

        <a href="#mitre-attack" onClick={(event) => { event.preventDefault(); scrollToSection("mitre-attack"); }}>MITRE ATT&CK</a>


        <p className="nav-title">
          ANALYSIS
        </p>

        <a href="#correlation-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("correlation-intelligence"); }}>Threat Map</a>

        <a href="#intelligence-analysis" onClick={(event) => { event.preventDefault(); scrollToSection("intelligence-analysis"); }}>Analytics</a>

        <a href="#latest-intelligence" onClick={(event) => { event.preventDefault(); scrollToSection("latest-intelligence"); }}>Data Sources</a>

      </nav>


      <div className="system-status" role="status">

        <span className={`status-dot is-${connectionStatus}`}></span>

        {CONNECTION_LABELS[connectionStatus]}

      </div>

    </aside>
  );
}
