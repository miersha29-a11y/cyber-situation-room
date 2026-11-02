import { useDashboard } from "./hooks/useDashboard";
import { Sidebar } from "./components/Sidebar";
import { StatusBanners } from "./components/StatusBanners";
import { Topbar } from "./components/Topbar";
import { KpiCards } from "./components/KpiCards";
import { ThreatActivity } from "./components/ThreatActivity";
import { VulnerabilityIntelligence } from "./components/VulnerabilityIntelligence";
import { CorrelationIntelligence } from "./components/CorrelationIntelligence";
import { ThreatIntelligence } from "./components/ThreatIntelligence";
import { IntelligenceAnalysis } from "./components/IntelligenceAnalysis";
import { MitreAttack } from "./components/MitreAttack";
import { LatestIntelligence } from "./components/LatestIntelligence";
import { ThreatDetailDrawer } from "./components/ThreatDetailDrawer";
import { CveDetailDrawer } from "./components/CveDetailDrawer";

function App() {
  const dashboard = useDashboard();

  return (

    <div className="app">

      {/* =====================================================
          SIDEBAR
          ===================================================== */}

      <Sidebar {...dashboard} />


      {/* =====================================================
          MAIN
          ===================================================== */}

      <main className="main" id="overview">

        <StatusBanners {...dashboard} />

        <Topbar {...dashboard} />


        {/* ===================================================
            KPI CARDS
            =================================================== */}

        <KpiCards {...dashboard} />


        {/* ===================================================
            CHARTS
            =================================================== */}

        <ThreatActivity {...dashboard} />


        {/* ===================================================
            VULNERABILITY INTELLIGENCE
            =================================================== */}

        <VulnerabilityIntelligence {...dashboard} />


        {/* ===================================================
            CORRELATION VISUALIZATION
            =================================================== */}

        <CorrelationIntelligence {...dashboard} />




        {/* ===================================================
            THREAT INTELLIGENCE
            =================================================== */}

        <ThreatIntelligence {...dashboard} />


        {/* ===================================================
            INTELLIGENCE ANALYSIS
            =================================================== */}

        <IntelligenceAnalysis {...dashboard} />


        {/* ===================================================
            MITRE ATT&CK
            =================================================== */}

        <MitreAttack {...dashboard} />


        {/* ===================================================
            LATEST INTELLIGENCE
            =================================================== */}

        <LatestIntelligence {...dashboard} />

      </main>


      {/* =====================================================
          THREAT INTELLIGENCE DETAIL OVERLAY
          ===================================================== */}

      <ThreatDetailDrawer {...dashboard} />


      {/* =====================================================
          CVE DETAIL OVERLAY
          ===================================================== */}

      <CveDetailDrawer {...dashboard} />

    </div>
  );
}

export default App;
