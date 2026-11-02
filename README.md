# Cyber Situation Room

A cybersecurity threat intelligence and vulnerability analysis platform designed to support SOC and CTI analyst workflows.

## Dashboard

![Cyber Situation Room Dashboard](docs/dashboard.png)

## Architecture

![Cyber Situation Room Architecture](docs/architecture.png)

## Overview

Cyber Situation Room combines threat intelligence, vulnerability intelligence, CISA advisories, NVD CVEs, CISA KEV data, correlation analysis, risk scoring, and MITRE ATT&CK evidence into an analyst-focused dashboard.

## Core Capabilities

- Threat Intelligence feed and filtering
- CISA advisory intelligence
- NVD vulnerability intelligence
- CISA KEV enrichment
- CVE correlation and relationship analysis
- Vulnerability prioritization
- CVSS and risk analysis
- Vulnerability timelines
- MITRE ATT&CK technique mapping
- Evidence-driven analyst workflow
- Security data visualization

## Analyst Workflow

Threat Intelligence -> CISA Advisory -> CVE Correlation -> NVD + CISA KEV -> Risk Analysis -> MITRE ATT&CK Evidence -> Analyst Investigation

## Technology Stack

### Frontend
- React
- TypeScript
- Vite
- Recharts
- TanStack React Query

### Backend
- Python
- FastAPI
- SQLAlchemy
- Uvicorn
- SQLite

### Intelligence Sources
- NVD
- CISA Known Exploited Vulnerabilities Catalog
- CISA threat and advisory intelligence
- MITRE ATT&CK

## API Endpoints

All endpoints are read-only `GET` requests. Full interactive documentation is served at `/docs` when the API is running.

```
GET /health
GET /cves?limit=500
GET /vulnerabilities/prioritized?limit=10
GET /vulnerabilities/risk-summary
GET /vulnerabilities/timeline?days=30
GET /vulnerabilities/risk-debug/{cve_id}
GET /threat-intelligence?limit=30
GET /threat-intelligence/summary
GET /threat-intelligence/{event_id}/correlations
GET /threat-intelligence/{event_id}/mitre-attack
GET /intelligence-analysis
GET /mitre-attack/analysis
GET /correlations/graph?limit=12
```

## Project Structure

cyber-situation-room/
  backend/
    main.py
    database.py
    models.py
    ingest_cves.py
    ingest_cisa.py
    ingest_attack.py
    enrich_kev.py
    cleanup_old_cves.py
    requirements.txt
  frontend/
    src/
      App.tsx
      App.css
      index.css
      main.tsx
      api.ts
  README.md
  .gitignore

## Getting Started

Tested with Python 3.12 and Node.js 22. Other versions may work but have not been checked.

### 1. Clone the repository

```bash
git clone https://github.com/miersha29-a11y/cyber-situation-room.git
cd cyber-situation-room
```

### 2. Set up the backend

Windows (PowerShell):

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS / Linux:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If PowerShell blocks `Activate.ps1`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call `.\.venv\Scripts\python.exe` directly.

### 3. Load the intelligence data

The SQLite database is not committed to the repository, so the dashboard is empty until these scripts are run. Run them from the `backend` folder with the virtual environment active, in this order:

```bash
python ingest_cves.py      # NVD CVEs published in the last 90 days
python enrich_kev.py       # flags CVEs listed in the CISA KEV catalogue (needs step 1 first)
python ingest_cisa.py      # CISA advisories and threat events
python ingest_attack.py    # MITRE ATT&CK Enterprise techniques
```

`enrich_kev.py` updates CVE records that already exist, so it must run after `ingest_cves.py`. The NVD script pauses between requests because NVD rate-limits clients without an API key, so it is the slowest step.

`cleanup_old_cves.py` is optional. It deletes every CVE not published in 2026, so do not run it unless that is what you want.

Re-run the ingest scripts whenever you want fresher data.

### 4. Start the API

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

Check it is up at http://127.0.0.1:8000/health. Interactive API docs are at http://127.0.0.1:8000/docs.

### 5. Start the frontend

In a second terminal:

```bash
cd frontend
npm ci
npm run dev
```

The frontend calls the API at `http://127.0.0.1:8000` by default. To point it somewhere else, copy `frontend/.env.example` to `frontend/.env` and change `VITE_API_BASE_URL`.

Open http://localhost:5173. The API only accepts browser requests from this origin (see CORS settings in `backend/main.py`).

### Production build

```bash
cd frontend
npm run build
```

The output is written to `frontend/dist/`.

## Validation

Checked against a fresh clone (Python 3.12, Node.js 22):

- The backend installs from `requirements.txt`, and every endpoint above returns HTTP 200 both on an empty database and on a small test dataset.
- `npm run build` and `npm run lint` complete with no errors.
- `npm audit --omit=dev` and `pip-audit` reported no known vulnerabilities at the time of checking.
- The dashboard was exercised in headless Chromium in three states: API stopped (error banner shown), API running with an empty database (ingest prompt shown), and API running with sample data (KPIs, charts, 7/30/90-day range switching, and the CVE and advisory detail panels all load with no console errors).

Not yet covered: there is no automated test suite in the repository, and live ingestion from NVD and CISA depends on those services being reachable.

## Security Focus

Cyber Threat Intelligence | Security Operations | Vulnerability Management | Threat Correlation | Security Analytics | MITRE ATT&CK

## Project Status

Functionally verified and prepared as a cybersecurity portfolio project.
