# NetSentinel

**Intelligent Network Fault & Threat Diagnosis Engine** — an offline-first cybersecurity hackathon project that analyzes packet captures, detects suspicious patterns, and explains findings with packet-level evidence.

## Repository structure

- `backend/` — FastAPI service and custom Scapy-based analysis engine
- `frontend/` — React + Vite dashboard

## Run locally (Windows PowerShell)

### 1. Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend (new terminal)

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL printed in the terminal (normally `http://localhost:5173`). Backend API docs: `http://localhost:8000/docs`.

## Current detection rules

- TCP SYN port-scan pattern: at least 15 distinct destination ports within 10 seconds for one source/target pair
- Conflicting ARP IP-to-MAC ownership
- High NXDOMAIN response count per source
- More than one DHCP server observed
- Elevated TCP RST count
- Repeated TCP sequence-number candidates

Thresholds are initial prototype heuristics, not universal security truths. Findings are indicators and require human verification.

## Safety

The tool analyzes uploaded capture files offline. It does not sniff live networks, inject packets, or transmit traffic. Test only with captures you own or are authorized to analyze. Upload size and packet count are bounded. Do not commit sensitive PCAPs containing credentials or personal data.

## Libraries

- Scapy — packet parsing
- FastAPI — backend API
- Uvicorn — ASGI server
- React — frontend
- Vite — frontend development/build tooling
- Recharts — reserved for upcoming traffic visualizations
- Lucide React — interface icons

Detection and diagnosis logic in `backend/app/analyzer.py` is custom project code, not a wrapper around Wireshark/tshark.
