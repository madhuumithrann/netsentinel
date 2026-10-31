# NetSentinel backend

## Setup

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API health: `http://localhost:8000/api/health`
Interactive API docs: `http://localhost:8000/docs`

Upload a `.pcap` or `.pcapng` file to `POST /api/analyze` using multipart form field `file`.

## Safety and limitations

- Offline analysis only; this service does not capture live traffic or transmit packets.
- Upload limit: 100 MB; packet limit: 500,000.
- Findings are indicators, not proof of an attack.
- The current engine is a hackathon prototype. Validate on lab-generated captures before relying on results.
