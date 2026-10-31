# NetSentinel backend

See the [main README](../README.md) for the full setup, and [docs/](../docs) for the detection
methodology, security design and evaluation.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt     # runtime + test dependencies
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Status, version, limits and the list of detectors |
| `POST /api/analyze` | Multipart upload, field `file` (`.pcap`, `.pcapng`, `.cap`) |
| `GET /api/samples` | Bundled synthetic sample captures |
| `POST /api/samples/{id}/analyze` | Analyse a bundled sample |

Interactive API docs: http://127.0.0.1:8000/docs

Useful commands (run from `backend/`):

```powershell
python -m pytest -q                 # automated tests
python -m lab.evaluate              # detection evaluation on labelled scenarios
python -m lab.generate_samples      # regenerate ../samples (deterministic)
python -m app.cli ..\samples\benign_office.pcap
```

Limits (override with environment variables): `NETSENTINEL_MAX_UPLOAD_MB` (100),
`NETSENTINEL_MAX_PACKETS` (300000), `NETSENTINEL_MAX_SECONDS` (90),
`NETSENTINEL_MAX_CONCURRENT` (2).

Analysis is offline only: the service never captures live traffic or sends packets. Findings
are evidence-based indicators, not proof.
