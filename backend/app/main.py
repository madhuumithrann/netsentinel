from pathlib import Path
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scapy.utils import RawPcapReader
from .analyzer import analyze_pcap

app = FastAPI(title="NetSentinel API", version="0.1.0", description="Offline PCAP diagnostics and threat indicators")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["*"])
MAX_UPLOAD = 100 * 1024 * 1024

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "NetSentinel"}

@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    name = (file.filename or "").lower()
    if not (name.endswith(".pcap") or name.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Upload a .pcap or .pcapng file")
    data = await file.read(MAX_UPLOAD + 1)
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded file is empty")
    if len(data) > MAX_UPLOAD:
        raise HTTPException(status_code=413, detail="Maximum upload size is 100 MB")
    # Validate capture structure before invoking the analyzer. The temporary file is always removed.
    suffix = ".pcapng" if name.endswith(".pcapng") else ".pcap"
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="netsentinel_", suffix=suffix, delete=False) as tmp:
            tmp.write(data); temp_path = Path(tmp.name)
        # A parser read validates the capture and bounds pathological packet counts.
        count = 0
        with RawPcapReader(str(temp_path)) as reader:
            for _ in reader:
                count += 1
                if count > 500_000:
                    raise ValueError("Capture exceeds the 500,000-packet analysis limit")
        result = analyze_pcap(temp_path)
        result["file"] = Path(file.filename).name
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not safely analyze this capture: {type(exc).__name__}: {str(exc)[:180]}")
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)
