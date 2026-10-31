"""NetSentinel HTTP API.

Security design
    * The request body is capped *while it streams in* (``BodySizeLimit``), so an oversized
      upload is rejected before it is buffered.
    * The capture format is verified from its magic number, not trusted from the file name.
    * Uploads are analysed straight from Starlette's spooled temporary file, which is deleted
      when the request ends. NetSentinel never writes its own copy, so nothing can be left
      behind (the original version leaked files on Windows when Scapy kept a handle open).
    * Analysis runs in a worker thread with a concurrency cap and a time limit.
    * Error messages are generic and never include paths, stack traces or packet contents.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .analyzer import analyze_file, analyze_pcap
from .capture import CaptureError
from .config import DEFAULT_SETTINGS
from .detectors import load_detectors

VERSION = "1.0.0"
LIMITS = DEFAULT_SETTINGS.limits
ALLOWED_EXTENSIONS = (".pcap", ".pcapng", ".cap")
SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"
# Multipart framing adds a few hundred bytes around the file itself.
MULTIPART_OVERHEAD = 64 * 1024

log = logging.getLogger("netsentinel")
_analysis_slots = threading.BoundedSemaphore(LIMITS.max_concurrent_analyses)


class BodySizeLimit:
    """ASGI middleware that rejects request bodies larger than the upload limit."""

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True
            if too_big:
                return await _reject(send, 413, "The upload exceeds the maximum allowed size.")
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _reject(send, 413, "The upload exceeds the maximum allowed size.")


class _BodyTooLarge(Exception):
    pass


async def _reject(send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


app = FastAPI(title="NetSentinel API", version=VERSION,
              description="Offline packet-capture diagnosis: faults, attacks and evidence-backed incidents.")
# Only local development origins may read API responses (any port, localhost or 127.0.0.1).
app.add_middleware(CORSMiddleware, allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d{1,5})?$",
                   allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
app.add_middleware(BodySizeLimit, max_bytes=LIMITS.max_upload_bytes + MULTIPART_OVERHEAD)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    return response


def _safe_name(raw: str | None) -> str:
    """Base name only, printable characters only, bounded length (it is echoed back)."""
    name = (raw or "capture").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9._ ()-]", "_", name).strip() or "capture"
    if len(name) > 120:
        stem, dot, ext = name.rpartition(".")
        name = (stem[:100] + dot + ext[:10]) if dot else name[:120]
    return name


def _run_analysis(fn, *args) -> dict[str, Any]:
    if not _analysis_slots.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="The analyzer is busy with other captures. Try again shortly.")
    try:
        return fn(*args)
    except CaptureError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except HTTPException:
        raise
    except Exception as exc:
        error_id = uuid.uuid4().hex[:8]
        # Log only the exception type: messages may contain paths or packet-derived text.
        log.error("analysis failed (error id %s): %s", error_id, type(exc).__name__)
        raise HTTPException(status_code=500,
                            detail=f"The capture could not be analysed (error id {error_id}).") from None
    finally:
        _analysis_slots.release()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "NetSentinel", "version": VERSION,
            "limits": {"max_upload_mb": LIMITS.max_upload_bytes // (1024 * 1024),
                       "max_packets": LIMITS.max_packets,
                       "max_analysis_seconds": LIMITS.max_analysis_seconds},
            "detectors": [getattr(m, "NAME", m.__name__) for m in load_detectors()]}


# Plain ``def``: FastAPI runs it in a worker thread, so CPU-heavy analysis never blocks the server.
@app.post("/api/analyze")
def analyze(file: UploadFile = File(...)) -> dict[str, Any]:
    name = _safe_name(file.filename)
    if not name.lower().endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Upload a .pcap, .pcapng or .cap capture file.")
    handle = file.file
    handle.seek(0, 2)
    size = handle.tell()
    handle.seek(0)
    if size == 0:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if size > LIMITS.max_upload_bytes:
        raise HTTPException(status_code=413, detail="The upload exceeds the maximum allowed size.")
    try:
        return _run_analysis(analyze_file, handle, name)
    finally:
        file.file.close()


def _manifest() -> list[dict[str, Any]]:
    path = SAMPLES_DIR / "manifest.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [s for s in data if isinstance(s, dict) and isinstance(s.get("id"), str)]


@app.get("/api/samples")
def samples() -> list[dict[str, Any]]:
    return [{k: s.get(k) for k in ("id", "title", "description", "file", "kind")} for s in _manifest()]


@app.post("/api/samples/{sample_id}/analyze")
def analyze_sample(sample_id: str) -> dict[str, Any]:
    # Only ids listed in the manifest are accepted, and the resolved path must stay inside
    # the samples directory, so the endpoint cannot be used to read arbitrary files.
    entry = next((s for s in _manifest() if s["id"] == sample_id), None)
    if entry is None:
        raise HTTPException(status_code=404, detail="Unknown sample.")
    path = (SAMPLES_DIR / str(entry.get("file", ""))).resolve()
    if SAMPLES_DIR.resolve() not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="Unknown sample.")
    return _run_analysis(analyze_pcap, path)


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
