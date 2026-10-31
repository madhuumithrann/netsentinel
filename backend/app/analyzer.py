"""NetSentinel analysis pipeline.

capture bytes -> safe parsing (capture.py) -> independent detectors (detectors/) ->
incident reconstruction and fault-vs-attack diagnosis (correlate.py) -> evidence summaries.

Analysis is offline: nothing here captures live traffic or sends packets.
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import IO, Any

from .capture import CaptureError, ParseReport, read_capture
from .config import DEFAULT_SETTINGS, Settings
from .context import AnalysisContext, AnalysisTimeout, is_private
from .correlate import build_incidents
from .detectors import load_detectors
from .evidence import summarize
from .model import SEVERITIES, Finding

__all__ = ["analyze_pcap", "analyze_file", "CaptureError"]

NOTICE = ("Findings are evidence-based indicators derived from this capture only. An 'attack' "
          "assessment means the traffic matches documented attack indicators, not that an attack is "
          "proven. Analysis ran offline; no packets were sent.")


def run_detectors(ctx: AnalysisContext) -> tuple[list[Finding], list[dict[str, Any]], list[str]]:
    findings: list[Finding] = []
    status: list[dict[str, Any]] = []
    warnings: list[str] = []
    for module in load_detectors():
        name = getattr(module, "NAME", module.__name__.rsplit(".", 1)[-1])
        started = time.monotonic()
        try:
            ctx.check_deadline()
            produced = module.detect(ctx) or []
            findings.extend(produced)
            status.append({"name": name, "findings": len(produced), "status": "ok",
                           "seconds": round(time.monotonic() - started, 3)})
        except AnalysisTimeout:
            status.append({"name": name, "findings": 0, "status": "skipped (time limit)"})
            warnings.append(f"Detector '{name}' was skipped because the analysis time limit was reached.")
        except Exception as exc:  # one broken detector must not take down the analysis
            status.append({"name": name, "findings": 0, "status": f"error ({type(exc).__name__})"})
            warnings.append(f"Detector '{name}' failed on this capture and was skipped.")
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (sev_rank.get(f.severity, 9), f.time_start or 0))
    for i, f in enumerate(findings, start=1):
        f.id = f"F-{i:03d}"
    return findings, status, warnings


def _traffic(ctx: AnalysisContext, settings: Settings) -> dict[str, Any]:
    records = ctx.records
    start, end = ctx.start_ts, ctx.end_ts
    duration = max(end - start, 0.0)
    buckets = 60
    width = duration / buckets if duration > 0 else 1.0
    series: list[dict[str, Any]] = [{"t": round(i * width, 3), "packets": 0, "TCP": 0, "UDP": 0,
                                     "Other": 0} for i in range(buckets if duration > 0 else 1)]
    protocols: Counter = Counter()
    talkers: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    convs: dict[tuple, dict[str, Any]] = {}
    for rec in records:
        proto = rec.protocol
        protocols[proto] += 1
        idx = min(int((rec.ts - start) / width), len(series) - 1) if duration > 0 else 0
        bucket = series[max(idx, 0)]
        bucket["packets"] += 1
        bucket["TCP" if rec.l4 == "TCP" else "UDP" if rec.l4 == "UDP" else "Other"] += 1
        src, dst = rec.ip_src or rec.arp_psrc, rec.ip_dst or rec.arp_pdst
        if src:
            talkers[src][0] += 1
            talkers[src][1] += rec.wirelen
        if src and dst:
            a, b = sorted((src, dst))
            key = (a, b, rec.l4 or proto)
            conv = convs.get(key)
            if conv is None:
                conv = convs[key] = {"a": a, "b": b, "protocol": rec.l4 or proto, "packets": 0,
                                     "bytes": 0, "first": rec.n, "start": round(rec.ts - start, 3),
                                     "end": 0.0}
            conv["packets"] += 1
            conv["bytes"] += rec.wirelen
            conv["end"] = round(rec.ts - start, 3)
    top = sorted(talkers.items(), key=lambda kv: kv[1][0], reverse=True)[:15]
    conversations = sorted(convs.values(), key=lambda c: c["packets"], reverse=True)
    return {
        "protocols": dict(protocols.most_common()),
        "series": series,
        "bucket_seconds": round(width, 3),
        "top_talkers": [{"ip": ip, "packets": v[0], "bytes": v[1], "local": is_private(ip)} for ip, v in top],
        "conversations": conversations[:settings.limits.max_conversations],
        "conversation_total": len(conversations),
        "tcp_connections": len(ctx.connections),
    }


def _hosts(ctx: AnalysisContext) -> list[dict[str, Any]]:
    roles: dict[str, set[str]] = defaultdict(set)
    for ip in ctx.gateway_ips:
        roles[ip].add("gateway")
    for ip in ctx.dns_servers:
        roles[ip].add("DNS server")
    for ip in ctx.dhcp_offered["server"]:
        roles[ip].add("DHCP server")
    out = []
    for ip, macs in sorted(ctx.ip_macs.items(), key=lambda kv: -sum(kv[1].values()))[:50]:
        out.append({"ip": ip, "macs": [m for m, _ in macs.most_common(4)],
                    "packets": sum(macs.values()), "roles": sorted(roles.get(ip, set()))})
    return out


def analyze_file(fileobj: IO[bytes], display_name: str = "capture",
                 settings: Settings = DEFAULT_SETTINGS) -> dict[str, Any]:
    """Analyse an already-open binary capture file object. The caller closes it."""
    started = time.monotonic()
    deadline = started + settings.limits.max_analysis_seconds
    records, report = read_capture(fileobj, settings.limits, deadline)
    ctx = AnalysisContext(records, settings, deadline)
    warnings = list(report.warnings)
    if report.stopped_early:
        warnings.insert(0, report.stopped_early)
    if not records:
        findings, status = [], []
    else:
        findings, status, detector_warnings = run_detectors(ctx)
        warnings.extend(detector_warnings)
    incidents, verdict = build_incidents(findings, ctx)
    limits = settings.limits

    referenced: list[int] = []
    for f in findings:
        referenced.extend(f.packet_numbers()[:limits.max_evidence_per_finding])
    referenced = sorted(set(referenced))[:limits.max_packet_summaries]
    start_ts = ctx.start_ts
    packets = {n: summarize(ctx.by_number[n], start_ts) for n in referenced if n in ctx.by_number}

    sev = Counter(f.severity for f in findings)
    duration = max(ctx.end_ts - ctx.start_ts, 0.0) if records else 0.0
    return {
        "file": Path(display_name).name[:200],
        "format": report.file_format,
        "packets_analyzed": len(records),
        "duration_seconds": round(duration, 3),
        "capture_start": start_ts if records else None,
        "parse": {"malformed_packets": report.malformed_packets, "truncated_file": report.truncated_file,
                  "stopped_early": report.stopped_early, "parse_seconds": report.parse_seconds},
        "warnings": warnings,
        "traffic": _traffic(ctx, settings) if records else {"protocols": {}, "series": [],
                                                            "top_talkers": [], "conversations": []},
        "hosts": _hosts(ctx) if records else [],
        "findings": [f.to_dict(limits.max_evidence_per_finding) for f in findings],
        "incidents": incidents,
        "verdict": verdict,
        "summary": {
            "findings": len(findings),
            "incidents": len(incidents),
            "faults": sum(f.assessment == "fault" for f in findings),
            "attacks": sum(f.assessment == "attack" for f in findings),
            "inconclusive": sum(f.assessment == "inconclusive" for f in findings),
            "benign": sum(f.assessment == "benign" for f in findings),
            "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
        },
        "packets": packets,
        "detectors": status,
        "analysis_seconds": round(time.monotonic() - started, 3),
        "notice": NOTICE,
    }


def analyze_pcap(path: str | Path, settings: Settings = DEFAULT_SETTINGS) -> dict[str, Any]:
    """Analyse a capture file on disk (used by tests, the CLI and bundled samples)."""
    with open(path, "rb") as handle:
        return analyze_file(handle, Path(path).name, settings)
