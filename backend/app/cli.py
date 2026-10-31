"""Command-line interface: diagnose a capture without starting the web dashboard.

    cd backend
    python -m app.cli ../samples/attack_arp_spoofing_mitm.pcap
    python -m app.cli capture.pcapng --json > report.json
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

from .analyzer import analyze_pcap
from .capture import CaptureError

WIDTH = 92


def _wrap(text: str, indent: str = "  ") -> str:
    return textwrap.fill(text, WIDTH, initial_indent=indent, subsequent_indent=" " * len(indent))


def render(result: dict) -> str:
    out = []
    v = result["verdict"]
    out.append("=" * WIDTH)
    out.append(f"NetSentinel diagnosis: {result['file']}  ({result['format']}, "
               f"{result['packets_analyzed']:,} packets, {result['duration_seconds']} s)")
    out.append("=" * WIDTH)
    out.append(f"VERDICT: {v['label'].upper()}")
    if v.get("headline"):
        out.append(_wrap(v["headline"]))
    for w in result["warnings"]:
        out.append(_wrap(f"! {w}"))
    findings = {f["id"]: f for f in result["findings"]}
    for inc in result["incidents"]:
        out.append("")
        out.append("-" * WIDTH)
        out.append(f"{inc['id']}  [{inc['verdict_label']}]  severity {inc['severity']}, "
                   f"confidence {inc['confidence']}")
        out.append(f"  {inc['title']}")
        out.append("-" * WIDTH)
        out.append(_wrap(inc["summary"]))
        out.append("  Likely cause:")
        out.append(_wrap(inc["likely_root_cause"], "    "))
        if inc["reasoning"]:
            out.append("  Why this verdict:")
            for r in inc["reasoning"][:8]:
                out.append(_wrap(f"[{r['points_to']}/{r['strength']}] {r['text']}", "    - "))
        for link in inc["links"]:
            out.append(_wrap(f"linked {link['from']} -> {link['to']} ({link['type']}): {link['basis']}", "    ~ "))
        if inc["timeline"]:
            out.append("  Timeline (packet numbers match Wireshark frame numbers):")
            for e in inc["timeline"][:12]:
                out.append(f"    {e['relative']:>9.3f}s  #{e['packet']:<7} {e['role'][:34]:<34} {e['info'][:40]}")
        out.append("  What to do:")
        for i, rec in enumerate(inc["recommendations"][:6], 1):
            out.append(_wrap(f"{i}. {rec}", "    "))
        if inc["uncertainty"]:
            out.append("  Uncertainty:")
            for u in inc["uncertainty"][:3]:
                out.append(_wrap(u, "    - "))
        ids = ", ".join(f"{fid} {findings[fid]['kind']}" for fid in inc["findings"] if fid in findings)
        out.append(f"  Findings: {ids}")
    if not result["incidents"]:
        out.append("")
        out.append(_wrap("No incidents. Detectors run: " + ", ".join(d["name"] for d in result["detectors"])))
    out.append("")
    out.append(_wrap(result["notice"], ""))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netsentinel", description="Diagnose faults and attacks in a capture file.")
    parser.add_argument("capture", type=Path, help="path to a .pcap or .pcapng file")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    args = parser.parse_args(argv)
    if not args.capture.is_file():
        print(f"error: {args.capture} is not a file", file=sys.stderr)
        return 2
    try:
        result = analyze_pcap(args.capture)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.json else render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
