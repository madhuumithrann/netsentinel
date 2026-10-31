"""Regenerate the synthetic sample captures shipped in ``samples/``.

    cd backend
    python -m lab.generate_samples

Every capture is built offline from the labelled scenarios in ``lab/scenarios``; no traffic
is captured from or sent to any network. Output is deterministic (fixed timestamps,
addresses and sequence numbers), so regenerating produces identical files.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

from scapy.utils import PcapNgWriter

from .scenarios import all_scenarios

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples"


def _kind(filename: str) -> str:
    for prefix in ("attack", "fault", "benign", "incident", "malformed"):
        if filename.startswith(prefix):
            return prefix
    return "other"


def main() -> int:
    SAMPLES.mkdir(exist_ok=True)
    manifest = []
    for scenario in all_scenarios():
        if not scenario.sample:
            continue
        path = SAMPLES / scenario.sample
        packets = scenario.packets()
        if path.suffix == ".pcapng":
            writer = PcapNgWriter(str(path))
            for p in packets:
                writer.write(p)
            writer.close()
        else:
            scenario.build().write(str(path))
        manifest.append({"id": path.stem, "file": path.name, "title": scenario.description,
                         "description": scenario.description, "kind": _kind(path.name),
                         "scenario": scenario.name, "packets": len(packets),
                         "expected_findings": sorted(scenario.expect)})
        print(f"wrote {path.relative_to(ROOT)} ({len(packets)} packets)")

    # A deliberately corrupt capture for demonstrating safe input handling: a valid header,
    # one good packet and then a record that claims 4 GB of data.
    benign = next((m for m in manifest if m["kind"] == "benign"), None)
    if benign:
        good = (SAMPLES / benign["file"]).read_bytes()
        first_len = struct.unpack("<I", good[24 + 8:24 + 12])[0]
        corrupt = good[:24 + 16 + first_len] + struct.pack("<IIII", 0, 0, 0xFFFFFFF0, 0xFFFFFFF0) + b"\x00" * 64
        (SAMPLES / "malformed_huge_record.pcap").write_bytes(corrupt)
        manifest.append({"id": "malformed_huge_record", "file": "malformed_huge_record.pcap",
                         "title": "Corrupt capture: a record claims 4 GB of data",
                         "description": "Tests safe input handling: the parser must stop cleanly and warn, "
                                        "not allocate 4 GB or crash.",
                         "kind": "malformed", "scenario": None, "packets": 1, "expected_findings": []})
        print("wrote samples/malformed_huge_record.pcap")

    order = {"benign": 0, "attack": 1, "incident": 2, "fault": 3, "malformed": 4, "other": 5}
    manifest.sort(key=lambda m: (order.get(m["kind"], 9), m["id"]))
    (SAMPLES / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote samples/manifest.json ({len(manifest)} samples)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
