"""Labelled synthetic scenarios with ground truth.

Each module in this package defines ``SCENARIOS: list[Scenario]``. A scenario declares which
finding kinds MUST appear (``expect``) and which MUST NOT appear (``forbid``), plus the
expected assessment for attack scenarios. The same scenarios drive the unit tests, the
evaluation report (precision / recall) and the sample captures shipped in ``samples/``.
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Callable

from scapy.packet import Packet

from ..packets import Timeline


@dataclass
class Scenario:
    name: str
    description: str
    build: Callable[[], Timeline]
    expect: set[str] = field(default_factory=set)       # finding kinds that must be reported
    forbid: set[str] = field(default_factory=set)       # finding kinds that must NOT be reported
    expect_assessment: dict[str, str] = field(default_factory=dict)  # kind -> assessment
    forbid_attacks: bool = False                        # no finding may be assessed as "attack"
    sample: str | None = None                           # file name when shipped in samples/

    def packets(self) -> list[Packet]:
        return self.build().packets()


def all_scenarios() -> list[Scenario]:
    out: list[Scenario] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        module = importlib.import_module(f"{__name__}.{info.name}")
        out.extend(getattr(module, "SCENARIOS", []))
    names = [s.name for s in out]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise ValueError(f"duplicate scenario names: {sorted(duplicates)}")
    return out
