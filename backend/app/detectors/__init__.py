"""Detector registry.

Every module in this package exposes ``NAME`` and ``detect(ctx) -> list[Finding]``.
Modules are discovered automatically and run in alphabetical order, so the output is
deterministic. A failing detector is isolated: it is reported in the analysis warnings and
the other detectors still run.
"""
from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType


def load_detectors() -> list[ModuleType]:
    modules = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        if hasattr(module, "detect"):
            modules.append(module)
    return modules
