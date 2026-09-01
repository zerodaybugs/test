#!/usr/bin/env python3
"""Run the existing Router holdings census, then a read-only upgrade-state census."""
from __future__ import annotations

import importlib.util
import runpy
from pathlib import Path

HERE = Path(__file__).resolve().parent
V2 = HERE / "termmax_router_holdings_census_v2_20260730.py"
BASE = HERE / "termmax_router_holdings_census_20260730.py"
PROBE = HERE / "termmax_router_upgrade_state_probe_20260731.py"

exit_code = 0
try:
    runpy.run_path(str(V2), run_name="__main__")
except SystemExit as exc:
    exit_code = int(exc.code or 0)

base_spec = importlib.util.spec_from_file_location("termmax_router_holdings_base_for_probe", BASE)
if base_spec is None or base_spec.loader is None:
    raise RuntimeError(f"cannot load base scanner: {BASE}")
base = importlib.util.module_from_spec(base_spec)
base_spec.loader.exec_module(base)

probe_spec = importlib.util.spec_from_file_location("termmax_router_upgrade_state_probe", PROBE)
if probe_spec is None or probe_spec.loader is None:
    raise RuntimeError(f"cannot load upgrade-state probe: {PROBE}")
probe = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(probe)
probe.run(base)

raise SystemExit(exit_code)
