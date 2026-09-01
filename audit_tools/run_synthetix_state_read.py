#!/usr/bin/env python3
"""Failure-capturing wrapper for the temporary read-only audit collector."""

from __future__ import annotations

import json
import pathlib
import runpy
import traceback

out = pathlib.Path("out")
out.mkdir(parents=True, exist_ok=True)
(out / "collector_started.json").write_text(json.dumps({"started": True}, indent=2), encoding="utf-8")

try:
    runpy.run_path("audit_tools/synthetix_state_read.py", run_name="__main__")
except BaseException as exc:
    failure = {
        "type": type(exc).__name__,
        "message": str(exc),
        "traceback": traceback.format_exc(),
    }
    (out / "collector_failure.json").write_text(json.dumps(failure, indent=2), encoding="utf-8")
    print(failure["traceback"])
    raise
