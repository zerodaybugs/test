#!/usr/bin/env python3
"""Diagnostic wrapper for the controlled delegation alias probe."""

from __future__ import annotations

import json
import pathlib
import traceback

import synthetix_delegation_alias_boundary as probe

OUT = pathlib.Path("delegation_alias_boundary_v2")
OUT.mkdir(parents=True, exist_ok=True)
probe.OUT = OUT

if __name__ == "__main__":
    try:
        probe.main()
    except BaseException as exc:  # noqa: BLE001
        failure = {
            "safety": "Synthetic zero-account signer and nonexistent IDs only; no delegation executed.",
            "probeCompleted": False,
            "failureType": type(exc).__name__,
            "failureMessage": str(exc)[:2000],
            "traceback": traceback.format_exc()[-12000:],
        }
        (OUT / "failure.json").write_text(json.dumps(failure, indent=2), encoding="utf-8")
        print(json.dumps(failure, indent=2))
