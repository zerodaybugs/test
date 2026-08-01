#!/usr/bin/env python3
"""Indexed-log wrapper with Routescan hex-field normalization.

Read-only only: no signer, transaction construction, broadcast, or state change.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

BASE_PATH = Path(__file__).with_name("termmax_erc4626_oracle_redeem_gap_20260801.py")
SPEC = importlib.util.spec_from_file_location("termmax_erc4626_oracle_gap_base_v3", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base scanner: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)


def _parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value or "0")
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _normalize(rows: list[Any]) -> list[Any]:
    normalized: list[Any] = []
    for row in rows:
        if isinstance(row, dict):
            item = dict(row)
            if "blockNumber" in item:
                item["blockNumber"] = _parse_int(item["blockNumber"])
            normalized.append(item)
        else:
            normalized.append(row)
    return normalized


def indexed_first_logs(address: str, start: int, end: int) -> tuple[list[Any], list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    try:
        rows, diag = base.routescan_logs(address, start, end)
        attempts.append({"ok": True, **diag})
        return _normalize(rows), attempts
    except Exception as exc:  # noqa: BLE001
        attempts.append({
            "ok": False,
            "transport": "routescan",
            "error": f"{type(exc).__name__}: {exc}",
        })
    for url in base.RPCS:
        try:
            rows, diag = base.direct_logs(url, address, start, end)
            attempts.append({"ok": True, **diag})
            return _normalize(rows), attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({
                "ok": False,
                "transport": "rpc",
                "url": url,
                "error": f"{type(exc).__name__}: {exc}",
            })
    raise RuntimeError(base.json.dumps(attempts))


base.all_logs = indexed_first_logs
raise SystemExit(base.main())
