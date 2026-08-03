#!/usr/bin/env python3
"""Resilient wrapper for the TermMax vault composition gate.

Adds indexed-log-first holder discovery from a conservative pre-deployment block,
then RPC rotation as fallback. The core order, vault, and settlement reads remain
those of termmax_vault_composition_gate_20260803.py. Read-only only.
"""
from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

BASE_PATH = Path(__file__).with_name("termmax_vault_composition_gate_20260803.py")
SPEC = importlib.util.spec_from_file_location("termmax_vault_composition_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base scanner: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

# The archive-node binary search in the base scanner can fail closed on public
# RPCs that do not serve old state. This block predates the vault deployment and
# therefore safely covers the complete share Transfer history.
HOLDER_SCAN_START_BLOCK = 24_000_000


def topic_hex(value: Any) -> str:
    text = value.hex() if hasattr(value, "hex") else str(value)
    return text if text.startswith("0x") else "0x" + text


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value or "0")
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def normalize_log(row: Any) -> Any:
    if not isinstance(row, dict):
        return row
    item = dict(row)
    if "blockNumber" in item:
        item["blockNumber"] = parse_int(item["blockNumber"])
    return item


def direct_logs(url: str, start: int, end: int) -> tuple[list[Any], dict[str, Any]]:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 45}))
    rows: list[Any] = []
    cursor = start
    sizes = [50_000, 10_000, 2_000, 500]
    size_index = 0
    request_count = 0
    while cursor <= end:
        upper = min(end, cursor + sizes[size_index] - 1)
        try:
            batch = w3.eth.get_logs({
                "address": base.VAULT,
                "fromBlock": cursor,
                "toBlock": upper,
                "topics": [topic_hex(base.TRANSFER_TOPIC)],
            })
            rows.extend(batch)
            cursor = upper + 1
            size_index = 0
            request_count += 1
        except Exception:
            if size_index + 1 < len(sizes):
                size_index += 1
                continue
            raise
    return rows, {"transport": "rpc", "url": url, "requestCount": request_count, "rowCount": len(rows)}


def routescan_logs(start: int, end: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    endpoint = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
    all_rows: list[dict[str, Any]] = []
    page = 1
    while True:
        params = {
            "module": "logs",
            "action": "getLogs",
            "address": base.VAULT,
            "fromBlock": start,
            "toBlock": end,
            "topic0": topic_hex(base.TRANSFER_TOPIC),
            "page": page,
            "offset": 1000,
        }
        payload: Any = None
        last_error: Exception | None = None
        for attempt in range(8):
            try:
                response = requests.get(
                    endpoint,
                    params=params,
                    timeout=60,
                    headers={"User-Agent": "ZeroDayBugs-TermMax-Readonly/5"},
                )
                if response.status_code == 429:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                time.sleep(1.25 * (attempt + 1))
        if payload is None:
            raise RuntimeError(f"Routescan failed: {last_error}")
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            lowered = rows.lower()
            if "no" in lowered or "not found" in lowered:
                break
            raise RuntimeError(f"unexpected Routescan response: {payload}")
        if not rows:
            break
        all_rows.extend(normalize_log(row) for row in rows)
        if len(rows) < 1000:
            break
        page += 1
        time.sleep(0.25)
    return all_rows, {
        "transport": "routescan",
        "endpoint": endpoint,
        "fromBlock": start,
        "toBlock": end,
        "pageCount": page,
        "rowCount": len(all_rows),
    }


def resilient_transfer_logs(_w3: Web3, _start: int, end: int) -> tuple[list[Any], list[dict[str, Any]]]:
    start = HOLDER_SCAN_START_BLOCK
    attempts: list[dict[str, Any]] = []

    # Indexed explorer first: avoids archive-node and wide eth_getLogs limits.
    try:
        rows, diag = routescan_logs(start, end)
        attempts.append({"ok": True, **diag})
        if rows:
            return rows, attempts
    except Exception as exc:  # noqa: BLE001
        attempts.append({"ok": False, "transport": "routescan", "error": f"{type(exc).__name__}: {exc}"})

    for url in base.RPCS:
        try:
            rows, diag = direct_logs(url, start, end)
            attempts.append({"ok": True, **diag})
            if rows:
                return rows, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"ok": False, "transport": "rpc", "url": url, "error": f"{type(exc).__name__}: {exc}"})

    # Preserve the higher-value order and settlement state if all holder
    # transports fail. The verdict exposes zero holders rather than guessing.
    return [], attempts


base.TRANSFER_TOPIC = topic_hex(base.TRANSFER_TOPIC)
base.get_transfer_logs = resilient_transfer_logs
raise SystemExit(base.main())
