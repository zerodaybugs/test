#!/usr/bin/env python3
"""Fast indexed-log wrapper for the public TermMax cross-chain inventory.

The underlying scanner performs current read-only RPC inspection. This wrapper
replaces expensive block-by-block `eth_getLogs` range splitting with Routescan's
public indexed `getLogs` endpoint, falling back to the original RPC scanner if
an explorer does not support a chain. No signer, key, transaction construction,
or broadcast capability is present.
"""
from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path
from typing import Any

import requests
from hexbytes import HexBytes
from web3 import Web3

BASE_PATH = Path(__file__).with_name("termmax_crosschain_delegated_newgt_inventory_20260728.py")
SPEC = importlib.util.spec_from_file_location("termmax_crosschain_inventory_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base scanner: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "ZeroDayBugs-TermMax-Indexed-Inventory/1.0"})


def parse_int(value: Any, fallback: int = 0) -> int:
    if value is None:
        return fallback
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return fallback
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def routescan_logs(
    chain_id: int,
    address: str,
    start_block: int,
    end_block: int,
    topic0: HexBytes,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    endpoint = f"https://api.routescan.io/v2/network/mainnet/evm/{chain_id}/etherscan/api"
    page = 1
    rows: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    while True:
        params = {
            "module": "logs",
            "action": "getLogs",
            "address": Web3.to_checksum_address(address),
            "fromBlock": start_block,
            "toBlock": end_block,
            "topic0": topic0.hex(),
            "page": page,
            "offset": 1000,
        }
        last: Exception | None = None
        payload: dict[str, Any] | None = None
        for attempt in range(7):
            try:
                response = SESSION.get(endpoint, params=params, timeout=75)
                if response.status_code == 429:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as exc:  # noqa: BLE001
                last = exc
                time.sleep(1.5 * (attempt + 1))
        if payload is None:
            raise RuntimeError(f"Routescan getLogs failed: {last}")
        result = payload.get("result", []) if isinstance(payload, dict) else []
        diagnostics.append(
            {
                "endpoint": endpoint,
                "page": page,
                "status": payload.get("status") if isinstance(payload, dict) else None,
                "message": payload.get("message") if isinstance(payload, dict) else None,
                "resultType": type(result).__name__,
                "count": len(result) if isinstance(result, list) else None,
            }
        )
        if isinstance(result, str):
            lowered = result.lower()
            if "no records" in lowered or "no logs" in lowered or "no transactions" in lowered:
                break
            raise RuntimeError(f"Routescan returned error string: {result}")
        if not isinstance(result, list) or not result:
            break
        rows.extend(result)
        if len(result) < 1000:
            break
        page += 1

    normalized: list[dict[str, Any]] = []
    for row in rows:
        normalized.append(
            {
                "address": Web3.to_checksum_address(row["address"]),
                "topics": [HexBytes(value) for value in row.get("topics", [])],
                "data": HexBytes(row.get("data") or "0x"),
                "blockNumber": parse_int(row.get("blockNumber")),
                "transactionHash": HexBytes(row["transactionHash"]),
                "transactionIndex": parse_int(row.get("transactionIndex")),
                "blockHash": HexBytes(row["blockHash"]),
                "logIndex": parse_int(row.get("logIndex")),
                "removed": False,
            }
        )
    return normalized, diagnostics


_original_scan_logs = base.scan_logs


def indexed_scan_logs(
    w3: Web3,
    address: str,
    start_block: int,
    end_block: int,
    event_topic: HexBytes,
):
    chain_id = int(w3.eth.chain_id)
    try:
        logs, diagnostics = routescan_logs(chain_id, address, start_block, end_block, event_topic)
        return logs, [{"mode": "routescan-indexed", **row} for row in diagnostics]
    except Exception as exc:  # noqa: BLE001
        logs, diagnostics = _original_scan_logs(w3, address, start_block, end_block, event_topic)
        return logs, [
            {
                "mode": "routescan-indexed-failed-rpc-fallback",
                "error": f"{type(exc).__name__}: {exc}",
            },
            *diagnostics,
        ]


base.scan_logs = indexed_scan_logs
raise SystemExit(base.main())
