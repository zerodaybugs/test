#!/usr/bin/env python3
"""Failover wrapper for the public read-only TermMax B2 TWAP scanner.

The original scanner's current-state calls were valid, but its selected RPC
returned HTTP 403 for eth_getLogs. This wrapper keeps the same analysis and
replaces only transport: current-state RPC prefers Binance's public endpoint,
while historical logs come from the public Routescan index. No signer,
transaction builder, private key, or state-changing call is present.
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

BASE_PATH = Path(__file__).with_name("termmax_b2_twap_binding_20260730.py")
SPEC = importlib.util.spec_from_file_location("termmax_b2_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base scanner: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

base.RPCS = [
    "https://bsc-dataseed.binance.org",
    "https://bsc.drpc.org",
    "https://1rpc.io/bnb",
    "https://bsc-rpc.publicnode.com",
]

ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/56/etherscan/api"


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value or "0")
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def normalize_log(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "address": Web3.to_checksum_address(raw["address"]),
        "blockNumber": parse_int(raw.get("blockNumber")),
        "transactionHash": HexBytes(raw["transactionHash"]),
        "transactionIndex": parse_int(raw.get("transactionIndex")),
        "blockHash": HexBytes(raw["blockHash"]),
        "logIndex": parse_int(raw.get("logIndex")),
        "data": HexBytes(raw.get("data") or "0x"),
        "topics": [HexBytes(topic) for topic in raw.get("topics", [])],
        "removed": False,
    }


def indexed_logs(
    _w3: Web3,
    from_block: int,
    to_block: int,
    topics: list[Any],
    address: str | None = None,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    page = 1
    while True:
        params: dict[str, Any] = {
            "module": "logs",
            "action": "getLogs",
            "fromBlock": from_block,
            "toBlock": to_block,
            "page": page,
            "offset": 1000,
        }
        if address:
            params["address"] = Web3.to_checksum_address(address)
        specified: list[int] = []
        for index, topic in enumerate(topics):
            if topic is not None:
                params[f"topic{index}"] = topic
                specified.append(index)
        for left, right in zip(specified, specified[1:]):
            params[f"topic{left}_{right}_opr"] = "and"

        last_error: Exception | None = None
        payload: Any = None
        for attempt in range(6):
            try:
                response = requests.get(
                    ROUTESCAN,
                    params=params,
                    timeout=60,
                    headers={"User-Agent": "ZeroDayBugs-TermMax-Readonly/2"},
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
        else:
            raise RuntimeError(f"Routescan logs failed: {last_error}; params={json.dumps(params)}")

        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            if "No" in rows or "not found" in rows.lower():
                break
            raise RuntimeError(f"unexpected Routescan response: {payload}")
        if not rows:
            break
        output.extend(normalize_log(row) for row in rows)
        if len(rows) < 1000:
            break
        page += 1
        time.sleep(0.25)
    return output


base.chunked_logs = indexed_logs
raise SystemExit(base.main())
