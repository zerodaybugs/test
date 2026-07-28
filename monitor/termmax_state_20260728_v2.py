#!/usr/bin/env python3
"""Compatibility wrapper for the public, read-only TermMax state monitor.

Fixes canonical topic encoding and falls back to chunked public JSON-RPC
``eth_getLogs`` if the indexed explorer rejects a query. No private key,
transaction signing, or transaction broadcast is possible in this program.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from hexbytes import HexBytes
from web3 import Web3

BASE_PATH = Path(__file__).with_name("termmax_state_20260728.py")
SPEC = importlib.util.spec_from_file_location("termmax_state_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base monitor: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)


def canonical_sig(abi: dict[str, Any]) -> str:
    encoded = f"{abi['name']}({','.join(x['type'] for x in abi['inputs'])})"
    return "0x" + bytes(Web3.keccak(text=encoded)).hex()


routescan_logs = base.logs
base.sig = canonical_sig


def rpc_fallback_logs(w3: Web3, name: str, latest: int) -> list[dict[str, Any]]:
    abi = base.EVENTS[name]
    topic0 = canonical_sig(abi)
    start = base.START_BLOCK
    preferred_step = 20_000
    out: list[dict[str, Any]] = []

    while start <= latest:
        step = preferred_step
        rows = None
        while rows is None:
            end = min(latest, start + step - 1)
            try:
                rows = w3.eth.get_logs(
                    {
                        "address": base.VAULT,
                        "topics": [topic0],
                        "fromBlock": start,
                        "toBlock": end,
                    }
                )
            except Exception:
                if step <= 1_000:
                    raise
                step = max(1_000, step // 2)

        for row in rows:
            decoded = base.get_event_data(w3.codec, abi, row)
            out.append(
                {
                    "event": name,
                    "blockNumber": int(row["blockNumber"]),
                    "blockHash": "0x" + bytes(HexBytes(row["blockHash"])).hex(),
                    "transactionHash": "0x" + bytes(HexBytes(row["transactionHash"])).hex(),
                    "logIndex": int(row["logIndex"]),
                    "args": dict(decoded["args"]),
                    "retrieval": "public-rpc-eth_getLogs",
                }
            )
        start = min(latest, start + step - 1) + 1

    return out


def robust_logs(w3: Web3, name: str, latest: int) -> list[dict[str, Any]]:
    try:
        rows = routescan_logs(w3, name, latest)
        for row in rows:
            row.setdefault("retrieval", "routescan-indexed-get")
        return rows
    except Exception as explorer_error:
        rows = rpc_fallback_logs(w3, name, latest)
        for row in rows:
            row["routescanFallbackReason"] = f"{type(explorer_error).__name__}: {explorer_error}"
        return rows


base.logs = robust_logs
raise SystemExit(base.main())
