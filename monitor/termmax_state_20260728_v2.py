#!/usr/bin/env python3
"""Compatibility wrapper for the public, read-only TermMax state monitor.

Uses canonical event topics, tolerates explorer fields represented as bare
``0x``, and falls back to chunked public ``eth_getLogs`` when necessary. No
private key, transaction signing, or transaction broadcast is possible.
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


def parse_num(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text in {"", "0x", "0X"}:
        return 0
    return int(text, 16) if text.lower().startswith("0x") else int(text, 10)


base.sig = canonical_sig


def indexed_logs(w3: Web3, name: str, latest: int) -> list[dict[str, Any]]:
    abi = base.EVENTS[name]
    page = 1
    raw_rows: list[dict[str, Any]] = []

    while True:
        payload = base.get_json(
            "etherscan/api",
            {
                "module": "logs",
                "action": "getLogs",
                "address": base.VAULT,
                "fromBlock": base.START_BLOCK,
                "toBlock": latest,
                "topic0": canonical_sig(abi),
                "page": page,
                "offset": 1000,
            },
        )
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            if "No records" in rows or "No logs" in rows:
                break
            raise RuntimeError(f"indexed log query failed: {payload}")
        if not rows:
            break
        raw_rows.extend(rows)
        if len(rows) < 1000:
            break
        page += 1

    out: list[dict[str, Any]] = []
    for row in raw_rows:
        log = {
            "address": Web3.to_checksum_address(row["address"]),
            "topics": [HexBytes(value) for value in row.get("topics", [])],
            "data": HexBytes(row.get("data") or "0x"),
            "blockNumber": parse_num(row.get("blockNumber")),
            "transactionHash": HexBytes(row["transactionHash"]),
            "transactionIndex": parse_num(row.get("transactionIndex")),
            "blockHash": HexBytes(row["blockHash"]),
            "logIndex": parse_num(row.get("logIndex")),
            "removed": bool(row.get("removed", False)),
        }
        decoded = base.get_event_data(w3.codec, abi, log)
        out.append(
            {
                "event": name,
                "blockNumber": log["blockNumber"],
                "blockHash": "0x" + bytes(log["blockHash"]).hex(),
                "transactionHash": "0x" + bytes(log["transactionHash"]).hex(),
                "logIndex": log["logIndex"],
                "args": dict(decoded["args"]),
                "retrieval": "routescan-indexed-get",
            }
        )
    return out


def rpc_logs_from_provider(w3: Web3, name: str, latest: int) -> list[dict[str, Any]]:
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


def rpc_fallback_logs(name: str, latest: int) -> list[dict[str, Any]]:
    errors: list[str] = []
    for url in base.RPCS:
        try:
            candidate = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 45}))
            if candidate.eth.chain_id != 1:
                raise RuntimeError("unexpected chain")
            return rpc_logs_from_provider(candidate, name, latest)
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError("all public getLogs providers failed: " + " | ".join(errors))


def robust_logs(w3: Web3, name: str, latest: int) -> list[dict[str, Any]]:
    try:
        return indexed_logs(w3, name, latest)
    except Exception as explorer_error:
        rows = rpc_fallback_logs(name, latest)
        for row in rows:
            row["routescanFallbackReason"] = f"{type(explorer_error).__name__}: {explorer_error}"
        return rows


base.logs = robust_logs
raise SystemExit(base.main())
