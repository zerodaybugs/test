#!/usr/bin/env python3
"""Fast read-only scan of active OracleAggregatorV2 configurations.

No market iteration and no state changes. This is the early kill gate for the
zero-price acceptance candidate: if every configured asset has a positive
minimum floor, an upstream zero answer cannot pass the aggregator.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

TOPIC = Web3.keccak(text="UpdateOracle(address,address,address,int256,int256,uint32,uint32)").hex()
ZERO = "0x0000000000000000000000000000000000000000"
CHAINS: dict[str, dict[str, Any]] = {
    "base": {
        "chainId": 8453,
        "oracle": "0xC1114E635661d13137E642828f1Da71948B2CaaD",
        "fromBlock": 44722441,
        "rpcs": ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://base.drpc.org"],
    },
    "b2": {
        "chainId": 223,
        "oracle": "0x3B798263e9eAE3254d86AC30b198F7AA2F82Fd82",
        "fromBlock": 31535305,
        "rpcs": ["https://rpc.bsquared.network", "https://b2-mainnet.alt.technology"],
    },
    "berachain": {
        "chainId": 80094,
        "oracle": "0xf5c6664c5b33e3FC16afA43621650652FcD85d65",
        "fromBlock": 19609794,
        "rpcs": ["https://berachain-rpc.publicnode.com", "https://rpc.berachain.com", "https://berachain.drpc.org"],
    },
    "pharos": {
        "chainId": 1672,
        "oracle": "0x490df22f542e778fAfAB441beB19d358bE048A20",
        "fromBlock": 5278169,
        "rpcs": ["https://rpc.pharos.xyz"],
    },
}
ABI = [
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"int256"},{"type":"int256"},{"type":"uint32"},{"type":"uint32"}
    ]},
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"uint256"},{"type":"uint8"}
    ]},
]
ROUND_ABI = [
    {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[
        {"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}
    ]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect(cfg: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in cfg["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            latest = w3.eth.block_number
            if chain_id != cfg["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "latest": latest})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def topic_address(topic: Any) -> str:
    return Web3.to_checksum_address("0x" + bytes(topic)[-20:].hex())


def logs(w3: Web3, address: str, start: int, end: int) -> tuple[list[Any], list[dict[str, Any]]]:
    found: list[Any] = []
    diag: list[dict[str, Any]] = []
    cursor = start
    step = 1_000_000
    while cursor <= end:
        stop = min(cursor + step - 1, end)
        try:
            batch = w3.eth.get_logs({
                "address": Web3.to_checksum_address(address),
                "fromBlock": cursor,
                "toBlock": stop,
                "topics": [TOPIC],
            })
            found.extend(batch)
            diag.append({"from": cursor, "to": stop, "ok": True, "count": len(batch), "step": step})
            cursor = stop + 1
            if step < 4_000_000:
                step *= 2
        except Exception as exc:  # noqa: BLE001
            diag.append({"from": cursor, "to": stop, "ok": False, "step": step, "error": f"{type(exc).__name__}: {exc}"})
            if step <= 5_000:
                raise
            step = max(step // 4, 5_000)
    return found, diag


def main() -> int:
    chain = os.environ["CHAIN"].strip().lower()
    cfg = CHAINS[chain]
    out = Path(os.environ.get("OUT_DIR", "evidence"))
    out.mkdir(parents=True, exist_ok=True)
    w3, rpc, attempts = connect(cfg)
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    events, diagnostics = logs(w3, cfg["oracle"], cfg["fromBlock"], latest)
    assets = sorted({topic_address(event["topics"][1]) for event in events if len(event["topics"]) >= 2})
    oracle = w3.eth.contract(address=Web3.to_checksum_address(cfg["oracle"]), abi=ABI)
    rows: list[dict[str, Any]] = []
    for asset in assets:
        config_r = safe(oracle.functions.oracles(asset).call, block_identifier=latest)
        price_r = safe(oracle.functions.getPrice(asset).call, block_identifier=latest)
        row: dict[str, Any] = {"asset": asset, "config": config_r, "getPrice": price_r}
        if config_r.get("ok"):
            agg, backup, max_price, min_price, heartbeat, backup_heartbeat = config_r["value"]
            row.update({
                "aggregator": agg,
                "backupAggregator": backup,
                "maxPrice": int(max_price),
                "minPrice": int(min_price),
                "heartbeat": int(heartbeat),
                "backupHeartbeat": int(backup_heartbeat),
                "zeroFloor": int(min_price) == 0 and agg != ZERO,
            })
            if agg != ZERO:
                feed = w3.eth.contract(address=Web3.to_checksum_address(agg), abi=ROUND_ABI)
                row["primaryRound"] = safe(feed.functions.latestRoundData().call, block_identifier=latest)
                row["primaryDecimals"] = safe(feed.functions.decimals().call, block_identifier=latest)
        rows.append(row)
    summary = {
        "chain": chain,
        "chainId": cfg["chainId"],
        "block": latest,
        "configuredAssets": len(rows),
        "zeroFloorAssets": sum(1 for row in rows if row.get("zeroFloor") is True),
        "currentZeroPrices": sum(1 for row in rows if row["getPrice"].get("ok") and int(row["getPrice"]["value"][0]) == 0),
    }
    result = {
        "schema": "termmax-crosschain-oracle-floor-fast/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "blockHash": block.hash.hex(),
        "oracle": cfg["oracle"],
        "logDiagnostics": diagnostics,
        "rows": rows,
        "summary": summary,
    }
    (out / "ORACLE_FLOOR_FAST_FULL.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
