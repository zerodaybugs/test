#!/usr/bin/env python3
"""Targeted public, read-only state snapshot for the TermMax USDC V2 vault.

It inspects the previously non-zero mature orders plus recent vault events. It
uses only public ``eth_call`` / block reads and indexed HTTPS GET requests.
"""
from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hexbytes import HexBytes
from web3 import Web3

BASE_PATH = Path(__file__).with_name("termmax_state_20260728.py")
SPEC = importlib.util.spec_from_file_location("termmax_target_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load base monitor")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

OUT = Path(__import__("os").environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
PREVIOUS_BLOCK = 25_597_355
TARGET_ORDERS = [
    "0x93257038ecc1337d296ec61b2629704fe89acfa5",  # previously impaired PT-RLP
    "0x667ddd85358e8765814f07efd1c4a9cad67521d7",  # largest mature near-par order
    "0xe7059ddd2dc6f7d54088628655d8c3a096804448",
    "0x66197a8bb9621a6da48e9c28fd6f23341901af8d",
    "0xd8409caa2497dfee072722a8155503f744514ca7",
    "0x69934e4a00133b566dd4853c65e254ea66544b34",  # next maturity control
]


def default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, HexBytes)):
        return "0x" + bytes(value).hex()
    return str(value)


def val(result: dict[str, Any], fallback: Any = None) -> Any:
    return result.get("value", fallback) if result.get("ok") else fallback


def parse_num(value: Any) -> int:
    if value is None or value == "" or str(value).lower() == "0x":
        return 0
    if isinstance(value, int):
        return value
    text = str(value)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def event_topic(abi: dict[str, Any]) -> str:
    signature = f"{abi['name']}({','.join(item['type'] for item in abi['inputs'])})"
    return "0x" + bytes(Web3.keccak(text=signature)).hex()


def recent_logs(w3: Web3, name: str, latest: int) -> list[dict[str, Any]]:
    abi = base.EVENTS[name]
    payload = base.get_json(
        "etherscan/api",
        {
            "module": "logs",
            "action": "getLogs",
            "address": base.VAULT,
            "fromBlock": PREVIOUS_BLOCK + 1,
            "toBlock": latest,
            "topic0": event_topic(abi),
            "page": 1,
            "offset": 1000,
        },
    )
    rows = payload.get("result", []) if isinstance(payload, dict) else []
    if isinstance(rows, str):
        if "No" in rows:
            return []
        raise RuntimeError(f"recent log query failed: {payload}")
    out = []
    for row in rows:
        log = {
            "address": Web3.to_checksum_address(row["address"]),
            "topics": [HexBytes(item) for item in row.get("topics", [])],
            "data": HexBytes(row.get("data") or "0x"),
            "blockNumber": parse_num(row.get("blockNumber")),
            "transactionHash": HexBytes(row["transactionHash"]),
            "transactionIndex": parse_num(row.get("transactionIndex")),
            "blockHash": HexBytes(row["blockHash"]),
            "logIndex": parse_num(row.get("logIndex")),
            "removed": False,
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
            }
        )
    return out


def main() -> int:
    w3, rpc, attempts = base.connect()
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    timestamp = int(block.timestamp)
    vault = w3.eth.contract(address=base.VAULT, abi=base.VAULT_ABI)

    state = {
        name: base.safe(getattr(vault.functions, name)().call, block_identifier=latest)
        for name in ["name", "symbol", "asset", "pool", "totalFt", "totalAssets", "totalSupply", "paused"]
    }
    state["maxDeposit"] = base.safe(
        vault.functions.maxDeposit("0x0000000000000000000000000000000000000000").call,
        block_identifier=latest,
    )

    orders = [base.inspect_order(w3, vault, address, latest, timestamp) for address in TARGET_ORDERS]
    resolved = [row for row in orders if row.get("economics", {}).get("recovery") is not None]
    mature = [row for row in resolved if row.get("matured")]
    losses = [row for row in mature if int(row["economics"].get("loss") or 0) > 0]
    good = [row for row in mature if int(row["economics"].get("quality1e18") or 0) >= 999_900_000_000_000_000]

    known_loss = sum(int(row["economics"]["loss"]) for row in losses)
    good_capacity = sum(int(row["economics"]["nominal"]) for row in good)
    total_assets = int(val(state["totalAssets"], 0) or 0)
    shares_needed = int(vault.functions.previewWithdraw(good_capacity).call(block_identifier=latest)) if good_capacity else 0
    maximum_excess = good_capacity * known_loss // total_assets if total_assets else 0

    holder_state = base.holders()
    capable = [row for row in holder_state.get("items", []) if row["balance"] >= shares_needed]
    best = max(good, key=lambda row: int(row["economics"]["quality1e18"]), default=None)
    simulations = []
    if best and holder_state.get("ok"):
        amount = min(1_000_000, int(best["economics"]["nominal"]))
        needed = int(vault.functions.previewWithdraw(amount).call(block_identifier=latest))
        holder = next((row for row in holder_state["items"] if row["balance"] >= needed), None)
        if holder:
            simulations.append(base.simulate(w3, vault, best["order"], amount, holder["address"], latest))
            simulations.append(
                base.simulate(
                    w3,
                    vault,
                    best["order"],
                    amount,
                    "0x2222222222222222222222222222222222222222",
                    latest,
                )
            )

    recent = {name: recent_logs(w3, name, latest) for name in base.EVENTS}
    collaterals = sorted(
        {
            row.get("addresses", {}).get("collateral")
            for row in orders
            if row.get("addresses", {}).get("collateral")
        }
    )
    buckets = []
    for collateral in collaterals:
        token = w3.eth.contract(address=Web3.to_checksum_address(collateral), abi=base.ERC20_ABI)
        buckets.append(
            {
                "collateral": collateral,
                "meta": base.token(w3, collateral, latest),
                "badDebt": base.safe(vault.functions.badDebtMapping(collateral).call, block_identifier=latest),
                "vaultBalance": base.safe(token.functions.balanceOf(base.VAULT).call, block_identifier=latest),
            }
        )

    result = {
        "schema": "termmax-targeted-public-state/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {
            "number": latest,
            "hash": "0x" + bytes(block.hash).hex(),
            "timestamp": timestamp,
            "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        },
        "vault": str(base.VAULT),
        "state": state,
        "orders": orders,
        "recentEvents": recent,
        "badDebtBuckets": buckets,
        "holders": holder_state,
        "economics": {
            "knownLatentLoss": known_loss,
            "knownGoodCapacity": good_capacity,
            "maximumProRataExcess": maximum_excess,
            "sharesNeeded": shares_needed,
            "capableHolders": capable,
            "worstOrder": max(losses, key=lambda row: int(row["economics"]["loss"]), default=None),
            "bestOrder": best,
        },
        "withdrawFtsReadOnlySimulations": simulations,
    }
    compact = {
        "generatedAtUtc": result["generatedAtUtc"],
        "block": result["block"],
        "state": state,
        "recentEventCounts": {name: len(rows) for name, rows in recent.items()},
        "economics": result["economics"],
        "nonzeroBadDebtBuckets": [row for row in buckets if int(val(row["badDebt"], 0) or 0) > 0],
        "simulations": simulations,
    }
    (OUT / "TARGETED_FULL.json").write_text(json.dumps(result, indent=2, default=default), encoding="utf-8")
    (OUT / "TARGETED_COMPACT.json").write_text(json.dumps(compact, indent=2, default=default), encoding="utf-8")
    print(json.dumps(compact, indent=2, default=default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
