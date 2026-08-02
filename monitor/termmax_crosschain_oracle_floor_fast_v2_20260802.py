#!/usr/bin/env python3
"""Resilient read-only TermMax OracleAggregatorV2 floor census.

The scanner discovers deployed oracle aggregators from repository deployment JSON,
identifies configured assets from UpdateOracle logs with adaptive RPC failover, and
reads the current oracle mapping and feed state. It never signs or broadcasts a
transaction and never mutates target-chain state.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from web3 import Web3

CHAIN = os.environ.get("CHAIN", "").strip().lower()
OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

CHAIN_CONFIG: dict[str, dict[str, Any]] = {
    "base": {
        "chain_id": 8453,
        "dirs": ["base-mainnet"],
        "rpcs": [
            "https://base-rpc.publicnode.com",
            "https://mainnet.base.org",
            "https://base.drpc.org",
            "https://1rpc.io/base",
        ],
    },
    "b2": {
        "chain_id": 223,
        "dirs": ["b2-mainnet"],
        "rpcs": [
            "https://rpc.bsquared.network",
            "https://b2-mainnet.alt.technology",
        ],
    },
    "berachain": {
        "chain_id": 80094,
        "dirs": ["bera-mainnet", "berachain-mainnet"],
        "rpcs": [
            "https://berachain-rpc.publicnode.com",
            "https://rpc.berachain.com",
            "https://berachain.drpc.org",
        ],
    },
    "pharos": {
        "chain_id": 688688,
        "dirs": ["pharos-mainnet", "pharos-testnet"],
        "rpcs": [
            "https://rpc.pharosnetwork.xyz",
            "https://testnet.dplabs-internal.com",
        ],
    },
}

if CHAIN not in CHAIN_CONFIG:
    raise SystemExit(f"unsupported CHAIN={CHAIN!r}")
CFG = CHAIN_CONFIG[CHAIN]

ORACLE_ABI = [
    {
        "type": "function",
        "name": "oracles",
        "stateMutability": "view",
        "inputs": [{"type": "address"}],
        "outputs": [
            {"type": "address", "name": "aggregator"},
            {"type": "address", "name": "backupAggregator"},
            {"type": "int256", "name": "maxPrice"},
            {"type": "int256", "name": "minPrice"},
            {"type": "uint32", "name": "heartbeat"},
            {"type": "uint32", "name": "backupHeartbeat"},
        ],
    },
    {
        "type": "function",
        "name": "getPrice",
        "stateMutability": "view",
        "inputs": [{"type": "address"}],
        "outputs": [{"type": "uint256"}, {"type": "uint8"}],
    },
]
ROUND_ABI = [
    {
        "type": "function",
        "name": "latestRoundData",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [
            {"type": "uint80"}, {"type": "int256"}, {"type": "uint256"},
            {"type": "uint256"}, {"type": "uint80"},
        ],
    },
    {"type": "function", "name": "decimals", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint8"}]},
    {"type": "function", "name": "description", "stateMutability": "view", "inputs": [], "outputs": [{"type": "string"}]},
]
ERC20_ABI = [
    {"type": "function", "name": "symbol", "stateMutability": "view", "inputs": [], "outputs": [{"type": "string"}]},
    {"type": "function", "name": "decimals", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint8"}]},
]

UPDATE_ORACLE_TOPIC = Web3.keccak(
    text="UpdateOracle(address,address,address,int256,int256,uint32,uint32)"
).hex()
ZERO = "0x0000000000000000000000000000000000000000"


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        if isinstance(value, (bytes, bytearray)):
            value = Web3.to_hex(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def iter_addresses(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from iter_addresses(child, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from iter_addresses(child, f"{path}[{index}]")
    elif isinstance(value, str) and len(value) == 42 and value.startswith("0x"):
        try:
            yield path, Web3.to_checksum_address(value)
        except ValueError:
            return


@dataclass(frozen=True)
class Candidate:
    address: str
    source_file: str
    json_path: str
    start_block: int


def discover_candidates() -> list[Candidate]:
    root = Path("deployments")
    candidates: dict[str, Candidate] = {}
    for dirname in CFG["dirs"]:
        directory = root / dirname
        if not directory.exists():
            continue
        for file in directory.rglob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
            except Exception:
                continue
            block_info = data.get("blockInfo") if isinstance(data, dict) else None
            start_block = 0
            if isinstance(block_info, dict) and block_info.get("number") is not None:
                try:
                    start_block = as_int(block_info["number"])
                except Exception:
                    start_block = 0
            for json_path, address in iter_addresses(data):
                lowered = json_path.lower()
                # Deployment files normally identify this as oracle/oracleAggregator.
                # Include all core-like candidates as a fallback, then ABI-probe them.
                if any(word in lowered for word in ("oracle", "aggregator", "core", "contract")):
                    old = candidates.get(address.lower())
                    row = Candidate(address, str(file), json_path, start_block)
                    if old is None or (old.start_block == 0 and start_block != 0):
                        candidates[address.lower()] = row
    return sorted(candidates.values(), key=lambda row: row.address.lower())


def connect_all() -> tuple[list[tuple[str, Web3]], list[dict[str, Any]]]:
    clients: list[tuple[str, Web3]] = []
    attempts: list[dict[str, Any]] = []
    for url in CFG["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
            chain_id = w3.eth.chain_id
            block = w3.eth.get_block("latest")
            if chain_id != CFG["chain_id"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            clients.append((url, w3))
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    if not clients:
        raise RuntimeError(f"no healthy RPC: {attempts}")
    return clients, attempts


def first_success(clients: list[tuple[str, Web3]], callback):
    errors: list[str] = []
    for url, w3 in clients:
        try:
            return callback(w3), url
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(" | ".join(errors))


def is_oracle_aggregator(clients: list[tuple[str, Web3]], address: str, block: int) -> tuple[bool, dict[str, Any]]:
    zero_asset = Web3.to_checksum_address("0x0000000000000000000000000000000000000001")
    diagnostics: dict[str, Any] = {}
    for url, w3 in clients:
        try:
            code = w3.eth.get_code(address, block_identifier=block)
            if not code:
                diagnostics[url] = "no code"
                continue
            contract = w3.eth.contract(address=address, abi=ORACLE_ABI)
            value = contract.functions.oracles(zero_asset).call(block_identifier=block)
            diagnostics[url] = {"ok": True, "tupleLength": len(value), "codeBytes": len(code)}
            if len(value) == 6:
                return True, diagnostics
        except Exception as exc:  # noqa: BLE001
            diagnostics[url] = f"{type(exc).__name__}: {exc}"
    return False, diagnostics


def get_logs_adaptive(
    clients: list[tuple[str, Web3]], address: str, start: int, end: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if start > end:
        return [], []
    logs: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    cursor = start
    chunk = min(250_000, max(end - start + 1, 1))
    client_index = 0
    while cursor <= end:
        upper = min(cursor + chunk - 1, end)
        success = False
        round_errors: list[str] = []
        for offset in range(len(clients)):
            index = (client_index + offset) % len(clients)
            url, w3 = clients[index]
            try:
                batch = w3.eth.get_logs({
                    "fromBlock": cursor,
                    "toBlock": upper,
                    "address": address,
                    "topics": [UPDATE_ORACLE_TOPIC],
                })
                logs.extend(dict(item) for item in batch)
                diagnostics.append({"from": cursor, "to": upper, "rpc": url, "ok": True, "logs": len(batch)})
                cursor = upper + 1
                client_index = (index + 1) % len(clients)
                if len(batch) == 0 and chunk < 250_000:
                    chunk = min(chunk * 2, 250_000)
                success = True
                break
            except Exception as exc:  # noqa: BLE001
                round_errors.append(f"{url}: {type(exc).__name__}: {exc}")
        if success:
            continue
        if chunk > 250:
            chunk = max(chunk // 4, 250)
            diagnostics.append({"from": cursor, "to": upper, "ok": False, "action": "shrink", "nextChunk": chunk, "errors": round_errors})
            continue
        raise RuntimeError(f"eth_getLogs failed at {cursor}-{upper}: {' | '.join(round_errors)}")
    return logs, diagnostics


def topic_address(topic: Any) -> str:
    raw = bytes(topic)
    return Web3.to_checksum_address("0x" + raw[-20:].hex())


def feed_state(clients: list[tuple[str, Web3]], address: str, block: int, timestamp: int) -> dict[str, Any]:
    if address.lower() == ZERO.lower():
        return {"address": address, "present": False}
    row: dict[str, Any] = {"address": address, "present": True}
    for url, w3 in clients:
        contract = w3.eth.contract(address=address, abi=ROUND_ABI)
        state = safe(contract.functions.latestRoundData().call, block_identifier=block)
        if state.get("ok"):
            value = state["value"]
            row.update({
                "rpc": url,
                "latestRoundData": state,
                "decimals": safe(contract.functions.decimals().call, block_identifier=block),
                "description": safe(contract.functions.description().call, block_identifier=block),
                "answer": int(value[1]),
                "updatedAt": int(value[3]),
                "ageSeconds": max(timestamp - int(value[3]), 0),
            })
            return row
        row.setdefault("errors", []).append({"rpc": url, **state})
    return row


def token_meta(clients: list[tuple[str, Web3]], address: str, block: int) -> dict[str, Any]:
    row = {"address": address}
    for url, w3 in clients:
        contract = w3.eth.contract(address=address, abi=ERC20_ABI)
        symbol = safe(contract.functions.symbol().call, block_identifier=block)
        if symbol.get("ok"):
            row.update({
                "rpc": url,
                "symbol": symbol,
                "decimals": safe(contract.functions.decimals().call, block_identifier=block),
            })
            return row
        row.setdefault("errors", []).append({"rpc": url, **symbol})
    return row


def main() -> int:
    clients, rpc_attempts = connect_all()
    latest_block, latest_rpc = first_success(clients, lambda w3: w3.eth.get_block("latest"))
    latest_number = int(latest_block.number)
    latest_timestamp = int(latest_block.timestamp)

    discovered = discover_candidates()
    aggregators: list[dict[str, Any]] = []
    configured_assets: dict[str, dict[str, Any]] = {}

    for candidate in discovered:
        probe_block = latest_number
        is_aggregator, diagnostics = is_oracle_aggregator(clients, candidate.address, probe_block)
        if not is_aggregator:
            continue
        start = candidate.start_block or max(latest_number - 8_000_000, 0)
        logs, log_diagnostics = get_logs_adaptive(clients, candidate.address, start, latest_number)
        assets: dict[str, dict[str, Any]] = {}
        for log in logs:
            topics = log.get("topics", [])
            if len(topics) < 2:
                continue
            asset = topic_address(topics[1])
            assets[asset.lower()] = {
                "asset": asset,
                "lastUpdateBlock": as_int(log["blockNumber"]),
                "transactionHash": Web3.to_hex(log["transactionHash"]),
                "logIndex": as_int(log["logIndex"]),
            }
        aggregator_row = {
            "address": candidate.address,
            "sourceFile": candidate.source_file,
            "jsonPath": candidate.json_path,
            "startBlock": start,
            "abiProbe": diagnostics,
            "updateLogCount": len(logs),
            "assetCount": len(assets),
            "logDiagnostics": log_diagnostics,
        }
        aggregators.append(aggregator_row)

        for asset_row in assets.values():
            asset = asset_row["asset"]
            for url, w3 in clients:
                contract = w3.eth.contract(address=candidate.address, abi=ORACLE_ABI)
                config = safe(contract.functions.oracles(asset).call, block_identifier=latest_number)
                if not config.get("ok"):
                    continue
                value = config["value"]
                primary = Web3.to_checksum_address(value[0])
                backup = Web3.to_checksum_address(value[1])
                current_price = safe(contract.functions.getPrice(asset).call, block_identifier=latest_number)
                row = {
                    **asset_row,
                    "oracleAggregator": candidate.address,
                    "rpc": url,
                    "token": token_meta(clients, asset, latest_number),
                    "primary": primary,
                    "backup": backup,
                    "maxPrice": int(value[2]),
                    "minPrice": int(value[3]),
                    "heartbeat": int(value[4]),
                    "backupHeartbeat": int(value[5]),
                    "getPrice": current_price,
                    "primaryState": feed_state(clients, primary, latest_number, latest_timestamp),
                    "backupState": feed_state(clients, backup, latest_number, latest_timestamp),
                }
                row["zeroFloor"] = row["minPrice"] == 0
                row["currentlyZeroPrice"] = bool(
                    current_price.get("ok") and int(current_price["value"][0]) == 0
                )
                configured_assets[f"{candidate.address.lower()}:{asset.lower()}"] = row
                break

    asset_rows = sorted(configured_assets.values(), key=lambda row: (row["oracleAggregator"].lower(), row["asset"].lower()))
    zero_floor_rows = [row for row in asset_rows if row["zeroFloor"]]
    current_zero_rows = [row for row in asset_rows if row["currentlyZeroPrice"]]

    result = {
        "schema": "termmax-crosschain-oracle-floor-fast/v2",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "chain": CHAIN,
        "chainId": CFG["chain_id"],
        "latestBlock": latest_number,
        "latestBlockHash": latest_block.hash.hex(),
        "latestTimestamp": latest_timestamp,
        "latestTimestampUtc": datetime.fromtimestamp(latest_timestamp, tz=timezone.utc).isoformat(),
        "latestRpc": latest_rpc,
        "rpcAttempts": rpc_attempts,
        "deploymentDirectories": CFG["dirs"],
        "candidateCount": len(discovered),
        "oracleAggregatorCount": len(aggregators),
        "aggregators": aggregators,
        "configuredAssetCount": len(asset_rows),
        "zeroFloorCount": len(zero_floor_rows),
        "currentlyZeroPriceCount": len(current_zero_rows),
        "assets": asset_rows,
        "verdict": {
            "scanComplete": True,
            "zeroFloorPresent": len(zero_floor_rows) > 0,
            "currentlyZeroPricePresent": len(current_zero_rows) > 0,
            "requiresMarketExposureMapping": len(zero_floor_rows) > 0,
            "criticalLiveGatePassed": False,
            "note": "Zero floor alone is not a Critical exploit; a permissionless zero-price trigger and active material debt exposure remain mandatory.",
        },
    }
    (OUT / "ORACLE_FLOOR_FAST_V2.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (OUT / "VERDICT.json").write_text(json.dumps(result["verdict"], indent=2), encoding="utf-8")
    print(json.dumps({
        "chain": CHAIN,
        "oracleAggregatorCount": len(aggregators),
        "configuredAssetCount": len(asset_rows),
        "zeroFloorCount": len(zero_floor_rows),
        "currentlyZeroPriceCount": len(current_zero_rows),
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        failure = {
            "schema": "termmax-crosschain-oracle-floor-fast/v2",
            "chain": CHAIN,
            "scanComplete": False,
            "fatalError": f"{type(exc).__name__}: {exc}",
        }
        (OUT / "FAILURE.json").write_text(json.dumps(failure, indent=2), encoding="utf-8")
        print(json.dumps(failure, indent=2))
        raise
