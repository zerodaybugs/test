#!/usr/bin/env python3
"""Read-only TermMax zero-price live-binding and exposure scanner.

The scanner enumerates markets from the deployed TermMaxFactoryV2 through
public explorer APIs, then reads current market, GT, oracle, and feed state by
JSON-RPC. It never constructs, signs, or broadcasts a transaction.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

ZERO = "0x0000000000000000000000000000000000000000"
CREATE_MARKET_TOPIC = Web3.keccak(text="CreateMarket(address,address,address)").hex()

CHAINS: dict[str, dict[str, Any]] = {
    "base": {
        "chainId": 8453,
        "factory": "0x08c50Bd46992d35694208eC3Cf1f1EDcE38f5fd1",
        "oracle": "0xC1114E635661d13137E642828f1Da71948B2CaaD",
        "fromBlock": 44722441,
        "rpcs": [
            "https://base-rpc.publicnode.com",
            "https://mainnet.base.org",
            "https://base.drpc.org",
            "https://1rpc.io/base",
        ],
        "explorers": [
            "https://base.blockscout.com/api",
            "https://api.routescan.io/v2/network/mainnet/evm/8453/etherscan/api",
        ],
    },
    "b2": {
        "chainId": 223,
        "factory": "0x5BA2d33fB50d08D7755787E729183FedD6a3F3e7",
        "oracle": "0x3B798263e9eAE3254d86AC30b198F7AA2F82Fd82",
        "fromBlock": 31535305,
        "rpcs": [
            "https://mainnet.b2-rpc.com",
            "https://rpc.bsquared.network",
            "https://b2-mainnet.alt.technology",
            "https://b2-mainnet-public.s.chainbase.com",
        ],
        "explorers": [
            "https://mainnet-blockscout.bsquared.network/api",
            "https://12d6a1773a-backend-blockscout.bsquared.network/api",
            "https://api.routescan.io/v2/network/mainnet/evm/223/etherscan/api",
        ],
    },
    "berachain": {
        "chainId": 80094,
        "factory": "0x2A15CC106bCa1Ee17a411d77A9C53eC3509d47C2",
        "oracle": "0xf5c6664c5b33e3FC16afA43621650652FcD85d65",
        "fromBlock": 19609794,
        "rpcs": [
            "https://rpc.berachain.com",
            "https://berachain-rpc.publicnode.com",
            "https://berachain.drpc.org",
        ],
        "explorers": [
            "https://api.berascan.com/api",
            "https://api.routescan.io/v2/network/mainnet/evm/80094/etherscan/api",
        ],
    },
    "pharos": {
        "chainId": 1672,
        "factory": "0xEDC206E67eAc5C949c0a90A02E29B4b2791c8395",
        "oracle": "0x490df22f542e778fAfAB441beB19d358bE048A20",
        "fromBlock": 5278169,
        "rpcs": ["https://rpc.pharos.xyz"],
        "explorers": [
            "https://pharosscan.xyz/api",
            "https://api.routescan.io/v2/network/mainnet/evm/1672/etherscan/api",
        ],
    },
}

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address","name":"treasurer"},{"type":"uint64","name":"maturity"},
        {"type":"tuple","name":"feeConfig","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
]
GT_ABI = [
    {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address","name":"collateral"},{"type":"address","name":"debtToken"},
        {"type":"address","name":"ft"},{"type":"address","name":"treasurer"},
        {"type":"uint64","name":"maturity"},{"type":"tuple","name":"loanConfig","components":[
            {"type":"address","name":"oracle"},{"type":"uint32","name":"liquidationLtv"},
            {"type":"uint32","name":"maxLtv"},{"type":"bool","name":"liquidatable"}
        ]}
    ]}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"tokenByIndex","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[
        {"type":"address"},{"type":"uint128"},{"type":"bytes"}
    ]},
]
ORACLE_ABI = [
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
    {"type":"function","name":"description","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        if isinstance(value, bytes):
            value = Web3.to_hex(value)
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


def normalize_hex(value: Any) -> str:
    text = value.hex() if hasattr(value, "hex") else str(value)
    return text if text.startswith("0x") else "0x" + text


def topic_address(value: Any) -> str:
    raw = bytes.fromhex(normalize_hex(value)[2:])
    return Web3.to_checksum_address("0x" + raw[-20:].hex())


def explorer_market_logs(cfg: dict[str, Any], latest: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    diagnostics: list[dict[str, Any]] = []
    params = {
        "module": "logs",
        "action": "getLogs",
        "fromBlock": str(cfg["fromBlock"]),
        "toBlock": str(latest),
        "address": cfg["factory"],
        "topic0": CREATE_MARKET_TOPIC,
    }
    for endpoint in cfg["explorers"]:
        try:
            response = requests.get(endpoint, params=params, timeout=45, headers={
                "User-Agent": "ZeroDayBugs-TermMax-ReadOnly/1.0",
                "Accept": "application/json",
            })
            response.raise_for_status()
            payload = response.json()
            result = payload.get("result") if isinstance(payload, dict) else None
            if isinstance(result, list):
                diagnostics.append({"endpoint": endpoint, "ok": True, "count": len(result)})
                return result, diagnostics
            diagnostics.append({"endpoint": endpoint, "ok": False, "payload": payload})
        except Exception as exc:  # noqa: BLE001
            diagnostics.append({"endpoint": endpoint, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    return [], diagnostics


def rpc_market_logs(w3: Web3, cfg: dict[str, Any], latest: int) -> tuple[list[Any], list[dict[str, Any]]]:
    """Small-window fallback used only when explorer APIs are unavailable."""
    diagnostics: list[dict[str, Any]] = []
    found: list[Any] = []
    cursor = cfg["fromBlock"]
    step = 2_000
    max_requests = 2_500
    requests_used = 0
    while cursor <= latest and requests_used < max_requests:
        stop = min(cursor + step - 1, latest)
        try:
            batch = w3.eth.get_logs({
                "address": Web3.to_checksum_address(cfg["factory"]),
                "fromBlock": cursor,
                "toBlock": stop,
                "topics": [CREATE_MARKET_TOPIC],
            })
            found.extend(batch)
            diagnostics.append({"from": cursor, "to": stop, "ok": True, "count": len(batch)})
        except Exception as exc:  # noqa: BLE001
            diagnostics.append({"from": cursor, "to": stop, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
        cursor = stop + 1
        requests_used += 1
    diagnostics.append({"requestsUsed": requests_used, "complete": cursor > latest})
    return found, diagnostics


def market_addresses(logs: list[Any]) -> list[str]:
    addresses: set[str] = set()
    for event in logs:
        topics = event.get("topics", []) if isinstance(event, dict) else event["topics"]
        if len(topics) >= 2 and normalize_hex(topics[0]).lower() == CREATE_MARKET_TOPIC.lower():
            addresses.add(topic_address(topics[1]))
    return sorted(addresses)


def token_row(w3: Web3, address: str, block: int, holder: str | None = None) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    c = w3.eth.contract(address=address, abi=ERC20_ABI)
    row: dict[str, Any] = {
        "address": address,
        "codeBytes": len(w3.eth.get_code(address, block_identifier=block)),
        "symbol": safe(c.functions.symbol().call, block_identifier=block),
        "decimals": safe(c.functions.decimals().call, block_identifier=block),
        "totalSupply": safe(c.functions.totalSupply().call, block_identifier=block),
    }
    if holder:
        row["balanceAtHolder"] = safe(c.functions.balanceOf(Web3.to_checksum_address(holder)).call, block_identifier=block)
    return row


def feed_row(w3: Web3, address: str, block: int, block_timestamp: int) -> dict[str, Any] | None:
    if address.lower() == ZERO.lower():
        return None
    address = Web3.to_checksum_address(address)
    c = w3.eth.contract(address=address, abi=ROUND_ABI)
    round_r = safe(c.functions.latestRoundData().call, block_identifier=block)
    row: dict[str, Any] = {
        "address": address,
        "codeBytes": len(w3.eth.get_code(address, block_identifier=block)),
        "decimals": safe(c.functions.decimals().call, block_identifier=block),
        "description": safe(c.functions.description().call, block_identifier=block),
        "latestRoundData": round_r,
    }
    if round_r.get("ok") and len(round_r["value"]) >= 4:
        answer = int(round_r["value"][1])
        updated_at = int(round_r["value"][3])
        row.update({
            "answer": answer,
            "updatedAt": updated_at,
            "ageSeconds": max(block_timestamp - updated_at, 0) if updated_at else None,
            "currentlyZero": answer == 0,
            "currentlyNegative": answer < 0,
        })
    return row


def oracle_side(w3: Web3, oracle: Any, asset: str, block: int, block_timestamp: int) -> dict[str, Any]:
    asset = Web3.to_checksum_address(asset)
    config_r = safe(oracle.functions.oracles(asset).call, block_identifier=block)
    price_r = safe(oracle.functions.getPrice(asset).call, block_identifier=block)
    row: dict[str, Any] = {"asset": asset, "config": config_r, "getPrice": price_r}
    if config_r.get("ok"):
        aggregator, backup, max_price, min_price, heartbeat, backup_heartbeat = config_r["value"]
        row.update({
            "aggregator": aggregator,
            "backupAggregator": backup,
            "maxPrice": int(max_price),
            "minPrice": int(min_price),
            "heartbeat": int(heartbeat),
            "backupHeartbeat": int(backup_heartbeat),
            "zeroFloor": int(min_price) == 0 and aggregator.lower() != ZERO.lower(),
            "primary": feed_row(w3, aggregator, block, block_timestamp),
            "backup": feed_row(w3, backup, block, block_timestamp),
        })
    return row


def inspect_market(w3: Web3, cfg: dict[str, Any], market_address: str, block: int, block_timestamp: int) -> dict[str, Any]:
    market_address = Web3.to_checksum_address(market_address)
    market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
    tokens_r = safe(market.functions.tokens().call, block_identifier=block)
    config_r = safe(market.functions.config().call, block_identifier=block)
    row: dict[str, Any] = {
        "market": market_address,
        "codeBytes": len(w3.eth.get_code(market_address, block_identifier=block)),
        "tokens": tokens_r,
        "config": config_r,
    }
    if not tokens_r.get("ok"):
        return row
    ft, xt, gt, collateral, debt = tokens_r["value"]
    maturity = None
    if config_r.get("ok"):
        maturity = int(config_r["value"][1])
    row.update({
        "maturity": maturity,
        "maturityUtc": datetime.fromtimestamp(maturity, tz=timezone.utc).isoformat() if maturity else None,
        "active": bool(maturity and maturity > block_timestamp),
        "ft": ft,
        "xt": xt,
        "gt": gt,
        "collateral": token_row(w3, collateral, block, gt),
        "debtToken": token_row(w3, debt, block, gt),
    })
    gt_contract = w3.eth.contract(address=Web3.to_checksum_address(gt), abi=GT_ABI)
    gt_cfg_r = safe(gt_contract.functions.getGtConfig().call, block_identifier=block)
    supply_r = safe(gt_contract.functions.totalSupply().call, block_identifier=block)
    row["gtConfig"] = gt_cfg_r
    row["gtSupply"] = supply_r
    total_debt = 0
    loans: list[dict[str, Any]] = []
    if supply_r.get("ok"):
        count = min(int(supply_r["value"]), 500)
        for index in range(count):
            token_id_r = safe(gt_contract.functions.tokenByIndex(index).call, block_identifier=block)
            if not token_id_r.get("ok"):
                continue
            token_id = int(token_id_r["value"])
            loan_r = safe(gt_contract.functions.loanInfo(token_id).call, block_identifier=block)
            if loan_r.get("ok"):
                debt_raw = int(loan_r["value"][1])
                total_debt += debt_raw
                loans.append({"tokenId": token_id, "debtRaw": debt_raw})
    row["loanCountScanned"] = len(loans)
    row["totalDebtRaw"] = total_debt
    row["loans"] = loans
    oracle_address = cfg["oracle"]
    if gt_cfg_r.get("ok"):
        oracle_address = gt_cfg_r["value"][5][0]
        row["maxLtv"] = int(gt_cfg_r["value"][5][2])
        row["liquidationLtv"] = int(gt_cfg_r["value"][5][1])
    oracle = w3.eth.contract(address=Web3.to_checksum_address(oracle_address), abi=ORACLE_ABI)
    row["oracle"] = oracle_address
    row["collateralOracle"] = oracle_side(w3, oracle, collateral, block, block_timestamp)
    row["debtOracle"] = oracle_side(w3, oracle, debt, block, block_timestamp)
    return row


def main() -> int:
    chain = os.environ["CHAIN"].strip().lower()
    cfg = CHAINS[chain]
    out = Path(os.environ.get("OUT_DIR", "evidence"))
    out.mkdir(parents=True, exist_ok=True)

    w3, rpc, rpc_attempts = connect(cfg)
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    logs, explorer_diag = explorer_market_logs(cfg, latest)
    rpc_diag: list[dict[str, Any]] = []
    if not logs:
        logs, rpc_diag = rpc_market_logs(w3, cfg, latest)
    markets = market_addresses(logs)
    rows = [inspect_market(w3, cfg, address, latest, int(block.timestamp)) for address in markets]

    active_rows = [row for row in rows if row.get("active")]
    zero_floor_sides: list[dict[str, Any]] = []
    for row in active_rows:
        for side in ("collateralOracle", "debtOracle"):
            oracle_row = row.get(side) or {}
            if oracle_row.get("zeroFloor"):
                zero_floor_sides.append({
                    "market": row["market"],
                    "side": side,
                    "asset": oracle_row.get("asset"),
                    "aggregator": oracle_row.get("aggregator"),
                    "currentPrice": oracle_row.get("getPrice"),
                    "totalDebtRaw": row.get("totalDebtRaw"),
                    "gtSupply": (row.get("gtSupply") or {}).get("value") if (row.get("gtSupply") or {}).get("ok") else None,
                })

    result = {
        "schema": "termmax-zero-price-live-binding/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "chain": chain,
        "chainId": cfg["chainId"],
        "rpc": rpc,
        "rpcAttempts": rpc_attempts,
        "block": {
            "number": latest,
            "hash": block.hash.hex(),
            "timestamp": int(block.timestamp),
            "timestampUtc": datetime.fromtimestamp(block.timestamp, tz=timezone.utc).isoformat(),
        },
        "factory": cfg["factory"],
        "oracleAggregator": cfg["oracle"],
        "explorerDiagnostics": explorer_diag,
        "rpcLogDiagnostics": rpc_diag,
        "marketCount": len(rows),
        "activeMarketCount": len(active_rows),
        "zeroFloorActiveSideCount": len(zero_floor_sides),
        "zeroFloorActiveSides": zero_floor_sides,
        "markets": rows,
    }
    summary = {
        "chain": chain,
        "marketCount": len(rows),
        "activeMarketCount": len(active_rows),
        "zeroFloorActiveSideCount": len(zero_floor_sides),
        "currentZeroPriceSideCount": sum(
            1
            for row in active_rows
            for side in ("collateralOracle", "debtOracle")
            if ((row.get(side) or {}).get("getPrice") or {}).get("ok")
            and int((row[side]["getPrice"]["value"])[0]) == 0
        ),
        "materialZeroFloorDebtRaw": sum(int(item.get("totalDebtRaw") or 0) for item in zero_floor_sides),
    }
    (out / "ZERO_PRICE_LIVE_BINDING_FULL.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
