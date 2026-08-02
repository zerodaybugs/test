#!/usr/bin/env python3
"""Read-only TermMax cross-chain oracle-floor and active-market exposure probe.

The probe discovers TermMax V2 markets from factory logs, reads each active
market's GT oracle, and tests whether debt/collateral prices can resolve to zero
or are configured without a minimum floor. It never signs, broadcasts, sends,
or simulates a state-changing transaction.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

ZERO = "0x0000000000000000000000000000000000000000"
ORACLE_UPDATE_TOPIC = Web3.keccak(text="UpdateOracle(address,address,address,int256,int256,uint32,uint32)").hex()
MARKET_CREATED_TOPIC = Web3.keccak(
    text=(
        "MarketCreated(address,address,address,"
        "(address,address,address,address,"
        "(address,uint64,(uint32,uint32,uint32,uint32,uint32,uint32)),"
        "(address,uint32,uint32,bool),bytes,string,string))"
    )
).hex()

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
        ],
    },
    "b2": {
        "chainId": 223,
        "factory": "0x5BA2d33fB50d08D7755787E729183FedD6a3F3e7",
        "oracle": "0x3B798263e9eAE3254d86AC30b198F7AA2F82Fd82",
        "fromBlock": 31535305,
        "rpcs": [
            "https://rpc.bsquared.network",
            "https://b2-mainnet.alt.technology",
        ],
    },
    "berachain": {
        "chainId": 80094,
        "factory": "0x2A15CC106bCa1Ee17a411d77A9C53eC3509d47C2",
        "oracle": "0xf5c6664c5b33e3FC16afA43621650652FcD85d65",
        "fromBlock": 19609794,
        "rpcs": [
            "https://berachain-rpc.publicnode.com",
            "https://rpc.berachain.com",
            "https://berachain.drpc.org",
        ],
    },
    "pharos": {
        "chainId": 1672,
        "factory": "0xEDC206E67eAc5C949c0a90A02E29B4b2791c8395",
        "oracle": "0x490df22f542e778fAfAB441beB19d358bE048A20",
        "fromBlock": 5278169,
        "rpcs": [
            "https://rpc.pharos.xyz",
        ],
    },
}

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[
        {"type":"tuple","components":[
            {"type":"address","name":"treasurer"},
            {"type":"uint64","name":"maturity"},
            {"type":"tuple","name":"feeConfig","components":[
                {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},
                {"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
            ]}
        ]}
    ]},
]
GT_ABI = [
    {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[
        {"type":"tuple","components":[
            {"type":"address","name":"collateral"},
            {"type":"address","name":"debtToken"},
            {"type":"address","name":"ft"},
            {"type":"address","name":"treasurer"},
            {"type":"uint64","name":"maturity"},
            {"type":"tuple","name":"loanConfig","components":[
                {"type":"address","name":"oracle"},
                {"type":"uint32","name":"liquidationLtv"},
                {"type":"uint32","name":"maxLtv"},
                {"type":"bool","name":"liquidatable"}
            ]}
        ]}
    ]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"tokenByIndex","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[
        {"type":"address"},{"type":"uint128"},{"type":"bytes"}
    ]},
]
ORACLE_ABI = [
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"address","name":"aggregator"},
        {"type":"address","name":"backupAggregator"},
        {"type":"int256","name":"maxPrice"},
        {"type":"int256","name":"minPrice"},
        {"type":"uint32","name":"heartbeat"},
        {"type":"uint32","name":"backupHeartbeat"}
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
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        elif isinstance(value, (bytes, bytearray)):
            value = Web3.to_hex(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def checksum(value: str) -> str:
    return Web3.to_checksum_address(value)


def topic_address(topic: Any) -> str:
    raw = bytes(topic)
    return checksum("0x" + raw[-20:].hex())


def connect(cfg: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in cfg["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 40}))
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            block = w3.eth.get_block("latest")
            if chain_id != cfg["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def scan_logs(
    w3: Web3,
    address: str,
    start: int,
    end: int,
    topic0: str | None,
) -> tuple[list[Any], list[dict[str, Any]]]:
    rows: list[Any] = []
    diagnostics: list[dict[str, Any]] = []
    cursor = start
    step = 100_000
    min_step = 250
    max_step = 500_000
    while cursor <= end:
        stop = min(cursor + step - 1, end)
        query: dict[str, Any] = {"address": checksum(address), "fromBlock": cursor, "toBlock": stop}
        if topic0:
            query["topics"] = [topic0]
        try:
            batch = w3.eth.get_logs(query)
            rows.extend(batch)
            diagnostics.append({"from": cursor, "to": stop, "ok": True, "count": len(batch), "step": step})
            cursor = stop + 1
            if len(batch) < 100 and step < max_step:
                step = min(step * 2, max_step)
        except Exception as exc:  # noqa: BLE001
            diagnostics.append({
                "from": cursor,
                "to": stop,
                "ok": False,
                "step": step,
                "error": f"{type(exc).__name__}: {exc}",
            })
            if step <= min_step:
                cursor = stop + 1
            else:
                step = max(step // 2, min_step)
    return rows, diagnostics


def code_info(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = checksum(address)
    code = bytes(w3.eth.get_code(address, block_identifier=block))
    return {
        "address": address,
        "codeBytes": len(code),
        "runtimeSha256": hashlib.sha256(code).hexdigest(),
    }


def token_meta(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = checksum(address)
    c = w3.eth.contract(address=address, abi=ERC20_ABI)
    return {
        **code_info(w3, address, block),
        "symbol": safe(c.functions.symbol().call, block_identifier=block),
        "decimals": safe(c.functions.decimals().call, block_identifier=block),
    }


def feed_info(w3: Web3, address: str, block: int, timestamp: int) -> dict[str, Any]:
    address = checksum(address)
    c = w3.eth.contract(address=address, abi=ROUND_ABI)
    latest = safe(c.functions.latestRoundData().call, block_identifier=block)
    row: dict[str, Any] = {
        **code_info(w3, address, block),
        "decimals": safe(c.functions.decimals().call, block_identifier=block),
        "description": safe(c.functions.description().call, block_identifier=block),
        "latestRoundData": latest,
    }
    if latest.get("ok") and len(latest["value"]) >= 4:
        answer = int(latest["value"][1])
        updated = int(latest["value"][3])
        row["answer"] = answer
        row["updatedAt"] = updated
        row["ageSeconds"] = max(timestamp - updated, 0) if updated else None
        row["answerIsNonPositive"] = answer <= 0
    return row


def oracle_side(
    w3: Web3,
    oracle_address: str,
    asset: str,
    block: int,
    timestamp: int,
) -> dict[str, Any]:
    oracle_address = checksum(oracle_address)
    asset = checksum(asset)
    c = w3.eth.contract(address=oracle_address, abi=ORACLE_ABI)
    config = safe(c.functions.oracles(asset).call, block_identifier=block)
    current = safe(c.functions.getPrice(asset).call, block_identifier=block)
    row: dict[str, Any] = {
        "oracle": code_info(w3, oracle_address, block),
        "asset": token_meta(w3, asset, block),
        "config": config,
        "getPrice": current,
    }
    if config.get("ok"):
        agg, backup, max_price, min_price, heartbeat, backup_heartbeat = config["value"]
        row["decodedConfig"] = {
            "aggregator": agg,
            "backupAggregator": backup,
            "maxPrice": int(max_price),
            "minPrice": int(min_price),
            "heartbeat": int(heartbeat),
            "backupHeartbeat": int(backup_heartbeat),
        }
        row["zeroFloor"] = int(min_price) == 0
        row["primaryFeed"] = feed_info(w3, agg, block, timestamp) if agg != ZERO else None
        row["backupFeed"] = feed_info(w3, backup, block, timestamp) if backup != ZERO else None
    else:
        row["decodedConfig"] = None
        row["zeroFloor"] = None
    row["currentPriceIsZero"] = bool(current.get("ok") and int(current["value"][0]) == 0)
    return row


def aggregate_debt(w3: Web3, gt_address: str, block: int) -> dict[str, Any]:
    gt_address = checksum(gt_address)
    gt = w3.eth.contract(address=gt_address, abi=GT_ABI)
    supply_r = safe(gt.functions.totalSupply().call, block_identifier=block)
    if not supply_r.get("ok"):
        return {"totalSupply": supply_r, "debt": 0, "scanned": 0, "truncated": False, "errors": []}
    supply = int(supply_r["value"])
    limit = min(supply, 5000)
    total_debt = 0
    errors: list[str] = []
    for index in range(limit):
        token_id_r = safe(gt.functions.tokenByIndex(index).call, block_identifier=block)
        if not token_id_r.get("ok"):
            errors.append(token_id_r.get("error", "tokenByIndex failed"))
            continue
        loan_r = safe(gt.functions.loanInfo(int(token_id_r["value"])).call, block_identifier=block)
        if not loan_r.get("ok"):
            errors.append(loan_r.get("error", "loanInfo failed"))
            continue
        total_debt += int(loan_r["value"][1])
    return {
        "totalSupply": supply,
        "debt": total_debt,
        "scanned": limit,
        "truncated": supply > limit,
        "errors": errors[:20],
    }


def main() -> int:
    chain = os.environ["CHAIN"].strip().lower()
    cfg = CHAINS[chain]
    out = Path(os.environ.get("OUT_DIR", "evidence"))
    out.mkdir(parents=True, exist_ok=True)

    w3, rpc, rpc_attempts = connect(cfg)
    block = w3.eth.get_block("latest")
    latest = int(block.number)
    timestamp = int(block.timestamp)
    if latest < cfg["fromBlock"]:
        raise RuntimeError(f"latest block {latest} predates configured deployment block {cfg['fromBlock']}")

    oracle_logs, oracle_log_diag = scan_logs(
        w3, cfg["oracle"], cfg["fromBlock"], latest, ORACLE_UPDATE_TOPIC
    )
    assets: set[str] = set()
    for log in oracle_logs:
        if len(log["topics"]) >= 2:
            assets.add(topic_address(log["topics"][1]))

    core_oracles: dict[str, Any] = {}
    for asset in sorted(assets):
        core_oracles[asset.lower()] = oracle_side(
            w3, cfg["oracle"], asset, latest, timestamp
        )

    market_logs, market_log_diag = scan_logs(
        w3, cfg["factory"], cfg["fromBlock"], latest, MARKET_CREATED_TOPIC
    )
    candidates: dict[str, dict[str, Any]] = {}
    for log in market_logs:
        if len(log["topics"]) >= 4:
            market = topic_address(log["topics"][1])
            candidates[market.lower()] = {
                "market": market,
                "eventCollateral": topic_address(log["topics"][2]),
                "eventDebtToken": topic_address(log["topics"][3]),
                "createdBlock": int(log["blockNumber"]),
                "txHash": log["transactionHash"].hex(),
            }

    markets: list[dict[str, Any]] = []
    active_flags: list[dict[str, Any]] = []
    for candidate in candidates.values():
        market_address = candidate["market"]
        market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
        tokens_r = safe(market.functions.tokens().call, block_identifier=latest)
        config_r = safe(market.functions.config().call, block_identifier=latest)
        row: dict[str, Any] = {**candidate, "tokens": tokens_r, "config": config_r}
        if not tokens_r.get("ok") or not config_r.get("ok"):
            row["validMarket"] = False
            markets.append(row)
            continue

        ft, xt, gt_address, collateral, debt_token = tokens_r["value"]
        maturity = int(config_r["value"][1])
        active = maturity > timestamp
        row.update({
            "validMarket": True,
            "active": active,
            "maturity": maturity,
            "maturityUtc": datetime.fromtimestamp(maturity, tz=timezone.utc).isoformat(),
            "ft": ft,
            "xt": xt,
            "gt": gt_address,
            "collateral": token_meta(w3, collateral, latest),
            "debtToken": token_meta(w3, debt_token, latest),
        })

        gt = w3.eth.contract(address=checksum(gt_address), abi=GT_ABI)
        gt_config_r = safe(gt.functions.getGtConfig().call, block_identifier=latest)
        row["gtConfig"] = gt_config_r
        row["exposure"] = aggregate_debt(w3, gt_address, latest)
        if gt_config_r.get("ok"):
            loan_config = gt_config_r["value"][5]
            oracle_address = loan_config[0]
            row["loanConfig"] = {
                "oracle": oracle_address,
                "liquidationLtv": int(loan_config[1]),
                "maxLtv": int(loan_config[2]),
                "liquidatable": bool(loan_config[3]),
            }
            row["collateralOracle"] = oracle_side(
                w3, oracle_address, collateral, latest, timestamp
            )
            row["debtOracle"] = oracle_side(
                w3, oracle_address, debt_token, latest, timestamp
            )
            if active:
                flags = {
                    "market": market_address,
                    "gt": gt_address,
                    "debt": row["exposure"]["debt"],
                    "debtZeroFloor": row["debtOracle"].get("zeroFloor"),
                    "debtCurrentPriceZero": row["debtOracle"].get("currentPriceIsZero"),
                    "collateralZeroFloor": row["collateralOracle"].get("zeroFloor"),
                    "collateralCurrentPriceZero": row["collateralOracle"].get("currentPriceIsZero"),
                    "oracleConfigReadable": bool(
                        row["debtOracle"]["config"].get("ok")
                        and row["collateralOracle"]["config"].get("ok")
                    ),
                }
                flags["criticalCandidate"] = bool(
                    flags["debt"] > 0
                    and (flags["debtZeroFloor"] is True or flags["debtCurrentPriceZero"] is True)
                )
                active_flags.append(flags)
        markets.append(row)

    result = {
        "schema": "termmax-crosschain-oracle-floor-probe/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "chain": chain,
        "chainId": cfg["chainId"],
        "rpc": rpc,
        "rpcAttempts": rpc_attempts,
        "block": {
            "number": latest,
            "hash": block.hash.hex(),
            "timestamp": timestamp,
            "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        },
        "factory": code_info(w3, cfg["factory"], latest),
        "coreOracle": code_info(w3, cfg["oracle"], latest),
        "oracleLogDiagnostics": oracle_log_diag,
        "marketLogDiagnostics": market_log_diag,
        "coreOracleAssets": core_oracles,
        "markets": markets,
        "activeMarketFlags": active_flags,
        "summary": {
            "configuredOracleAssets": len(core_oracles),
            "zeroFloorCoreAssets": sum(1 for x in core_oracles.values() if x.get("zeroFloor") is True),
            "marketEvents": len(candidates),
            "validMarkets": sum(1 for x in markets if x.get("validMarket")),
            "activeMarkets": sum(1 for x in markets if x.get("active")),
            "activeDebtZeroFloorMarkets": sum(1 for x in active_flags if x.get("debtZeroFloor") is True),
            "activeDebtZeroPriceMarkets": sum(1 for x in active_flags if x.get("debtCurrentPriceZero") is True),
            "criticalCandidates": sum(1 for x in active_flags if x.get("criticalCandidate")),
        },
    }
    (out / "CROSSCHAIN_ORACLE_FLOOR_FULL.json").write_text(
        json.dumps(result, indent=2, default=str), encoding="utf-8"
    )
    (out / "SUMMARY.json").write_text(
        json.dumps(result["summary"], indent=2), encoding="utf-8"
    )
    (out / "ACTIVE_MARKET_FLAGS.json").write_text(
        json.dumps(active_flags, indent=2), encoding="utf-8"
    )
    print(json.dumps(result["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
