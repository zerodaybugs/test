#!/usr/bin/env python3
"""Read-only B2/WBNB TWAP binding and TermMax exposure scanner.

This program performs public JSON-RPC reads only. It has no signer, private key,
transaction construction, or broadcast capability.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

B2 = Web3.to_checksum_address("0x783c3f003f172c6Ac5AC700218a357d2D66Ee2a2")
WBNB = Web3.to_checksum_address("0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")
DEPLOYED_FEED = Web3.to_checksum_address("0xB4f9b4400942Df49BE77142aDD987c99a6802501")
CURRENT_FACTORY = Web3.to_checksum_address("0x4a34b4cAaA6AD23B95d6ec6394472fbB857eB064")
CURRENT_ORACLE = Web3.to_checksum_address("0x3e3C07Fa1e5255AAab334d5E9ABc61AbF0057F2C")
START_BLOCK = 67_563_000
CURRENT_FACTORY_START = 92_629_573

RPCS = [
    os.environ.get("BSC_RPC_URL", "").strip(),
    "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed.binance.org",
    "https://bsc.drpc.org",
    "https://1rpc.io/bnb",
]
RPCS = [x for x in RPCS if x]

FEED_ABI = [
    {"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"twapPeriod","stateMutability":"view","inputs":[],"outputs":[{"type":"uint32"}]},
    {"type":"function","name":"baseToken","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"quoteToken","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[{"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
ORACLE_ABI = [
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"address","name":"aggregator"},{"type":"address","name":"backupAggregator"},
        {"type":"int256","name":"maxPrice"},{"type":"int256","name":"minPrice"},
        {"type":"uint32","name":"heartbeat"},{"type":"uint32","name":"backupHeartbeat"}
    ]},
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}]}]}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
POOL_ABI = [
    {"type":"function","name":"token0","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"token1","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"fee","stateMutability":"view","inputs":[],"outputs":[{"type":"uint24"}]},
    {"type":"function","name":"liquidity","stateMutability":"view","inputs":[],"outputs":[{"type":"uint128"}]},
    {"type":"function","name":"slot0","stateMutability":"view","inputs":[],"outputs":[{"type":"uint160"},{"type":"int24"},{"type":"uint16"},{"type":"uint16"},{"type":"uint16"},{"type":"uint32"},{"type":"bool"}]},
]

UPDATE_ORACLE_TOPIC = Web3.keccak(text="UpdateOracle(address,address,address,int256,int256,uint32,uint32)").hex()
MARKET_CREATED_TOPIC = Web3.keccak(text="MarketCreated(address,address,address,(address,address,address,address,(address,uint64,(uint32,uint32,uint32,uint32,uint32,uint32)),(address,uint32,uint32,bool),bytes,string,string))").hex()


def jdefault(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if hasattr(value, "items"):
        return dict(value)
    return str(value)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def value(result: dict[str, Any], default: Any = None) -> Any:
    return result.get("value", default) if result.get("ok") else default


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            latest = w3.eth.block_number
            block = w3.eth.get_block(latest)
            if chain_id != 56:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": latest, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address.lower().replace("0x", "")


def chunked_logs(w3: Web3, from_block: int, to_block: int, topics: list[Any], address: str | None = None) -> list[Any]:
    output: list[Any] = []
    sizes = [50_000, 10_000, 2_000]
    cursor = from_block
    size_index = 0
    while cursor <= to_block:
        end = min(to_block, cursor + sizes[size_index] - 1)
        params: dict[str, Any] = {"fromBlock": cursor, "toBlock": end, "topics": topics}
        if address:
            params["address"] = Web3.to_checksum_address(address)
        try:
            output.extend(w3.eth.get_logs(params))
            cursor = end + 1
            size_index = 0
        except Exception:
            if size_index + 1 < len(sizes):
                size_index += 1
                continue
            raise
    return output


def token_meta(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    token = w3.eth.contract(address=address, abi=ERC20_ABI)
    return {
        "address": address,
        "symbol": safe(token.functions.symbol().call, block_identifier=block),
        "decimals": safe(token.functions.decimals().call, block_identifier=block),
        "totalSupply": safe(token.functions.totalSupply().call, block_identifier=block),
    }


def inspect_market(w3: Web3, market_address: str, latest: int, timestamp: int) -> dict[str, Any]:
    market_address = Web3.to_checksum_address(market_address)
    market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
    tokens_r = safe(market.functions.tokens().call, block_identifier=latest)
    config_r = safe(market.functions.config().call, block_identifier=latest)
    paused_r = safe(market.functions.paused().call, block_identifier=latest)
    row: dict[str, Any] = {
        "market": market_address,
        "codeBytes": len(w3.eth.get_code(market_address, block_identifier=latest)),
        "tokens": tokens_r,
        "config": config_r,
        "paused": paused_r,
    }
    tokens = value(tokens_r)
    if not tokens or len(tokens) != 5:
        return row
    ft, xt, gt, collateral, debt = [Web3.to_checksum_address(x) for x in tokens]
    cfg = value(config_r)
    maturity = int(cfg[1]) if cfg else 0
    row.update({
        "ft": token_meta(w3, ft, latest),
        "xt": token_meta(w3, xt, latest),
        "gt": gt,
        "collateral": token_meta(w3, collateral, latest),
        "debtToken": token_meta(w3, debt, latest),
        "maturity": maturity,
        "matured": bool(maturity and timestamp >= maturity),
        "b2IsCollateral": collateral.lower() == B2.lower(),
        "b2IsDebt": debt.lower() == B2.lower(),
    })
    collateral_token = w3.eth.contract(address=collateral, abi=ERC20_ABI)
    debt_token = w3.eth.contract(address=debt, abi=ERC20_ABI)
    ft_token = w3.eth.contract(address=ft, abi=ERC20_ABI)
    row["collateralBalanceAtGt"] = safe(collateral_token.functions.balanceOf(gt).call, block_identifier=latest)
    row["debtBalanceAtMarket"] = safe(debt_token.functions.balanceOf(market_address).call, block_identifier=latest)
    row["ftBalanceAtMarket"] = safe(ft_token.functions.balanceOf(market_address).call, block_identifier=latest)
    return row


def main() -> int:
    w3, rpc, attempts = connect()
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    timestamp = int(block.timestamp)

    feed = w3.eth.contract(address=DEPLOYED_FEED, abi=FEED_ABI)
    feed_state = {
        "address": DEPLOYED_FEED,
        "codeBytes": len(w3.eth.get_code(DEPLOYED_FEED, block_identifier=latest)),
        "pool": safe(feed.functions.pool().call, block_identifier=latest),
        "twapPeriod": safe(feed.functions.twapPeriod().call, block_identifier=latest),
        "baseToken": safe(feed.functions.baseToken().call, block_identifier=latest),
        "quoteToken": safe(feed.functions.quoteToken().call, block_identifier=latest),
        "decimals": safe(feed.functions.decimals().call, block_identifier=latest),
        "latestRoundData": safe(feed.functions.latestRoundData().call, block_identifier=latest),
    }

    pool_state: dict[str, Any] | None = None
    pool_addr = value(feed_state["pool"])
    if pool_addr:
        pool_addr = Web3.to_checksum_address(pool_addr)
        pool = w3.eth.contract(address=pool_addr, abi=POOL_ABI)
        token0 = value(safe(pool.functions.token0().call, block_identifier=latest))
        token1 = value(safe(pool.functions.token1().call, block_identifier=latest))
        pool_state = {
            "address": pool_addr,
            "codeBytes": len(w3.eth.get_code(pool_addr, block_identifier=latest)),
            "token0": token_meta(w3, token0, latest) if token0 else None,
            "token1": token_meta(w3, token1, latest) if token1 else None,
            "fee": safe(pool.functions.fee().call, block_identifier=latest),
            "liquidity": safe(pool.functions.liquidity().call, block_identifier=latest),
            "slot0": safe(pool.functions.slot0().call, block_identifier=latest),
        }
        if token0:
            c0 = w3.eth.contract(address=Web3.to_checksum_address(token0), abi=ERC20_ABI)
            pool_state["token0Balance"] = safe(c0.functions.balanceOf(pool_addr).call, block_identifier=latest)
        if token1:
            c1 = w3.eth.contract(address=Web3.to_checksum_address(token1), abi=ERC20_ABI)
            pool_state["token1Balance"] = safe(c1.functions.balanceOf(pool_addr).call, block_identifier=latest)

    # Discover every OracleAggregator that has ever emitted UpdateOracle for B2.
    oracle_logs = chunked_logs(
        w3,
        START_BLOCK,
        latest,
        [UPDATE_ORACLE_TOPIC, topic_address(B2)],
    )
    oracle_addresses = {CURRENT_ORACLE}
    oracle_events = []
    for log in oracle_logs:
        oracle_addresses.add(Web3.to_checksum_address(log["address"]))
        oracle_events.append({
            "address": Web3.to_checksum_address(log["address"]),
            "blockNumber": int(log["blockNumber"]),
            "transactionHash": log["transactionHash"].hex(),
            "topics": [x.hex() for x in log["topics"]],
            "data": log["data"].hex(),
        })

    oracle_bindings = []
    for address in sorted(oracle_addresses):
        oracle = w3.eth.contract(address=address, abi=ORACLE_ABI)
        cfg_r = safe(oracle.functions.oracles(B2).call, block_identifier=latest)
        price_r = safe(oracle.functions.getPrice(B2).call, block_identifier=latest)
        cfg = value(cfg_r)
        aggregator = Web3.to_checksum_address(cfg[0]) if cfg and int(cfg[0], 16) else None
        backup = Web3.to_checksum_address(cfg[1]) if cfg and int(cfg[1], 16) else None
        oracle_bindings.append({
            "oracleAggregator": address,
            "codeBytes": len(w3.eth.get_code(address, block_identifier=latest)),
            "configuration": cfg_r,
            "getPrice": price_r,
            "usesDeployedFeed": bool(
                (aggregator and aggregator.lower() == DEPLOYED_FEED.lower())
                or (backup and backup.lower() == DEPLOYED_FEED.lower())
            ),
        })

    # Discover all TermMax MarketCreated events where B2 is collateral or debt.
    market_logs: list[Any] = []
    for topic_position in (2, 3):
        topics: list[Any] = [MARKET_CREATED_TOPIC, None, None, None]
        topics[topic_position] = topic_address(B2)
        market_logs.extend(chunked_logs(w3, START_BLOCK, latest, topics))
    # Also collect current-factory markets to detect indirect feed use.
    market_logs.extend(
        chunked_logs(w3, CURRENT_FACTORY_START, latest, [MARKET_CREATED_TOPIC], address=CURRENT_FACTORY)
    )

    markets_by_address: dict[str, dict[str, Any]] = {}
    event_rows = []
    for log in market_logs:
        topics = log["topics"]
        if len(topics) < 4:
            continue
        market_address = Web3.to_checksum_address("0x" + topics[1].hex()[-40:])
        event_rows.append({
            "factory": Web3.to_checksum_address(log["address"]),
            "market": market_address,
            "collateralTopic": Web3.to_checksum_address("0x" + topics[2].hex()[-40:]),
            "debtTopic": Web3.to_checksum_address("0x" + topics[3].hex()[-40:]),
            "blockNumber": int(log["blockNumber"]),
            "transactionHash": log["transactionHash"].hex(),
        })
        markets_by_address.setdefault(market_address.lower(), inspect_market(w3, market_address, latest, timestamp))

    relevant_markets = [
        row for row in markets_by_address.values()
        if row.get("b2IsCollateral") or row.get("b2IsDebt")
    ]
    active_relevant = [
        row for row in relevant_markets
        if not row.get("matured") and value(row.get("paused", {}), False) is not True
    ]
    collateral_exposure_raw = sum(
        int(value(row.get("collateralBalanceAtGt", {}), 0) or 0)
        for row in active_relevant if row.get("b2IsCollateral")
    )
    debt_market_reserve_raw = sum(
        int(value(row.get("debtBalanceAtMarket", {}), 0) or 0)
        for row in active_relevant if row.get("b2IsDebt")
    )

    uses_feed = any(row["usesDeployedFeed"] for row in oracle_bindings)
    verdict = {
        "feedHasCode": feed_state["codeBytes"] > 0,
        "feedBoundInAnyOracleAggregator": uses_feed,
        "b2RelevantMarketCount": len(relevant_markets),
        "activeB2RelevantMarketCount": len(active_relevant),
        "activeB2CollateralRaw": collateral_exposure_raw,
        "activeB2DebtReserveRaw": debt_market_reserve_raw,
        "materialityGate": bool(active_relevant and (collateral_exposure_raw > 0 or debt_market_reserve_raw > 0)),
        "nextStep": (
            "LOCAL_FORK_MANIPULATION_COST_AND_PROFIT_TEST"
            if uses_feed and active_relevant and (collateral_exposure_raw > 0 or debt_market_reserve_raw > 0)
            else "KILL_NO_LIVE_BINDING_OR_EXPOSURE"
        ),
    }

    result = {
        "schema": "termmax-b2-twap-binding/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {
            "number": latest,
            "hash": block.hash.hex(),
            "timestamp": timestamp,
            "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        },
        "feed": feed_state,
        "pool": pool_state,
        "oracleEvents": oracle_events,
        "oracleBindings": oracle_bindings,
        "marketEvents": event_rows,
        "allDiscoveredMarkets": list(markets_by_address.values()),
        "relevantMarkets": relevant_markets,
        "activeRelevantMarkets": active_relevant,
        "verdict": verdict,
    }
    compact = {
        "generatedAtUtc": result["generatedAtUtc"],
        "block": result["block"],
        "feed": feed_state,
        "pool": pool_state,
        "oracleBindings": oracle_bindings,
        "activeRelevantMarkets": active_relevant,
        "verdict": verdict,
    }
    (OUT / "B2_TWAP_BINDING_FULL.json").write_text(json.dumps(result, indent=2, default=jdefault), encoding="utf-8")
    (OUT / "B2_TWAP_BINDING_COMPACT.json").write_text(json.dumps(compact, indent=2, default=jdefault), encoding="utf-8")
    (OUT / "VERDICT.txt").write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    print(json.dumps(compact, indent=2, default=jdefault))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
