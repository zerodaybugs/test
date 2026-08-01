#!/usr/bin/env python3
"""Read-only TermMax active-market ERC4626 oracle/redeem-gap scanner.

The scanner reads public Ethereum state only. It discovers current TermMax V2
markets and factory-created price feeds, identifies TermMaxERC4626PriceFeed
bindings, and compares convertToAssets() with previewRedeem(). It has no signer,
private key, transaction construction, or broadcast capability.
"""
from __future__ import annotations

import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

CHAIN_ID = 1
FACTORY = Web3.to_checksum_address("0xc1E9640F04B802Bbf0B02a4e9Fe394039AbE8B59")
PRICE_FEED_FACTORY = Web3.to_checksum_address("0xFD9B5ee419C56f5ED3E86ba70953342906a7dE2B")
START_BLOCK = 24_883_366

RPCS = [
    os.environ.get("ETH_RPC_URL", "").strip(),
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://rpc.mevblocker.io",
    "https://eth.llamarpc.com",
]
RPCS = [x for x in RPCS if x]

MARKET_CREATED_TOPIC = Web3.keccak(
    text="MarketCreated(address,address,address,(address,address,address,address,(address,uint64,(uint32,uint32,uint32,uint32,uint32,uint32)),(address,uint32,uint32,bool),bytes,string,string))"
).hex()
PRICE_FEED_CREATED_TOPIC = Web3.keccak(text="PriceFeedCreated(address)").hex()

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
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
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
ORACLE_V1_ABI = [
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"address","name":"aggregator"},{"type":"address","name":"backupAggregator"},{"type":"uint32","name":"heartbeat"}
    ]},
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
ORACLE_V2_ABI = [
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"address","name":"aggregator"},{"type":"address","name":"backupAggregator"},
        {"type":"int256","name":"maxPrice"},{"type":"int256","name":"minPrice"},
        {"type":"uint32","name":"heartbeat"},{"type":"uint32","name":"backupHeartbeat"}
    ]},
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
FEED_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"assetPriceFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[
        {"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}
    ]},
]
VAULT_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]


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
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 40}))
            chain_id = w3.eth.chain_id
            block = w3.eth.get_block("latest")
            if chain_id != CHAIN_ID:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def direct_logs(url: str, address: str, start: int, end: int) -> tuple[list[Any], dict[str, Any]]:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 50}))
    output: list[Any] = []
    cursor = start
    sizes = [50_000, 10_000, 2_000, 500]
    size_index = 0
    requests_count = 0
    while cursor <= end:
        last = min(end, cursor + sizes[size_index] - 1)
        try:
            output.extend(w3.eth.get_logs({"address": address, "fromBlock": cursor, "toBlock": last}))
            cursor = last + 1
            size_index = 0
            requests_count += 1
        except Exception:
            if size_index + 1 < len(sizes):
                size_index += 1
                continue
            raise
    return output, {"transport": "rpc", "url": url, "requestCount": requests_count, "rowCount": len(output)}


def routescan_logs(address: str, start: int, end: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    endpoint = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
    rows_all: list[dict[str, Any]] = []
    page = 1
    while True:
        params = {
            "module": "logs", "action": "getLogs", "address": address,
            "fromBlock": start, "toBlock": end, "page": page, "offset": 1000,
        }
        payload: Any = None
        last_error: Exception | None = None
        for attempt in range(7):
            try:
                response = requests.get(endpoint, params=params, timeout=60, headers={"User-Agent":"ZeroDayBugs-TermMax-Readonly/3"})
                if response.status_code == 429:
                    time.sleep(1.5 * (attempt + 1)); continue
                response.raise_for_status()
                payload = response.json(); break
            except Exception as exc:  # noqa: BLE001
                last_error = exc; time.sleep(1.25 * (attempt + 1))
        if payload is None:
            raise RuntimeError(f"Routescan failed: {last_error}")
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            if "No" in rows or "not found" in rows.lower():
                break
            raise RuntimeError(f"unexpected Routescan response: {payload}")
        if not rows:
            break
        rows_all.extend(rows)
        if len(rows) < 1000:
            break
        page += 1
        time.sleep(0.25)
    return rows_all, {"transport":"routescan","endpoint":endpoint,"pageCount":page,"rowCount":len(rows_all)}


def all_logs(address: str, start: int, end: int) -> tuple[list[Any], list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            rows, diag = direct_logs(url, address, start, end)
            attempts.append({"ok": True, **diag})
            return rows, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"ok": False, "transport":"rpc", "url":url, "error":f"{type(exc).__name__}: {exc}"})
    try:
        rows, diag = routescan_logs(address, start, end)
        attempts.append({"ok": True, **diag})
        return rows, attempts
    except Exception as exc:  # noqa: BLE001
        attempts.append({"ok": False, "transport":"routescan", "error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def topic_hex(topic: Any) -> str:
    raw = topic.hex() if hasattr(topic, "hex") else str(topic)
    return raw if raw.startswith("0x") else "0x" + raw


def topic_address(topic: Any) -> str:
    return Web3.to_checksum_address("0x" + topic_hex(topic)[-40:])


def token_meta(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    token = w3.eth.contract(address=address, abi=ERC20_ABI)
    return {
        "address": address,
        "codeBytes": len(w3.eth.get_code(address, block_identifier=block)),
        "symbol": safe(token.functions.symbol().call, block_identifier=block),
        "name": safe(token.functions.name().call, block_identifier=block),
        "decimals": safe(token.functions.decimals().call, block_identifier=block),
        "totalSupply": safe(token.functions.totalSupply().call, block_identifier=block),
    }


def inspect_feed(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    feed = w3.eth.contract(address=address, abi=FEED_ABI)
    asset_r = safe(feed.functions.asset().call, block_identifier=block)
    underlying_feed_r = safe(feed.functions.assetPriceFeed().call, block_identifier=block)
    row: dict[str, Any] = {
        "address": address,
        "codeBytes": len(w3.eth.get_code(address, block_identifier=block)),
        "asset": asset_r,
        "assetPriceFeed": underlying_feed_r,
        "decimals": safe(feed.functions.decimals().call, block_identifier=block),
        "latestRoundData": safe(feed.functions.latestRoundData().call, block_identifier=block),
        "isERC4626Feed": bool(asset_r.get("ok") and underlying_feed_r.get("ok")),
    }
    vault_addr = value(asset_r)
    if not row["isERC4626Feed"] or not vault_addr:
        return row
    vault_addr = Web3.to_checksum_address(vault_addr)
    vault = w3.eth.contract(address=vault_addr, abi=VAULT_ABI)
    decimals_r = safe(vault.functions.decimals().call, block_identifier=block)
    decimals = int(value(decimals_r, 18) or 18)
    unit = 10 ** decimals
    convert_r = safe(vault.functions.convertToAssets(unit).call, block_identifier=block)
    preview_r = safe(vault.functions.previewRedeem(unit).call, block_identifier=block)
    convert = int(value(convert_r, 0) or 0)
    preview = int(value(preview_r, 0) or 0)
    gap = max(convert - preview, 0)
    gap_bps = (gap * 10_000 // convert) if convert else 0
    underlying_r = safe(vault.functions.asset().call, block_identifier=block)
    row["vault"] = {
        "address": vault_addr,
        "meta": token_meta(w3, vault_addr, block),
        "underlying": underlying_r,
        "underlyingMeta": token_meta(w3, value(underlying_r), block) if value(underlying_r) else None,
        "decimals": decimals_r,
        "unitShares": unit,
        "totalSupply": safe(vault.functions.totalSupply().call, block_identifier=block),
        "totalAssets": safe(vault.functions.totalAssets().call, block_identifier=block),
        "convertToAssetsUnit": convert_r,
        "previewRedeemUnit": preview_r,
        "redeemGapRaw": gap,
        "redeemGapBps": gap_bps,
    }
    return row


def oracle_binding(w3: Web3, oracle_addr: str, asset: str, block: int) -> dict[str, Any]:
    oracle_addr = Web3.to_checksum_address(oracle_addr)
    asset = Web3.to_checksum_address(asset)
    v2 = w3.eth.contract(address=oracle_addr, abi=ORACLE_V2_ABI)
    cfg_v2 = safe(v2.functions.oracles(asset).call, block_identifier=block)
    if cfg_v2.get("ok"):
        cfg = value(cfg_v2)
        return {
            "version": "v2", "address": oracle_addr, "configuration": cfg_v2,
            "primary": Web3.to_checksum_address(cfg[0]),
            "backup": Web3.to_checksum_address(cfg[1]),
            "getPrice": safe(v2.functions.getPrice(asset).call, block_identifier=block),
        }
    v1 = w3.eth.contract(address=oracle_addr, abi=ORACLE_V1_ABI)
    cfg_v1 = safe(v1.functions.oracles(asset).call, block_identifier=block)
    if cfg_v1.get("ok"):
        cfg = value(cfg_v1)
        return {
            "version": "v1", "address": oracle_addr, "configuration": cfg_v1,
            "primary": Web3.to_checksum_address(cfg[0]),
            "backup": Web3.to_checksum_address(cfg[1]),
            "getPrice": safe(v1.functions.getPrice(asset).call, block_identifier=block),
        }
    return {"version":"unknown","address":oracle_addr,"v2Error":cfg_v2,"v1Error":cfg_v1}


def inspect_market(w3: Web3, market_addr: str, event_collateral: str, event_debt: str, block: int, timestamp: int, feeds: dict[str, dict[str, Any]]) -> dict[str, Any]:
    market_addr = Web3.to_checksum_address(market_addr)
    market = w3.eth.contract(address=market_addr, abi=MARKET_ABI)
    tokens_r = safe(market.functions.tokens().call, block_identifier=block)
    config_r = safe(market.functions.config().call, block_identifier=block)
    row: dict[str, Any] = {
        "market": market_addr,
        "eventCollateral": event_collateral,
        "eventDebtToken": event_debt,
        "codeBytes": len(w3.eth.get_code(market_addr, block_identifier=block)),
        "tokens": tokens_r,
        "config": config_r,
        "paused": safe(market.functions.paused().call, block_identifier=block),
    }
    tokens = value(tokens_r)
    cfg = value(config_r)
    if not tokens or len(tokens) != 5 or not cfg:
        return row
    ft, xt, gt, collateral, debt = [Web3.to_checksum_address(x) for x in tokens]
    maturity = int(cfg[1])
    row.update({
        "ft": token_meta(w3, ft, block),
        "xt": token_meta(w3, xt, block),
        "gt": token_meta(w3, gt, block),
        "collateral": token_meta(w3, collateral, block),
        "debtToken": token_meta(w3, debt, block),
        "maturity": maturity,
        "maturityUtc": datetime.fromtimestamp(maturity, tz=timezone.utc).isoformat(),
        "active": timestamp < maturity,
    })
    collateral_token = w3.eth.contract(address=collateral, abi=ERC20_ABI)
    row["collateralBalanceAtGt"] = safe(collateral_token.functions.balanceOf(gt).call, block_identifier=block)
    gt_contract = w3.eth.contract(address=gt, abi=GT_ABI)
    gt_cfg_r = safe(gt_contract.functions.getGtConfig().call, block_identifier=block)
    row["gtConfig"] = gt_cfg_r
    gt_cfg = value(gt_cfg_r)
    if not gt_cfg:
        return row
    loan_cfg = gt_cfg[5]
    oracle_addr = Web3.to_checksum_address(loan_cfg[0])
    row["maxLtv"] = int(loan_cfg[2])
    row["liquidationLtv"] = int(loan_cfg[1])
    row["liquidatable"] = bool(loan_cfg[3])
    coll_binding = oracle_binding(w3, oracle_addr, collateral, block)
    debt_binding = oracle_binding(w3, oracle_addr, debt, block)
    row["collateralOracle"] = coll_binding
    row["debtOracle"] = debt_binding
    bound: list[dict[str, Any]] = []
    for side, binding in (("primary", coll_binding.get("primary")), ("backup", coll_binding.get("backup"))):
        if not binding:
            continue
        feed = feeds.get(binding.lower())
        if feed and feed.get("isERC4626Feed"):
            gap_bps = int(feed.get("vault", {}).get("redeemGapBps", 0) or 0)
            max_ltv = int(row["maxLtv"])
            # Overvaluation-induced unbacked fraction at max LTV, in 1e8 ratio units.
            overvaluation_ratio_1e8 = gap_bps * 10_000
            gross_borrow_ratio_1e8 = max_ltv
            effective_redeem_value_ratio_1e8 = 100_000_000 - overvaluation_ratio_1e8
            theoretical_bad_debt_ratio_1e8 = max(gross_borrow_ratio_1e8 - effective_redeem_value_ratio_1e8, 0)
            bound.append({
                "side": side,
                "feed": binding,
                "feedDetails": feed,
                "redeemGapBps": gap_bps,
                "maxLtv1e8": max_ltv,
                "theoreticalBadDebtRatio1e8": theoretical_bad_debt_ratio_1e8,
            })
    row["erc4626OracleBindings"] = bound
    return row


def main() -> int:
    w3, rpc, rpc_attempts = connect()
    block = w3.eth.get_block("latest")
    latest = int(block.number)
    timestamp = int(block.timestamp)

    factory_logs, factory_log_attempts = all_logs(FACTORY, START_BLOCK, latest)
    feed_logs, feed_log_attempts = all_logs(PRICE_FEED_FACTORY, START_BLOCK, latest)

    market_topic_counts: Counter[str] = Counter()
    market_events: dict[str, dict[str, Any]] = {}
    for log in factory_logs:
        topics = log["topics"] if isinstance(log, dict) else log.topics
        t0 = topic_hex(topics[0]) if topics else ""
        market_topic_counts[t0] += 1
        if t0.lower() != MARKET_CREATED_TOPIC.lower() or len(topics) < 4:
            continue
        market = topic_address(topics[1])
        market_events[market.lower()] = {
            "market": market,
            "collateral": topic_address(topics[2]),
            "debtToken": topic_address(topics[3]),
            "blockNumber": int(log["blockNumber"]),
            "transactionHash": topic_hex(log["transactionHash"]),
        }

    feed_topic_counts: Counter[str] = Counter()
    feed_addresses: set[str] = set()
    feed_events: list[dict[str, Any]] = []
    for log in feed_logs:
        topics = log["topics"] if isinstance(log, dict) else log.topics
        t0 = topic_hex(topics[0]) if topics else ""
        feed_topic_counts[t0] += 1
        if t0.lower() != PRICE_FEED_CREATED_TOPIC.lower() or len(topics) < 2:
            continue
        feed = topic_address(topics[1])
        feed_addresses.add(feed)
        feed_events.append({
            "feed": feed,
            "blockNumber": int(log["blockNumber"]),
            "transactionHash": topic_hex(log["transactionHash"]),
        })

    feed_rows = [inspect_feed(w3, address, latest) for address in sorted(feed_addresses)]
    feed_map = {row["address"].lower(): row for row in feed_rows}
    market_rows = [
        inspect_market(w3, row["market"], row["collateral"], row["debtToken"], latest, timestamp, feed_map)
        for row in market_events.values()
    ]
    active = [row for row in market_rows if row.get("active")]
    bound = [row for row in active if row.get("erc4626OracleBindings")]
    positive_gap = [
        row for row in bound
        if any(int(x.get("redeemGapBps", 0) or 0) > 0 for x in row.get("erc4626OracleBindings", []))
    ]
    bad_debt_capable = [
        row for row in positive_gap
        if any(int(x.get("theoreticalBadDebtRatio1e8", 0) or 0) > 0 for x in row.get("erc4626OracleBindings", []))
    ]

    verdict = {
        "marketEventCount": len(market_events),
        "activeMarketCount": len(active),
        "priceFeedEventCount": len(feed_addresses),
        "erc4626PriceFeedCount": sum(1 for row in feed_rows if row.get("isERC4626Feed")),
        "activeERC4626BoundMarketCount": len(bound),
        "activePositiveRedeemGapMarketCount": len(positive_gap),
        "activeBadDebtCapableRedeemGapMarketCount": len(bad_debt_capable),
        "nextStep": "PINNED_FORK_PROFIT_TEST" if bad_debt_capable else "KILL_OR_HOLD_NO_LIVE_BAD_DEBT_CAPABLE_BINDING",
    }
    result = {
        "schema": "termmax-erc4626-oracle-redeem-gap/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "rpc": rpc,
        "rpcAttempts": rpc_attempts,
        "block": {
            "number": latest, "hash": block.hash.hex(), "timestamp": timestamp,
            "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        },
        "factory": FACTORY,
        "priceFeedFactory": PRICE_FEED_FACTORY,
        "topics": {"marketCreated": MARKET_CREATED_TOPIC, "priceFeedCreated": PRICE_FEED_CREATED_TOPIC},
        "factoryLogAttempts": factory_log_attempts,
        "feedLogAttempts": feed_log_attempts,
        "factoryTopicCounts": dict(market_topic_counts),
        "feedTopicCounts": dict(feed_topic_counts),
        "marketEvents": list(market_events.values()),
        "feedEvents": feed_events,
        "feeds": feed_rows,
        "markets": market_rows,
        "activeMarkets": active,
        "activeERC4626BoundMarkets": bound,
        "activePositiveRedeemGapMarkets": positive_gap,
        "activeBadDebtCapableRedeemGapMarkets": bad_debt_capable,
        "verdict": verdict,
    }
    compact = {
        "generatedAtUtc": result["generatedAtUtc"],
        "block": result["block"],
        "factoryLogAttempts": factory_log_attempts,
        "feedLogAttempts": feed_log_attempts,
        "factoryTopicCounts": dict(market_topic_counts),
        "feedTopicCounts": dict(feed_topic_counts),
        "activeERC4626BoundMarkets": bound,
        "activePositiveRedeemGapMarkets": positive_gap,
        "activeBadDebtCapableRedeemGapMarkets": bad_debt_capable,
        "verdict": verdict,
    }
    (OUT / "ERC4626_ORACLE_REDEEM_GAP_FULL.json").write_text(json.dumps(result, indent=2, default=jdefault), encoding="utf-8")
    (OUT / "ERC4626_ORACLE_REDEEM_GAP_COMPACT.json").write_text(json.dumps(compact, indent=2, default=jdefault), encoding="utf-8")
    (OUT / "VERDICT.txt").write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    print(json.dumps(compact, indent=2, default=jdefault))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
