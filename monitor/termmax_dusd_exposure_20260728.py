#!/usr/bin/env python3
"""Read-only TermMax DUSD/Makina exposure inventory on Ethereum.

The monitor enumerates all known TermMax V2 MarketCreated events, filters DUSD
markets, reconstructs order liquidity and active oracle configuration, and
records the current Makina share-price chain. It performs no state-changing
call and contains no signer or transaction-broadcast functionality.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hexbytes import HexBytes
from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

DUSD = Web3.to_checksum_address("0x1e33E98aF620F1D563fcD3cfd3C75acE841204ef")
DUSD_ADAPTER = Web3.to_checksum_address("0x458e718fF8687b6eBF2dE22AeBa13f2d2d50a537")
MAKINA_ORACLE = Web3.to_checksum_address("0xFFCBc7A7eEF2796C277095C66067aC749f4cA078")
CURRENT_ORACLE_AGGREGATOR = Web3.to_checksum_address("0x16110F65047a46D39FFEB3dadd61ed33ec9FaBC2")

FACTORIES = [
    (Web3.to_checksum_address("0xF2BDa87CA467eB90A1b68f824cB136baA68a8177"), 23_430_000, "legacy-v2-a"),
    (Web3.to_checksum_address("0x5b8B26a6734B5eABDBe6C5A19580Ab2D0424f027"), 23_430_000, "legacy-v2-b"),
    (Web3.to_checksum_address("0xc1E9640F04B802Bbf0B02a4e9Fe394039AbE8B59"), 24_883_366, "current-v2"),
]

RPC_URLS = [
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
]

MARKET_CREATED_TOPIC = "0x" + Web3.keccak(
    text="MarketCreated(address,address,address,(address,address,address,address,(address,uint64,(uint32,uint32,uint32,uint32,uint32,uint32)),(address,uint32,uint32,bool),bytes,string,string))"
).hex()
CREATE_ORDER_TOPIC = "0x" + Web3.keccak(text="CreateOrder(address,address)").hex()
UPDATE_ORACLE_TOPIC = "0x" + Web3.keccak(text="UpdateOracle(address,address,address,int256,int256,uint32,uint32)").hex()

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}]}]}]},
]
GT_ABI = [
    {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"address"},{"type":"uint32"},{"type":"uint32"},{"type":"bool"}]}]}]},
]
ORDER_ABI = [
    {"type":"function","name":"tokenReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"orderExpiryTimestamp","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
ORACLE_AGGREGATOR_ABI = [
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address"},{"type":"address"},{"type":"int256"},{"type":"int256"},{"type":"uint32"},{"type":"uint32"}]},
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
ADAPTER_ABI = [
    {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[{"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"dusdOracle","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
MAKINA_ORACLE_ABI = [
    {"type":"function","name":"getSharePrice","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"shareOwner","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"description","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]
SHARE_OWNER_ABI = [
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"lastTotalAum","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"machine","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]


def default(value: Any) -> Any:
    if isinstance(value, (HexBytes, bytes, bytearray)):
        return "0x" + bytes(value).hex()
    return str(value)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        return {"ok": True, "value": list(value) if isinstance(value, tuple) else value}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def val(result: dict[str, Any], fallback: Any = None) -> Any:
    return result.get("value", fallback) if result.get("ok") else fallback


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts = []
    for url in RPC_URLS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 45}))
            chain_id = w3.eth.chain_id
            latest = w3.eth.block_number
            block = w3.eth.get_block(latest)
            if chain_id != 1:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": latest, "hash": "0x" + bytes(block.hash).hex()})
            return w3, url, attempts
        except Exception as exc:
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def topic_address(value: Any) -> str:
    raw = HexBytes(value).hex()
    raw = raw[2:] if raw.startswith("0x") else raw
    return Web3.to_checksum_address("0x" + raw[-40:])


def rpc_logs(w3: Web3, address: str, topic0: str, start: int, end: int, step_hint: int = 100_000) -> list[Any]:
    output: list[Any] = []
    cursor = int(start)
    while cursor <= end:
        step = step_hint
        rows = None
        while rows is None:
            window_end = min(end, cursor + step - 1)
            try:
                rows = w3.eth.get_logs({"address": address, "topics": [topic0], "fromBlock": cursor, "toBlock": window_end})
            except Exception:
                if step <= 1_000:
                    raise
                step = max(1_000, step // 2)
        output.extend(rows)
        cursor = min(end, cursor + step - 1) + 1
    return output


def token_meta(w3: Web3, token: str, block: int) -> dict[str, Any]:
    contract = w3.eth.contract(address=token, abi=ERC20_ABI)
    return {
        "address": token,
        "symbol": safe(contract.functions.symbol().call, block_identifier=block),
        "name": safe(contract.functions.name().call, block_identifier=block),
        "decimals": safe(contract.functions.decimals().call, block_identifier=block),
        "totalSupply": safe(contract.functions.totalSupply().call, block_identifier=block),
    }


def discover_markets(w3: Web3, latest: int) -> list[dict[str, Any]]:
    output = []
    for factory, start, label in FACTORIES:
        try:
            rows = rpc_logs(w3, factory, MARKET_CREATED_TOPIC, start, latest)
            for row in rows:
                topics = row["topics"]
                if len(topics) < 4:
                    continue
                output.append({
                    "factory": factory,
                    "factoryLabel": label,
                    "market": topic_address(topics[1]),
                    "collateral": topic_address(topics[2]),
                    "debtToken": topic_address(topics[3]),
                    "blockNumber": int(row["blockNumber"]),
                    "transactionHash": "0x" + bytes(row["transactionHash"]).hex(),
                })
        except Exception as exc:
            output.append({"factory": factory, "factoryLabel": label, "discoveryError": f"{type(exc).__name__}: {exc}"})
    return output


def inspect_market(w3: Web3, row: dict[str, Any], block: int, timestamp: int) -> dict[str, Any]:
    market_address = row["market"]
    market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
    result = dict(row)
    result["tokens"] = safe(market.functions.tokens().call, block_identifier=block)
    result["config"] = safe(market.functions.config().call, block_identifier=block)
    tokens = val(result["tokens"])
    if not tokens:
        return result
    ft, xt, gt, collateral, debt = [Web3.to_checksum_address(item) for item in tokens]
    result["addresses"] = {"ft": ft, "xt": xt, "gt": gt, "collateral": collateral, "debtToken": debt}
    result["ftMeta"] = token_meta(w3, ft, block)
    result["xtMeta"] = token_meta(w3, xt, block)
    result["collateralMeta"] = token_meta(w3, collateral, block)
    result["debtMeta"] = token_meta(w3, debt, block)
    gt_contract = w3.eth.contract(address=gt, abi=GT_ABI)
    result["gtConfig"] = safe(gt_contract.functions.getGtConfig().call, block_identifier=block)
    cfg = val(result["config"])
    maturity = int(cfg[1]) if cfg else 0
    result["maturity"] = maturity
    result["matured"] = bool(maturity and timestamp >= maturity)

    order_rows = rpc_logs(w3, market_address, CREATE_ORDER_TOPIC, row["blockNumber"], block)
    orders = []
    for event in order_rows:
        if len(event["topics"]) < 3:
            continue
        maker = topic_address(event["topics"][1])
        order_address = topic_address(event["topics"][2])
        order = w3.eth.contract(address=order_address, abi=ORDER_ABI)
        token_contracts = {
            "ft": w3.eth.contract(address=ft, abi=ERC20_ABI),
            "xt": w3.eth.contract(address=xt, abi=ERC20_ABI),
            "debt": w3.eth.contract(address=debt, abi=ERC20_ABI),
            "collateral": w3.eth.contract(address=collateral, abi=ERC20_ABI),
        }
        balances = {
            name: safe(contract.functions.balanceOf(order_address).call, block_identifier=block)
            for name, contract in token_contracts.items()
        }
        orders.append({
            "order": order_address,
            "maker": maker,
            "createdBlock": int(event["blockNumber"]),
            "transactionHash": "0x" + bytes(event["transactionHash"]).hex(),
            "tokenReserves": safe(order.functions.tokenReserves().call, block_identifier=block),
            "expiry": safe(order.functions.orderExpiryTimestamp().call, block_identifier=block),
            "balances": balances,
        })
    result["orders"] = orders
    result["liquidity"] = {
        "orderCount": len(orders),
        "debtBalanceRaw": sum(int(val(order["balances"]["debt"], 0) or 0) for order in orders),
        "ftBalanceRaw": sum(int(val(order["balances"]["ft"], 0) or 0) for order in orders),
        "xtBalanceRaw": sum(int(val(order["balances"]["xt"], 0) or 0) for order in orders),
        "collateralBalanceRaw": sum(int(val(order["balances"]["collateral"], 0) or 0) for order in orders),
    }
    return result


def main() -> int:
    w3, rpc, attempts = connect()
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    timestamp = int(block.timestamp)

    all_markets = discover_markets(w3, latest)
    dusd_rows = [
        row for row in all_markets
        if row.get("market") and (row.get("collateral", "").lower() == DUSD.lower() or row.get("debtToken", "").lower() == DUSD.lower())
    ]
    inspected = [inspect_market(w3, row, latest, timestamp) for row in dusd_rows]

    unique_aggregators = {CURRENT_ORACLE_AGGREGATOR.lower(): CURRENT_ORACLE_AGGREGATOR}
    for market in inspected:
        gt_cfg = val(market.get("gtConfig", {}))
        if gt_cfg and len(gt_cfg) > 5:
            oracle_address = Web3.to_checksum_address(gt_cfg[5][0])
            unique_aggregators[oracle_address.lower()] = oracle_address

    aggregators = []
    for address in unique_aggregators.values():
        contract = w3.eth.contract(address=address, abi=ORACLE_AGGREGATOR_ABI)
        aggregators.append({
            "address": address,
            "codeBytes": len(w3.eth.get_code(address, block_identifier=latest)),
            "dusdOracleConfig": safe(contract.functions.oracles(DUSD).call, block_identifier=latest),
            "dusdPrice": safe(contract.functions.getPrice(DUSD).call, block_identifier=latest),
        })

    adapter = w3.eth.contract(address=DUSD_ADAPTER, abi=ADAPTER_ABI)
    makina = w3.eth.contract(address=MAKINA_ORACLE, abi=MAKINA_ORACLE_ABI)
    share_owner_result = safe(makina.functions.shareOwner().call, block_identifier=latest)
    share_owner_address = val(share_owner_result)
    share_owner = None
    if share_owner_address:
        share_owner_address = Web3.to_checksum_address(share_owner_address)
        owner_contract = w3.eth.contract(address=share_owner_address, abi=SHARE_OWNER_ABI)
        share_owner = {
            "address": share_owner_address,
            "codeBytes": len(w3.eth.get_code(share_owner_address, block_identifier=latest)),
            "totalSupply": safe(owner_contract.functions.totalSupply().call, block_identifier=latest),
            "lastTotalAum": safe(owner_contract.functions.lastTotalAum().call, block_identifier=latest),
            "machine": safe(owner_contract.functions.machine().call, block_identifier=latest),
            "asset": safe(owner_contract.functions.asset().call, block_identifier=latest),
            "decimals": safe(owner_contract.functions.decimals().call, block_identifier=latest),
        }

    result = {
        "schema": "termmax-dusd-exposure/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {"number": latest, "hash": "0x" + bytes(block.hash).hex(), "timestamp": timestamp, "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()},
        "addresses": {"dusd": DUSD, "termmaxAdapter": DUSD_ADAPTER, "makinaOracle": MAKINA_ORACLE, "currentOracleAggregator": CURRENT_ORACLE_AGGREGATOR},
        "codes": {"dusd": len(w3.eth.get_code(DUSD, block_identifier=latest)), "termmaxAdapter": len(w3.eth.get_code(DUSD_ADAPTER, block_identifier=latest)), "makinaOracleProxy": len(w3.eth.get_code(MAKINA_ORACLE, block_identifier=latest))},
        "adapter": {
            "asset": safe(adapter.functions.asset().call, block_identifier=latest),
            "dusdOracle": safe(adapter.functions.dusdOracle().call, block_identifier=latest),
            "decimals": safe(adapter.functions.decimals().call, block_identifier=latest),
            "latestRoundData": safe(adapter.functions.latestRoundData().call, block_identifier=latest),
        },
        "makinaOracle": {
            "sharePrice": safe(makina.functions.getSharePrice().call, block_identifier=latest),
            "decimals": safe(makina.functions.decimals().call, block_identifier=latest),
            "description": safe(makina.functions.description().call, block_identifier=latest),
            "shareOwner": share_owner_result,
        },
        "shareOwner": share_owner,
        "marketDiscovery": {"allRows": len(all_markets), "errors": [row for row in all_markets if row.get("discoveryError")]},
        "dusdMarkets": inspected,
        "oracleAggregators": aggregators,
    }

    total_debt = sum(int(market.get("liquidity", {}).get("debtBalanceRaw", 0)) for market in inspected)
    current_configured = any(
        val(item["dusdOracleConfig"], [ZERO := "0x0000000000000000000000000000000000000000"])[0].lower() == DUSD_ADAPTER.lower()
        if val(item["dusdOracleConfig"]) else False
        for item in aggregators
    )
    result["decision"] = {
        "dusdMarketCount": len(inspected),
        "dusdAsCollateralCount": sum(1 for market in inspected if market.get("addresses", {}).get("collateral", "").lower() == DUSD.lower()),
        "dusdAsDebtCount": sum(1 for market in inspected if market.get("addresses", {}).get("debtToken", "").lower() == DUSD.lower()),
        "aggregateOrderDebtBalanceRaw": total_debt,
        "adapterConfiguredInObservedAggregators": current_configured,
        "candidateState": "ACTIVE" if inspected and current_configured and total_debt > 0 else "NO_CURRENT_LIVE_EXPOSURE",
    }

    (OUT / "DUSD_EXPOSURE_FULL.json").write_text(json.dumps(result, indent=2, default=default), encoding="utf-8")
    compact = {"generatedAtUtc": result["generatedAtUtc"], "block": result["block"], "addresses": result["addresses"], "adapter": result["adapter"], "makinaOracle": result["makinaOracle"], "shareOwner": result["shareOwner"], "dusdMarkets": result["dusdMarkets"], "oracleAggregators": result["oracleAggregators"], "decision": result["decision"]}
    (OUT / "DUSD_EXPOSURE_COMPACT.json").write_text(json.dumps(compact, indent=2, default=default), encoding="utf-8")
    print(json.dumps(compact, indent=2, default=default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
