#!/usr/bin/env python3
"""Read-only multi-chain TermMax V2 vault state and bad-debt inventory.

Only JSON-RPC read methods are used. No key, signature, transaction submission,
or state mutation is implemented.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

OUT = Path("termmax-multivault-readonly")

TOPICS = {
    "RedeemOrder": "0x21f71f6609f50b01dbe90a67add86958b134ef6fa7e8c668df45730004806242",
    "NewOrderCreated": "0x3ca4bef6cb680238d8c3dcdcca83a5aadcadff2571d3a2c67ee85b2750944b97",
    "Deposit": "0xdcbc1c05240f31ff3ad067ef1ee35ce4997762752e3a095284754544f4c709d7",
    "Withdraw": "0xfbde797d201c681b91056529119e0b02407c7bb96a4a2c75c01fc9667232c8db",
    "WithdrawFts": "0x53239297447654f3a1c8342314051bc2fe9134b7bbe4a390eade008bb5eca1f2",
    "DealBadDebt": "0xaf2e30fae2dfd1a90059cf53415e90c4ee9d151c1b1861df8f8a5963069c47f4",
}

SELECTORS = {
    "name": "0x06fdde03",
    "symbol": "0x95d89b41",
    "asset": "0x38d52e0f",
    "pool": "0x16f0115b",
    "totalFt": "0x69c42125",
    "totalAssets": "0x01e1d114",
    "totalSupply": "0x18160ddd",
    "paused": "0x5c975abb",
    "maxDeposit": "0x402d267d",
    "badDebtMapping": "0x618f9694",
    "orderMaturity": "0xac33207f",
    "market": "0x80f55605",
    "tokens": "0x9d63848a",
    "orderExpiryTimestamp": "0x3a0d3561",
    "balanceOf": "0x70a08231",
    "decimals": "0x313ce567",
}

CHAINS: list[dict[str, Any]] = [
    {
        "name": "ethereum",
        "chainId": 1,
        "rpcs": [
            "https://rpc.mevblocker.io",
            "https://eth.drpc.org",
            "https://1rpc.io/eth",
            "https://ethereum-rpc.publicnode.com",
            "https://eth.llamarpc.com",
            "https://rpc.flashbots.net",
        ],
        "initialSpan": 200_000,
        "maxSpan": 400_000,
        "minSpan": 1_000,
        "vaults": [
            ["termmax-usdc-v2", "0xf488ccdf04079cc03183cdb6a147d12cf97f9317", 23_490_022],
            ["prime-yield", "0x17337c22cf8b7c1b6fc86f0ef7fcf05a7fa93f48", 23_516_443],
            ["termmax-weth-v2", "0x95fb87609f80c47e3102b976455023d2b9be9b8f", 23_490_023],
            ["coinshift-rlusd", "0x7a84fcb839beb377861001c6339a986b9e6d6d68", 24_338_283],
            ["xaue-xaut", "0x7fb02aea6f04d44a61e413fa220caf18dcd626fb", 24_832_207],
            ["mezencap-ext", "0x394ec054e8275c40c45f116683f250a3e40ea34d", 24_036_283],
            ["edge-usdc", "0xbbf747e83f2f1650f7b303f6166fc3fe8a5b0ce5", 23_540_487],
            ["ellen-usdc", "0xe3e545abfa18019bcd74aba2c13dc569d6d018a8", 24_832_165],
        ],
    },
    {
        "name": "arbitrum",
        "chainId": 42161,
        "rpcs": [
            "https://arb1.arbitrum.io/rpc",
            "https://arbitrum-one-rpc.publicnode.com",
            "https://1rpc.io/arb",
        ],
        "initialSpan": 2_000_000,
        "maxSpan": 5_000_000,
        "minSpan": 10_000,
        "vaults": [
            ["termmax-usdc-v2", "0xcb94abcffbf5cc76a55f9c1496632a26d19f9947", 385_285_861],
            ["termmax-weth-v2", "0xb6692acb982c2da0775c947cb329b04ebfb4e0ac", 385_285_866],
        ],
    },
    {
        "name": "bnb",
        "chainId": 56,
        "rpcs": [
            "https://bsc-rpc.publicnode.com",
            "https://bsc-dataseed.binance.org",
            "https://1rpc.io/bnb",
            "https://bsc-dataseed1.defibit.io",
        ],
        "initialSpan": 300_000,
        "maxSpan": 1_000_000,
        "minSpan": 2_000,
        "vaults": [
            ["alpha-vault-1", "0x086c120290850e4698645a5689c2428d6e7789de", 60_000_000],
            ["alpha-vault-2", "0x41d4b8385ab112380158eac2f4cabb9baef1bb45", 60_000_000],
            ["alpha-vault-3", "0xe749d471db186a6dab068059b29498feb3a01b38", 60_000_000],
            ["alpha-vault-4", "0xa6d02815d3ff570b795d6c0551cfcef915609142", 60_000_000],
        ],
    },
]


def word(data: str, index: int = 0) -> str:
    raw = (data or "0x").removeprefix("0x")
    start = index * 64
    return raw[start : start + 64].ljust(64, "0")


def uint(data: str, index: int = 0) -> int:
    return int(word(data, index) or "0", 16)


def address_word(data: str, index: int = 0) -> str:
    return "0x" + word(data, index)[-40:].lower()


def topic_address(topic: str) -> str:
    return "0x" + topic.removeprefix("0x")[-40:].lower()


def abi_address_arg(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def decode_string(data: str) -> str:
    try:
        raw = data.removeprefix("0x")
        if not raw:
            return ""
        offset = int(raw[:64], 16)
        p = offset * 2
        length = int(raw[p : p + 64], 16)
        return bytes.fromhex(raw[p + 64 : p + 64 + length * 2]).decode("utf-8", errors="replace")
    except Exception:
        return ""


@dataclass
class RpcPool:
    chain: str
    chain_id: int
    urls: list[str]
    attempts: list[dict[str, Any]]

    def call_one(self, url: str, method: str, params: list[Any]) -> Any:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"content-type": "application/json", "user-agent": "termmax-multivault-readonly/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=45) as response:
            body = json.load(response)
        if body.get("error"):
            raise RuntimeError(f"{method}: {body['error']}")
        return body.get("result")

    def call(self, method: str, params: list[Any]) -> tuple[Any, str]:
        errors: list[str] = []
        for url in self.urls:
            try:
                result = self.call_one(url, method, params)
                return result, url
            except Exception as exc:
                errors.append(f"{url}: {type(exc).__name__}: {exc}")
        raise RuntimeError(" | ".join(errors))

    def initialize(self) -> int:
        for url in self.urls:
            try:
                chain = int(self.call_one(url, "eth_chainId", []), 16)
                latest = int(self.call_one(url, "eth_blockNumber", []), 16)
                if chain != self.chain_id:
                    raise RuntimeError(f"wrong chain {chain}")
                self.attempts.append({"url": url, "ok": True, "latest": latest})
                self.urls = [url] + [x for x in self.urls if x != url]
                return latest
            except Exception as exc:
                self.attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
        raise RuntimeError(f"no working RPC for {self.chain}: {self.attempts}")


def safe_call(pool: RpcPool, to: str, data: str, decoder: str = "uint", block: str = "latest") -> dict[str, Any]:
    try:
        raw, rpc_url = pool.call("eth_call", [{"to": to, "data": data}, block])
        if decoder == "uint":
            value: Any = uint(raw)
        elif decoder == "bool":
            value = bool(uint(raw))
        elif decoder == "address":
            value = address_word(raw)
        elif decoder == "string":
            value = decode_string(raw)
        elif decoder == "raw":
            value = raw
        else:
            raise ValueError(decoder)
        return {"ok": True, "value": value, "rpc": rpc_url}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def get_code(pool: RpcPool, address: str, block: str = "latest") -> dict[str, Any]:
    try:
        code, url = pool.call("eth_getCode", [address, block])
        return {
            "ok": True,
            "code": code,
            "bytes": max(0, (len(code) - 2) // 2),
            "sha256": hashlib.sha256(bytes.fromhex(code.removeprefix("0x"))).hexdigest() if code != "0x" else None,
            "rpc": url,
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def decode_event(log: dict[str, Any]) -> dict[str, Any]:
    topic0 = log.get("topics", [""])[0].lower()
    name = next((k for k, v in TOPICS.items() if v == topic0), "Unknown")
    topics = log.get("topics", [])
    data = log.get("data", "0x")
    base: dict[str, Any] = {
        "event": name,
        "address": log.get("address", "").lower(),
        "blockNumber": int(log["blockNumber"], 16),
        "transactionHash": log["transactionHash"],
        "logIndex": int(log["logIndex"], 16),
    }
    if name == "NewOrderCreated" and len(topics) >= 4:
        base.update(caller=topic_address(topics[1]), market=topic_address(topics[2]), order=topic_address(topics[3]))
    elif name == "RedeemOrder" and len(topics) >= 3:
        base.update(caller=topic_address(topics[1]), order=topic_address(topics[2]), badDebt=uint(data, 0), deliveryAmount=uint(data, 1))
    elif name == "Deposit" and len(topics) >= 3:
        base.update(caller=topic_address(topics[1]), owner=topic_address(topics[2]), assets=uint(data, 0), shares=uint(data, 1))
    elif name == "Withdraw" and len(topics) >= 4:
        base.update(caller=topic_address(topics[1]), receiver=topic_address(topics[2]), owner=topic_address(topics[3]), assets=uint(data, 0), shares=uint(data, 1))
    elif name == "WithdrawFts" and len(topics) >= 4:
        base.update(caller=topic_address(topics[1]), recipient=topic_address(topics[2]), order=topic_address(topics[3]), amount=uint(data, 0), shares=uint(data, 1))
    elif name == "DealBadDebt" and len(topics) >= 4:
        base.update(caller=topic_address(topics[1]), recipient=topic_address(topics[2]), collateral=topic_address(topics[3]), badDebt=uint(data, 0), shares=uint(data, 1), collateralOut=uint(data, 2))
    else:
        base.update(topics=topics, data=data)
    return base


def get_logs_adaptive(pool: RpcPool, addresses: list[str], start: int, latest: int, initial_span: int, max_span: int, min_span: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    all_logs: list[dict[str, Any]] = []
    progress: list[dict[str, Any]] = []
    current = start
    span = initial_span
    while current <= latest:
        end = min(latest, current + span - 1)
        query = {"address": addresses, "fromBlock": hex(current), "toBlock": hex(end), "topics": [list(TOPICS.values())]}
        try:
            part, url = pool.call("eth_getLogs", [query])
            all_logs.extend(part)
            progress.append({"from": current, "to": end, "span": span, "count": len(part), "rpc": url})
            current = end + 1
            if len(part) < 500:
                span = min(max_span, span * 2)
        except Exception as exc:
            progress.append({"from": current, "to": end, "span": span, "error": str(exc)})
            if span <= min_span:
                combined: list[dict[str, Any]] = []
                for address in addresses:
                    one = dict(query)
                    one["address"] = address
                    part, _ = pool.call("eth_getLogs", [one])
                    combined.extend(part)
                all_logs.extend(combined)
                progress.append({"from": current, "to": end, "span": span, "count": len(combined), "fallback": "per-address"})
                current = end + 1
            else:
                span = max(min_span, span // 2)
        time.sleep(0.02)
    all_logs.sort(key=lambda x: (int(x["blockNumber"], 16), int(x["logIndex"], 16)))
    return all_logs, progress


def inspect_order(pool: RpcPool, vault: str, order: str, event_market: str) -> dict[str, Any]:
    market_call = safe_call(pool, order, SELECTORS["market"], "address")
    market = market_call.get("value") if market_call.get("ok") else event_market
    tokens_raw = safe_call(pool, market, SELECTORS["tokens"], "raw") if market else {"ok": False, "error": "no market"}
    result: dict[str, Any] = {
        "order": order,
        "market": market,
        "marketCall": market_call,
        "orderMaturity": safe_call(pool, vault, SELECTORS["orderMaturity"] + abi_address_arg(order), "uint"),
        "orderExpiryTimestamp": safe_call(pool, order, SELECTORS["orderExpiryTimestamp"], "uint"),
        "pool": safe_call(pool, order, SELECTORS["pool"], "address"),
        "tokensRaw": tokens_raw,
    }
    if tokens_raw.get("ok"):
        raw = tokens_raw["value"]
        tokens = {"ft": address_word(raw, 0), "xt": address_word(raw, 1), "gt": address_word(raw, 2), "collateral": address_word(raw, 3), "debtToken": address_word(raw, 4)}
        result["tokens"] = tokens
        result["ftBalance"] = safe_call(pool, tokens["ft"], SELECTORS["balanceOf"] + abi_address_arg(order), "uint")
        result["xtBalance"] = safe_call(pool, tokens["xt"], SELECTORS["balanceOf"] + abi_address_arg(order), "uint")
        result["collateralSymbol"] = safe_call(pool, tokens["collateral"], SELECTORS["symbol"], "string")
        result["collateralDecimals"] = safe_call(pool, tokens["collateral"], SELECTORS["decimals"], "uint")
    return result


def inspect_vault(pool: RpcPool, label: str, vault: str, start_block: int, events: list[dict[str, Any]]) -> dict[str, Any]:
    code = get_code(pool, vault)
    state = {
        "name": safe_call(pool, vault, SELECTORS["name"], "string"),
        "symbol": safe_call(pool, vault, SELECTORS["symbol"], "string"),
        "asset": safe_call(pool, vault, SELECTORS["asset"], "address"),
        "pool": safe_call(pool, vault, SELECTORS["pool"], "address"),
        "totalFt": safe_call(pool, vault, SELECTORS["totalFt"], "uint"),
        "totalAssets": safe_call(pool, vault, SELECTORS["totalAssets"], "uint"),
        "totalSupply": safe_call(pool, vault, SELECTORS["totalSupply"], "uint"),
        "paused": safe_call(pool, vault, SELECTORS["paused"], "bool"),
        "maxDeposit": safe_call(pool, vault, SELECTORS["maxDeposit"] + abi_address_arg(vault), "uint"),
    }
    asset = state["asset"].get("value") if state["asset"].get("ok") else None
    asset_symbol = safe_call(pool, asset, SELECTORS["symbol"], "string") if asset else {"ok": False}
    asset_decimals = safe_call(pool, asset, SELECTORS["decimals"], "uint") if asset else {"ok": False}
    decimals = int(asset_decimals.get("value", 18)) if asset_decimals.get("ok") else 18
    material_threshold = max(100, 10**decimals // 100)
    own_events = [e for e in events if e["address"] == vault]
    counts = {name: sum(1 for e in own_events if e["event"] == name) for name in TOPICS}
    new_orders: dict[str, dict[str, Any]] = {}
    for event in own_events:
        if event["event"] == "NewOrderCreated":
            new_orders[event["order"]] = event
    order_states = [inspect_order(pool, vault, order, event["market"]) for order, event in new_orders.items()]
    collaterals: dict[str, dict[str, Any]] = {}
    for order in order_states:
        tokens = order.get("tokens")
        if not tokens:
            continue
        collateral = tokens["collateral"]
        if collateral not in collaterals:
            collaterals[collateral] = {
                "collateral": collateral,
                "symbol": safe_call(pool, collateral, SELECTORS["symbol"], "string"),
                "decimals": safe_call(pool, collateral, SELECTORS["decimals"], "uint"),
                "badDebtMapping": safe_call(pool, vault, SELECTORS["badDebtMapping"] + abi_address_arg(collateral), "uint"),
                "vaultBalance": safe_call(pool, collateral, SELECTORS["balanceOf"] + abi_address_arg(vault), "uint"),
            }
    material_redeems = [e for e in own_events if e["event"] == "RedeemOrder" and e.get("badDebt", 0) >= material_threshold]
    current_material_buckets = []
    for bucket in collaterals.values():
        bad = bucket["badDebtMapping"].get("value", 0) if bucket["badDebtMapping"].get("ok") else 0
        bal = bucket["vaultBalance"].get("value", 0) if bucket["vaultBalance"].get("ok") else 0
        if bad >= material_threshold or bal > 0:
            current_material_buckets.append(bucket)
    active_material_orders = []
    for order in order_states:
        maturity = order["orderMaturity"].get("value", 0) if order["orderMaturity"].get("ok") else 0
        ft_balance = order.get("ftBalance", {}).get("value", 0) if order.get("ftBalance", {}).get("ok") else 0
        if maturity and ft_balance >= material_threshold:
            active_material_orders.append(order)
    total_assets = state["totalAssets"].get("value", 0) if state["totalAssets"].get("ok") else 0
    total_supply = state["totalSupply"].get("value", 0) if state["totalSupply"].get("ok") else 0
    max_deposit = state["maxDeposit"].get("value", 0) if state["maxDeposit"].get("ok") else 0
    return {
        "label": label,
        "vault": vault,
        "startBlock": start_block,
        "code": code,
        "state": state,
        "assetSymbol": asset_symbol,
        "assetDecimals": asset_decimals,
        "materialThresholdRaw": material_threshold,
        "eventCounts": counts,
        "materialRedeemOrderEvents": material_redeems,
        "currentCollateralBuckets": list(collaterals.values()),
        "currentMaterialBuckets": current_material_buckets,
        "orders": order_states,
        "activeMaterialOrders": active_material_orders,
        "gates": {
            "materialVault": total_assets >= material_threshold,
            "depositOpen": max_deposit > 0,
            "SNAV1CurrentLiveTrigger": bool(current_material_buckets and total_supply > 0 and max_deposit > 0),
            "WQ1MultiOrderPrecondition": len(active_material_orders) >= 2,
        },
    }


def block_meta(pool: RpcPool, number: int) -> dict[str, Any]:
    block, url = pool.call("eth_getBlockByNumber", [hex(number), False])
    ts = int(block["timestamp"], 16)
    return {"number": number, "hash": block.get("hash"), "timestamp": ts, "timestampUtc": dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat(), "rpc": url}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "termmax-multivault-readonly/v1",
        "generatedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "safety": {"signedTransactions": 0, "broadcastTransactions": 0, "methods": ["eth_chainId", "eth_blockNumber", "eth_getCode", "eth_call", "eth_getLogs", "eth_getBlockByNumber"]},
        "chains": [],
    }
    errors: list[dict[str, Any]] = []
    for config in CHAINS:
        pool = RpcPool(config["name"], config["chainId"], list(config["rpcs"]), [])
        try:
            latest = pool.initialize()
            code_present: list[tuple[str, str, int]] = []
            for label, address, start in config["vaults"]:
                address = address.lower()
                code = get_code(pool, address)
                if code.get("ok") and code.get("bytes", 0) > 0:
                    code_present.append((label, address, start))
            if code_present:
                raw_logs, progress = get_logs_adaptive(pool, [x[1] for x in code_present], min(x[2] for x in code_present), latest, config["initialSpan"], config["maxSpan"], config["minSpan"])
                events = [decode_event(log) for log in raw_logs]
            else:
                progress, events = [], []
            vault_results = []
            for label, address, start in code_present:
                try:
                    vault_results.append(inspect_vault(pool, label, address, start, events))
                except Exception as exc:
                    errors.append({"chain": config["name"], "vault": address, "stage": "inspect_vault", "error": f"{type(exc).__name__}: {exc}"})
            report["chains"].append({
                "name": config["name"],
                "chainId": config["chainId"],
                "rpcAttempts": pool.attempts,
                "latestBlock": block_meta(pool, latest),
                "configuredVaults": len(config["vaults"]),
                "codePresentVaults": len(code_present),
                "scanProgress": progress,
                "events": events,
                "vaults": vault_results,
            })
        except Exception as exc:
            errors.append({"chain": config["name"], "stage": "chain", "error": f"{type(exc).__name__}: {exc}", "rpcAttempts": pool.attempts})
    report["errors"] = errors
    all_vaults = [v for c in report["chains"] for v in c["vaults"]]
    report["portfolio"] = {
        "vaultsInspected": len(all_vaults),
        "SNAV1CurrentLiveTriggers": [{"chain": c["name"], "vault": v["vault"], "label": v["label"]} for c in report["chains"] for v in c["vaults"] if v["gates"]["SNAV1CurrentLiveTrigger"]],
        "WQ1MultiOrderPreconditions": [{"chain": c["name"], "vault": v["vault"], "label": v["label"], "activeOrders": len(v["activeMaterialOrders"])} for c in report["chains"] for v in c["vaults"] if v["gates"]["WQ1MultiOrderPrecondition"]],
        "MaterialBadDebtHistory": [{"chain": c["name"], "vault": v["vault"], "label": v["label"], "events": len(v["materialRedeemOrderEvents"])} for c in report["chains"] for v in c["vaults"] if v["materialRedeemOrderEvents"]],
    }
    report["status"] = "PASS" if report["chains"] and all_vaults else "INCOMPLETE"
    (OUT / "SUMMARY.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    concise = {
        "status": report["status"],
        "chainsCompleted": [c["name"] for c in report["chains"]],
        "vaultsInspected": len(all_vaults),
        "snavCurrentHits": len(report["portfolio"]["SNAV1CurrentLiveTriggers"]),
        "wq1PreconditionHits": len(report["portfolio"]["WQ1MultiOrderPreconditions"]),
        "materialBadDebtHistoryHits": len(report["portfolio"]["MaterialBadDebtHistory"]),
        "errors": len(errors),
        "portfolio": report["portfolio"],
    }
    (OUT / "CONCISE.json").write_text(json.dumps(concise, indent=2), encoding="utf-8")
    print(json.dumps(concise, indent=2))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
