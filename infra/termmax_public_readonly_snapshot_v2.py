#!/usr/bin/env python3
"""Failover, read-only TermMax Ethereum vault snapshot.

Allowed JSON-RPC methods only: eth_call, eth_getLogs, eth_getTransactionReceipt,
eth_getBlockByNumber, eth_getCode, eth_getStorageAt, eth_blockNumber, eth_chainId.
No signing or transaction-broadcast method exists in this program.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

VAULT = "0xf488ccdf04079cc03183cdb6a147d12cf97f9317"
DEPLOYMENT_BLOCK = 23_490_022
SETTLEMENT_TX = "0xfd90c3e14fa8c97160a3673bb90657e233b66061c70b5b2e6bccfcd1fa66aab4"
OUT = Path("termmax-public-readonly")
RPCS = [
    "https://eth.llamarpc.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://rpc.flashbots.net",
    "https://rpc.mevblocker.io",
    "https://ethereum-rpc.publicnode.com",
    "https://cloudflare-eth.com",
    "https://eth-mainnet.public.blastapi.io",
]
TOPICS = {
    "RedeemOrder": "0x21f71f6609f50b01dbe90a67add86958b134ef6fa7e8c668df45730004806242",
    "NewOrderCreated": "0x3ca4bef6cb680238d8c3dcdcca83a5aadcadff2571d3a2c67ee85b2750944b97",
    "Deposit": "0xdcbc1c05240f31ff3ad067ef1ee35ce4997762752e3a095284754544f4c709d7",
    "Withdraw": "0xfbde797d201c681b91056529119e0b02407c7bb96a4a2c75c01fc9667232c8db",
    "WithdrawFts": "0x53239297447654f3a1c8342314051bc2fe9134b7bbe4a390eade008bb5eca1f2",
    "DealBadDebt": "0xaf2e30fae2dfd1a90059cf53415e90c4ee9d151c1b1861df8f8a5963069c47f4",
}
S = {
    "name": "0x06fdde03", "symbol": "0x95d89b41", "asset": "0x38d52e0f",
    "pool": "0x16f0115b", "curator": "0xe66f53b7", "guardian": "0x452a9320",
    "owner": "0x8da5cb5b", "performanceFeeRate": "0x0ffbfda4",
    "performanceFee": "0x87788782", "accretingPrincipal": "0x594d16f7",
    "totalFt": "0x69c42125", "totalAssets": "0x01e1d114",
    "totalSupply": "0x18160ddd", "paused": "0x5c975abb",
    "maxDeposit": "0x402d267d", "badDebtMapping": "0x618f9694",
    "orderMaturity": "0xac33207f", "market": "0x80f55605",
    "tokens": "0x9d63848a", "balanceOf": "0x70a08231", "decimals": "0x313ce567",
}
EIP1967_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def raw_rpc(url: str, method: str, params: list[Any]) -> Any:
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url, data=data,
        headers={"content-type": "application/json", "user-agent": "Mozilla/5.0 termmax-readonly"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=40) as response:
        payload = json.load(response)
    if payload.get("error"):
        raise RuntimeError(payload["error"])
    return payload.get("result")


class Pool:
    def __init__(self) -> None:
        self.preferred: str | None = None
        self.attempts: list[dict[str, Any]] = []

    def call(self, method: str, params: list[Any], preferred: str | None = None) -> tuple[Any, str]:
        ordered: list[str] = []
        for candidate in (preferred, self.preferred, *RPCS):
            if candidate and candidate not in ordered:
                ordered.append(candidate)
        errors: list[str] = []
        for url in ordered:
            try:
                result = raw_rpc(url, method, params)
                if method in {"eth_chainId", "eth_blockNumber"}:
                    self.preferred = url
                self.attempts.append({"method": method, "url": url, "ok": True})
                return result, url
            except Exception as exc:  # noqa: BLE001
                text = f"{url}: {type(exc).__name__}: {exc}"
                errors.append(text)
                self.attempts.append({"method": method, "url": url, "ok": False, "error": text})
        raise RuntimeError(f"all RPCs failed for {method}: {' | '.join(errors)}")


POOL = Pool()


def word(data: str, index: int) -> str:
    raw = (data or "0x").removeprefix("0x")
    return raw[index * 64:(index + 1) * 64].ljust(64, "0")


def u(data: str, index: int = 0) -> int:
    return int(word(data, index), 16)


def addr_word(data: str, index: int = 0) -> str:
    return "0x" + word(data, index)[-40:].lower()


def topic_addr(topic: str) -> str:
    return "0x" + topic.removeprefix("0x")[-40:].lower()


def arg_addr(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64, "0")


def dyn_string(data: str) -> str:
    try:
        raw = data.removeprefix("0x")
        offset = int(raw[:64], 16) * 2
        length = int(raw[offset:offset + 64], 16)
        return bytes.fromhex(raw[offset + 64:offset + 64 + length * 2]).decode(errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def call(to: str, data: str, kind: str = "uint", block: str = "latest") -> dict[str, Any]:
    try:
        result, url = POOL.call("eth_call", [{"to": to, "data": data}, block])
        if kind == "uint": value: Any = u(result)
        elif kind == "bool": value = bool(u(result))
        elif kind == "address": value = addr_word(result)
        elif kind == "string": value = dyn_string(result)
        elif kind == "raw": value = result
        else: raise ValueError(kind)
        return {"ok": True, "value": value, "rpc": url}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def decode_event(log: dict[str, Any]) -> dict[str, Any]:
    topic0 = log["topics"][0].lower()
    name = next((key for key, value in TOPICS.items() if value == topic0), "Unknown")
    result: dict[str, Any] = {
        "event": name, "blockNumber": int(log["blockNumber"], 16),
        "transactionHash": log["transactionHash"], "logIndex": int(log["logIndex"], 16),
    }
    topics, data = log.get("topics", []), log.get("data", "0x")
    if name == "RedeemOrder" and len(topics) >= 3:
        result.update(caller=topic_addr(topics[1]), order=topic_addr(topics[2]), badDebt=u(data, 0), deliveryAmount=u(data, 1))
    elif name == "NewOrderCreated" and len(topics) >= 4:
        result.update(caller=topic_addr(topics[1]), market=topic_addr(topics[2]), order=topic_addr(topics[3]))
    elif name == "Deposit" and len(topics) >= 3:
        result.update(caller=topic_addr(topics[1]), owner=topic_addr(topics[2]), assets=u(data, 0), shares=u(data, 1))
    elif name == "Withdraw" and len(topics) >= 4:
        result.update(caller=topic_addr(topics[1]), receiver=topic_addr(topics[2]), owner=topic_addr(topics[3]), assets=u(data, 0), shares=u(data, 1))
    elif name == "WithdrawFts" and len(topics) >= 4:
        result.update(caller=topic_addr(topics[1]), recipient=topic_addr(topics[2]), order=topic_addr(topics[3]), amount=u(data, 0), shares=u(data, 1))
    elif name == "DealBadDebt" and len(topics) >= 4:
        result.update(caller=topic_addr(topics[1]), recipient=topic_addr(topics[2]), collateral=topic_addr(topics[3]), badDebt=u(data, 0), shares=u(data, 1), collateralOut=u(data, 2))
    else:
        result.update(topics=topics, data=data)
    return result


def scan_topic(topic: str, start: int, latest: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    logs: list[dict[str, Any]] = []
    progress: list[dict[str, Any]] = []
    current, span = start, 50_000
    complete = True
    while current <= latest:
        end = min(latest, current + span - 1)
        query = {"address": VAULT, "fromBlock": hex(current), "toBlock": hex(end), "topics": [topic]}
        try:
            part, used = POOL.call("eth_getLogs", [query])
            logs.extend(part)
            progress.append({"from": current, "to": end, "count": len(part), "rpc": used})
            current = end + 1
            if len(part) < 100 and span < 200_000: span *= 2
        except Exception as exc:  # noqa: BLE001
            progress.append({"from": current, "to": end, "error": str(exc), "span": span})
            if span <= 2_000:
                complete = False
                break
            span = max(2_000, span // 2)
        time.sleep(0.02)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))
    return logs, progress, complete


def block_meta(number: int) -> dict[str, Any]:
    block, url = POOL.call("eth_getBlockByNumber", [hex(number), False])
    timestamp = int(block["timestamp"], 16)
    return {"number": number, "hash": block["hash"], "timestamp": timestamp,
            "timestampUtc": dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat(), "rpc": url}


def inspect_order(order: str, event_market: str) -> dict[str, Any]:
    market_result = call(order, S["market"], "address")
    market = market_result.get("value") if market_result.get("ok") else event_market
    tokens_result = call(market, S["tokens"], "raw")
    out: dict[str, Any] = {
        "order": order, "market": market, "marketCall": market_result,
        "orderMaturity": call(VAULT, S["orderMaturity"] + arg_addr(order)),
        "pool": call(order, S["pool"], "address"), "tokensRaw": tokens_result,
    }
    if tokens_result.get("ok"):
        raw = tokens_result["value"]
        tokens = {"ft": addr_word(raw, 0), "xt": addr_word(raw, 1), "gt": addr_word(raw, 2),
                  "collateral": addr_word(raw, 3), "debtToken": addr_word(raw, 4)}
        out["tokens"] = tokens
        out["ftBalance"] = call(tokens["ft"], S["balanceOf"] + arg_addr(order))
        out["xtBalance"] = call(tokens["xt"], S["balanceOf"] + arg_addr(order))
        out["collateralSymbol"] = call(tokens["collateral"], S["symbol"], "string")
        out["collateralDecimals"] = call(tokens["collateral"], S["decimals"])
    return out


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    chain, chain_rpc = POOL.call("eth_chainId", [])
    latest_hex, latest_rpc = POOL.call("eth_blockNumber", [])
    if int(chain, 16) != 1: raise RuntimeError(f"wrong chain {chain}")
    latest = int(latest_hex, 16)

    receipt, receipt_rpc = POOL.call("eth_getTransactionReceipt", [SETTLEMENT_TX])
    if not receipt: raise RuntimeError("settlement receipt missing")
    settlement_block = int(receipt["blockNumber"], 16)
    receipt_events = [decode_event(log) for log in receipt.get("logs", []) if log.get("address", "").lower() == VAULT]
    exact = next((event for event in receipt_events if event["event"] == "RedeemOrder"), None)
    if exact is None: raise RuntimeError("RedeemOrder missing from exact receipt")

    all_logs: list[dict[str, Any]] = []
    scan_status: dict[str, Any] = {}
    for name, topic in TOPICS.items():
        start = DEPLOYMENT_BLOCK if name in {"RedeemOrder", "NewOrderCreated"} else settlement_block
        logs, progress, complete = scan_topic(topic, start, latest)
        all_logs.extend(logs)
        scan_status[name] = {"complete": complete, "count": len(logs), "progress": progress}
    unique = {(log["transactionHash"], log["logIndex"]): log for log in all_logs}
    events = [decode_event(log) for log in unique.values()]
    events.sort(key=lambda item: (item["blockNumber"], item["logIndex"]))

    views: dict[str, Any] = {}
    for name in ("name", "symbol"): views[name] = call(VAULT, S[name], "string")
    for name in ("asset", "pool", "curator", "guardian", "owner"): views[name] = call(VAULT, S[name], "address")
    for name in ("performanceFeeRate", "performanceFee", "accretingPrincipal", "totalFt", "totalAssets", "totalSupply"):
        views[name] = call(VAULT, S[name])
    views["paused"] = call(VAULT, S["paused"], "bool")
    views["maxDepositVault"] = call(VAULT, S["maxDeposit"] + arg_addr(VAULT))

    implementation_raw, storage_rpc = POOL.call("eth_getStorageAt", [VAULT, EIP1967_SLOT, "latest"])
    implementation = addr_word(implementation_raw)
    vault_code, _ = POOL.call("eth_getCode", [VAULT, "latest"])
    implementation_code, _ = POOL.call("eth_getCode", [implementation, "latest"])

    creations: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["event"] == "NewOrderCreated": creations[event["order"]] = event
    creations.setdefault(exact["order"], {"order": exact["order"], "market": "0x0000000000000000000000000000000000000000"})
    orders = [inspect_order(order, event.get("market", "0x0000000000000000000000000000000000000000"))
              for order, event in creations.items()]

    collateral_map: dict[str, dict[str, Any]] = {}
    for order in orders:
        tokens = order.get("tokens")
        if not tokens: continue
        collateral = tokens["collateral"]
        collateral_map.setdefault(collateral, {
            "collateral": collateral,
            "symbol": order.get("collateralSymbol"), "decimals": order.get("collateralDecimals"),
            "badDebtMapping": call(VAULT, S["badDebtMapping"] + arg_addr(collateral)),
            "vaultBalance": call(collateral, S["balanceOf"] + arg_addr(VAULT)),
        })

    asset = views.get("asset", {}).get("value")
    pool = views.get("pool", {}).get("value")
    balances: dict[str, Any] = {}
    if asset:
        balances["assetBalance"] = call(asset, S["balanceOf"] + arg_addr(VAULT))
        balances["assetSymbol"] = call(asset, S["symbol"], "string")
        balances["assetDecimals"] = call(asset, S["decimals"])
    if pool and pool != "0x0000000000000000000000000000000000000000":
        balances["poolShareBalance"] = call(pool, S["balanceOf"] + arg_addr(VAULT))
        balances["poolSymbol"] = call(pool, S["symbol"], "string")

    post = {name: [event for event in events if event["event"] == name and event["blockNumber"] > settlement_block]
            for name in ("Deposit", "Withdraw", "WithdrawFts", "DealBadDebt")}
    summary = {
        "schema": "termmax-public-readonly-snapshot/v2",
        "generatedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "safety": {"signedTransactions": 0, "broadcastTransactions": 0,
                   "allowedMethods": ["eth_call", "eth_getLogs", "eth_getTransactionReceipt", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt", "eth_blockNumber", "eth_chainId"]},
        "chainRpc": chain_rpc, "latestRpc": latest_rpc, "latestBlock": block_meta(latest),
        "vault": VAULT, "deploymentBlock": DEPLOYMENT_BLOCK, "implementation": implementation,
        "implementationStorageRpc": storage_rpc, "vaultCodeBytes": (len(vault_code) - 2) // 2,
        "implementationCodeBytes": (len(implementation_code) - 2) // 2,
        "views": views, "balances": balances,
        "exactSettlement": {"transactionHash": SETTLEMENT_TX, "receiptRpc": receipt_rpc,
                            "status": int(receipt["status"], 16), "block": block_meta(settlement_block),
                            "decodedRedeemOrder": exact, "vaultEvents": receipt_events},
        "scanStatus": scan_status,
        "eventCounts": {name: sum(1 for event in events if event["event"] == name) for name in TOPICS},
        "events": events, "postExactSettlement": post, "orders": orders,
        "collaterals": list(collateral_map.values()), "rpcAttempts": POOL.attempts,
    }
    (OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n")
    (OUT / "EXACT_RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (OUT / "SUMMARY.md").write_text(
        "# TermMax public read-only snapshot v2\n\n"
        f"- Latest block: `{latest}`\n- Exact RedeemOrder: `{json.dumps(exact, sort_keys=True)}`\n"
        f"- Event counts: `{json.dumps(summary['eventCounts'], sort_keys=True)}`\n"
        f"- Current collateral buckets: `{json.dumps(summary['collaterals'], sort_keys=True)}`\n"
        f"- Post-settlement activity counts: `{json.dumps({k: len(v) for k, v in post.items()}, sort_keys=True)}`\n\n"
        "No transaction was signed or broadcast.\n"
    )
    result = {"status": "PASS", "latestBlock": latest, "exactRedeemOrder": exact,
              "eventCounts": summary["eventCounts"], "currentCollateralBuckets": summary["collaterals"],
              "postSettlementActivity": {key: len(value) for key, value in post.items()}}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "FATAL.txt").write_text(f"{type(exc).__name__}: {exc}\n")
        print(f"FATAL: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
