#!/usr/bin/env python3
"""Read-only TermMax Ethereum vault inventory.

Uses only eth_call, eth_getLogs, eth_getTransactionReceipt, eth_getBlockByNumber,
eth_getCode, and eth_getStorageAt. It never signs or broadcasts a transaction.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

VAULT = "0xf488ccdf04079cc03183cdb6a147d12cf97f9317"
DEPLOYMENT_BLOCK = 23_490_022
EXACT_SETTLEMENT_TX = "0xfd90c3e14fa8c97160a3673bb90657e233b66061c70b5b2e6bccfcd1fa66aab4"
OUT = Path("termmax-public-readonly")
RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
]

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
    "curator": "0xe66f53b7",
    "guardian": "0x452a9320",
    "owner": "0x8da5cb5b",
    "performanceFeeRate": "0x0ffbfda4",
    "performanceFee": "0x87788782",
    "accretingPrincipal": "0x594d16f7",
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

EIP1967_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076"
    "cc3735a920a3ca505d382bbc"
)


def rpc(url: str, method: str, params: list[Any], request_id: int = 1) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"content-type": "application/json", "user-agent": "termmax-public-readonly/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=45) as response:
        payload = json.load(response)
    if payload.get("error"):
        raise RuntimeError(f"{method}: {payload['error']}")
    return payload.get("result")


def choose_rpc() -> tuple[str, int, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            chain = int(rpc(url, "eth_chainId", []), 16)
            latest = int(rpc(url, "eth_blockNumber", []), 16)
            if chain != 1:
                raise RuntimeError(f"wrong chain id {chain}")
            attempts.append({"url": url, "ok": True, "latest": latest})
            return url, latest, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(f"no working Ethereum RPC: {attempts}")


def word(data: str, index: int) -> str:
    raw = data.removeprefix("0x")
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
    if not data or data == "0x":
        return ""
    try:
        raw = data.removeprefix("0x")
        offset = int(raw[:64], 16)
        length_at = offset * 2
        length = int(raw[length_at : length_at + 64], 16)
        start = length_at + 64
        return bytes.fromhex(raw[start : start + length * 2]).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def eth_call(url: str, to: str, data: str, block: str = "latest") -> str:
    return rpc(url, "eth_call", [{"to": to, "data": data}, block])


def safe_call(url: str, to: str, data: str, decoder: str = "uint", block: str = "latest") -> dict[str, Any]:
    try:
        result = eth_call(url, to, data, block)
        if decoder == "uint":
            value: Any = uint(result)
        elif decoder == "bool":
            value = bool(uint(result))
        elif decoder == "address":
            value = address_word(result)
        elif decoder == "string":
            value = decode_string(result)
        elif decoder == "raw":
            value = result
        else:
            raise ValueError(decoder)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def get_logs_adaptive(url: str, latest: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    logs: list[dict[str, Any]] = []
    progress: list[dict[str, Any]] = []
    current = DEPLOYMENT_BLOCK
    span = 100_000
    topic_or = list(TOPICS.values())
    while current <= latest:
        end = min(latest, current + span - 1)
        query = {
            "address": VAULT,
            "fromBlock": hex(current),
            "toBlock": hex(end),
            "topics": [topic_or],
        }
        try:
            part = rpc(url, "eth_getLogs", [query])
            logs.extend(part)
            progress.append({"from": current, "to": end, "span": span, "count": len(part)})
            current = end + 1
            if len(part) < 500 and span < 400_000:
                span = min(400_000, span * 2)
        except Exception as exc:  # noqa: BLE001
            progress.append({"from": current, "to": end, "span": span, "error": str(exc)})
            if span <= 1_000:
                raise
            span = max(1_000, span // 2)
        time.sleep(0.03)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))
    return logs, progress


def decode_event(log: dict[str, Any]) -> dict[str, Any]:
    topic0 = log["topics"][0].lower()
    name = next((event for event, topic in TOPICS.items() if topic == topic0), "Unknown")
    base = {
        "event": name,
        "blockNumber": int(log["blockNumber"], 16),
        "transactionHash": log["transactionHash"],
        "logIndex": int(log["logIndex"], 16),
    }
    topics = log.get("topics", [])
    data = log.get("data", "0x")
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


def block_metadata(url: str, block_number: int) -> dict[str, Any]:
    block = rpc(url, "eth_getBlockByNumber", [hex(block_number), False])
    return {
        "number": block_number,
        "hash": block.get("hash"),
        "timestamp": int(block["timestamp"], 16),
        "timestampUtc": dt.datetime.fromtimestamp(int(block["timestamp"], 16), tz=dt.timezone.utc).isoformat(),
    }


def inspect_order(url: str, order: str, created_market: str) -> dict[str, Any]:
    market_call = safe_call(url, order, SELECTORS["market"], "address")
    market = market_call.get("value") if market_call.get("ok") else created_market
    tokens_raw = safe_call(url, market, SELECTORS["tokens"], "raw") if market else {"ok": False, "error": "no market"}
    result: dict[str, Any] = {
        "order": order,
        "market": market,
        "marketCall": market_call,
        "orderMaturity": safe_call(url, VAULT, SELECTORS["orderMaturity"] + abi_address_arg(order), "uint"),
        "orderExpiryTimestamp": safe_call(url, order, SELECTORS["orderExpiryTimestamp"], "uint"),
        "pool": safe_call(url, order, SELECTORS["pool"], "address"),
        "tokensRaw": tokens_raw,
    }
    if tokens_raw.get("ok"):
        raw = tokens_raw["value"]
        tokens = {
            "ft": address_word(raw, 0),
            "xt": address_word(raw, 1),
            "gt": address_word(raw, 2),
            "collateral": address_word(raw, 3),
            "debtToken": address_word(raw, 4),
        }
        result["tokens"] = tokens
        result["ftBalance"] = safe_call(url, tokens["ft"], SELECTORS["balanceOf"] + abi_address_arg(order), "uint")
        result["xtBalance"] = safe_call(url, tokens["xt"], SELECTORS["balanceOf"] + abi_address_arg(order), "uint")
        result["collateralSymbol"] = safe_call(url, tokens["collateral"], SELECTORS["symbol"], "string")
        result["collateralDecimals"] = safe_call(url, tokens["collateral"], SELECTORS["decimals"], "uint")
    return result


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    url, latest, attempts = choose_rpc()
    latest_meta = block_metadata(url, latest)

    receipt = rpc(url, "eth_getTransactionReceipt", [EXACT_SETTLEMENT_TX])
    if not receipt:
        raise RuntimeError("exact settlement receipt not found")
    settlement_block = int(receipt["blockNumber"], 16)
    settlement_meta = block_metadata(url, settlement_block)
    receipt_events = [decode_event(log) for log in receipt.get("logs", []) if log.get("address", "").lower() == VAULT]

    logs, progress = get_logs_adaptive(url, latest)
    events = [decode_event(log) for log in logs]

    implementation_raw = rpc(url, "eth_getStorageAt", [VAULT, EIP1967_IMPLEMENTATION_SLOT, "latest"])
    implementation = address_word(implementation_raw)
    code = rpc(url, "eth_getCode", [VAULT, "latest"])
    implementation_code = rpc(url, "eth_getCode", [implementation, "latest"])

    views: dict[str, Any] = {}
    for name in ("name", "symbol"):
        views[name] = safe_call(url, VAULT, SELECTORS[name], "string")
    for name in ("asset", "pool", "curator", "guardian", "owner"):
        views[name] = safe_call(url, VAULT, SELECTORS[name], "address")
    for name in ("performanceFeeRate", "performanceFee", "accretingPrincipal", "totalFt", "totalAssets", "totalSupply"):
        views[name] = safe_call(url, VAULT, SELECTORS[name], "uint")
    views["paused"] = safe_call(url, VAULT, SELECTORS["paused"], "bool")
    views["maxDepositVault"] = safe_call(url, VAULT, SELECTORS["maxDeposit"] + abi_address_arg(VAULT), "uint")

    asset = views.get("asset", {}).get("value")
    pool = views.get("pool", {}).get("value")
    token_balances: dict[str, Any] = {}
    if asset:
        token_balances["assetBalance"] = safe_call(url, asset, SELECTORS["balanceOf"] + abi_address_arg(VAULT), "uint")
        token_balances["assetSymbol"] = safe_call(url, asset, SELECTORS["symbol"], "string")
        token_balances["assetDecimals"] = safe_call(url, asset, SELECTORS["decimals"], "uint")
    if pool and pool != "0x0000000000000000000000000000000000000000":
        token_balances["poolShareBalance"] = safe_call(url, pool, SELECTORS["balanceOf"] + abi_address_arg(VAULT), "uint")
        token_balances["poolSymbol"] = safe_call(url, pool, SELECTORS["symbol"], "string")

    order_creation: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["event"] == "NewOrderCreated":
            order_creation[event["order"]] = event
    orders = [inspect_order(url, order, event["market"]) for order, event in order_creation.items()]

    collaterals: dict[str, dict[str, Any]] = {}
    for order in orders:
        tokens = order.get("tokens")
        if not tokens:
            continue
        collateral = tokens["collateral"]
        if collateral not in collaterals:
            collaterals[collateral] = {
                "collateral": collateral,
                "symbol": order.get("collateralSymbol"),
                "decimals": order.get("collateralDecimals"),
                "badDebtMapping": safe_call(url, VAULT, SELECTORS["badDebtMapping"] + abi_address_arg(collateral), "uint"),
                "vaultCollateralBalance": safe_call(url, collateral, SELECTORS["balanceOf"] + abi_address_arg(VAULT), "uint"),
            }

    redeem_events = [event for event in events if event["event"] == "RedeemOrder"]
    deal_events = [event for event in events if event["event"] == "DealBadDebt"]
    deposits = [event for event in events if event["event"] == "Deposit"]
    withdrawals = [event for event in events if event["event"] == "Withdraw"]
    withdraw_fts = [event for event in events if event["event"] == "WithdrawFts"]
    exact_redeem = next((event for event in receipt_events if event["event"] == "RedeemOrder"), None)

    post_exact = {
        "deposits": [event for event in deposits if event["blockNumber"] > settlement_block],
        "withdrawals": [event for event in withdrawals if event["blockNumber"] > settlement_block],
        "withdrawFts": [event for event in withdraw_fts if event["blockNumber"] > settlement_block],
        "dealBadDebt": [event for event in deal_events if event["blockNumber"] > settlement_block],
    }

    summary = {
        "schema": "termmax-public-readonly-snapshot/v1",
        "generatedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "safety": {
            "signedTransactions": 0,
            "broadcastTransactions": 0,
            "methods": ["eth_call", "eth_getLogs", "eth_getTransactionReceipt", "eth_getBlockByNumber", "eth_getCode", "eth_getStorageAt"],
        },
        "rpc": url,
        "rpcAttempts": attempts,
        "latestBlock": latest_meta,
        "vault": VAULT,
        "deploymentBlock": DEPLOYMENT_BLOCK,
        "implementation": implementation,
        "vaultCodeBytes": (len(code) - 2) // 2,
        "implementationCodeBytes": (len(implementation_code) - 2) // 2,
        "views": views,
        "tokenBalances": token_balances,
        "exactSettlement": {
            "transactionHash": EXACT_SETTLEMENT_TX,
            "transactionStatus": int(receipt["status"], 16),
            "block": settlement_meta,
            "decodedRedeemOrder": exact_redeem,
            "vaultEventsInReceipt": receipt_events,
        },
        "eventCounts": {name: sum(1 for event in events if event["event"] == name) for name in TOPICS},
        "redeemEvents": redeem_events,
        "dealBadDebtEvents": deal_events,
        "postExactSettlement": post_exact,
        "orders": orders,
        "collaterals": list(collaterals.values()),
        "logScanProgress": progress,
    }

    (OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (OUT / "EXACT_RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    (OUT / "RAW_LOGS.json").write_text(json.dumps(logs, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# TermMax public read-only snapshot",
        "",
        f"- RPC: `{url}`",
        f"- Latest block: `{latest}`",
        f"- Vault: `{VAULT}`",
        f"- Implementation: `{implementation}`",
        f"- Exact settlement block: `{settlement_block}`",
        f"- Exact RedeemOrder: `{json.dumps(exact_redeem, sort_keys=True)}`",
        f"- RedeemOrder count: `{len(redeem_events)}`",
        f"- DealBadDebt count: `{len(deal_events)}`",
        f"- Deposits after exact settlement: `{len(post_exact['deposits'])}`",
        f"- Withdrawals after exact settlement: `{len(post_exact['withdrawals'])}`",
        f"- Current collateral buckets: `{json.dumps(list(collaterals.values()), sort_keys=True)}`",
        "",
        "No transaction was signed or broadcast.",
    ]
    (OUT / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "PASS",
        "latestBlock": latest,
        "exactRedeemOrder": exact_redeem,
        "redeemCount": len(redeem_events),
        "dealBadDebtCount": len(deal_events),
        "postSettlementDeposits": len(post_exact["deposits"]),
        "postSettlementWithdrawals": len(post_exact["withdrawals"]),
        "collateralBuckets": len(collaterals),
    }, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "FATAL.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        print(f"FATAL: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
