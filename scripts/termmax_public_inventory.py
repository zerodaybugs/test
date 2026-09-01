#!/usr/bin/env python3
"""Read-only public Ethereum inventory for TermMax V2 markets, vaults and orders."""
import json
import os
import time
import urllib.request
from pathlib import Path

OUT = Path(os.environ.get("OUT_DIR", "termmax-public-inventory"))
OUT.mkdir(parents=True, exist_ok=True)
START_BLOCK = int(os.environ.get("START_BLOCK", "22000000"))
ENDPOINTS = [
    x for x in os.environ.get("RPC_CANDIDATES", "").split() if x
] or [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://1rpc.io/eth",
    "https://eth.drpc.org",
    "https://cloudflare-eth.com",
]

TOPIC_MARKET_CREATED = "0x3f544a0e66146e1c515b04e3d00d07fabc299aa08db26f13ae0a2e3797503286"
TOPIC_VAULT_CREATED = "0xbec73c77ba89c2c3ae92a9b6b0fd32d6702691976f3c31962a992499b08549e4"
TOPIC_NEW_ORDER = "0x3ca4bef6cb680238d8c3dcdcca83a5aadcadff2571d3a2c67ee85b2750944b97"
TOPIC_REDEEM_ORDER = "0x21f71f6609f50b01dbe90a67add86958b134ef6fa7e8c668df45730004806242"
TOPIC_WITHDRAW_FTS = "0x53239297447654f3a1c8342314051bc2fe9134b7bbe4a390eade008bb5eca1f2"

SEL = {
    "asset": "0x38d52e0f",
    "totalAssets": "0x01e1d114",
    "totalSupply": "0x18160ddd",
    "name": "0x06fdde03",
    "symbol": "0x95d89b41",
    "decimals": "0x313ce567",
    "curator": "0xe66f53b7",
    "guardian": "0x452a9320",
    "paused": "0x5c975abb",
    "performanceFeeRate": "0x0ffbfda4",
    "pool": "0x16f0115b",
    "tokens": "0x9d63848a",
    "config": "0x79502c55",
    "market": "0x80f55605",
    "tokenReserves": "0x4bad9510",
    "getRealReserves": "0xd5501b0b",
    "virtualXtReserve": "0x07e470f3",
    "orderExpiryTimestamp": "0x3a0d3561",
}
SEL_ADDR = {
    "maxDeposit": "0x402d267d",
    "badDebtMapping": "0x618f9694",
    "orderMaturity": "0xac33207f",
    "balanceOf": "0x70a08231",
}

raw = {"endpointTests": [], "rpc": [], "logProgress": {}}
request_id = 0


def rpc_url(url, method, params, timeout=60, record=True):
    global request_id
    request_id += 1
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "termmax-public-inventory/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        obj = json.loads(response.read().decode())
    if record:
        raw["rpc"].append({"method": method, "params": params, "response": obj})
    if "error" in obj:
        raise RuntimeError(f"{method}: {obj['error']}")
    return obj["result"]


def choose_endpoint():
    for url in ENDPOINTS:
        try:
            chain = rpc_url(url, "eth_chainId", [], record=False)
            latest = rpc_url(url, "eth_blockNumber", [], record=False)
            ok = int(chain, 16) == 1
            raw["endpointTests"].append({"url": url, "chainId": chain, "latest": latest, "ok": ok})
            if ok:
                return url, int(latest, 16)
        except Exception as exc:
            raw["endpointTests"].append({"url": url, "ok": False, "error": repr(exc)})
    raise RuntimeError("No working Ethereum RPC endpoint")


def get_logs_adaptive(url, from_block, to_block, topics, label, address=None):
    logs = []
    progress = []
    current = from_block
    span = 50_000
    while current <= to_block:
        end = min(current + span - 1, to_block)
        filt = {"fromBlock": hex(current), "toBlock": hex(end), "topics": topics}
        if address is not None:
            filt["address"] = address
        try:
            part = rpc_url(url, "eth_getLogs", [filt], timeout=90, record=False)
            logs.extend(part)
            progress.append({"from": current, "to": end, "count": len(part), "span": span})
            current = end + 1
            if len(part) < 100 and span < 100_000:
                span = min(span * 2, 100_000)
        except Exception as exc:
            progress.append({"from": current, "to": end, "span": span, "error": repr(exc)})
            if span <= 100:
                raise
            span = max(span // 2, 100)
        if len(progress) % 25 == 0:
            (OUT / f"{label}_progress.json").write_text(json.dumps(progress, indent=2))
    raw["logProgress"][label] = progress
    (OUT / f"{label}_progress.json").write_text(json.dumps(progress, indent=2))
    return logs


def address_from_topic(topic):
    return "0x" + topic[-40:]


def word_chunks(data):
    if not data or data == "0x":
        return []
    blob = data[2:]
    return [blob[i : i + 64] for i in range(0, len(blob), 64)]


def uint_from_result(data, index=0):
    words = word_chunks(data)
    return int(words[index], 16) if len(words) > index else None


def bool_from_result(data):
    value = uint_from_result(data)
    return bool(value) if value is not None else None


def address_from_result(data, index=0):
    words = word_chunks(data)
    return "0x" + words[index][-40:] if len(words) > index else None


def string_from_result(data):
    if not data or data == "0x":
        return None
    blob = bytes.fromhex(data[2:])
    try:
        if len(blob) >= 64:
            offset = int.from_bytes(blob[:32], "big")
            if offset + 32 <= len(blob):
                length = int.from_bytes(blob[offset : offset + 32], "big")
                return blob[offset + 32 : offset + 32 + length].decode("utf-8", "replace").strip("\x00")
        return blob[:32].rstrip(b"\x00").decode("utf-8", "replace")
    except Exception:
        return None


def arg_address(selector, address):
    return selector + address.lower().replace("0x", "").rjust(64, "0")


def eth_call(url, to, data, block_hex):
    return rpc_url(url, "eth_call", [{"to": to, "data": data}, block_hex], record=False)


def safe_call(url, to, data, block_hex):
    try:
        return eth_call(url, to, data, block_hex)
    except Exception as exc:
        return {"error": repr(exc)}


def static_u(url, to, selector, block_hex):
    result = safe_call(url, to, selector, block_hex)
    return result if isinstance(result, dict) else uint_from_result(result)


def static_a(url, to, selector, block_hex):
    result = safe_call(url, to, selector, block_hex)
    return result if isinstance(result, dict) else address_from_result(result)


def static_s(url, to, selector, block_hex):
    result = safe_call(url, to, selector, block_hex)
    return result if isinstance(result, dict) else string_from_result(result)


def address_arg_u(url, to, selector, arg, block_hex):
    result = safe_call(url, to, arg_address(selector, arg), block_hex)
    return result if isinstance(result, dict) else uint_from_result(result)


def decode_clone_implementation(code):
    if not code or code == "0x":
        return None
    body = code[2:].lower()
    marker = "363d3d373d3d3d363d73"
    pos = body.find(marker)
    if pos >= 0 and len(body) >= pos + len(marker) + 40:
        return "0x" + body[pos + len(marker) : pos + len(marker) + 40]
    return None


def token_info(url, token, block_hex):
    if not token or token.lower() == "0x" + "0" * 40:
        return None
    return {
        "address": token,
        "name": static_s(url, token, SEL["name"], block_hex),
        "symbol": static_s(url, token, SEL["symbol"], block_hex),
        "decimals": static_u(url, token, SEL["decimals"], block_hex),
        "totalSupply": static_u(url, token, SEL["totalSupply"], block_hex),
    }


url, latest = choose_endpoint()
block_hex = hex(latest)
block_obj = rpc_url(url, "eth_getBlockByNumber", [block_hex, False], record=False)
snapshot = {
    "endpoint": url,
    "chainId": 1,
    "block": latest,
    "blockHex": block_hex,
    "blockHash": block_obj["hash"],
    "timestamp": int(block_obj["timestamp"], 16),
    "startBlock": START_BLOCK,
}

market_logs = get_logs_adaptive(url, START_BLOCK, latest, [TOPIC_MARKET_CREATED], "market_created")
vault_logs = get_logs_adaptive(url, START_BLOCK, latest, [TOPIC_VAULT_CREATED], "vault_created")
(OUT / "MARKET_CREATED_LOGS.json").write_text(json.dumps(market_logs, indent=2))
(OUT / "VAULT_CREATED_LOGS.json").write_text(json.dumps(vault_logs, indent=2))

markets_by_address = {}
for log in market_logs:
    if len(log.get("topics", [])) < 4:
        continue
    market = address_from_topic(log["topics"][1])
    markets_by_address[market.lower()] = {
        "market": market,
        "collateralFromEvent": address_from_topic(log["topics"][2]),
        "debtFromEvent": address_from_topic(log["topics"][3]),
        "factory": log["address"],
        "createdBlock": int(log["blockNumber"], 16),
        "createdTx": log["transactionHash"],
    }

vaults = []
for log in vault_logs:
    if len(log.get("topics", [])) < 3:
        continue
    vaults.append(
        {
            "vault": address_from_topic(log["topics"][1]),
            "creator": address_from_topic(log["topics"][2]),
            "factory": log["address"],
            "createdBlock": int(log["blockNumber"], 16),
            "createdTx": log["transactionHash"],
        }
    )

market_cache = {}
token_cache = {}


def read_market(market):
    key = market.lower()
    if key in market_cache:
        return market_cache[key]
    base = markets_by_address.get(key, {"market": market})
    tokens_raw = safe_call(url, market, SEL["tokens"], block_hex)
    token_words = word_chunks(tokens_raw) if isinstance(tokens_raw, str) else []
    tokens = ["0x" + word[-40:] for word in token_words[:5]] if len(token_words) >= 5 else [None] * 5
    config_raw = safe_call(url, market, SEL["config"], block_hex)
    config_words = word_chunks(config_raw) if isinstance(config_raw, str) else []
    maturity = int(config_words[1], 16) if len(config_words) >= 2 else None
    name = static_s(url, market, SEL["name"], block_hex)
    ft, xt, gt, collateral, debt = tokens
    for token in [ft, xt, collateral, debt]:
        if token and token.lower() not in token_cache:
            token_cache[token.lower()] = token_info(url, token, block_hex)
    code = rpc_url(url, "eth_getCode", [market, block_hex], record=False)
    info = {
        **base,
        "name": name,
        "tokens": {"ft": ft, "xt": xt, "gt": gt, "collateral": collateral, "debt": debt},
        "maturity": maturity,
        "matured": maturity is not None and snapshot["timestamp"] >= maturity,
        "codeBytes": max((len(code) - 2) // 2, 0),
        "cloneImplementation": decode_clone_implementation(code),
        "marketDebtBalance": address_arg_u(url, debt, SEL_ADDR["balanceOf"], market, block_hex) if debt else None,
        "gtCollateralBalance": address_arg_u(url, collateral, SEL_ADDR["balanceOf"], gt, block_hex) if collateral and gt else None,
        "gtTotalSupply": static_u(url, gt, SEL["totalSupply"], block_hex) if gt else None,
    }
    market_cache[key] = info
    return info


vault_results = []
for vault_meta in vaults:
    vault = vault_meta["vault"]
    created = vault_meta["createdBlock"]
    event_logs = get_logs_adaptive(
        url,
        created,
        latest,
        [[TOPIC_NEW_ORDER, TOPIC_REDEEM_ORDER, TOPIC_WITHDRAW_FTS]],
        f"vault_{vault.lower()}_events",
        address=vault,
    )
    new_orders = []
    redeem_events = []
    withdraw_ft_events = []
    for log in event_logs:
        topic0 = log["topics"][0].lower()
        if topic0 == TOPIC_NEW_ORDER.lower() and len(log["topics"]) >= 4:
            new_orders.append(
                {
                    "caller": address_from_topic(log["topics"][1]),
                    "market": address_from_topic(log["topics"][2]),
                    "order": address_from_topic(log["topics"][3]),
                    "block": int(log["blockNumber"], 16),
                    "tx": log["transactionHash"],
                }
            )
        elif topic0 == TOPIC_REDEEM_ORDER.lower() and len(log["topics"]) >= 3:
            words = word_chunks(log.get("data", "0x"))
            redeem_events.append(
                {
                    "caller": address_from_topic(log["topics"][1]),
                    "order": address_from_topic(log["topics"][2]),
                    "badDebt": int(words[0], 16) if len(words) > 0 else None,
                    "deliveryAmount": int(words[1], 16) if len(words) > 1 else None,
                    "block": int(log["blockNumber"], 16),
                    "tx": log["transactionHash"],
                }
            )
        elif topic0 == TOPIC_WITHDRAW_FTS.lower() and len(log["topics"]) >= 4:
            words = word_chunks(log.get("data", "0x"))
            withdraw_ft_events.append(
                {
                    "caller": address_from_topic(log["topics"][1]),
                    "recipient": address_from_topic(log["topics"][2]),
                    "order": address_from_topic(log["topics"][3]),
                    "amount": int(words[0], 16) if len(words) > 0 else None,
                    "shares": int(words[1], 16) if len(words) > 1 else None,
                    "block": int(log["blockNumber"], 16),
                    "tx": log["transactionHash"],
                }
            )

    asset = static_a(url, vault, SEL["asset"], block_hex)
    code = rpc_url(url, "eth_getCode", [vault, block_hex], record=False)
    vault_info = {
        **vault_meta,
        "name": static_s(url, vault, SEL["name"], block_hex),
        "symbol": static_s(url, vault, SEL["symbol"], block_hex),
        "asset": asset,
        "assetInfo": token_info(url, asset, block_hex) if isinstance(asset, str) else None,
        "totalAssets": static_u(url, vault, SEL["totalAssets"], block_hex),
        "totalSupply": static_u(url, vault, SEL["totalSupply"], block_hex),
        "maxDeposit": address_arg_u(url, vault, SEL_ADDR["maxDeposit"], "0x" + "0" * 40, block_hex),
        "paused": bool_from_result(safe_call(url, vault, SEL["paused"], block_hex)) if isinstance(safe_call(url, vault, SEL["paused"], block_hex), str) else safe_call(url, vault, SEL["paused"], block_hex),
        "curator": static_a(url, vault, SEL["curator"], block_hex),
        "guardian": static_a(url, vault, SEL["guardian"], block_hex),
        "performanceFeeRate": static_u(url, vault, SEL["performanceFeeRate"], block_hex),
        "pool": static_a(url, vault, SEL["pool"], block_hex),
        "codeBytes": max((len(code) - 2) // 2, 0),
        "cloneImplementation": decode_clone_implementation(code),
        "orderCount": len(new_orders),
        "withdrawFtsEventCount": len(withdraw_ft_events),
        "redeemOrderEventCount": len(redeem_events),
        "withdrawFtsEvents": withdraw_ft_events,
        "redeemOrderEvents": redeem_events,
        "orders": [],
    }

    for order_meta in new_orders:
        order = order_meta["order"]
        market = order_meta["market"]
        market_info = read_market(market)
        ft = market_info.get("tokens", {}).get("ft")
        collateral = market_info.get("tokens", {}).get("collateral")
        reserves_raw = safe_call(url, order, SEL["tokenReserves"], block_hex)
        real_raw = safe_call(url, order, SEL["getRealReserves"], block_hex)
        reserve_words = word_chunks(reserves_raw) if isinstance(reserves_raw, str) else []
        real_words = word_chunks(real_raw) if isinstance(real_raw, str) else []
        order_code = rpc_url(url, "eth_getCode", [order, block_hex], record=False)
        order_info = {
            **order_meta,
            "marketState": market_info,
            "marketGetter": static_a(url, order, SEL["market"], block_hex),
            "tokenReserves": {
                "ft": int(reserve_words[0], 16) if len(reserve_words) > 0 else None,
                "xt": int(reserve_words[1], 16) if len(reserve_words) > 1 else None,
            },
            "realReserves": {
                "ft": int(real_words[0], 16) if len(real_words) > 0 else None,
                "xt": int(real_words[1], 16) if len(real_words) > 1 else None,
            },
            "virtualXtReserve": static_u(url, order, SEL["virtualXtReserve"], block_hex),
            "orderExpiryTimestamp": static_u(url, order, SEL["orderExpiryTimestamp"], block_hex),
            "pool": static_a(url, order, SEL["pool"], block_hex),
            "ftBalance": address_arg_u(url, ft, SEL_ADDR["balanceOf"], order, block_hex) if ft else None,
            "vaultBadDebtForCollateral": address_arg_u(url, vault, SEL_ADDR["badDebtMapping"], collateral, block_hex) if collateral else None,
            "vaultOrderMaturity": address_arg_u(url, vault, SEL_ADDR["orderMaturity"], order, block_hex),
            "codeBytes": max((len(order_code) - 2) // 2, 0),
            "cloneImplementation": decode_clone_implementation(order_code),
            "redeemEvents": [x for x in redeem_events if x["order"].lower() == order.lower()],
            "withdrawFtsEvents": [x for x in withdraw_ft_events if x["order"].lower() == order.lower()],
        }
        vault_info["orders"].append(order_info)
    vault_results.append(vault_info)

# Include markets not referenced by a vault as well.
for market in list(markets_by_address.values()):
    read_market(market["market"])

summary = {
    "snapshot": snapshot,
    "marketCount": len(market_cache),
    "vaultCount": len(vault_results),
    "multiOrderVaultCount": sum(1 for v in vault_results if v["orderCount"] >= 2),
    "positiveTvlVaultCount": sum(1 for v in vault_results if isinstance(v.get("totalAssets"), int) and v["totalAssets"] > 0),
    "vaultsWithCurrentBadDebt": [
        v["vault"]
        for v in vault_results
        if any(isinstance(o.get("vaultBadDebtForCollateral"), int) and o["vaultBadDebtForCollateral"] > 0 for o in v["orders"])
    ],
    "vaultsWithWithdrawFtsHistory": [v["vault"] for v in vault_results if v["withdrawFtsEventCount"] > 0],
    "vaults": [
        {
            "vault": v["vault"],
            "name": v["name"],
            "asset": v["asset"],
            "totalAssets": v["totalAssets"],
            "totalSupply": v["totalSupply"],
            "orderCount": v["orderCount"],
            "withdrawFtsEventCount": v["withdrawFtsEventCount"],
            "redeemOrderEventCount": v["redeemOrderEventCount"],
            "currentBadDebtOrders": sum(
                1 for o in v["orders"] if isinstance(o.get("vaultBadDebtForCollateral"), int) and o["vaultBadDebtForCollateral"] > 0
            ),
        }
        for v in vault_results
    ],
}

(OUT / "SNAPSHOT.json").write_text(json.dumps(snapshot, indent=2))
(OUT / "MARKETS.json").write_text(json.dumps(list(market_cache.values()), indent=2))
(OUT / "TOKENS.json").write_text(json.dumps(list(token_cache.values()), indent=2))
(OUT / "VAULTS.json").write_text(json.dumps(vault_results, indent=2))
(OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2))
(OUT / "RPC_AND_PROGRESS.json").write_text(json.dumps(raw, indent=2))
print(json.dumps(summary, indent=2))
