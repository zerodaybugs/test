#!/usr/bin/env python3
"""Read-only inspection of TermMax Prime Yield's OracleAggregator mappings and feeds."""
from __future__ import annotations

import datetime as dt
import json
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("termmax-prime-oracle-mapping")
RPCS = [
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://ethereum-rpc.publicnode.com",
]
ORACLE = "0xe3a31690392e8e18dc3d862651c079339e2c1ade"
WST_RBTC = "0xa3ca88cfb7bbe9cfbd47df053ffa2130c7e6f770"
STR_BTC = "0xb2723d5df98689eca6a4e7321121662ddb9b3017"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
SETTLEMENT_BLOCK = 24_826_646

S = {
    "oracles": "0xaddd5099",
    "pendingOracles": "0x98efa279",
    "getPrice": "0x41976e09",
    "latestRoundData": "0xfeaf968c",
    "decimals": "0x313ce567",
    "description": "0x7284e416",
    "version": "0x54fd4d50",
    "owner": "0x8da5cb5b",
}


def rpc_one(url: str, method: str, params: list[Any]) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"content-type": "application/json", "user-agent": "termmax-prime-oracle-readonly/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        body = json.load(response)
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body.get("result")


def rpc(method: str, params: list[Any]) -> tuple[Any, str]:
    errors: list[str] = []
    for url in RPCS:
        try:
            return rpc_one(url, method, params), url
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(" | ".join(errors))


def word(data: str, index: int = 0) -> str:
    raw = (data or "0x").removeprefix("0x")
    return raw[index * 64 : (index + 1) * 64].ljust(64, "0")


def uint(data: str, index: int = 0) -> int:
    return int(word(data, index) or "0", 16)


def signed_uint(data: str, index: int = 0) -> int:
    value = uint(data, index)
    return value - (1 << 256) if value >= (1 << 255) else value


def address_word(data: str, index: int = 0) -> str:
    return "0x" + word(data, index)[-40:].lower()


def arg_address(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64, "0")


def decode_string(data: str) -> str:
    try:
        raw = data.removeprefix("0x")
        offset = int(raw[:64], 16)
        at = offset * 2
        length = int(raw[at : at + 64], 16)
        return bytes.fromhex(raw[at + 64 : at + 64 + length * 2]).decode("utf-8", errors="replace")
    except Exception:
        return ""


def safe_call(to: str, data: str, block: int | str = "latest") -> dict[str, Any]:
    tag = hex(block) if isinstance(block, int) else block
    try:
        raw, url = rpc("eth_call", [{"to": to, "data": data}, tag])
        return {"ok": True, "raw": raw, "rpc": url, "blockTag": tag}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "blockTag": tag}


def safe_code(address: str, block: int | str = "latest") -> dict[str, Any]:
    tag = hex(block) if isinstance(block, int) else block
    try:
        raw, url = rpc("eth_getCode", [address, tag])
        return {"ok": True, "bytes": max(0, (len(raw) - 2) // 2), "raw": raw, "rpc": url, "blockTag": tag}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "blockTag": tag}


def oracle_mapping(asset: str, block: int | str) -> dict[str, Any]:
    response = safe_call(ORACLE, S["oracles"] + arg_address(asset), block)
    if response.get("ok"):
        response["decoded"] = {
            "aggregator": address_word(response["raw"], 0),
            "backupAggregator": address_word(response["raw"], 1),
            "heartbeat": uint(response["raw"], 2),
        }
    pending = safe_call(ORACLE, S["pendingOracles"] + arg_address(asset), block)
    if pending.get("ok"):
        pending["decoded"] = {
            "aggregator": address_word(pending["raw"], 0),
            "backupAggregator": address_word(pending["raw"], 1),
            "heartbeat": uint(pending["raw"], 2),
            "validAt": uint(pending["raw"], 3),
        }
    return {"active": response, "pending": pending}


def feed_state(address: str, block: int | str) -> dict[str, Any]:
    zero = "0x0000000000000000000000000000000000000000"
    if not address or address == zero:
        return {"address": address, "configured": False}
    latest = safe_call(address, S["latestRoundData"], block)
    if latest.get("ok"):
        latest["decoded"] = {
            "roundId": uint(latest["raw"], 0),
            "answer": signed_uint(latest["raw"], 1),
            "startedAt": uint(latest["raw"], 2),
            "updatedAt": uint(latest["raw"], 3),
            "answeredInRound": uint(latest["raw"], 4),
        }
    decimals = safe_call(address, S["decimals"], block)
    if decimals.get("ok"):
        decimals["value"] = uint(decimals["raw"])
    description = safe_call(address, S["description"], block)
    if description.get("ok"):
        description["value"] = decode_string(description["raw"])
    version = safe_call(address, S["version"], block)
    if version.get("ok"):
        version["value"] = uint(version["raw"])
    return {
        "address": address,
        "configured": True,
        "code": safe_code(address, block),
        "latestRoundData": latest,
        "decimals": decimals,
        "description": description,
        "version": version,
    }


def asset_state(label: str, asset: str, block: int | str) -> dict[str, Any]:
    mapping = oracle_mapping(asset, block)
    active = mapping["active"].get("decoded", {}) if mapping["active"].get("ok") else {}
    price = safe_call(ORACLE, S["getPrice"] + arg_address(asset), block)
    if price.get("ok"):
        price["decoded"] = {"price": uint(price["raw"], 0), "decimals": uint(price["raw"], 1)}
    return {
        "label": label,
        "asset": asset,
        "mapping": mapping,
        "aggregator": feed_state(active.get("aggregator", ""), block),
        "backupAggregator": feed_state(active.get("backupAggregator", ""), block),
        "getPrice": price,
    }


def block_meta(number: int) -> dict[str, Any]:
    block, url = rpc("eth_getBlockByNumber", [hex(number), False])
    timestamp = int(block["timestamp"], 16)
    return {
        "number": number,
        "hash": block.get("hash"),
        "timestamp": timestamp,
        "timestampUtc": dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat(),
        "rpc": url,
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    latest_hex, _ = rpc("eth_blockNumber", [])
    latest = int(latest_hex, 16)
    blocks = {
        "settlement": SETTLEMENT_BLOCK,
        "latest": latest,
    }
    result: dict[str, Any] = {
        "schema": "termmax-prime-oracle-mapping/v1",
        "generatedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "safety": {"signedTransactions": 0, "broadcastTransactions": 0},
        "oracle": ORACLE,
        "oracleCode": safe_code(ORACLE),
        "owner": safe_call(ORACLE, S["owner"]),
        "blocks": {name: block_meta(number) for name, number in blocks.items()},
        "snapshots": {},
    }
    for name, number in blocks.items():
        result["snapshots"][name] = {
            "wstrBTC": asset_state("wstrBTC", WST_RBTC, number),
            "strBTC": asset_state("strBTC", STR_BTC, number),
            "USDC": asset_state("USDC", USDC, number),
        }
    current = result["snapshots"]["latest"]
    result["status"] = "PASS" if current["USDC"]["getPrice"].get("ok") else "INCOMPLETE"
    (OUT / "SUMMARY.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    concise = {
        "status": result["status"],
        "wstrBTC": current["wstrBTC"],
        "strBTC": current["strBTC"],
        "USDC": current["USDC"],
    }
    (OUT / "CONCISE.json").write_text(json.dumps(concise, indent=2), encoding="utf-8")
    print(json.dumps(concise, indent=2))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
