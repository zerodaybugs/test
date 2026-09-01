#!/usr/bin/env python3
"""Read-only OracleAggregator configuration event history for Prime Yield assets."""
from __future__ import annotations

import datetime as dt
import json
import time
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("termmax-prime-oracle-history")
RPCS = [
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://ethereum-rpc.publicnode.com",
]
ORACLE = "0xe3a31690392e8e18dc3d862651c079339e2c1ade"
START_BLOCK = 23_000_000
ASSETS = {
    "wstrBTC": "0xa3ca88cfb7bbe9cfbd47df053ffa2130c7e6f770",
    "strBTC": "0xb2723d5df98689eca6a4e7321121662ddb9b3017",
    "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
}
TOPICS = {
    "UpdateOracle": "0x1fde9522e8fecea62ddfd7a16a09129167e338cfdce86f3b8742a7aacaf34535",
    "SubmitPendingOracle": "0x3fa96d5be1017ee5b004406bdd188cafc8b272e02d02e80dfae54d13ab6524e6",
    "RevokePendingOracle": "0xdd57585963a156fef3b0e5cefd9f863861b2ba7de76e2ad31c7bed65d741c446",
}


def rpc_one(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json", "user-agent": "termmax-prime-oracle-history/1.0"},
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


def uint_word(data: str, index: int = 0) -> int:
    raw = (data or "0x").removeprefix("0x")
    part = raw[index * 64 : (index + 1) * 64].ljust(64, "0")
    return int(part or "0", 16)


def topic_address(topic: str) -> str:
    return "0x" + topic.removeprefix("0x")[-40:].lower()


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


def get_logs(latest: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    logs: list[dict[str, Any]] = []
    progress: list[dict[str, Any]] = []
    current = START_BLOCK
    span = 250_000
    while current <= latest:
        end = min(latest, current + span - 1)
        query = {
            "address": ORACLE,
            "fromBlock": hex(current),
            "toBlock": hex(end),
            "topics": [list(TOPICS.values())],
        }
        try:
            part, url = rpc("eth_getLogs", [query])
            logs.extend(part)
            progress.append({"from": current, "to": end, "span": span, "count": len(part), "rpc": url})
            current = end + 1
            if len(part) < 100:
                span = min(500_000, span * 2)
        except Exception as exc:
            progress.append({"from": current, "to": end, "span": span, "error": str(exc)})
            if span <= 1_000:
                raise
            span = max(1_000, span // 2)
        time.sleep(0.02)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))
    return logs, progress


def decode(log: dict[str, Any]) -> dict[str, Any]:
    topic0 = log["topics"][0].lower()
    event = next((name for name, topic in TOPICS.items() if topic == topic0), "Unknown")
    topics = log.get("topics", [])
    data = log.get("data", "0x")
    result: dict[str, Any] = {
        "event": event,
        "blockNumber": int(log["blockNumber"], 16),
        "transactionHash": log["transactionHash"],
        "logIndex": int(log["logIndex"], 16),
    }
    if len(topics) >= 2:
        result["asset"] = topic_address(topics[1])
        result["assetLabel"] = next((name for name, address in ASSETS.items() if address == result["asset"]), None)
    if event in ("UpdateOracle", "SubmitPendingOracle") and len(topics) >= 4:
        result["aggregator"] = topic_address(topics[2])
        result["backupAggregator"] = topic_address(topics[3])
        result["heartbeat"] = uint_word(data, 0)
        if event == "SubmitPendingOracle":
            result["validAt"] = uint_word(data, 1)
    return result


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    latest_hex, _ = rpc("eth_blockNumber", [])
    latest = int(latest_hex, 16)
    raw_logs, progress = get_logs(latest)
    events = [decode(log) for log in raw_logs]
    relevant = [event for event in events if event.get("asset") in set(ASSETS.values())]
    blocks = sorted({event["blockNumber"] for event in relevant})
    metadata = {str(block): block_meta(block) for block in blocks}
    for event in relevant:
        event["block"] = metadata[str(event["blockNumber"])]
    result = {
        "schema": "termmax-prime-oracle-history/v1",
        "generatedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "safety": {"signedTransactions": 0, "broadcastTransactions": 0},
        "oracle": ORACLE,
        "startBlock": START_BLOCK,
        "latestBlock": block_meta(latest),
        "scanProgress": progress,
        "allOracleEvents": events,
        "relevantEvents": relevant,
        "status": "PASS",
    }
    (OUT / "SUMMARY.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    concise = {
        "status": "PASS",
        "allEventCount": len(events),
        "relevantEventCount": len(relevant),
        "relevantEvents": relevant,
    }
    (OUT / "CONCISE.json").write_text(json.dumps(concise, indent=2), encoding="utf-8")
    print(json.dumps(concise, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
