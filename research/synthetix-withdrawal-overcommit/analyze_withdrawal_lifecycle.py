#!/usr/bin/env python3
"""Read-only historical lifecycle analysis for the Synthetix Deposit proxy.

Uses public Ethereum JSON-RPC only. No transaction is signed or submitted. The
output contains public event-level metadata, aggregate latency statistics, and
current request status counts. No private API/account data is accessed.
"""

from __future__ import annotations

import collections
import json
import pathlib
import statistics
import time
import urllib.request
from typing import Any

from eth_abi import decode
from eth_utils import keccak, to_checksum_address

OUT = pathlib.Path("lifecycle_evidence")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
PROXY = to_checksum_address("0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B")
CREATION_BLOCK = 23_739_792
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 20 * 1024 * 1024

REQUESTED_TOPIC = "0x" + keccak(text="WithdrawalRequested(uint256,address,address[],uint256[],uint256)").hex()
STATUS_TOPIC = "0x" + keccak(text="WithdrawalStatusChanged(uint256,address,uint8,uint256)").hex()
STATUS_NAMES = {
    0: "Requested",
    1: "Validated",
    2: "Disbursed",
    3: "Denied",
    4: "Disputed",
    5: "Cancelled",
    6: "Expired",
}
FINAL = {"Disbursed", "Denied", "Cancelled", "Expired"}


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("response too large")
        return json.loads(body)


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            parsed = post_json(url, payload)
            if "error" in parsed:
                error = parsed.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                errors.append(f"{code}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def get_logs(start: int, end: int, topics: list[Any]) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [{"address": PROXY, "fromBlock": hex(start), "toBlock": hex(end), "topics": topics}],
        )
    except Exception:
        if start >= end:
            raise
        midpoint = (start + end) // 2
        return get_logs(start, midpoint, topics) + get_logs(midpoint + 1, end, topics)


def indexed_uint(topic: str) -> int:
    return int(topic, 16)


def indexed_address(topic: str) -> str:
    return to_checksum_address("0x" + topic[-40:])


def percentile(values: list[int], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * p
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def stats(values: list[int]) -> dict[str, Any]:
    return {
        "count": len(values),
        "min": min(values) if values else None,
        "median": statistics.median(values) if values else None,
        "p90": percentile(values, 0.90),
        "p95": percentile(values, 0.95),
        "max": max(values) if values else None,
        "over30s": sum(value >= 30 for value in values),
        "over60s": sum(value >= 60 for value in values),
        "over180s": sum(value >= 180 for value in values),
        "over300s": sum(value >= 300 for value in values),
    }


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    logs = get_logs(CREATION_BLOCK, latest, [[REQUESTED_TOPIC, STATUS_TOPIC]])
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))

    block_timestamps: dict[int, int] = {}

    def timestamp(block_number: int) -> int:
        if block_number not in block_timestamps:
            block = rpc("eth_getBlockByNumber", [hex(block_number), False])
            block_timestamps[block_number] = int(block["timestamp"], 16)
            time.sleep(0.02)
        return block_timestamps[block_number]

    requests: dict[int, dict[str, Any]] = {}
    transaction_requests: dict[str, list[int]] = collections.defaultdict(list)
    status_event_count = 0

    for log in logs:
        topics = log.get("topics", [])
        if not topics:
            continue
        topic0 = str(topics[0]).lower()
        block_number = int(log["blockNumber"], 16)
        ts = timestamp(block_number)
        tx_hash = log["transactionHash"]

        if topic0 == REQUESTED_TOPIC.lower() and len(topics) >= 3:
            request_id = indexed_uint(topics[1])
            user = indexed_address(topics[2])
            data = bytes.fromhex(str(log.get("data", "0x"))[2:])
            decoded = decode(["address[]", "uint256[]", "uint256"], data)
            tokens = [to_checksum_address(value) for value in decoded[0]]
            amounts = [int(value) for value in decoded[1]]
            event_timestamp = int(decoded[2])
            requests[request_id] = {
                "id": request_id,
                "user": user,
                "tokens": tokens,
                "amounts": amounts,
                "requestedBlock": block_number,
                "requestedTimestamp": event_timestamp or ts,
                "requestTx": tx_hash,
                "events": [],
            }
            transaction_requests[tx_hash].append(request_id)

        elif topic0 == STATUS_TOPIC.lower() and len(topics) >= 4:
            status_event_count += 1
            request_id = indexed_uint(topics[1])
            user = indexed_address(topics[2])
            status_value = indexed_uint(topics[3])
            status_name = STATUS_NAMES.get(status_value, f"Unknown({status_value})")
            reason = int(str(log.get("data", "0x0")), 16)
            entry = requests.setdefault(
                request_id,
                {
                    "id": request_id,
                    "user": user,
                    "tokens": [],
                    "amounts": [],
                    "requestedBlock": None,
                    "requestedTimestamp": None,
                    "requestTx": None,
                    "events": [],
                },
            )
            entry["events"].append(
                {
                    "status": status_name,
                    "block": block_number,
                    "timestamp": ts,
                    "transactionHash": tx_hash,
                    "reasonCode": reason,
                }
            )

    validation_latencies: list[int] = []
    final_latencies: list[int] = []
    validated_to_final: list[int] = []
    final_status_counts: collections.Counter[str] = collections.Counter()
    current_status_counts: collections.Counter[str] = collections.Counter()
    unresolved: list[dict[str, Any]] = []

    for request in requests.values():
        requested_at = request.get("requestedTimestamp")
        events = request.get("events", [])
        first_validated = next((event for event in events if event["status"] == "Validated"), None)
        final_event = next((event for event in events if event["status"] in FINAL), None)
        current_status = events[-1]["status"] if events else "Requested"
        current_status_counts[current_status] += 1

        if requested_at is not None and first_validated:
            validation_latencies.append(max(0, int(first_validated["timestamp"]) - int(requested_at)))
        if requested_at is not None and final_event:
            final_latencies.append(max(0, int(final_event["timestamp"]) - int(requested_at)))
            final_status_counts[final_event["status"]] += 1
        if first_validated and final_event:
            validated_to_final.append(max(0, int(final_event["timestamp"]) - int(first_validated["timestamp"])))

        if current_status not in FINAL:
            unresolved.append(
                {
                    "id": request["id"],
                    "status": current_status,
                    "ageSecondsAtSnapshot": latest and max(0, timestamp(latest) - int(requested_at or timestamp(latest))),
                    "requestTx": request.get("requestTx"),
                }
            )

    multi_request_batches: list[dict[str, Any]] = []
    for tx_hash, request_ids in transaction_requests.items():
        if len(request_ids) <= 1:
            continue
        users = [requests[request_id]["user"] for request_id in request_ids]
        multi_request_batches.append(
            {
                "transactionHash": tx_hash,
                "requestCount": len(request_ids),
                "distinctDestinationCount": len(set(users)),
                "requestIds": request_ids,
            }
        )

    summary = {
        "safety": "Public Ethereum JSON-RPC event and block reads only; no transaction signed or submitted.",
        "proxy": PROXY,
        "creationBlock": CREATION_BLOCK,
        "latestBlock": latest,
        "requestedEventCount": sum(1 for request in requests.values() if request.get("requestTx")),
        "statusEventCount": status_event_count,
        "currentStatusCounts": dict(current_status_counts),
        "finalStatusCounts": dict(final_status_counts),
        "requestToValidationSeconds": stats(validation_latencies),
        "requestToFinalSeconds": stats(final_latencies),
        "validationToFinalSeconds": stats(validated_to_final),
        "multiRequestBatchCount": len(multi_request_batches),
        "maxRequestsInSingleTransaction": max((item["requestCount"] for item in multi_request_batches), default=1),
        "maxDistinctDestinationsInSingleTransaction": max(
            (item["distinctDestinationCount"] for item in multi_request_batches), default=1
        ),
        "unresolvedCount": len(unresolved),
        "unresolved": unresolved,
    }

    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (OUT / "multi_request_batches.json").write_text(json.dumps(multi_request_batches, indent=2), encoding="utf-8")
    (OUT / "requests.json").write_text(json.dumps(sorted(requests.values(), key=lambda item: item["id"]), indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
