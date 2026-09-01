#!/usr/bin/env python3
"""Read-only historical lifecycle analysis for the Synthetix Deposit proxy.

Uses public Ethereum JSON-RPC only. No transaction is signed or submitted. The
output contains public event metadata and aggregate latency statistics. The
collector checkpoints progress and preserves diagnostics on any failure.
"""

from __future__ import annotations

import collections
import hashlib
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
CHUNK = 50_000
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 20 * 1024 * 1024

REQUESTED_TOPIC = "0x" + keccak(text="WithdrawalRequested(uint256,address,address[],uint256[],uint256)").hex()
STATUS_TOPIC = "0x" + keccak(text="WithdrawalStatusChanged(uint256,address,uint8,uint256)").hex()
STATUS_NAMES = {0: "Requested", 1: "Validated", 2: "Disbursed", 3: "Denied", 4: "Disputed", 5: "Cancelled", 6: "Expired"}
FINAL = {"Disbursed", "Denied", "Cancelled", "Expired"}

DIAG: dict[str, Any] = {
    "stage": "initializing",
    "rpcCalls": 0,
    "rangesAttempted": 0,
    "rangesCompleted": 0,
    "logCount": 0,
    "decodeErrors": [],
    "blockReads": 0,
}


def checkpoint() -> None:
    (OUT / "progress.json").write_text(json.dumps(DIAG, indent=2), encoding="utf-8")


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
    DIAG["rpcCalls"] += 1
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


def collect_logs(latest: int) -> list[dict[str, Any]]:
    DIAG["stage"] = "collecting_logs"
    logs: list[dict[str, Any]] = []
    start = CREATION_BLOCK
    while start <= latest:
        end = min(latest, start + CHUNK - 1)
        DIAG["rangesAttempted"] += 1
        result = rpc(
            "eth_getLogs",
            [{
                "address": PROXY,
                "fromBlock": hex(start),
                "toBlock": hex(end),
                "topics": [[REQUESTED_TOPIC, STATUS_TOPIC]],
            }],
        )
        logs.extend(result)
        DIAG["rangesCompleted"] += 1
        DIAG["logCount"] = len(logs)
        checkpoint()
        start = end + 1
        time.sleep(0.05)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))
    return logs


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


def run() -> dict[str, Any]:
    latest = int(rpc("eth_blockNumber", []), 16)
    DIAG["latestBlock"] = latest
    checkpoint()
    logs = collect_logs(latest)

    DIAG["stage"] = "decoding_events"
    block_timestamps: dict[int, int] = {}

    def timestamp(block_number: int) -> int:
        if block_number not in block_timestamps:
            block = rpc("eth_getBlockByNumber", [hex(block_number), False])
            block_timestamps[block_number] = int(block["timestamp"], 16)
            DIAG["blockReads"] += 1
        return block_timestamps[block_number]

    requests: dict[int, dict[str, Any]] = {}
    transaction_requests: dict[str, list[int]] = collections.defaultdict(list)
    status_event_count = 0

    for index, log in enumerate(logs):
        try:
            topics = log.get("topics", [])
            if not topics:
                continue
            topic0 = str(topics[0]).lower()
            block_number = int(log["blockNumber"], 16)
            ts = timestamp(block_number)
            tx_hash = log["transactionHash"]

            if topic0 == REQUESTED_TOPIC.lower() and len(topics) >= 3:
                request_id = int(topics[1], 16)
                user = indexed_address(topics[2])
                raw = bytes.fromhex(str(log.get("data", "0x"))[2:])
                tokens_raw, amounts_raw, event_timestamp_raw = decode(["address[]", "uint256[]", "uint256"], raw)
                requests[request_id] = {
                    "id": request_id,
                    "user": user,
                    "tokens": [to_checksum_address(value) for value in tokens_raw],
                    "amounts": [int(value) for value in amounts_raw],
                    "requestedBlock": block_number,
                    "requestedTimestamp": int(event_timestamp_raw) or ts,
                    "requestTx": tx_hash,
                    "events": [],
                }
                transaction_requests[tx_hash].append(request_id)

            elif topic0 == STATUS_TOPIC.lower() and len(topics) >= 4:
                status_event_count += 1
                request_id = int(topics[1], 16)
                user = indexed_address(topics[2])
                status_value = int(topics[3], 16)
                data_hex = str(log.get("data", "0x0"))
                reason = int(data_hex, 16) if data_hex not in ("0x", "") else 0
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
                entry["events"].append({
                    "status": STATUS_NAMES.get(status_value, f"Unknown({status_value})"),
                    "block": block_number,
                    "timestamp": ts,
                    "transactionHash": tx_hash,
                    "reasonCode": reason,
                })
        except Exception as exc:  # noqa: BLE001
            DIAG["decodeErrors"].append({
                "index": index,
                "transactionHash": log.get("transactionHash"),
                "errorType": type(exc).__name__,
                "errorSha256": hashlib.sha256(str(exc).encode()).hexdigest(),
            })
        if index % 25 == 0:
            DIAG["decodedEvents"] = index + 1
            checkpoint()

    latest_timestamp = timestamp(latest)
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
            unresolved.append({
                "id": request["id"],
                "status": current_status,
                "ageSecondsAtSnapshot": max(0, latest_timestamp - int(requested_at or latest_timestamp)),
                "requestTx": request.get("requestTx"),
            })

    multi_request_batches: list[dict[str, Any]] = []
    for tx_hash, request_ids in transaction_requests.items():
        if len(request_ids) <= 1:
            continue
        users = [requests[request_id]["user"] for request_id in request_ids]
        multi_request_batches.append({
            "transactionHash": tx_hash,
            "requestCount": len(request_ids),
            "distinctDestinationCount": len(set(users)),
            "requestIds": request_ids,
        })

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
        "maxDistinctDestinationsInSingleTransaction": max((item["distinctDestinationCount"] for item in multi_request_batches), default=1),
        "unresolvedCount": len(unresolved),
        "unresolved": unresolved,
        "diagnostics": DIAG,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (OUT / "multi_request_batches.json").write_text(json.dumps(multi_request_batches, indent=2), encoding="utf-8")
    (OUT / "requests.json").write_text(json.dumps(sorted(requests.values(), key=lambda item: item["id"]), indent=2), encoding="utf-8")
    DIAG["stage"] = "completed"
    checkpoint()
    return summary


def main() -> None:
    try:
        result = run()
    except BaseException as exc:  # noqa: BLE001
        DIAG["stage"] = "failed"
        DIAG["failureType"] = type(exc).__name__
        DIAG["failureSha256"] = hashlib.sha256(str(exc).encode()).hexdigest()
        checkpoint()
        result = {
            "safety": "Public Ethereum JSON-RPC reads only; no transaction signed or submitted.",
            "completed": False,
            "diagnostics": DIAG,
        }
        (OUT / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
