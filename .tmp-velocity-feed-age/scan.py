#!/usr/bin/env python3
"""Read-only census of Pyth Lazer envelope time vs feed observation time in Velocity updates."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import random
import struct
import time
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

VELOCITY_PROGRAM = os.environ.get(
    "VELOCITY_PROGRAM", "vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P"
)
SOL_ORACLE = os.environ.get(
    "SOL_ORACLE", "2k3UHX6ehRFzx5fTVvbL6FwXhMjkucjJDL9MuVKLo8TV"
)
LIMIT = min(50000, max(100, int(os.environ.get("SIGNATURE_LIMIT", "20000"))))
WORKERS = min(8, max(1, int(os.environ.get("WORKERS", "6"))))
OUT = Path(os.environ.get("OUT_DIR", "evidence-velocity-feed-age"))
OUT.mkdir(parents=True, exist_ok=True)
RPCS = [
    "https://solana-rpc.publicnode.com",
    "https://api.mainnet-beta.solana.com",
    "https://solana.drpc.org",
    "https://mainnet-beta.solflare.network",
]
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SOLANA_MAGIC = struct.pack("<I", 2182742457)
PAYLOAD_MAGIC = 2479346549


def b58decode(value: str) -> bytes:
    n = 0
    for char in value:
        n = n * 58 + ALPHABET.index(char)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = len(value) - len(value.lstrip("1"))
    return b"\0" * leading + raw


def request(url: str, method: str, params: list[Any], timeout: int = 180) -> Any:
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": random.randint(1, 2**31 - 1),
            "method": method,
            "params": params,
        }
    ).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "content-type": "application/json",
            "user-agent": "ReadOnly-Velocity-Feed-Age-Census/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        result = json.loads(response.read())
    if result.get("error") is not None:
        raise RuntimeError(result["error"])
    return result.get("result")


def select_rpc() -> tuple[str, list[dict[str, Any]]]:
    attempts = []
    for url in RPCS:
        try:
            slot = request(url, "getSlot", [{"commitment": "finalized"}], 60)
            attempts.append({"rpc": url, "ok": True, "slot": slot})
            return url, attempts
        except Exception as exc:
            attempts.append({"rpc": url, "ok": False, "error": repr(exc)})
    raise RuntimeError(attempts)


def fetch_signatures(url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    before = None
    while len(rows) < LIMIT:
        count = min(1000, LIMIT - len(rows))
        opts: dict[str, Any] = {"limit": count, "commitment": "finalized"}
        if before:
            opts["before"] = before
        page = request(url, "getSignaturesForAddress", [SOL_ORACLE, opts], 180)
        if not page:
            break
        rows.extend(page)
        before = page[-1]["signature"]
        print(f"signatures={len(rows)}", flush=True)
        if len(page) < count:
            break
        time.sleep(0.15)
    return rows


def fetch_tx(row: dict[str, Any]) -> tuple[str, Any, str | None]:
    seed = int(row.get("slot", 0)) % len(RPCS)
    providers = RPCS[seed:] + RPCS[:seed]
    params = [
        row["signature"],
        {
            "encoding": "json",
            "commitment": "finalized",
            "maxSupportedTransactionVersion": 0,
        },
    ]
    errors = []
    for round_no in range(3):
        for url in providers:
            try:
                return row["signature"], request(url, "getTransaction", params, 180), url
            except Exception as exc:
                errors.append(f"{url}:{exc!r}")
        time.sleep(0.5 * (2**round_no))
    return row["signature"], None, " | ".join(errors)


def key_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("pubkey"), str):
        return value["pubkey"]
    return str(value)


def resolve_keys(tx: dict[str, Any]) -> list[str]:
    message = tx["transaction"]["message"]
    raw = message.get("accountKeys", message.get("staticAccountKeys", []))
    keys = [key_string(item) for item in raw]
    loaded = (tx.get("meta", {}) or {}).get("loadedAddresses", {}) or {}
    keys.extend(key_string(item) for item in loaded.get("writable", []))
    keys.extend(key_string(item) for item in loaded.get("readonly", []))
    return keys


def resolve_program_id(ix: dict[str, Any], keys: list[str]) -> str | None:
    if isinstance(ix.get("programId"), str):
        return ix["programId"]
    index = ix.get("programIdIndex")
    if isinstance(index, int) and 0 <= index < len(keys):
        return keys[index]
    return None


def read_exact(data: bytes, offset: int, length: int) -> tuple[bytes, int]:
    end = offset + length
    if end > len(data):
        raise ValueError("truncated payload")
    return data[offset:end], end


def read_option_i64(data: bytes, offset: int) -> tuple[int | None, int]:
    present_raw, offset = read_exact(data, offset, 1)
    if present_raw[0] == 0:
        return None, offset
    raw, offset = read_exact(data, offset, 8)
    return struct.unpack("<q", raw)[0], offset


def read_option_u64(data: bytes, offset: int) -> tuple[int | None, int]:
    present_raw, offset = read_exact(data, offset, 1)
    if present_raw[0] == 0:
        return None, offset
    raw, offset = read_exact(data, offset, 8)
    return struct.unpack("<Q", raw)[0], offset


def parse_payload(payload: bytes) -> dict[str, Any]:
    if len(payload) < 14:
        raise ValueError("short payload")
    magic = struct.unpack_from("<I", payload, 0)[0]
    if magic != PAYLOAD_MAGIC:
        raise ValueError(f"payload magic {magic}")
    timestamp_us = struct.unpack_from("<Q", payload, 4)[0]
    channel_id = payload[12]
    num_feeds = payload[13]
    offset = 14
    feeds = []
    for _ in range(num_feeds):
        raw, offset = read_exact(payload, offset, 5)
        feed_id = struct.unpack_from("<I", raw, 0)[0]
        num_properties = raw[4]
        properties: dict[int, Any] = {}
        for _ in range(num_properties):
            prop_raw, offset = read_exact(payload, offset, 1)
            prop = prop_raw[0]
            if prop in {0, 1, 2, 5, 10, 11}:
                raw, offset = read_exact(payload, offset, 8)
                properties[prop] = struct.unpack("<q", raw)[0]
            elif prop == 3:
                raw, offset = read_exact(payload, offset, 2)
                properties[prop] = struct.unpack("<H", raw)[0]
            elif prop == 4:
                raw, offset = read_exact(payload, offset, 2)
                properties[prop] = struct.unpack("<h", raw)[0]
            elif prop == 6:
                properties[prop], offset = read_option_i64(payload, offset)
            elif prop in {7, 8, 12}:
                properties[prop], offset = read_option_u64(payload, offset)
            elif prop == 9:
                raw, offset = read_exact(payload, offset, 2)
                properties[prop] = struct.unpack("<h", raw)[0]
            else:
                raise ValueError(f"unknown property {prop}")
        feeds.append(
            {
                "feedId": feed_id,
                "price": properties.get(0),
                "bestBidPrice": properties.get(1),
                "bestAskPrice": properties.get(2),
                "publisherCount": properties.get(3),
                "exponent": properties.get(4),
                "confidence": properties.get(5),
                "feedUpdateTimestampUs": properties.get(12),
                "properties": properties,
            }
        )
    if offset != len(payload):
        raise ValueError(f"payload trailing bytes {len(payload) - offset}")
    return {
        "payloadTimestampUs": timestamp_us,
        "channelId": channel_id,
        "feeds": feeds,
    }


def extract_messages(data: bytes) -> list[dict[str, Any]]:
    messages = []
    start = 0
    while True:
        index = data.find(SOLANA_MAGIC, start)
        if index < 0:
            break
        start = index + 1
        if index + 102 > len(data):
            continue
        payload_len = struct.unpack_from("<H", data, index + 100)[0]
        end = index + 102 + payload_len
        if end > len(data):
            continue
        message = data[index:end]
        payload = message[102:]
        try:
            parsed = parse_payload(payload)
        except Exception:
            continue
        messages.append(
            {
                "offset": index,
                "bytes": len(message),
                "messageSha256": hashlib.sha256(message).hexdigest(),
                **parsed,
            }
        )
    return messages


def classify_transaction(row: dict[str, Any], tx: dict[str, Any], rpc: str | None) -> list[dict[str, Any]]:
    if (tx.get("meta", {}) or {}).get("err") is not None:
        return []
    keys = resolve_keys(tx)
    message = tx["transaction"]["message"]
    instructions = message.get("instructions", message.get("compiledInstructions", []))
    observations = []
    seen_messages = set()
    for instruction_index, ix in enumerate(instructions):
        if resolve_program_id(ix, keys) != VELOCITY_PROGRAM:
            continue
        value = ix.get("data")
        if not isinstance(value, str):
            continue
        try:
            data = b58decode(value)
        except Exception:
            continue
        for parsed in extract_messages(data):
            if parsed["messageSha256"] in seen_messages:
                continue
            seen_messages.add(parsed["messageSha256"])
            for feed in parsed["feeds"]:
                feed_ts = feed.get("feedUpdateTimestampUs")
                age_us = (
                    parsed["payloadTimestampUs"] - feed_ts
                    if isinstance(feed_ts, int)
                    else None
                )
                observations.append(
                    {
                        "signature": row["signature"],
                        "slot": row.get("slot"),
                        "blockTime": tx.get("blockTime"),
                        "rpc": rpc,
                        "instructionIndex": instruction_index,
                        "messageSha256": parsed["messageSha256"],
                        "messageBytes": parsed["bytes"],
                        "payloadTimestampUs": parsed["payloadTimestampUs"],
                        "channelId": parsed["channelId"],
                        **feed,
                        "feedAgeUs": age_us,
                        "feedAgeSeconds": age_us / 1_000_000 if age_us is not None else None,
                    }
                )
    return observations


def main() -> int:
    selected_rpc, rpc_attempts = select_rpc()
    signatures = fetch_signatures(selected_rpc)
    observations: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(fetch_tx, row): row for row in signatures}
        for count, future in enumerate(concurrent.futures.as_completed(futures), 1):
            row = futures[future]
            try:
                signature, tx, rpc = future.result()
                if tx is None:
                    failures.append({"signature": signature, "detail": rpc})
                else:
                    observations.extend(classify_transaction(row, tx, rpc))
            except Exception as exc:
                failures.append({"signature": row["signature"], "error": repr(exc)})
            if count % 100 == 0:
                print(
                    f"transactions={count}/{len(signatures)} observations={len(observations)} failures={len(failures)}",
                    flush=True,
                )

    age_rows = [row for row in observations if row.get("feedAgeUs") is not None]
    positive_age = [row for row in age_rows if row["feedAgeUs"] > 0]
    groups: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in age_rows:
        groups[(int(row["feedId"]), int(row["feedUpdateTimestampUs"]))].append(row)

    group_rows = []
    for (feed_id, feed_ts), rows in groups.items():
        slots = [int(row["slot"]) for row in rows if row.get("slot") is not None]
        payload_times = [int(row["payloadTimestampUs"]) for row in rows]
        prices = sorted({str(row.get("price")) for row in rows})
        group_rows.append(
            {
                "feedId": feed_id,
                "feedUpdateTimestampUs": str(feed_ts),
                "observations": len(rows),
                "minSlot": min(slots) if slots else None,
                "maxSlot": max(slots) if slots else None,
                "slotSpan": max(slots) - min(slots) if slots else None,
                "minPayloadTimestampUs": str(min(payload_times)),
                "maxPayloadTimestampUs": str(max(payload_times)),
                "maxEnvelopeAgeUs": str(max(payload_times) - feed_ts),
                "maxEnvelopeAgeSeconds": (max(payload_times) - feed_ts) / 1_000_000,
                "distinctPrices": prices,
                "signatures": sorted({row["signature"] for row in rows})[:20],
            }
        )
    group_rows.sort(
        key=lambda row: (
            float(row["maxEnvelopeAgeSeconds"]),
            int(row["slotSpan"] or 0),
            int(row["observations"]),
        ),
        reverse=True,
    )

    top_ages = sorted(
        age_rows,
        key=lambda row: (float(row["feedAgeSeconds"]), int(row.get("slot") or 0)),
        reverse=True,
    )[:100]
    thresholds = [0, 0.2, 1, 5, 15, 30, 48, 60, 120, 300]
    age_threshold_counts = {
        str(value): sum(float(row["feedAgeSeconds"]) >= value for row in age_rows)
        for value in thresholds
    }
    per_feed: dict[str, Any] = {}
    for feed_id in sorted({int(row["feedId"]) for row in age_rows}):
        rows = [row for row in age_rows if int(row["feedId"]) == feed_id]
        per_feed[str(feed_id)] = {
            "observations": len(rows),
            "positiveAgeObservations": sum(row["feedAgeUs"] > 0 for row in rows),
            "maxAgeSeconds": max(float(row["feedAgeSeconds"]) for row in rows),
            "maxAgeWitness": max(rows, key=lambda row: float(row["feedAgeSeconds"])),
        }

    result = {
        "verdict": "COMPLETE",
        "velocityProgram": VELOCITY_PROGRAM,
        "solOracle": SOL_ORACLE,
        "requestedSignatures": LIMIT,
        "receivedSignatures": len(signatures),
        "fetchedFailures": failures,
        "observations": len(observations),
        "observationsWithFeedTimestamp": len(age_rows),
        "positiveFeedAgeObservations": len(positive_age),
        "maxFeedAgeSeconds": max(
            (float(row["feedAgeSeconds"]) for row in age_rows), default=None
        ),
        "ageThresholdCounts": age_threshold_counts,
        "maxRepeatedTimestampSlotSpan": max(
            (int(row["slotSpan"] or 0) for row in group_rows), default=None
        ),
        "maxRepeatedTimestampEnvelopeAgeSeconds": max(
            (float(row["maxEnvelopeAgeSeconds"]) for row in group_rows), default=None
        ),
        "perFeed": per_feed,
        "channelCounts": dict(Counter(str(row["channelId"]) for row in observations)),
        "rpcSelection": {"selected": selected_rpc, "attempts": rpc_attempts},
        "safety": {
            "publicChainWrites": 0,
            "publicTransactionsSigned": 0,
            "publicTransactionsSent": 0,
            "rpcMethods": ["getSlot", "getSignaturesForAddress", "getTransaction"],
        },
    }

    (OUT / "SUMMARY.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (OUT / "TOP_FEED_AGE_WITNESSES.json").write_text(
        json.dumps(top_ages, indent=2, sort_keys=True) + "\n"
    )
    (OUT / "REPEATED_FEED_TIMESTAMP_GROUPS.json").write_text(
        json.dumps(group_rows[:1000], indent=2, sort_keys=True) + "\n"
    )
    (OUT / "OBSERVATIONS.json").write_text(
        json.dumps(observations, indent=2, sort_keys=True) + "\n"
    )
    (OUT / "SIGNATURES.json").write_text(
        json.dumps(signatures, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
