#!/usr/bin/env python3
"""Profile signed Pyth Lazer payload schemas and timing in finalized transactions.

This is a public-data, read-only classifier. It never constructs, signs, or sends a
transaction. Exact signed messages are retained only for bounded witnesses.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import random
import struct
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

PROGRAM = os.environ.get("PROGRAM_ID", "pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt")
INDEX_PATH = Path(os.environ.get("INDEX_PATH", "index/sample.json"))
OUT = Path(os.environ.get("OUT_DIR", "out"))
OUT.mkdir(parents=True, exist_ok=True)
SHARD = int(os.environ.get("SHARD", "0"))
SHARDS = max(1, int(os.environ.get("SHARDS", "12")))
WORKERS = max(1, min(10, int(os.environ.get("WORKERS", "8"))))
TARGET_FEEDS = {1: "BTC", 2: "ETH", 6: "SOL", 110: "HYPE"}
RPCS = [
    "https://solana-rpc.publicnode.com",
    "https://api.mainnet-beta.solana.com",
    "https://solana.drpc.org",
    "https://1rpc.io/solana",
    "https://mainnet-beta.solflare.network",
    "https://solana-mainnet.rpc.extrnode.com",
]
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SOLANA_FORMAT_MAGIC = 2182742457
PAYLOAD_FORMAT_MAGIC = 2479346549
VERIFY_DISC = hashlib.sha256(b"global:verify_message").digest()[:8]


def b58decode(value: str) -> bytes:
    n = 0
    for char in value:
        n = n * 58 + ALPHABET.index(char)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = len(value) - len(value.lstrip("1"))
    return b"\0" * leading + raw


def request(endpoint: str, method: str, params: list[Any], timeout: int = 180) -> Any:
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": random.randint(1, 2**31 - 1),
        "method": method,
        "params": params,
    }).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": f"Pyth-Lazer-Public-Profile-Shard-{SHARD}/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        payload = json.loads(response.read())
    if payload.get("error") is not None:
        raise RuntimeError(json.dumps(payload["error"], sort_keys=True))
    return payload.get("result")


def fetch_transaction(row: dict[str, Any]) -> tuple[dict[str, Any], Any, str | None, list[str]]:
    seed = int(hashlib.sha256(row["signature"].encode()).hexdigest()[:8], 16)
    start = seed % len(RPCS)
    providers = RPCS[start:] + RPCS[:start]
    params = [
        row["signature"],
        {
            "encoding": "json",
            "commitment": "finalized",
            "maxSupportedTransactionVersion": 0,
        },
    ]
    errors: list[str] = []
    for round_no in range(4):
        for endpoint in providers:
            try:
                tx = request(endpoint, "getTransaction", params)
                if tx is None:
                    raise RuntimeError("null transaction")
                return row, tx, endpoint, errors
            except Exception as exc:
                errors.append(f"{endpoint}: {type(exc).__name__}: {exc}")
        time.sleep(min(8.0, 0.4 * (2 ** round_no)) + random.random() * 0.2)
    return row, None, None, errors


def key_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and isinstance(value.get("pubkey"), str):
        return value["pubkey"]
    return str(value)


def combined_keys(tx: dict[str, Any]) -> list[str]:
    message = tx["transaction"]["message"]
    static = message.get("accountKeys", message.get("staticAccountKeys", []))
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    return [
        *[key_string(value) for value in static],
        *[key_string(value) for value in loaded.get("writable", [])],
        *[key_string(value) for value in loaded.get("readonly", [])],
    ]


def resolve_program_id(ix: dict[str, Any], keys: list[str]) -> str | None:
    if isinstance(ix.get("programId"), str):
        return ix["programId"]
    index = ix.get("programIdIndex")
    if isinstance(index, int) and 0 <= index < len(keys):
        return keys[index]
    return None


def iter_pyth_instructions(tx: dict[str, Any]) -> Iterable[tuple[dict[str, Any], str, int, int | None, str | None]]:
    message = tx["transaction"]["message"]
    keys = combined_keys(tx)
    top = message.get("instructions", message.get("compiledInstructions", [])) or []
    top_programs = [resolve_program_id(ix, keys) for ix in top]
    for index, ix in enumerate(top):
        if resolve_program_id(ix, keys) == PROGRAM:
            yield ix, "top-level", index, None, None
    for group in (tx.get("meta") or {}).get("innerInstructions", []) or []:
        parent_index = group.get("index")
        parent_program = (
            top_programs[parent_index]
            if isinstance(parent_index, int) and 0 <= parent_index < len(top_programs)
            else None
        )
        for inner_index, ix in enumerate(group.get("instructions", []) or []):
            if resolve_program_id(ix, keys) == PROGRAM:
                yield ix, "inner", inner_index, parent_index if isinstance(parent_index, int) else None, parent_program


def extract_signed_message(ix: dict[str, Any]) -> bytes | None:
    data_value = ix.get("data")
    if not isinstance(data_value, str):
        return None
    try:
        data = b58decode(data_value)
    except Exception:
        return None
    if len(data) < 12 or data[:8] != VERIFY_DISC:
        return None
    length = struct.unpack_from("<I", data, 8)[0]
    start = 12
    end = start + length
    if end > len(data):
        return None
    return data[start:end]


def read_optional_i64(buffer: bytes, offset: int) -> tuple[int | None, int]:
    value = struct.unpack_from("<q", buffer, offset)[0]
    return (None if value == 0 else value), offset + 8


def read_optional_u64(buffer: bytes, offset: int) -> tuple[int | None, int]:
    present = buffer[offset] != 0
    offset += 1
    if not present:
        return None, offset
    return struct.unpack_from("<Q", buffer, offset)[0], offset + 8


def decode_message(message: bytes) -> dict[str, Any]:
    if len(message) < 102:
        raise ValueError("short Solana message")
    if struct.unpack_from("<I", message, 0)[0] != SOLANA_FORMAT_MAGIC:
        raise ValueError("unexpected envelope magic")
    payload_len = struct.unpack_from("<H", message, 100)[0]
    payload = message[102:102 + payload_len]
    if len(payload) != payload_len or 102 + payload_len != len(message):
        raise ValueError("envelope length mismatch")
    if len(payload) < 14 or struct.unpack_from("<I", payload, 0)[0] != PAYLOAD_FORMAT_MAGIC:
        raise ValueError("unexpected payload magic")

    offset = 4
    timestamp_us = struct.unpack_from("<Q", payload, offset)[0]
    offset += 8
    channel = payload[offset]
    offset += 1
    feed_count = payload[offset]
    offset += 1
    feeds: list[dict[str, Any]] = []

    for _ in range(feed_count):
        if offset + 5 > len(payload):
            raise ValueError("truncated feed header")
        feed_id = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        property_count = payload[offset]
        offset += 1
        props: list[int] = []
        values: dict[str, Any] = {}
        for _ in range(property_count):
            if offset >= len(payload):
                raise ValueError("truncated property id")
            prop = payload[offset]
            offset += 1
            props.append(prop)
            if prop in {0, 1, 2, 5, 10, 11}:
                value, offset = read_optional_i64(payload, offset)
            elif prop == 3:
                value = struct.unpack_from("<H", payload, offset)[0]
                offset += 2
            elif prop in {4, 9}:
                value = struct.unpack_from("<h", payload, offset)[0]
                offset += 2
            elif prop == 6:
                present = payload[offset] != 0
                offset += 1
                if present:
                    value = struct.unpack_from("<q", payload, offset)[0]
                    offset += 8
                else:
                    value = None
            elif prop in {7, 8, 12}:
                value, offset = read_optional_u64(payload, offset)
            else:
                raise ValueError(f"unsupported property {prop}")
            values[str(prop)] = value
        feeds.append({"feedId": feed_id, "properties": props, "values": values})
    if offset != len(payload):
        raise ValueError(f"payload trailing bytes: {len(payload) - offset}")
    return {
        "timestampUs": timestamp_us,
        "channel": channel,
        "feeds": feeds,
        "messageSha256": hashlib.sha256(message).hexdigest(),
        "messageBytes": len(message),
    }


def safe_bps(numerator: int | None, denominator: int | None) -> float | None:
    if numerator is None or denominator in (None, 0):
        return None
    return abs(float(numerator) / float(denominator)) * 10_000.0


def classify_target(feed: dict[str, Any], timestamp_us: int) -> dict[str, Any]:
    props = feed["properties"]
    values = feed["values"]
    price = values.get("0")
    exponent = values.get("4")
    signed_conf = values.get("5")
    bid = values.get("1")
    ask = values.get("2")
    feed_ts = values.get("12")
    signed_conf_bps = safe_bps(signed_conf, price)
    spread_bps: float | None = None
    if bid is not None and ask is not None and price not in (None, 0) and bid < ask:
        spread_bps = float(ask - bid) / abs(float(price)) * 10_000.0
    velocity_conf_bps = spread_bps if spread_bps is not None else 20.0
    understatement = signed_conf_bps - velocity_conf_bps if signed_conf_bps is not None else None
    age_us = timestamp_us - feed_ts if isinstance(feed_ts, int) else None
    shape_compatible = (
        len(props) > 0
        and props[0] == 0
        and price not in (None, 0)
        and exponent is not None
        and feed_ts is not None
    )
    return {
        "feedId": feed["feedId"],
        "symbol": TARGET_FEEDS[feed["feedId"]],
        "properties": props,
        "values": values,
        "shapeCompatible": shape_compatible,
        "signedConfidenceBps": signed_conf_bps,
        "bidAskSpreadBps": spread_bps,
        "velocityDerivedConfidenceBps": velocity_conf_bps,
        "confidenceUnderstatementBps": understatement,
        "feedAgeUs": age_us,
        "feedAgeSeconds": age_us / 1_000_000.0 if isinstance(age_us, int) else None,
    }


def bounded_push(rows: list[dict[str, Any]], row: dict[str, Any], key: str, limit: int = 100) -> None:
    rows.append(row)
    rows.sort(key=lambda item: float(item.get(key) or -1e100), reverse=True)
    del rows[limit:]


def main() -> int:
    sample = json.loads(INDEX_PATH.read_text())
    selected = [row for index, row in enumerate(sample) if index % SHARDS == SHARD]
    failures: list[dict[str, Any]] = []
    parse_failures: list[dict[str, Any]] = []
    channels: Counter[str] = Counter()
    parents: Counter[str] = Counter()
    schemas: Counter[str] = Counter()
    target_records = 0
    verified_messages = 0
    fetched_transactions = 0
    target_by_feed: Counter[str] = Counter()
    positive_understatement = 0
    age_over_4s = 0
    age_over_48s = 0
    non_default_channel = 0
    non_default_compatible_target = 0
    top_understatement: list[dict[str, Any]] = []
    top_age: list[dict[str, Any]] = []
    top_signed_confidence: list[dict[str, Any]] = []
    exact_witnesses: dict[str, dict[str, Any]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(fetch_transaction, row): row for row in selected}
        for completed, future in enumerate(concurrent.futures.as_completed(futures), 1):
            row = futures[future]
            try:
                _, tx, endpoint, errors = future.result()
            except Exception as exc:
                failures.append({"signature": row["signature"], "error": f"future: {type(exc).__name__}: {exc}"})
                continue
            if tx is None:
                failures.append({
                    "signature": row["signature"],
                    "slot": row.get("slot"),
                    "errors": errors[-12:],
                })
                continue
            fetched_transactions += 1
            meta = tx.get("meta") or {}
            if meta.get("err") is not None:
                continue
            for ix, source, instruction_index, parent_index, parent_program in iter_pyth_instructions(tx):
                message = extract_signed_message(ix)
                if message is None:
                    continue
                try:
                    decoded = decode_message(message)
                except Exception as exc:
                    parse_failures.append({
                        "signature": row["signature"],
                        "slot": row.get("slot"),
                        "error": f"{type(exc).__name__}: {exc}",
                    })
                    continue
                verified_messages += 1
                channels[str(decoded["channel"])] += 1
                parents[str(parent_program)] += 1
                if decoded["channel"] != 3:
                    non_default_channel += 1

                message_targets: list[dict[str, Any]] = []
                for feed in decoded["feeds"]:
                    schema_key = f"{feed['feedId']}|{decoded['channel']}|{','.join(map(str, feed['properties']))}"
                    schemas[schema_key] += 1
                    if feed["feedId"] not in TARGET_FEEDS:
                        continue
                    target = classify_target(feed, decoded["timestampUs"])
                    target_records += 1
                    target_by_feed[str(feed["feedId"])] += 1
                    message_targets.append(target)
                    base = {
                        "signature": row["signature"],
                        "slot": row.get("slot"),
                        "blockTime": tx.get("blockTime", row.get("blockTime")),
                        "rpc": endpoint,
                        "source": source,
                        "instructionIndex": instruction_index,
                        "parentInstructionIndex": parent_index,
                        "parentProgramId": parent_program,
                        "channel": decoded["channel"],
                        "payloadTimestampUs": decoded["timestampUs"],
                        "messageSha256": decoded["messageSha256"],
                        "messageBytes": decoded["messageBytes"],
                        **target,
                    }
                    if isinstance(target["confidenceUnderstatementBps"], (int, float)):
                        bounded_push(top_understatement, base, "confidenceUnderstatementBps")
                        if target["shapeCompatible"] and target["confidenceUnderstatementBps"] > 0:
                            positive_understatement += 1
                    if isinstance(target["feedAgeSeconds"], (int, float)):
                        bounded_push(top_age, base, "feedAgeSeconds")
                        if target["shapeCompatible"] and target["feedAgeSeconds"] >= 4:
                            age_over_4s += 1
                        if target["shapeCompatible"] and target["feedAgeSeconds"] >= 48:
                            age_over_48s += 1
                    if isinstance(target["signedConfidenceBps"], (int, float)):
                        bounded_push(top_signed_confidence, base, "signedConfidenceBps")

                if decoded["channel"] != 3 and any(t.get("shapeCompatible") for t in message_targets):
                    non_default_compatible_target += 1

                material = any(
                    t.get("shapeCompatible")
                    and (
                        (isinstance(t.get("confidenceUnderstatementBps"), (int, float)) and t["confidenceUnderstatementBps"] > 0)
                        or (isinstance(t.get("feedAgeSeconds"), (int, float)) and t["feedAgeSeconds"] >= 4)
                        or decoded["channel"] != 3
                    )
                    for t in message_targets
                )
                if material:
                    exact_witnesses[decoded["messageSha256"]] = {
                        "signature": row["signature"],
                        "slot": row.get("slot"),
                        "blockTime": tx.get("blockTime", row.get("blockTime")),
                        "rpc": endpoint,
                        "parentProgramId": parent_program,
                        "channel": decoded["channel"],
                        "payloadTimestampUs": decoded["timestampUs"],
                        "messageSha256": decoded["messageSha256"],
                        "messageBytes": decoded["messageBytes"],
                        "messageHex": message.hex(),
                        "targetFeeds": message_targets,
                        "allFeedIds": [f["feedId"] for f in decoded["feeds"]],
                        "allFeedSchemas": [
                            {"feedId": f["feedId"], "properties": f["properties"]}
                            for f in decoded["feeds"]
                        ],
                    }
            if completed % 250 == 0 or completed == len(selected):
                print(
                    f"SHARD={SHARD} PROGRESS={completed}/{len(selected)} "
                    f"FETCHED={fetched_transactions} FAILURES={len(failures)} "
                    f"MESSAGES={verified_messages} TARGETS={target_records}",
                    flush=True,
                )

    witnesses = list(exact_witnesses.values())

    def witness_score(item: dict[str, Any]) -> float:
        best = 0.0
        for target in item.get("targetFeeds", []):
            best = max(
                best,
                float(target.get("confidenceUnderstatementBps") or 0),
                float(target.get("feedAgeSeconds") or 0),
            )
        if item.get("channel") != 3:
            best = max(best, 1000.0)
        return best

    witnesses.sort(key=witness_score, reverse=True)
    witnesses = witnesses[:100]

    coverage = fetched_transactions / len(selected) if selected else 0.0
    schema_rows = []
    for key, count in schemas.most_common():
        feed_id, channel, props = key.split("|", 2)
        schema_rows.append({
            "feedId": int(feed_id),
            "channel": int(channel),
            "properties": [int(value) for value in props.split(",") if value != ""],
            "count": count,
        })

    summary = {
        "status": "PASS_PUBLIC_PAYLOAD_PROFILE_SHARD" if coverage >= 0.99 else "INCOMPLETE_PUBLIC_PAYLOAD_PROFILE_SHARD",
        "shard": SHARD,
        "shards": SHARDS,
        "selectedTransactions": len(selected),
        "fetchedTransactions": fetched_transactions,
        "fetchFailures": len(failures),
        "coverage": coverage,
        "verifiedMessages": verified_messages,
        "targetFeedRecords": target_records,
        "targetRecordsByFeed": dict(target_by_feed),
        "channels": dict(channels),
        "parentPrograms": dict(parents),
        "schemas": schema_rows,
        "positiveConfidenceUnderstatementRecords": positive_understatement,
        "targetFeedAgeAtLeast4Seconds": age_over_4s,
        "targetFeedAgeAtLeast48Seconds": age_over_48s,
        "nonDefaultChannelMessages": non_default_channel,
        "nonDefaultChannelCompatibleTargetMessages": non_default_compatible_target,
        "parseFailures": len(parse_failures),
        "topConfidenceUnderstatement": top_understatement,
        "topFeedAge": top_age,
        "topSignedConfidence": top_signed_confidence,
        "exactWitnessCount": len(witnesses),
        "publicChainTransactionsSigned": 0,
        "publicChainTransactionsSent": 0,
        "publicChainWrites": 0,
    }
    (OUT / f"shard-{SHARD}-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (OUT / f"shard-{SHARD}-witnesses.json").write_text(json.dumps(witnesses, indent=2, sort_keys=True) + "\n")
    (OUT / f"shard-{SHARD}-failures.json").write_text(json.dumps(failures[:500], indent=2, sort_keys=True) + "\n")
    (OUT / f"shard-{SHARD}-parse-failures.json").write_text(json.dumps(parse_failures[:500], indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "status": summary["status"],
        "shard": SHARD,
        "coverage": coverage,
        "verifiedMessages": verified_messages,
        "targetFeedRecords": target_records,
        "positiveConfidenceUnderstatementRecords": positive_understatement,
        "targetFeedAgeAtLeast4Seconds": age_over_4s,
        "targetFeedAgeAtLeast48Seconds": age_over_48s,
        "nonDefaultChannelMessages": non_default_channel,
        "nonDefaultChannelCompatibleTargetMessages": non_default_compatible_target,
    }, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
