#!/usr/bin/env python3
"""Read-only classifier for recent Pyth Lazer Solana program transactions."""
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
LIMIT = min(10000, max(100, int(os.environ.get("SIGNATURE_LIMIT", "3000"))))
WORKERS = min(8, max(1, int(os.environ.get("WORKERS", "5"))))
OUT = Path(os.environ.get("OUT_DIR", "evidence-usage"))
OUT.mkdir(parents=True, exist_ok=True)
RPCS = [
    "https://solana-rpc.publicnode.com",
    "https://api.mainnet-beta.solana.com",
    "https://solana.drpc.org",
    "https://mainnet-beta.solflare.network",
]
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SOLANA_FORMAT_MAGIC = 2182742457
LE_ECDSA_FORMAT_MAGIC = 1296547300
PAYLOAD_FORMAT_MAGIC = 2479346549


def b58decode(value: str) -> bytes:
    n = 0
    for char in value:
        n = n * 58 + ALPHABET.index(char)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = len(value) - len(value.lstrip("1"))
    return b"\0" * leading + raw


def b58encode(value: bytes) -> str:
    n = int.from_bytes(value, "big")
    encoded = ""
    while n:
        n, remainder = divmod(n, 58)
        encoded = ALPHABET[remainder] + encoded
    leading = len(value) - len(value.lstrip(b"\0"))
    return "1" * leading + (encoded or "")


def discriminator(name: str) -> bytes:
    return hashlib.sha256(f"global:{name}".encode()).digest()[:8]


DISCS = {
    discriminator("initialize"): "initialize",
    discriminator("update"): "update",
    discriminator("update_ecdsa_signer"): "update_ecdsa_signer",
    discriminator("verify_message"): "verify_message",
    discriminator("verify_ecdsa_message"): "verify_ecdsa_message",
}


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
            "user-agent": "ReadOnly-Pyth-Lazer-Usage/2.0",
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
        page = request(url, "getSignaturesForAddress", [PROGRAM, opts], 180)
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
    providers = RPCS[row["slot"] % len(RPCS) :] + RPCS[: row["slot"] % len(RPCS)]
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


def static_writability(message: dict[str, Any], static_raw: list[Any]) -> list[bool]:
    explicit: list[bool] = []
    has_explicit = True
    for item in static_raw:
        if isinstance(item, dict) and (
            "writable" in item or "isWritable" in item
        ):
            explicit.append(bool(item.get("writable", item.get("isWritable", False))))
        else:
            has_explicit = False
            break
    if has_explicit:
        return explicit

    header = message.get("header", {}) or {}
    required = int(header.get("numRequiredSignatures", 0) or 0)
    readonly_signed = int(header.get("numReadonlySignedAccounts", 0) or 0)
    readonly_unsigned = int(header.get("numReadonlyUnsignedAccounts", 0) or 0)
    count = len(static_raw)
    signed_writable_end = max(0, required - readonly_signed)
    unsigned_writable_end = max(required, count - readonly_unsigned)
    return [
        index < signed_writable_end
        or (required <= index < unsigned_writable_end)
        for index in range(count)
    ]


def resolve_program_id(ix: dict[str, Any], keys: list[str]) -> str | None:
    if isinstance(ix.get("programId"), str):
        return ix["programId"]
    pidx = ix.get("programIdIndex")
    if isinstance(pidx, int) and 0 <= pidx < len(keys):
        return keys[pidx]
    return None


def decode_anchor_message(name: str, data: bytes) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    if name not in {"verify_message", "verify_ecdsa_message"} or len(data) < 12:
        return parsed

    message_len = struct.unpack_from("<I", data, 8)[0]
    message_start = 12
    message_end = message_start + message_len
    parsed["messageLen"] = message_len
    parsed["instructionDataLen"] = len(data)
    parsed["encodedLenConsistent"] = message_end <= len(data)
    if message_end > len(data):
        return parsed

    message_data = data[message_start:message_end]
    parsed["messageSha256"] = hashlib.sha256(message_data).hexdigest()
    parsed["instructionTrailingBytes"] = len(data) - message_end

    if name == "verify_message" and message_end + 3 <= len(data):
        parsed["ed25519InstructionIndex"] = struct.unpack_from("<H", data, message_end)[0]
        parsed["signatureIndex"] = data[message_end + 2]
        parsed["expectedAnchorInstructionLen"] = message_end + 3
    elif name == "verify_ecdsa_message":
        parsed["expectedAnchorInstructionLen"] = message_end

    if len(message_data) < 4:
        return parsed
    magic = struct.unpack_from("<I", message_data, 0)[0]
    parsed["formatMagic"] = magic

    if name == "verify_message" and magic == SOLANA_FORMAT_MAGIC:
        envelope_header = 4 + 64 + 32 + 2
        payload_len_offset = 4 + 64 + 32
        parsed["format"] = "solana-ed25519"
        if len(message_data) >= 4 + 64 + 32:
            parsed["embeddedEd25519Pubkey"] = b58encode(message_data[68:100])
    elif name == "verify_ecdsa_message" and magic == LE_ECDSA_FORMAT_MAGIC:
        envelope_header = 4 + 64 + 1 + 2
        payload_len_offset = 4 + 64 + 1
        parsed["format"] = "le-ecdsa"
        if len(message_data) >= 69:
            parsed["recoveryId"] = message_data[68]
    else:
        parsed["format"] = "unexpected"
        return parsed

    if len(message_data) < envelope_header:
        parsed["envelopeComplete"] = False
        return parsed

    payload_len = struct.unpack_from("<H", message_data, payload_len_offset)[0]
    expected_message_len = envelope_header + payload_len
    parsed["envelopeComplete"] = expected_message_len <= len(message_data)
    parsed["declaredPayloadLen"] = payload_len
    parsed["expectedMessageLen"] = expected_message_len
    parsed["unsignedTrailingBytes"] = max(0, len(message_data) - expected_message_len)
    parsed["messageLengthExact"] = expected_message_len == len(message_data)
    if expected_message_len > len(message_data):
        return parsed

    payload = message_data[envelope_header:expected_message_len]
    trailing = message_data[expected_message_len:]
    parsed["payloadSha256"] = hashlib.sha256(payload).hexdigest()
    if trailing:
        parsed["unsignedTrailingSha256"] = hashlib.sha256(trailing).hexdigest()
        parsed["unsignedTrailingHexPrefix"] = trailing[:64].hex()

    if len(payload) >= 14:
        parsed["payloadMagic"] = struct.unpack_from("<I", payload, 0)[0]
        parsed["payloadTimestampUs"] = struct.unpack_from("<Q", payload, 4)[0]
        parsed["payloadChannelId"] = payload[12]
        parsed["payloadNumFeeds"] = payload[13]
        parsed["payloadMagicExpected"] = parsed["payloadMagic"] == PAYLOAD_FORMAT_MAGIC
    return parsed


def instruction_accounts(
    ix: dict[str, Any], keys: list[str], writable: list[bool]
) -> list[dict[str, Any]]:
    indexes = ix.get("accounts", ix.get("accountKeyIndexes", []))
    accounts = []
    for position, account_index in enumerate(indexes):
        if isinstance(account_index, int) and 0 <= account_index < len(keys):
            accounts.append(
                {
                    "position": position,
                    "pubkey": keys[account_index],
                    "writable": writable[account_index],
                }
            )
    return accounts


def classify_one(
    *,
    row: dict[str, Any],
    tx: dict[str, Any],
    rpc: str | None,
    ix: dict[str, Any],
    keys: list[str],
    writable: list[bool],
    source: str,
    instruction_index: int,
    parent_index: int | None,
    parent_program_id: str | None,
) -> dict[str, Any] | None:
    program_id = resolve_program_id(ix, keys)
    if program_id != PROGRAM:
        return None

    data_value = ix.get("data", "")
    try:
        data = b58decode(data_value) if isinstance(data_value, str) else bytes(data_value)
    except Exception:
        data = b""
    name = DISCS.get(data[:8], "unknown")
    parsed = decode_anchor_message(name, data)
    meta = tx.get("meta", {}) or {}
    return {
        "signature": row["signature"],
        "slot": row["slot"],
        "blockTime": tx.get("blockTime"),
        "transactionError": meta.get("err"),
        "transactionSucceeded": meta.get("err") is None,
        "source": source,
        "instructionIndex": instruction_index,
        "parentInstructionIndex": parent_index,
        "parentProgramId": parent_program_id,
        "stackHeight": ix.get("stackHeight"),
        "instruction": name,
        "instructionDataBytes": len(data),
        "instructionDataSha256": hashlib.sha256(data).hexdigest(),
        "accounts": instruction_accounts(ix, keys, writable),
        "parsed": parsed,
        "rpc": rpc,
        "logMessages": meta.get("logMessages", []),
    }


def classify(row: dict[str, Any], tx: dict[str, Any], rpc: str | None) -> list[dict[str, Any]]:
    message = tx["transaction"]["message"]
    static_raw = message.get("accountKeys", message.get("staticAccountKeys", []))
    static_keys = [key_string(item) for item in static_raw]
    static_writable = static_writability(message, static_raw)
    loaded = tx.get("meta", {}).get("loadedAddresses", {}) or {}
    loaded_w = [key_string(item) for item in loaded.get("writable", [])]
    loaded_r = [key_string(item) for item in loaded.get("readonly", [])]
    keys = static_keys + loaded_w + loaded_r
    writable = static_writable + [True] * len(loaded_w) + [False] * len(loaded_r)

    top_level = message.get("instructions", message.get("compiledInstructions", []))
    top_level_programs = [resolve_program_id(ix, keys) for ix in top_level]
    out: list[dict[str, Any]] = []

    for index, ix in enumerate(top_level):
        record = classify_one(
            row=row,
            tx=tx,
            rpc=rpc,
            ix=ix,
            keys=keys,
            writable=writable,
            source="top-level",
            instruction_index=index,
            parent_index=None,
            parent_program_id=None,
        )
        if record is not None:
            out.append(record)

    for group in (tx.get("meta", {}) or {}).get("innerInstructions", []) or []:
        parent_index = group.get("index")
        parent_program_id = (
            top_level_programs[parent_index]
            if isinstance(parent_index, int) and 0 <= parent_index < len(top_level_programs)
            else None
        )
        for inner_index, ix in enumerate(group.get("instructions", []) or []):
            record = classify_one(
                row=row,
                tx=tx,
                rpc=rpc,
                ix=ix,
                keys=keys,
                writable=writable,
                source="inner",
                instruction_index=inner_index,
                parent_index=parent_index if isinstance(parent_index, int) else None,
                parent_program_id=parent_program_id,
            )
            if record is not None:
                out.append(record)
    return out


def counter_dict(values: Iterable[Any]) -> dict[str, int]:
    return dict(Counter(str(value) for value in values))


def main() -> int:
    selected, rpc_attempts = select_rpc()
    signatures = fetch_signatures(selected)
    records: list[dict[str, Any]] = []
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(fetch_tx, row): row for row in signatures}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            row = futures[future]
            try:
                sig, tx, rpc = future.result()
                if tx is None:
                    failures.append({"signature": sig, "detail": rpc})
                else:
                    records.extend(classify(row, tx, rpc))
            except Exception as exc:
                failures.append({"signature": row["signature"], "error": repr(exc)})
            if i % 100 == 0:
                print(
                    f"transactions={i}/{len(signatures)} instructions={len(records)} failures={len(failures)}",
                    flush=True,
                )

    counts = Counter(item["instruction"] for item in records)
    success_counts = Counter(
        item["instruction"] for item in records if item["transactionSucceeded"]
    )
    ecdsa = [item for item in records if item["instruction"] == "verify_ecdsa_message"]
    ed = [item for item in records if item["instruction"] == "verify_message"]
    trailing = [
        item
        for item in records
        if int(item.get("parsed", {}).get("unsignedTrailingBytes", 0) or 0) > 0
    ]
    unknown = [item for item in records if item["instruction"] == "unknown"]
    result = {
        "verdict": "COMPLETE",
        "classifierVersion": 2,
        "programId": PROGRAM,
        "requestedSignatures": LIMIT,
        "receivedSignatures": len(signatures),
        "classifiedInstructions": len(records),
        "topLevelInstructions": sum(item["source"] == "top-level" for item in records),
        "innerInstructions": sum(item["source"] == "inner" for item in records),
        "fetchFailures": failures,
        "instructionCounts": dict(counts),
        "successfulInstructionCounts": dict(success_counts),
        "verifyEcdsaCalls": len(ecdsa),
        "verifyEcdsaSuccesses": sum(item["transactionSucceeded"] for item in ecdsa),
        "verifyEd25519Calls": len(ed),
        "verifyEd25519Successes": sum(item["transactionSucceeded"] for item in ed),
        "unsignedTrailingMessageCalls": len(trailing),
        "unknownDiscriminatorCalls": len(unknown),
        "callerProgramCounts": counter_dict(
            item["parentProgramId"]
            for item in records
            if item["source"] == "inner" and item["parentProgramId"]
        ),
        "callerInstructionCounts": counter_dict(
            f"{item['parentProgramId']}::{item['instruction']}"
            for item in records
            if item["source"] == "inner" and item["parentProgramId"]
        ),
        "formatCounts": counter_dict(
            item.get("parsed", {}).get("format", "not-parsed") for item in records
        ),
        "rpcSelection": {"selected": selected, "attempts": rpc_attempts},
        "safety": {
            "publicChainWrites": 0,
            "publicTransactionsSigned": 0,
            "publicTransactionsSent": 0,
            "rpcMethods": ["getSlot", "getSignaturesForAddress", "getTransaction"],
        },
    }
    (OUT / "USAGE_SUMMARY.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    (OUT / "CLASSIFIED_INSTRUCTIONS.json").write_text(
        json.dumps(records, indent=2, sort_keys=True) + "\n"
    )
    (OUT / "TRAILING_MESSAGE_CALLS.json").write_text(
        json.dumps(trailing, indent=2, sort_keys=True) + "\n"
    )
    (OUT / "UNKNOWN_DISCRIMINATOR_CALLS.json").write_text(
        json.dumps(unknown, indent=2, sort_keys=True) + "\n"
    )
    (OUT / "SIGNATURES.json").write_text(
        json.dumps(signatures, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
