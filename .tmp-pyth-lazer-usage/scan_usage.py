#!/usr/bin/env python3
"""Read-only classifier for recent Pyth Lazer Solana program transactions."""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import random
import struct
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

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


def b58decode(value: str) -> bytes:
    n = 0
    for char in value:
        n = n * 58 + ALPHABET.index(char)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = len(value) - len(value.lstrip("1"))
    return b"\0" * leading + raw


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
    body = json.dumps({"jsonrpc": "2.0", "id": random.randint(1, 2**31 - 1), "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json", "user-agent": "ReadOnly-Pyth-Lazer-Usage/1.0"})
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
    providers = RPCS[row["slot"] % len(RPCS):] + RPCS[:row["slot"] % len(RPCS)]
    params = [row["signature"], {"encoding": "json", "commitment": "finalized", "maxSupportedTransactionVersion": 0}]
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


def classify(row: dict[str, Any], tx: dict[str, Any], rpc: str | None) -> list[dict[str, Any]]:
    message = tx["transaction"]["message"]
    static_raw = message.get("accountKeys", message.get("staticAccountKeys", []))
    static_keys = [key_string(item) for item in static_raw]
    static_writable = []
    for item in static_raw:
        if isinstance(item, dict):
            static_writable.append(bool(item.get("writable", item.get("isWritable", False))))
        else:
            static_writable.append(False)
    loaded = tx.get("meta", {}).get("loadedAddresses", {}) or {}
    loaded_w = [key_string(item) for item in loaded.get("writable", [])]
    loaded_r = [key_string(item) for item in loaded.get("readonly", [])]
    keys = static_keys + loaded_w + loaded_r
    writable = static_writable + [True] * len(loaded_w) + [False] * len(loaded_r)
    instructions = message.get("instructions", message.get("compiledInstructions", []))
    out = []
    for index, ix in enumerate(instructions):
        if ix.get("programId") == PROGRAM:
            program_id = PROGRAM
        else:
            pidx = ix.get("programIdIndex")
            program_id = keys[pidx] if isinstance(pidx, int) and pidx < len(keys) else None
        if program_id != PROGRAM:
            continue
        data_value = ix.get("data", "")
        try:
            data = b58decode(data_value) if isinstance(data_value, str) else bytes(data_value)
        except Exception:
            data = b""
        name = DISCS.get(data[:8], "unknown")
        account_indexes = ix.get("accounts", ix.get("accountKeyIndexes", []))
        accounts = []
        for pos, account_index in enumerate(account_indexes):
            if isinstance(account_index, int) and account_index < len(keys):
                accounts.append({"position": pos, "pubkey": keys[account_index], "writable": writable[account_index]})
        parsed: dict[str, Any] = {}
        if name in {"verify_message", "verify_ecdsa_message"} and len(data) >= 12:
            message_len = struct.unpack_from("<I", data, 8)[0]
            parsed["messageLen"] = message_len
            parsed["encodedLenConsistent"] = 12 + message_len <= len(data)
            if name == "verify_message" and 12 + message_len + 3 <= len(data):
                parsed["ed25519InstructionIndex"] = struct.unpack_from("<H", data, 12 + message_len)[0]
                parsed["signatureIndex"] = data[14 + message_len]
        out.append({
            "signature": row["signature"],
            "slot": row["slot"],
            "blockTime": tx.get("blockTime"),
            "transactionError": tx.get("meta", {}).get("err"),
            "instructionIndex": index,
            "instruction": name,
            "instructionDataBytes": len(data),
            "accounts": accounts,
            "parsed": parsed,
            "rpc": rpc,
            "logMessages": tx.get("meta", {}).get("logMessages", []),
        })
    return out


def main() -> int:
    selected, rpc_attempts = select_rpc()
    signatures = fetch_signatures(selected)
    records = []
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
                print(f"transactions={i}/{len(signatures)} instructions={len(records)} failures={len(failures)}", flush=True)
    counts = Counter(item["instruction"] for item in records)
    success_counts = Counter(item["instruction"] for item in records if item["transactionError"] is None)
    ecdsa = [item for item in records if item["instruction"] == "verify_ecdsa_message"]
    ed = [item for item in records if item["instruction"] == "verify_message"]
    result = {
        "verdict": "COMPLETE",
        "programId": PROGRAM,
        "requestedSignatures": LIMIT,
        "receivedSignatures": len(signatures),
        "classifiedInstructions": len(records),
        "fetchFailures": failures,
        "instructionCounts": dict(counts),
        "successfulInstructionCounts": dict(success_counts),
        "verifyEcdsaCalls": len(ecdsa),
        "verifyEcdsaSuccesses": sum(item["transactionError"] is None for item in ecdsa),
        "verifyEd25519Calls": len(ed),
        "verifyEd25519Successes": sum(item["transactionError"] is None for item in ed),
        "rpcSelection": {"selected": selected, "attempts": rpc_attempts},
        "safety": {"publicChainWrites": 0, "publicTransactionsSigned": 0, "publicTransactionsSent": 0, "rpcMethods": ["getSlot", "getSignaturesForAddress", "getTransaction"]},
    }
    (OUT / "USAGE_SUMMARY.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (OUT / "CLASSIFIED_INSTRUCTIONS.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    (OUT / "SIGNATURES.json").write_text(json.dumps(signatures, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
