#!/usr/bin/env python3
"""Read-only Solana block snapshotter for a fixed public slot list.

The script only calls getBlock, filters transactions that reference a supplied
public program id, and writes deterministic evidence files. It never signs or
submits a transaction.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path(os.environ.get("OUT_DIR", "evidence-blocks"))
PROGRAM_ID = os.environ.get(
    "PROGRAM_ID", "vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P"
)
SLOTS = [
    436560468,
    436560480,
    436490534,
    436490544,
    436552523,
    436552532,
    436560839,
    436560848,
    436464627,
    436464635,
    436489848,
    436489856,
    436499012,
    436499020,
    436499787,
    436499795,
]
RPCS = [
    "https://solana-rpc.publicnode.com",
    "https://api.mainnet-beta.solana.com",
    "https://solana.drpc.org",
    "https://rpc.ankr.com/solana",
    "https://mainnet-beta.solflare.network",
]
MAX_WORKERS = min(4, max(1, int(os.environ.get("MAX_WORKERS", "3"))))
OUT.mkdir(parents=True, exist_ok=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def rpc_call(url: str, method: str, params: list[Any], *, timeout: int = 180) -> Any:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": random.randint(1, 2**31 - 1), "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": "Public-ReadOnly-Solana-Block-Snapshot/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read())
    if body.get("error") is not None:
        raise RuntimeError(f"{url} {method}: {body['error']}")
    return body.get("result")


def fetch_block(slot: int) -> tuple[int, dict[str, Any]]:
    errors: list[str] = []
    params = [
        slot,
        {
            "commitment": "finalized",
            "encoding": "json",
            "transactionDetails": "full",
            "rewards": False,
            "maxSupportedTransactionVersion": 0,
        },
    ]
    providers = RPCS[slot % len(RPCS) :] + RPCS[: slot % len(RPCS)]
    for round_no in range(4):
        for url in providers:
            try:
                block = rpc_call(url, "getBlock", params)
                if not isinstance(block, dict) or not isinstance(block.get("transactions"), list):
                    raise RuntimeError("null or malformed block")
                return slot, {"rpc": url, "attemptRound": round_no, "block": block}
            except Exception as exc:
                errors.append(f"round={round_no} rpc={url} error={exc!r}")
                time.sleep(min(8.0, 0.4 * (2**round_no)))
    raise RuntimeError(f"slot {slot} failed across all providers: {' | '.join(errors)}")


def key_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if isinstance(value.get("pubkey"), str):
            return value["pubkey"]
        if isinstance(value.get("key"), str):
            return value["key"]
    return str(value)


def transaction_mentions_program(record: dict[str, Any]) -> bool:
    try:
        tx = record["transaction"]
        message = tx["message"]
        keys = [key_string(k) for k in message.get("accountKeys", message.get("staticAccountKeys", []))]
        loaded = record.get("meta", {}).get("loadedAddresses", {}) or {}
        keys.extend(key_string(k) for k in loaded.get("writable", []))
        keys.extend(key_string(k) for k in loaded.get("readonly", []))
        if PROGRAM_ID in keys:
            return True
        return PROGRAM_ID in json.dumps(record, separators=(",", ":"))
    except Exception:
        return PROGRAM_ID in json.dumps(record, separators=(",", ":"))


def signature_of(record: dict[str, Any]) -> str | None:
    sigs = record.get("transaction", {}).get("signatures", [])
    return sigs[0] if sigs and isinstance(sigs[0], str) else None


def main() -> int:
    started = int(time.time())
    fetched: dict[int, dict[str, Any]] = {}
    failures: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_map = {pool.submit(fetch_block, slot): slot for slot in SLOTS}
        for future in concurrent.futures.as_completed(future_map):
            slot = future_map[future]
            try:
                _, result = future.result()
                fetched[slot] = result
                print(f"FETCHED slot={slot} txs={len(result['block']['transactions'])} rpc={result['rpc']}", flush=True)
            except Exception as exc:
                failures.append({"slot": slot, "error": repr(exc)})
                print(f"FAILED slot={slot} error={exc!r}", file=sys.stderr, flush=True)

    manifest_rows: list[dict[str, Any]] = []
    block_summaries: list[dict[str, Any]] = []
    for slot in sorted(fetched):
        result = fetched[slot]
        block = result["block"]
        transactions = block.get("transactions", [])
        selected: list[dict[str, Any]] = []
        for tx_index, record in enumerate(transactions):
            if transaction_mentions_program(record):
                selected.append(
                    {
                        "transactionIndex": tx_index,
                        "signature": signature_of(record),
                        "record": record,
                    }
                )
        evidence = {
            "slot": slot,
            "blockTime": block.get("blockTime"),
            "blockHeight": block.get("blockHeight"),
            "blockhash": block.get("blockhash"),
            "parentSlot": block.get("parentSlot"),
            "previousBlockhash": block.get("previousBlockhash"),
            "rpc": result["rpc"],
            "attemptRound": result["attemptRound"],
            "totalTransactions": len(transactions),
            "programId": PROGRAM_ID,
            "matchingTransactions": selected,
        }
        filename = f"BLOCK_{slot}_VELOCITY_TRANSACTIONS.json"
        data = json_bytes(evidence)
        (OUT / filename).write_bytes(data)
        manifest_rows.append({"file": filename, "bytes": len(data), "sha256": sha256_bytes(data)})
        block_summaries.append(
            {
                "slot": slot,
                "blockTime": block.get("blockTime"),
                "totalTransactions": len(transactions),
                "matchingTransactions": len(selected),
                "signatures": [row["signature"] for row in selected],
                "rpc": result["rpc"],
            }
        )

    verdict = "PASS" if not failures and len(fetched) == len(SLOTS) and all(row["matchingTransactions"] > 0 for row in block_summaries) else "FAIL"
    summary = {
        "verdict": verdict,
        "programId": PROGRAM_ID,
        "requestedSlots": SLOTS,
        "requestedSlotCount": len(SLOTS),
        "fetchedSlotCount": len(fetched),
        "failureCount": len(failures),
        "failures": failures,
        "blocks": block_summaries,
        "startedUnix": started,
        "completedUnix": int(time.time()),
        "safety": {
            "publicChainWrites": 0,
            "publicTransactionsSigned": 0,
            "publicTransactionsSent": 0,
            "productionPrivateKeys": 0,
            "rpcMethods": ["getBlock"],
        },
    }
    summary_data = json_bytes(summary)
    (OUT / "SUMMARY.json").write_bytes(summary_data)
    manifest_rows.append({"file": "SUMMARY.json", "bytes": len(summary_data), "sha256": sha256_bytes(summary_data)})

    manifest_data = json_bytes(manifest_rows)
    (OUT / "EVIDENCE_MANIFEST.json").write_bytes(manifest_data)
    with (OUT / "SHA256SUMS.txt").open("w", encoding="utf-8", newline="\n") as handle:
        for row in manifest_rows:
            handle.write(f"{row['sha256']}  {row['file']}\n")

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
