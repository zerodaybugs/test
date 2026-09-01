#!/usr/bin/env python3
"""Targeted read-only reconstruction of all successful Synthetix Deposit withdrawal calldata.

The previous broad contract-log scan hit RPC provider limits. This version filters exclusively on the
verified WithdrawalRequested event topic, then downloads and decodes only the corresponding public
transactions. It determines whether production has ever reached multi-entry, multi-token,
duplicate-token or repeated beneficiary/token request shapes implicated by local-fork invariants.

Safety: public Ethereum JSON-RPC reads only; no signer, credential, account access, eth_call
impersonation, transaction, or state mutation. Identities are hashed in the output; only public
transaction hashes for structurally exceptional calls are retained.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
from collections import Counter
from typing import Any

from eth_abi import decode
from eth_utils import keccak

OUT = pathlib.Path("synthetix_withdrawal_calldata_fast")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = [
    os.getenv("ETH_RPC_URL", "https://ethereum-rpc.publicnode.com"),
    "https://eth.llamarpc.com",
    "https://eth.drpc.org",
    "https://rpc.mevblocker.io",
]
DEPOSIT = "0xd62595c3c23b690baee0935e107a209cb1dbd37b"
START_BLOCK = 23_739_792
CHUNK = 100_000
MAX_RESPONSE = 12 * 1024 * 1024
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
REQUEST_SIG = "requestWithdrawal((address[],uint256[],address)[])"
REQUEST_SELECTOR = "0x" + keccak(text=REQUEST_SIG)[:4].hex()
EVENT_SIG = "WithdrawalRequested(uint256,address,address[],uint256[],uint256)"
EVENT_TOPIC = "0x" + keccak(text=EVENT_SIG).hex()


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def rpc(method: str, params: list[Any], retries: int = 6) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for attempt in range(retries):
        for url in RPC_URLS:
            request = urllib.request.Request(
                url,
                data=payload,
                headers={"User-Agent": UA, "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise RuntimeError("response exceeded cap")
                parsed = json.loads(raw)
                if parsed.get("error"):
                    raise RuntimeError(str(parsed["error"]))
                return parsed.get("result")
            except Exception as exc:  # noqa: BLE001
                last = f"{type(exc).__name__}:{exc}"
        time.sleep(min(10, 2**attempt))
    raise RuntimeError(f"RPC {method} failed: {last}")


def get_logs(start: int, end: int) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [{"address": DEPOSIT, "fromBlock": hex(start), "toBlock": hex(end), "topics": [EVENT_TOPIC]}],
        )
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return get_logs(start, middle) + get_logs(middle + 1, end)


def decode_entries(input_data: str) -> list[tuple[list[str], list[int], str]]:
    if input_data[:10].lower() != REQUEST_SELECTOR:
        raise ValueError("wrong selector")
    values = decode(["(address[],uint256[],address)[]"], bytes.fromhex(input_data[10:]))[0]
    return [
        ([str(token).lower() for token in tokens], [int(amount) for amount in amounts], str(beneficiary).lower())
        for tokens, amounts, beneficiary in values
    ]


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    logs: list[dict[str, Any]] = []
    chunks = 0
    for start in range(START_BLOCK, latest + 1, CHUNK):
        end = min(latest, start + CHUNK - 1)
        batch = get_logs(start, end)
        logs.extend(batch)
        chunks += 1
        (OUT / "progress.json").write_text(
            json.dumps({"latest": latest, "chunks": chunks, "eventLogs": len(logs)}, indent=2),
            encoding="utf-8",
        )
        time.sleep(0.05)

    tx_hashes = sorted({str(log["transactionHash"]) for log in logs if log.get("transactionHash")})
    selector_counts: Counter[str] = Counter()
    shape_counts: Counter[str] = Counter()
    caller_hash_counts: Counter[str] = Counter()
    decoded_count = 0
    failures: list[dict[str, Any]] = []
    exceptional: list[dict[str, Any]] = []
    max_entries = 0
    max_tokens = 0
    counts = Counter()

    for index, tx_hash in enumerate(tx_hashes):
        tx = rpc("eth_getTransactionByHash", [tx_hash])
        if not tx or str(tx.get("to") or "").lower() != DEPOSIT:
            continue
        input_data = str(tx.get("input") or "0x")
        selector = input_data[:10].lower()
        selector_counts[selector] += 1
        if selector != REQUEST_SELECTOR:
            continue
        try:
            entries = decode_entries(input_data)
        except Exception as exc:  # noqa: BLE001
            failures.append({"transactionHash": tx_hash, "errorType": type(exc).__name__, "errorSha256": sha(str(exc))})
            continue

        decoded_count += 1
        caller_hash_counts[sha(str(tx.get("from") or "").lower())] += 1
        max_entries = max(max_entries, len(entries))
        beneficiary_counts = Counter(entry[2] for entry in entries)
        pair_counts: Counter[tuple[str, str]] = Counter()
        entry_meta = []

        for entry_index, (tokens, amounts, beneficiary) in enumerate(entries):
            token_counts = Counter(tokens)
            duplicates = [token for token, count in token_counts.items() if count > 1]
            max_tokens = max(max_tokens, len(tokens))
            if len(tokens) != len(amounts):
                counts["malformedLengths"] += 1
            if len(tokens) > 1:
                counts["multiTokenEntries"] += 1
            if duplicates:
                counts["duplicateTokenEntries"] += 1
            for token in tokens:
                pair_counts[(beneficiary, token)] += 1
            entry_meta.append(
                {
                    "entryIndex": entry_index,
                    "beneficiarySha256": sha(beneficiary),
                    "tokenCount": len(tokens),
                    "uniqueTokenCount": len(token_counts),
                    "hasDuplicateToken": bool(duplicates),
                    "tokenSha256": [sha(token) for token in tokens],
                    "amountsSha256": sha("|".join(map(str, amounts))),
                    "aggregateAmountByTokenHash": {
                        sha(token): sha(str(sum(amount for actual, amount in zip(tokens, amounts) if actual == token)))
                        for token in sorted(token_counts)
                    },
                }
            )

        repeated_beneficiary = any(count > 1 for count in beneficiary_counts.values())
        repeated_pair = any(count > 1 for count in pair_counts.values())
        if len(entries) > 1:
            counts["multiEntryCalls"] += 1
        if repeated_beneficiary:
            counts["repeatedBeneficiaryBatches"] += 1
        if repeated_pair:
            counts["repeatedBeneficiaryTokenPairBatches"] += 1

        shape = f"entries={len(entries)};tokens={','.join(str(len(entry[0])) for entry in entries)}"
        shape_counts[shape] += 1
        if (
            len(entries) > 1
            or any(len(entry[0]) > 1 for entry in entries)
            or any(len(set(entry[0])) < len(entry[0]) for entry in entries)
            or repeated_beneficiary
            or repeated_pair
        ):
            exceptional.append(
                {
                    "transactionHash": tx_hash,
                    "blockNumber": int(tx["blockNumber"], 16),
                    "entryCount": len(entries),
                    "uniqueBeneficiaryCount": len(beneficiary_counts),
                    "repeatedBeneficiary": repeated_beneficiary,
                    "repeatedBeneficiaryTokenPair": repeated_pair,
                    "entries": entry_meta,
                }
            )

        if index % 20 == 0:
            (OUT / "decode-progress.json").write_text(
                json.dumps({"processed": index + 1, "candidates": len(tx_hashes), "decoded": decoded_count}, indent=2),
                encoding="utf-8",
            )
        time.sleep(0.04)

    summary = {
        "safety": "Public Ethereum JSON-RPC reads only; no signer, transaction or state mutation.",
        "depositProxy": DEPOSIT,
        "startBlock": START_BLOCK,
        "latestBlock": latest,
        "eventSignature": EVENT_SIG,
        "eventTopic": EVENT_TOPIC,
        "requestSignature": REQUEST_SIG,
        "requestSelector": REQUEST_SELECTOR,
        "eventLogCount": len(logs),
        "uniqueEventTransactionCount": len(tx_hashes),
        "decodedRequestCallCount": decoded_count,
        "decodeFailureCount": len(failures),
        "uniqueCallerCount": len(caller_hash_counts),
        "maxEntryCount": max_entries,
        "maxTokenCountPerEntry": max_tokens,
        "counts": dict(counts),
        "shapeCounts": dict(shape_counts.most_common()),
        "selectorCounts": dict(selector_counts.most_common()),
        "callerHashCounts": dict(caller_hash_counts.most_common()),
        "exceptionalCallCount": len(exceptional),
        "exceptionalCalls": exceptional,
        "decodeFailures": failures,
        "verdict": (
            "PRODUCTION_COMPLEX_WITHDRAWAL_SHAPE_OBSERVED"
            if exceptional
            else "ONLY_SINGLE_ENTRY_SINGLE_TOKEN_WITHDRAWALS_OBSERVED"
        ),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "eventLogCount": summary["eventLogCount"],
        "decodedRequestCallCount": decoded_count,
        "maxEntryCount": max_entries,
        "maxTokenCountPerEntry": max_tokens,
        "counts": dict(counts),
        "exceptionalCallCount": len(exceptional),
        "verdict": summary["verdict"],
    }, indent=2))


if __name__ == "__main__":
    main()
