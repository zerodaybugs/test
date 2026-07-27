#!/usr/bin/env python3
"""Read-only reconstruction of all successful Deposit.requestWithdrawal calldata.

Purpose
-------
Determine whether the production relayer has ever submitted multi-entry, multi-token,
duplicate-token, or repeated-beneficiary withdrawal batches. This is the missing
reachability gate for several local-fork invariants in the in-scope Deposit proxy.

Safety
------
* public Ethereum JSON-RPC reads only;
* no wallet, private key, signature, eth_call impersonation, or transaction;
* output contains public transaction identifiers plus structural metadata only;
* token amounts are summarized and hashed rather than used for any state change.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from typing import Any

from eth_abi import decode
from eth_utils import keccak, to_checksum_address

OUT = pathlib.Path("synthetix_withdrawal_calldata_history")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = [
    os.getenv("ETH_RPC_URL", "https://ethereum-rpc.publicnode.com"),
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
]
DEPOSIT = "0xd62595c3c23b690baee0935e107a209cb1dbd37b"
START_BLOCK = 22_000_000
CHUNK = 20_000
MAX_RESPONSE = 16 * 1024 * 1024
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
REQUEST_SIG = "requestWithdrawal((address[],uint256[],address)[])"
REQUEST_SELECTOR = "0x" + keccak(text=REQUEST_SIG)[:4].hex()


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def rpc(method: str, params: list[Any], retries: int = 5) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last_error: Exception | None = None
    for attempt in range(retries):
        for url in RPC_URLS:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"User-Agent": UA, "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as response:
                    raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise RuntimeError("RPC response exceeded safety cap")
                parsed = json.loads(raw)
                if parsed.get("error"):
                    raise RuntimeError(str(parsed["error"]))
                return parsed.get("result")
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, RuntimeError, json.JSONDecodeError) as exc:
                last_error = exc
                continue
        time.sleep(min(8, 2 ** attempt))
    raise RuntimeError(f"RPC failed for {method}: {last_error}")


def get_logs(start: int, end: int) -> list[dict[str, Any]]:
    return rpc(
        "eth_getLogs",
        [{"address": DEPOSIT, "fromBlock": hex(start), "toBlock": hex(end)}],
    )


def fetch_transaction(tx_hash: str) -> dict[str, Any] | None:
    return rpc("eth_getTransactionByHash", [tx_hash])


def normalize_address(value: str) -> str:
    return to_checksum_address(value).lower()


def decode_request(input_data: str) -> list[tuple[list[str], list[int], str]]:
    if not input_data.startswith(REQUEST_SELECTOR):
        raise ValueError("wrong selector")
    raw = bytes.fromhex(input_data[10:])
    decoded = decode(["(address[],uint256[],address)[]"], raw)[0]
    output: list[tuple[list[str], list[int], str]] = []
    for tokens, amounts, beneficiary in decoded:
        output.append(
            (
                [normalize_address(token) for token in tokens],
                [int(amount) for amount in amounts],
                normalize_address(beneficiary),
            )
        )
    return output


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    unique_tx_hashes: set[str] = set()
    total_logs = 0
    progress = []

    for start in range(START_BLOCK, latest + 1, CHUNK):
        end = min(latest, start + CHUNK - 1)
        logs = get_logs(start, end)
        total_logs += len(logs)
        unique_tx_hashes.update(log["transactionHash"] for log in logs if log.get("transactionHash"))
        progress.append({"from": start, "to": end, "logCount": len(logs)})
        (OUT / "progress.json").write_text(
            json.dumps(
                {
                    "latest": latest,
                    "chunksProcessed": len(progress),
                    "logsSeen": total_logs,
                    "uniqueTransactionHashes": len(unique_tx_hashes),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        time.sleep(0.08)

    calls = []
    failures = []
    selector_counts: Counter[str] = Counter()
    caller_counts: Counter[str] = Counter()
    shape_counts: Counter[str] = Counter()
    duplicate_token_entries = []
    repeated_beneficiary_batches = []
    repeated_beneficiary_token_pairs = []
    multi_entry_calls = []
    multi_token_entries = []
    malformed_length_entries = []

    for index, tx_hash in enumerate(sorted(unique_tx_hashes)):
        tx = fetch_transaction(tx_hash)
        if not tx or (tx.get("to") or "").lower() != DEPOSIT:
            continue
        input_data = tx.get("input") or "0x"
        selector = input_data[:10].lower() if len(input_data) >= 10 else input_data.lower()
        selector_counts[selector] += 1
        if selector != REQUEST_SELECTOR:
            continue
        try:
            entries = decode_request(input_data)
        except Exception as exc:
            failures.append({"txHash": tx_hash, "errorType": type(exc).__name__, "errorSha256": sha(str(exc))})
            continue

        block = int(tx["blockNumber"], 16) if tx.get("blockNumber") else None
        caller = (tx.get("from") or "").lower()
        caller_counts[caller] += 1
        beneficiary_counts = Counter(entry[2] for entry in entries)
        pair_counts: Counter[tuple[str, str]] = Counter()
        entry_summaries = []

        for entry_index, (tokens, amounts, beneficiary) in enumerate(entries):
            if len(tokens) != len(amounts):
                malformed_length_entries.append({"txHash": tx_hash, "entryIndex": entry_index})
            token_counts = Counter(tokens)
            duplicates = sorted(token for token, count in token_counts.items() if count > 1)
            for token in tokens:
                pair_counts[(beneficiary, token)] += 1
            amount_material = "|".join(str(amount) for amount in amounts)
            item = {
                "entryIndex": entry_index,
                "beneficiary": beneficiary,
                "tokenCount": len(tokens),
                "uniqueTokenCount": len(token_counts),
                "duplicateTokens": duplicates,
                "tokens": tokens,
                "amountsSha256": sha(amount_material),
                "aggregateAmountByToken": {
                    token: str(sum(amount for token2, amount in zip(tokens, amounts) if token2 == token))
                    for token in sorted(token_counts)
                },
            }
            entry_summaries.append(item)
            if duplicates:
                duplicate_token_entries.append({"txHash": tx_hash, "block": block, **item})
            if len(tokens) > 1:
                multi_token_entries.append({"txHash": tx_hash, "block": block, **item})

        repeated_beneficiaries = sorted(beneficiary for beneficiary, count in beneficiary_counts.items() if count > 1)
        repeated_pairs = [
            {"beneficiary": beneficiary, "token": token, "occurrences": count}
            for (beneficiary, token), count in sorted(pair_counts.items())
            if count > 1
        ]
        if repeated_beneficiaries:
            repeated_beneficiary_batches.append(
                {"txHash": tx_hash, "block": block, "beneficiaries": repeated_beneficiaries}
            )
        if repeated_pairs:
            repeated_beneficiary_token_pairs.append({"txHash": tx_hash, "block": block, "pairs": repeated_pairs})
        if len(entries) > 1:
            multi_entry_calls.append(
                {
                    "txHash": tx_hash,
                    "block": block,
                    "entryCount": len(entries),
                    "beneficiaryCount": len(beneficiary_counts),
                }
            )

        shape = f"entries={len(entries)};tokenCounts={','.join(str(len(entry[0])) for entry in entries)}"
        shape_counts[shape] += 1
        calls.append(
            {
                "txHash": tx_hash,
                "block": block,
                "transactionIndex": int(tx["transactionIndex"], 16) if tx.get("transactionIndex") else None,
                "caller": caller,
                "entryCount": len(entries),
                "uniqueBeneficiaryCount": len(beneficiary_counts),
                "entries": entry_summaries,
            }
        )
        if index % 25 == 0:
            (OUT / "decode-progress.json").write_text(
                json.dumps({"processed": index + 1, "candidateTransactions": len(unique_tx_hashes), "requestCalls": len(calls)}, indent=2),
                encoding="utf-8",
            )
        time.sleep(0.05)

    summary = {
        "safety": "Public Ethereum RPC reads only; no signatures, transactions, or state changes.",
        "depositProxy": DEPOSIT,
        "requestWithdrawalSignature": REQUEST_SIG,
        "requestWithdrawalSelector": REQUEST_SELECTOR,
        "startBlock": START_BLOCK,
        "latestBlock": latest,
        "contractLogCount": total_logs,
        "uniqueContractTransactionCount": len(unique_tx_hashes),
        "decodedRequestWithdrawalCallCount": len(calls),
        "decodeFailureCount": len(failures),
        "callerCount": len(caller_counts),
        "multiEntryCallCount": len(multi_entry_calls),
        "multiTokenEntryCount": len(multi_token_entries),
        "duplicateTokenEntryCount": len(duplicate_token_entries),
        "repeatedBeneficiaryBatchCount": len(repeated_beneficiary_batches),
        "repeatedBeneficiaryTokenPairBatchCount": len(repeated_beneficiary_token_pairs),
        "malformedLengthEntryCount": len(malformed_length_entries),
        "maxEntryCount": max((call["entryCount"] for call in calls), default=0),
        "maxTokenCountPerEntry": max((entry["tokenCount"] for call in calls for entry in call["entries"]), default=0),
        "shapeCounts": dict(shape_counts.most_common()),
        "selectorCounts": dict(selector_counts.most_common()),
        "callerCounts": dict(caller_counts.most_common()),
        "duplicateTokenEntries": duplicate_token_entries,
        "multiTokenEntries": multi_token_entries,
        "multiEntryCalls": multi_entry_calls,
        "repeatedBeneficiaryBatches": repeated_beneficiary_batches,
        "repeatedBeneficiaryTokenPairs": repeated_beneficiary_token_pairs,
        "decodeFailures": failures,
        "verdict": (
            "HISTORICAL_DUPLICATE_TOKEN_REACHABILITY_OBSERVED"
            if duplicate_token_entries
            else "NO_HISTORICAL_DUPLICATE_TOKEN_ENTRY_OBSERVED"
        ),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (OUT / "calls.json").write_text(json.dumps(calls, indent=2, sort_keys=True), encoding="utf-8")
    (OUT / "chunks.json").write_text(json.dumps(progress, indent=2), encoding="utf-8")
    print(json.dumps({
        "requestCalls": len(calls),
        "multiEntryCalls": len(multi_entry_calls),
        "multiTokenEntries": len(multi_token_entries),
        "duplicateTokenEntries": len(duplicate_token_entries),
        "repeatedBeneficiaryTokenPairBatches": len(repeated_beneficiary_token_pairs),
        "verdict": summary["verdict"],
    }, indent=2))


if __name__ == "__main__":
    main()
