#!/usr/bin/env python3
"""Read-only correlation of zero-sentinel Synthetix deposit events.

The production frontend commonly emits ``subAccountId = 0`` on deposits. This
collector tests whether those events bind account provisioning to the event
beneficiary or incorrectly to the token depositor, and whether public history
contains account-creation race or orphaning indicators.

Safety constraints:
- public Ethereum JSON-RPC logs/blocks only;
- unsigned PAPI ``getSubAccountIds`` queries only;
- no signature, credential, order, balance read, transaction, or state change;
- raw wallet addresses and account IDs are never written to artifacts;
- bounded query count and fixed per-request delay.
"""
from __future__ import annotations

import collections
import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

from eth_utils import to_checksum_address

OUT = pathlib.Path("zero_sentinel_account_correlation")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
PAPI_INFO = "https://papi.synthetix.io/v1/info"
DEPOSIT_PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
CREATION_BLOCK = 23_739_792
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 5 * 1024 * 1024
MAX_DISCOVERY_QUERIES = 500
DISCOVERY_DELAY_SECONDS = 0.15
BLOCK_DELAY_SECONDS = 0.01
FIVE_MINUTES = 300


def digest(value: str) -> str:
    return hashlib.sha256(value.lower().encode()).hexdigest()


def digest_exact(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1)


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                error = parsed.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                errors.append(f"{url}:status={status},code={code}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}:{type(exc).__name__}")
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def get_logs(start: int, end: int) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [
                {
                    "address": DEPOSIT_PROXY,
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [ASSET_DEPOSITED_TOPIC],
                }
            ],
        )
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return get_logs(start, middle) + get_logs(middle + 1, end)


def topic_address(topic: str) -> str:
    return to_checksum_address("0x" + topic[-40:])


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def discover(address: str) -> dict[str, Any]:
    status, body = post_json(
        PAPI_INFO,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": address,
                "includeDelegations": True,
            }
        },
    )
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    ids = {"owned": set(), "delegated": set(), "managed": set()}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            ids["owned"] = {str(value) for value in response}
        elif isinstance(response, dict):
            ids["owned"] = {str(value) for value in response.get("subAccountIds", []) or []}
            ids["delegated"] = {str(value) for value in response.get("delegatedSubAccountIds", []) or []}
            ids["managed"] = {str(value) for value in response.get("managedSubAccountIds", []) or []}
    error = parsed.get("error") if isinstance(parsed, dict) else None
    return {
        "ids": ids,
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error.get("code") if isinstance(error, dict) else None,
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "bodyBytes": len(body),
        "responseSchema": schema(response),
    }


def access_counts(record: dict[str, Any] | None) -> dict[str, int]:
    if not record:
        return {"owned": 0, "delegated": 0, "managed": 0, "total": 0}
    result = {key: len(record["ids"][key]) for key in ("owned", "delegated", "managed")}
    result["total"] = sum(result.values())
    return result


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    logs = get_logs(CREATION_BLOCK, latest)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))

    events: list[dict[str, Any]] = []
    block_numbers: set[int] = set()
    for log in logs:
        topics = log.get("topics", [])
        data = str(log.get("data", "0x")).removeprefix("0x")
        if len(topics) < 4 or len(data) < 128:
            continue
        block_number = int(log["blockNumber"], 16)
        event = {
            "depositor": topic_address(topics[1]),
            "beneficiary": topic_address(topics[2]),
            "token": topic_address(topics[3]),
            "amount": int(data[:64], 16),
            "subAccountId": int(data[64:128], 16),
            "blockNumber": block_number,
            "transactionHash": str(log["transactionHash"]),
            "logIndex": int(log["logIndex"], 16),
        }
        events.append(event)
        block_numbers.add(block_number)

    block_timestamps: dict[int, int] = {}
    for index, block_number in enumerate(sorted(block_numbers)):
        block = rpc("eth_getBlockByNumber", [hex(block_number), False])
        block_timestamps[block_number] = int(block["timestamp"], 16)
        if index + 1 < len(block_numbers):
            time.sleep(BLOCK_DELAY_SECONDS)
    for event in events:
        event["timestamp"] = block_timestamps[event["blockNumber"]]

    zero_events = [event for event in events if event["subAccountId"] == 0]
    nonzero_events = [event for event in events if event["subAccountId"] != 0]
    cross_party = [event for event in zero_events if event["depositor"].lower() != event["beneficiary"].lower()]

    by_beneficiary: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    by_transaction: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    by_block_and_beneficiary: dict[tuple[int, str], list[dict[str, Any]]] = collections.defaultdict(list)
    participant_frequency: collections.Counter[str] = collections.Counter()
    for event in zero_events:
        beneficiary = event["beneficiary"]
        depositor = event["depositor"]
        by_beneficiary[beneficiary].append(event)
        by_transaction[event["transactionHash"]].append(event)
        by_block_and_beneficiary[(event["blockNumber"], beneficiary)].append(event)
        participant_frequency[beneficiary] += 2
        participant_frequency[depositor] += 1

    repeated_within_five_minutes: list[dict[str, Any]] = []
    burst_beneficiaries: set[str] = set()
    for beneficiary, beneficiary_events in by_beneficiary.items():
        beneficiary_events.sort(key=lambda item: (item["timestamp"], item["logIndex"]))
        minimum_gap: int | None = None
        close_pair_count = 0
        for previous, current in zip(beneficiary_events, beneficiary_events[1:]):
            gap = max(0, current["timestamp"] - previous["timestamp"])
            minimum_gap = gap if minimum_gap is None else min(minimum_gap, gap)
            if gap <= FIVE_MINUTES:
                close_pair_count += 1
        if close_pair_count:
            burst_beneficiaries.add(beneficiary)
            repeated_within_five_minutes.append(
                {
                    "beneficiarySha256": digest(beneficiary),
                    "eventCount": len(beneficiary_events),
                    "closePairCount": close_pair_count,
                    "minimumGapSeconds": minimum_gap,
                    "firstBlock": beneficiary_events[0]["blockNumber"],
                    "lastBlock": beneficiary_events[-1]["blockNumber"],
                }
            )

    same_transaction_batches = [items for items in by_transaction.values() if len(items) > 1]
    same_block_beneficiary_batches = [items for items in by_block_and_beneficiary.values() if len(items) > 1]

    # Query all participants when bounded. Otherwise guarantee complete coverage of
    # cross-party identities and timing anomalies, then fill remaining capacity by
    # event frequency.
    all_participants = set(participant_frequency)
    required_participants = {
        address
        for event in cross_party
        for address in (event["depositor"], event["beneficiary"])
    } | burst_beneficiaries
    if len(required_participants) > MAX_DISCOVERY_QUERIES:
        raise RuntimeError(
            f"Required anomaly coverage needs {len(required_participants)} account-discovery queries, "
            f"exceeding safety cap {MAX_DISCOVERY_QUERIES}."
        )
    if len(all_participants) <= MAX_DISCOVERY_QUERIES:
        queried_participants = list(all_participants)
        full_participant_coverage = True
    else:
        remaining = MAX_DISCOVERY_QUERIES - len(required_participants)
        extras = [
            address
            for address, _count in participant_frequency.most_common()
            if address not in required_participants
        ][:remaining]
        queried_participants = list(required_participants) + extras
        full_participant_coverage = False

    discoveries: dict[str, dict[str, Any]] = {}
    for index, address in enumerate(queried_participants):
        discoveries[address] = discover(address)
        if index + 1 < len(queried_participants):
            time.sleep(DISCOVERY_DELAY_SECONDS)

    cross_party_results: list[dict[str, Any]] = []
    cross_party_categories: collections.Counter[str] = collections.Counter()
    for event in cross_party:
        beneficiary_record = discoveries.get(event["beneficiary"])
        depositor_record = discoveries.get(event["depositor"])
        beneficiary_counts = access_counts(beneficiary_record)
        depositor_counts = access_counts(depositor_record)
        beneficiary_ids = set().union(*(beneficiary_record["ids"].values())) if beneficiary_record else set()
        depositor_ids = set().union(*(depositor_record["ids"].values())) if depositor_record else set()
        intersection_count = len(beneficiary_ids & depositor_ids)

        if beneficiary_counts["owned"] > 0 and depositor_counts["total"] == 0:
            category = "beneficiary_owned_only"
        elif beneficiary_counts["total"] > 0 and depositor_counts["total"] == 0:
            category = "beneficiary_access_only"
        elif beneficiary_counts["total"] > 0 and depositor_counts["total"] > 0 and intersection_count > 0:
            category = "both_share_account_access"
        elif beneficiary_counts["total"] > 0 and depositor_counts["total"] > 0:
            category = "both_separate_account_access"
        elif beneficiary_counts["total"] == 0 and depositor_counts["total"] > 0:
            category = "depositor_only_access"
        else:
            category = "neither_currently_mapped"
        cross_party_categories[category] += 1

        cross_party_results.append(
            {
                "blockNumber": event["blockNumber"],
                "timestamp": event["timestamp"],
                "transactionHashSha256": digest_exact(event["transactionHash"]),
                "logIndex": event["logIndex"],
                "depositorSha256": digest(event["depositor"]),
                "beneficiarySha256": digest(event["beneficiary"]),
                "tokenSha256": digest(event["token"]),
                "amountPositive": event["amount"] > 0,
                "category": category,
                "beneficiaryAccessCounts": beneficiary_counts,
                "depositorAccessCounts": depositor_counts,
                "sharedAccountIdCount": intersection_count,
                "beneficiaryApi": {
                    "httpStatus": beneficiary_record.get("httpStatus") if beneficiary_record else None,
                    "apiStatus": beneficiary_record.get("apiStatus") if beneficiary_record else None,
                    "errorCode": beneficiary_record.get("errorCode") if beneficiary_record else None,
                },
                "depositorApi": {
                    "httpStatus": depositor_record.get("httpStatus") if depositor_record else None,
                    "apiStatus": depositor_record.get("apiStatus") if depositor_record else None,
                    "errorCode": depositor_record.get("errorCode") if depositor_record else None,
                },
            }
        )

    beneficiary_mapping_counts: collections.Counter[str] = collections.Counter()
    queried_beneficiary_summaries: list[dict[str, Any]] = []
    for beneficiary, beneficiary_events in by_beneficiary.items():
        record = discoveries.get(beneficiary)
        if record is None:
            continue
        counts = access_counts(record)
        if counts["owned"] > 0:
            category = "owned"
        elif counts["delegated"] > 0:
            category = "delegated_only"
        elif counts["managed"] > 0:
            category = "managed_only"
        else:
            category = "no_current_access"
        beneficiary_mapping_counts[category] += 1
        queried_beneficiary_summaries.append(
            {
                "beneficiarySha256": digest(beneficiary),
                "zeroDepositEventCount": len(beneficiary_events),
                "depositorDistinctCount": len({event["depositor"].lower() for event in beneficiary_events}),
                "crossPartyEventCount": sum(
                    event["depositor"].lower() != event["beneficiary"].lower()
                    for event in beneficiary_events
                ),
                "currentAccessCategory": category,
                "accessCounts": counts,
                "firstBlock": min(event["blockNumber"] for event in beneficiary_events),
                "lastBlock": max(event["blockNumber"] for event in beneficiary_events),
            }
        )

    suspicious_beneficiaries = [
        item
        for item in queried_beneficiary_summaries
        if item["crossPartyEventCount"] > 0
        or item["currentAccessCategory"] == "no_current_access"
        or item["accessCounts"]["owned"] > 1
    ]

    same_transaction_summary = [
        {
            "transactionHashSha256": digest_exact(items[0]["transactionHash"]),
            "blockNumber": items[0]["blockNumber"],
            "eventCount": len(items),
            "distinctDepositorCount": len({item["depositor"].lower() for item in items}),
            "distinctBeneficiaryCount": len({item["beneficiary"].lower() for item in items}),
            "crossPartyEventCount": sum(
                item["depositor"].lower() != item["beneficiary"].lower() for item in items
            ),
        }
        for items in same_transaction_batches
    ]
    same_block_summary = [
        {
            "beneficiarySha256": digest(items[0]["beneficiary"]),
            "blockNumber": items[0]["blockNumber"],
            "eventCount": len(items),
            "distinctDepositorCount": len({item["depositor"].lower() for item in items}),
            "crossPartyEventCount": sum(
                item["depositor"].lower() != item["beneficiary"].lower() for item in items
            ),
        }
        for items in same_block_beneficiary_batches
    ]

    summary = {
        "safety": (
            "Public Ethereum RPC and unsigned PAPI account-discovery only; no raw wallet "
            "addresses or account IDs retained."
        ),
        "proxy": DEPOSIT_PROXY,
        "creationBlock": CREATION_BLOCK,
        "latestBlock": latest,
        "assetDepositedEventCount": len(events),
        "zeroSubAccountSentinelCount": len(zero_events),
        "nonZeroSubAccountEventCount": len(nonzero_events),
        "uniqueZeroBeneficiaryCount": len(by_beneficiary),
        "uniqueZeroParticipantCount": len(all_participants),
        "queriedParticipantCount": len(queried_participants),
        "fullParticipantCoverage": full_participant_coverage,
        "crossPartyZeroEventCount": len(cross_party),
        "crossPartyDistinctBeneficiaryCount": len({event["beneficiary"].lower() for event in cross_party}),
        "crossPartyDistinctDepositorCount": len({event["depositor"].lower() for event in cross_party}),
        "crossPartyCategoryCounts": dict(cross_party_categories),
        "crossPartyStrongIdentityMismatchCount": cross_party_categories["depositor_only_access"],
        "crossPartyUnresolvedCount": cross_party_categories["neither_currently_mapped"],
        "sameTransactionMultiZeroDepositBatchCount": len(same_transaction_batches),
        "sameBlockBeneficiaryMultiZeroDepositBatchCount": len(same_block_beneficiary_batches),
        "beneficiaryRepeatedWithinFiveMinutesCount": len(repeated_within_five_minutes),
        "queriedBeneficiaryMappingCounts": dict(beneficiary_mapping_counts),
        "queriedBeneficiaryNoCurrentAccessCount": beneficiary_mapping_counts["no_current_access"],
        "queriedBeneficiaryMultipleOwnedAccountCount": sum(
            item["accessCounts"]["owned"] > 1 for item in queried_beneficiary_summaries
        ),
        "crossPartyEvents": cross_party_results,
        "sameTransactionBatches": same_transaction_summary,
        "sameBlockBeneficiaryBatches": same_block_summary,
        "repeatedWithinFiveMinutes": repeated_within_five_minutes,
        "suspiciousBeneficiaries": suspicious_beneficiaries,
    }

    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "assetDepositedEventCount",
                    "zeroSubAccountSentinelCount",
                    "uniqueZeroBeneficiaryCount",
                    "uniqueZeroParticipantCount",
                    "queriedParticipantCount",
                    "fullParticipantCoverage",
                    "crossPartyZeroEventCount",
                    "crossPartyCategoryCounts",
                    "crossPartyStrongIdentityMismatchCount",
                    "crossPartyUnresolvedCount",
                    "sameTransactionMultiZeroDepositBatchCount",
                    "sameBlockBeneficiaryMultiZeroDepositBatchCount",
                    "beneficiaryRepeatedWithinFiveMinutesCount",
                    "queriedBeneficiaryMappingCounts",
                )
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
