#!/usr/bin/env python3
"""Checksum-corrected read-only correlation of Synthetix deposit identities.

Only public Ethereum JSON-RPC reads and unsigned PAPI account-discovery queries
are performed. Raw participant addresses and subaccount IDs are never written.
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

OUT = pathlib.Path("deposit_identity_correlation_v2")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
PAPI_INFO = "https://papi.synthetix.io/v1/info"
PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
CREATION_BLOCK = 23_739_792
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
MAX_BODY = 5 * 1024 * 1024
MAX_PARTICIPANTS = 100
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"


def sha(value: str) -> str:
    return hashlib.sha256(value.lower().encode()).hexdigest()


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
    failures: list[str] = []
    for endpoint in RPC_URLS:
        try:
            status, body = post_json(endpoint, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                failures.append(f"{endpoint}:{status}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{endpoint}:{type(exc).__name__}")
    raise RuntimeError("RPC failure: " + " | ".join(failures))


def logs_split(start: int, end: int) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [{"address": PROXY, "fromBlock": hex(start), "toBlock": hex(end), "topics": [ASSET_DEPOSITED_TOPIC]}],
        )
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return logs_split(start, middle) + logs_split(middle + 1, end)


def topic_address(topic: str) -> str:
    return "0x" + topic[-40:]


def discover(address: str) -> dict[str, Any]:
    checksum = to_checksum_address(address)
    status, body = post_json(
        PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": checksum, "includeDelegations": True}},
    )
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    ids = {"owned": set(), "delegated": set(), "managed": set()}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            ids["owned"] = {str(item) for item in response}
        elif isinstance(response, dict):
            ids["owned"] = {str(item) for item in response.get("subAccountIds", []) or []}
            ids["delegated"] = {str(item) for item in response.get("delegatedSubAccountIds", []) or []}
            ids["managed"] = {str(item) for item in response.get("managedSubAccountIds", []) or []}
    error = parsed.get("error") if isinstance(parsed, dict) else None
    return {
        "ids": ids,
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error.get("code") if isinstance(error, dict) else None,
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "bodyBytes": len(body),
    }


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    raw_logs = logs_split(CREATION_BLOCK, latest)
    raw_logs.sort(key=lambda row: (int(row["blockNumber"], 16), int(row["logIndex"], 16)))

    events: list[dict[str, Any]] = []
    participants: set[str] = set()
    for log in raw_logs:
        topics = log.get("topics", [])
        data = str(log.get("data", "0x")).removeprefix("0x")
        if len(topics) < 4 or len(data) < 128:
            continue
        depositor = topic_address(topics[1]).lower()
        beneficiary = topic_address(topics[2]).lower()
        subaccount_id = str(int(data[64:128], 16))
        event = {
            "depositor": depositor,
            "beneficiary": beneficiary,
            "subaccountId": subaccount_id,
            "blockNumber": int(log["blockNumber"], 16),
            "transactionHash": str(log["transactionHash"]),
            "logIndex": int(log["logIndex"], 16),
        }
        events.append(event)
        if subaccount_id != "0":
            participants.update((depositor, beneficiary))

    if len(participants) > MAX_PARTICIPANTS:
        raise RuntimeError(f"Participant cap exceeded: {len(participants)} > {MAX_PARTICIPANTS}")

    discoveries: dict[str, dict[str, Any]] = {}
    for index, address in enumerate(sorted(participants)):
        discoveries[address] = discover(address)
        if index + 1 < len(participants):
            time.sleep(0.35)

    categories: collections.Counter[str] = collections.Counter()
    records: list[dict[str, Any]] = []

    def has(address: str, role: str, account_id: str) -> bool:
        return account_id in discoveries[address]["ids"][role]

    for event in events:
        account_id = event["subaccountId"]
        if account_id == "0":
            categories["zero_sentinel"] += 1
            continue
        depositor = event["depositor"]
        beneficiary = event["beneficiary"]
        flags = {
            "beneficiaryOwned": has(beneficiary, "owned", account_id),
            "beneficiaryDelegated": has(beneficiary, "delegated", account_id),
            "beneficiaryManaged": has(beneficiary, "managed", account_id),
            "depositorOwned": has(depositor, "owned", account_id),
            "depositorDelegated": has(depositor, "delegated", account_id),
            "depositorManaged": has(depositor, "managed", account_id),
        }
        beneficiary_any = any(flags[name] for name in ("beneficiaryOwned", "beneficiaryDelegated", "beneficiaryManaged"))
        depositor_any = any(flags[name] for name in ("depositorOwned", "depositorDelegated", "depositorManaged"))
        if flags["beneficiaryOwned"]:
            category = "beneficiary_owned_match"
        elif beneficiary_any:
            category = "beneficiary_nonowner_access_match"
        elif depositor_any:
            category = "depositor_only_match"
        else:
            category = "no_participant_match"
        categories[category] += 1
        records.append(
            {
                "blockNumber": event["blockNumber"],
                "transactionHashSha256": hashlib.sha256(event["transactionHash"].encode()).hexdigest(),
                "logIndex": event["logIndex"],
                "depositorSha256": sha(depositor),
                "beneficiarySha256": sha(beneficiary),
                "depositorEqualsBeneficiary": depositor == beneficiary,
                "subAccountIdSha256": hashlib.sha256(account_id.encode()).hexdigest(),
                "category": category,
                "matches": flags,
                "beneficiaryCounts": {role: len(discoveries[beneficiary]["ids"][role]) for role in ("owned", "delegated", "managed")},
                "depositorCounts": {role: len(discoveries[depositor]["ids"][role]) for role in ("owned", "delegated", "managed")},
                "beneficiaryApi": {key: discoveries[beneficiary][key] for key in ("httpStatus", "apiStatus", "errorCode")},
                "depositorApi": {key: discoveries[depositor][key] for key in ("httpStatus", "apiStatus", "errorCode")},
            }
        )

    api_failures = sum(
        record["httpStatus"] != 200 or record["apiStatus"] != "ok"
        for record in discoveries.values()
    )
    summary = {
        "safety": "Public Ethereum reads and unsigned checksummed account discovery only; no raw identities or account IDs retained.",
        "proxy": PROXY,
        "creationBlock": CREATION_BLOCK,
        "latestBlock": latest,
        "assetDepositedEventCount": len(events),
        "zeroSubAccountSentinelCount": categories["zero_sentinel"],
        "nonZeroSubAccountEventCount": len(records),
        "queriedParticipantCount": len(participants),
        "participantApiFailureCount": api_failures,
        "categoryCounts": dict(categories),
        "strongIdentityMismatchCount": categories["depositor_only_match"],
        "unresolvedIdentityCount": categories["no_participant_match"],
        "correlatedNonZeroEvents": records,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({key: summary[key] for key in (
        "assetDepositedEventCount", "zeroSubAccountSentinelCount", "nonZeroSubAccountEventCount",
        "queriedParticipantCount", "participantApiFailureCount", "categoryCounts",
        "strongIdentityMismatchCount", "unresolvedIdentityCount")}, indent=2))


if __name__ == "__main__":
    main()
