#!/usr/bin/env python3
"""Correlate public Synthetix deposit events with unsigned account discovery.

Safety properties:
- public Ethereum JSON-RPC log/block reads only;
- unsigned PAPI `getSubAccountIds` queries only;
- no signatures, credentials, transactions, orders, positions, or balances;
- raw wallet addresses are never written to artifacts;
- only non-zero event subaccount IDs are queried/correlated.
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

OUT = pathlib.Path("deposit_identity_correlation")
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
MAX_PARTICIPANTS = 400


def digest(value: str) -> str:
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
    return "0x" + topic[-40:]


def parse_account_ids(body: bytes, status: int) -> dict[str, Any]:
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
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
    error_code = error.get("code") if isinstance(error, dict) else None
    return {
        "ids": ids,
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "bodyBytes": len(body),
    }


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
    return parse_account_ids(body, status)


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    logs = get_logs(CREATION_BLOCK, latest)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))

    events: list[dict[str, Any]] = []
    participant_frequency: collections.Counter[str] = collections.Counter()
    zero_subaccount_count = 0

    for log in logs:
        topics = log.get("topics", [])
        data = str(log.get("data", "0x")).removeprefix("0x")
        if len(topics) < 4 or len(data) < 128:
            continue
        depositor = topic_address(topics[1]).lower()
        beneficiary = topic_address(topics[2]).lower()
        token = topic_address(topics[3]).lower()
        amount = int(data[:64], 16)
        subaccount_id = str(int(data[64:128], 16))
        if subaccount_id == "0":
            zero_subaccount_count += 1
        else:
            participant_frequency[depositor] += 1
            participant_frequency[beneficiary] += 1
        events.append(
            {
                "depositor": depositor,
                "beneficiary": beneficiary,
                "token": token,
                "amount": amount,
                "subaccountId": subaccount_id,
                "blockNumber": int(log["blockNumber"], 16),
                "transactionHash": str(log["transactionHash"]),
                "logIndex": int(log["logIndex"], 16),
            }
        )

    participants = [address for address, _ in participant_frequency.most_common()]
    if len(participants) > MAX_PARTICIPANTS:
        raise RuntimeError(
            f"Non-zero subaccount correlation requires {len(participants)} participant queries, exceeding safety cap {MAX_PARTICIPANTS}."
        )

    discoveries: dict[str, dict[str, Any]] = {}
    for index, address in enumerate(participants):
        discoveries[address] = discover(address)
        if index + 1 < len(participants):
            time.sleep(0.25)

    category_counts: collections.Counter[str] = collections.Counter()
    correlated: list[dict[str, Any]] = []

    def contains(address: str, role: str, subaccount_id: str) -> bool:
        record = discoveries.get(address)
        return bool(record and subaccount_id in record["ids"][role])

    for event in events:
        subaccount_id = event["subaccountId"]
        if subaccount_id == "0":
            category_counts["zero_sentinel"] += 1
            continue

        depositor = event["depositor"]
        beneficiary = event["beneficiary"]
        flags = {
            "beneficiaryOwned": contains(beneficiary, "owned", subaccount_id),
            "beneficiaryDelegated": contains(beneficiary, "delegated", subaccount_id),
            "beneficiaryManaged": contains(beneficiary, "managed", subaccount_id),
            "depositorOwned": contains(depositor, "owned", subaccount_id),
            "depositorDelegated": contains(depositor, "delegated", subaccount_id),
            "depositorManaged": contains(depositor, "managed", subaccount_id),
        }
        beneficiary_any = any(flags[key] for key in ("beneficiaryOwned", "beneficiaryDelegated", "beneficiaryManaged"))
        depositor_any = any(flags[key] for key in ("depositorOwned", "depositorDelegated", "depositorManaged"))

        if flags["beneficiaryOwned"]:
            category = "beneficiary_owned_match"
        elif beneficiary_any:
            category = "beneficiary_nonowner_access_match"
        elif depositor_any:
            category = "depositor_only_match"
        else:
            category = "no_participant_match"
        category_counts[category] += 1

        correlated.append(
            {
                "blockNumber": event["blockNumber"],
                "transactionHashSha256": hashlib.sha256(event["transactionHash"].encode()).hexdigest(),
                "logIndex": event["logIndex"],
                "depositorSha256": digest(depositor),
                "beneficiarySha256": digest(beneficiary),
                "tokenSha256": digest(event["token"]),
                "depositorEqualsBeneficiary": depositor == beneficiary,
                "amountPositive": event["amount"] > 0,
                "subAccountIdSha256": hashlib.sha256(subaccount_id.encode()).hexdigest(),
                "category": category,
                "matches": flags,
                "beneficiaryDiscoveryStatus": {
                    "httpStatus": discoveries[beneficiary]["httpStatus"],
                    "apiStatus": discoveries[beneficiary]["apiStatus"],
                    "errorCode": discoveries[beneficiary]["errorCode"],
                    "ownedCount": len(discoveries[beneficiary]["ids"]["owned"]),
                    "delegatedCount": len(discoveries[beneficiary]["ids"]["delegated"]),
                    "managedCount": len(discoveries[beneficiary]["ids"]["managed"]),
                },
                "depositorDiscoveryStatus": {
                    "httpStatus": discoveries[depositor]["httpStatus"],
                    "apiStatus": discoveries[depositor]["apiStatus"],
                    "errorCode": discoveries[depositor]["errorCode"],
                    "ownedCount": len(discoveries[depositor]["ids"]["owned"]),
                    "delegatedCount": len(discoveries[depositor]["ids"]["delegated"]),
                    "managedCount": len(discoveries[depositor]["ids"]["managed"]),
                },
            }
        )

    summary = {
        "safety": "Public Ethereum RPC plus unsigned PAPI account-discovery only; raw participant identities and account IDs are not retained.",
        "proxy": DEPOSIT_PROXY,
        "creationBlock": CREATION_BLOCK,
        "latestBlock": latest,
        "assetDepositedEventCount": len(events),
        "zeroSubAccountSentinelCount": zero_subaccount_count,
        "nonZeroSubAccountEventCount": len(events) - zero_subaccount_count,
        "queriedParticipantCount": len(participants),
        "categoryCounts": dict(category_counts),
        "strongIdentityMismatchCount": category_counts["depositor_only_match"],
        "unresolvedIdentityCount": category_counts["no_participant_match"],
        "correlatedNonZeroEvents": correlated,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "assetDepositedEventCount",
                    "zeroSubAccountSentinelCount",
                    "nonZeroSubAccountEventCount",
                    "queriedParticipantCount",
                    "categoryCounts",
                    "strongIdentityMismatchCount",
                    "unresolvedIdentityCount",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
