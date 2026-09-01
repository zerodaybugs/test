#!/usr/bin/env python3
"""Correlate all public production deposit beneficiaries with the official test API.

Safety properties:
- public Ethereum log reads only;
- unsigned `getSubAccountIds` queries only;
- no signatures, credentials, orders, positions, balances, or mutations;
- query the test API first and query production only for wallets with test access;
- raw wallet addresses and account IDs are never persisted;
- bounded participant count and throttled requests.

Goal: identify any same-wallet, same-subaccount-ID overlap between the production and
test databases. Since both environments use the same EIP-712 domain, such an overlap
would be a prerequisite for cross-environment signed-request replay.
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

OUT = pathlib.Path("cross_env_full_correlation")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
PROD_INFO = "https://papi.synthetix.io/v1/info"
TEST_INFO = "https://api.test.synthetix.io/v1/info"
DEPOSIT_PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
CREATION_BLOCK = 23_739_792
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 3 * 1024 * 1024
MAX_PARTICIPANTS = 500
REQUEST_DELAY_SECONDS = 0.28


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


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
                raise RuntimeError("response too large")
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
                errors.append(f"status={status},code={code}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
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


def parse_sets(status: int, body: bytes) -> tuple[dict[str, set[str]], dict[str, Any]]:
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    result = {"owned": set(), "delegated": set(), "managed": set()}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            result["owned"] = {str(value) for value in response}
        elif isinstance(response, dict):
            result["owned"] = {str(value) for value in response.get("subAccountIds", []) or []}
            result["delegated"] = {str(value) for value in response.get("delegatedSubAccountIds", []) or []}
            result["managed"] = {str(value) for value in response.get("managedSubAccountIds", []) or []}
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    return result, {
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "counts": {key: len(value) for key, value in result.items()},
    }


def discover(url: str, wallet: str) -> tuple[dict[str, set[str]], dict[str, Any]]:
    status, body = post_json(
        url,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": wallet,
                "includeDelegations": True,
            }
        },
    )
    return parse_sets(status, body)


def union(values: dict[str, set[str]]) -> set[str]:
    return set().union(*values.values())


def role_intersections(test: dict[str, set[str]], prod: dict[str, set[str]]) -> dict[str, int]:
    output: dict[str, int] = {}
    for test_role, test_values in test.items():
        for prod_role, prod_values in prod.items():
            output[f"test_{test_role}__prod_{prod_role}"] = len(test_values & prod_values)
    return output


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    logs = get_logs(CREATION_BLOCK, latest)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))

    beneficiary_frequency: collections.Counter[str] = collections.Counter()
    depositor_frequency: collections.Counter[str] = collections.Counter()
    zero_sentinel_events = 0
    nonzero_events = 0
    for log in logs:
        topics = log.get("topics", [])
        data = str(log.get("data", "0x")).removeprefix("0x")
        if len(topics) < 3 or len(data) < 128:
            continue
        depositor = to_checksum_address("0x" + str(topics[1])[-40:])
        beneficiary = to_checksum_address("0x" + str(topics[2])[-40:])
        subaccount_id = int(data[64:128], 16)
        depositor_frequency[depositor] += 1
        beneficiary_frequency[beneficiary] += 1
        if subaccount_id == 0:
            zero_sentinel_events += 1
        else:
            nonzero_events += 1

    participants = [address for address, _ in beneficiary_frequency.most_common()]
    if len(participants) > MAX_PARTICIPANTS:
        raise RuntimeError(
            f"Participant count {len(participants)} exceeds safety cap {MAX_PARTICIPANTS}."
        )

    rows: list[dict[str, Any]] = []
    test_positive_count = 0
    overlap_wallet_count = 0
    total_overlap_ids: set[str] = set()
    test_role_totals = collections.Counter()
    prod_role_totals_for_test_positive = collections.Counter()
    role_pair_totals = collections.Counter()
    non_ok_test_count = 0

    for index, wallet in enumerate(participants):
        test_sets, test_meta = discover(TEST_INFO, wallet)
        test_all = union(test_sets)
        for role, values in test_sets.items():
            test_role_totals[role] += len(values)

        row: dict[str, Any] = {
            "walletSha256": digest(wallet.lower()),
            "productionDepositEventCount": beneficiary_frequency[wallet],
            "alsoDepositorEventCount": depositor_frequency[wallet],
            "test": test_meta,
            "testUnionCount": len(test_all),
        }

        if test_meta["httpStatus"] != 200 or test_meta["apiStatus"] != "ok":
            non_ok_test_count += 1

        if test_all:
            test_positive_count += 1
            prod_sets, prod_meta = discover(PROD_INFO, wallet)
            prod_all = union(prod_sets)
            overlap = test_all & prod_all
            intersections = role_intersections(test_sets, prod_sets)
            for role, values in prod_sets.items():
                prod_role_totals_for_test_positive[role] += len(values)
            role_pair_totals.update(intersections)
            if overlap:
                overlap_wallet_count += 1
                total_overlap_ids.update(overlap)
            row.update(
                {
                    "production": prod_meta,
                    "productionUnionCount": len(prod_all),
                    "intersectionCount": len(overlap),
                    "intersectionIdSha256": sorted(digest(value) for value in overlap),
                    "roleIntersections": intersections,
                }
            )
            time.sleep(REQUEST_DELAY_SECONDS)
        else:
            row.update(
                {
                    "production": None,
                    "productionUnionCount": None,
                    "intersectionCount": 0,
                    "intersectionIdSha256": [],
                    "roleIntersections": {},
                }
            )

        rows.append(row)
        # Write progress on every row so a transient failure still leaves useful evidence.
        progress = {
            "processed": index + 1,
            "total": len(participants),
            "testPositiveCount": test_positive_count,
            "overlapWalletCount": overlap_wallet_count,
            "nonOkTestCount": non_ok_test_count,
        }
        (OUT / "progress.json").write_text(json.dumps(progress, indent=2), encoding="utf-8")
        if index + 1 < len(participants):
            time.sleep(REQUEST_DELAY_SECONDS)

    summary = {
        "safety": "Public Ethereum logs and unsigned account discovery only; no identities or account IDs retained.",
        "proxy": DEPOSIT_PROXY,
        "creationBlock": CREATION_BLOCK,
        "latestBlock": latest,
        "assetDepositedEventCount": len(logs),
        "zeroSentinelEventCount": zero_sentinel_events,
        "nonzeroSubaccountEventCount": nonzero_events,
        "uniqueBeneficiaryCount": len(participants),
        "uniqueDepositorCount": len(depositor_frequency),
        "processedBeneficiaryCount": len(rows),
        "testDiscoveryNonOkCount": non_ok_test_count,
        "walletsWithAnyTestAccess": test_positive_count,
        "walletsWithAnySameIdCrossEnvironmentOverlap": overlap_wallet_count,
        "uniqueOverlappingAccountIdCount": len(total_overlap_ids),
        "overlappingAccountIdSha256": sorted(digest(value) for value in total_overlap_ids),
        "testRoleTotals": dict(test_role_totals),
        "productionRoleTotalsForTestPositiveWallets": dict(prod_role_totals_for_test_positive),
        "rolePairIntersectionTotals": dict(role_pair_totals),
        "results": rows,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "assetDepositedEventCount",
                    "uniqueBeneficiaryCount",
                    "processedBeneficiaryCount",
                    "testDiscoveryNonOkCount",
                    "walletsWithAnyTestAccess",
                    "walletsWithAnySameIdCrossEnvironmentOverlap",
                    "uniqueOverlappingAccountIdCount",
                    "testRoleTotals",
                    "productionRoleTotalsForTestPositiveWallets",
                    "rolePairIntersectionTotals",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
