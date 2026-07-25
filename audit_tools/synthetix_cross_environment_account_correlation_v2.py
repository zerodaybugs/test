#!/usr/bin/env python3
"""Checksummed production-versus-test account-ID correlation for public deposit beneficiaries."""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
from typing import Any

from eth_utils import to_checksum_address

import synthetix_cross_environment_boundary as base

OUT = pathlib.Path("cross_environment_account_correlation_v2")
OUT.mkdir(parents=True, exist_ok=True)


def digest(value: str) -> str:
    return hashlib.sha256(value.lower().encode()).hexdigest()


def beneficiary_from_receipt(tx_hash: str) -> str | None:
    receipt = base.rpc("eth_getTransactionReceipt", [tx_hash])
    if not isinstance(receipt, dict):
        return None
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        if (
            str(log.get("address", "")).lower() == base.DEPOSIT_PROXY.lower()
            and len(topics) >= 3
            and str(topics[0]).lower() == base.ASSET_DEPOSITED_TOPIC.lower()
        ):
            return to_checksum_address("0x" + str(topics[2])[-40:])
    return None


def main() -> None:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for tx_hash in base.DEPOSIT_TX_HASHES:
        wallet = beneficiary_from_receipt(tx_hash)
        if not wallet or wallet.lower() in seen:
            continue
        seen.add(wallet.lower())
        prod_sets, prod_meta = base.account_ids(base.PROD_INFO, wallet)
        time.sleep(0.35)
        test_sets, test_meta = base.account_ids(base.TEST_INFO, wallet)
        intersection = {key: prod_sets[key] & test_sets[key] for key in ("owned", "delegated", "managed")}
        records.append(
            {
                "walletSha256": digest(wallet),
                "txHashSha256": hashlib.sha256(tx_hash.encode()).hexdigest(),
                "production": prod_meta,
                "test": test_meta,
                "productionIdsSha256": {key: sorted(hashlib.sha256(v.encode()).hexdigest() for v in values) for key, values in prod_sets.items()},
                "testIdsSha256": {key: sorted(hashlib.sha256(v.encode()).hexdigest() for v in values) for key, values in test_sets.items()},
                "intersectionCounts": {key: len(values) for key, values in intersection.items()},
                "intersectionIdsSha256": {key: sorted(hashlib.sha256(v.encode()).hexdigest() for v in values) for key, values in intersection.items()},
            }
        )
        time.sleep(0.4)
    summary = {
        "safety": "Public Ethereum receipts and unsigned getSubAccountIds queries only; identities and account IDs hashed before persistence.",
        "walletCount": len(records),
        "walletsWithProductionOwnedAccounts": sum(item["production"]["counts"]["owned"] > 0 for item in records),
        "walletsWithTestOwnedAccounts": sum(item["test"]["counts"]["owned"] > 0 for item in records),
        "walletsWithAnyIntersection": sum(any(v > 0 for v in item["intersectionCounts"].values()) for item in records),
        "totalProductionCounts": {key: sum(item["production"]["counts"][key] for item in records) for key in ("owned", "delegated", "managed")},
        "totalTestCounts": {key: sum(item["test"]["counts"][key] for item in records) for key in ("owned", "delegated", "managed")},
        "totalIntersectionCounts": {key: sum(item["intersectionCounts"][key] for item in records) for key in ("owned", "delegated", "managed")},
        "records": records,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("walletCount", "walletsWithProductionOwnedAccounts", "walletsWithTestOwnedAccounts", "walletsWithAnyIntersection", "totalProductionCounts", "totalTestCounts", "totalIntersectionCounts")}, indent=2))


if __name__ == "__main__":
    main()
