#!/usr/bin/env python3
"""Read-only discovery of public deterministic development accounts in Synthetix's test API.

Uses the standard public Hardhat/Anvil mnemonic only. No credential is secret, no request is
signed, and no state is changed. The output retains address hashes and account counts, not raw
account IDs. A positive result would provide a safe, non-sensitive test account for validating
WebSocket authentication replay semantics end to end without touching a real user.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

from eth_account import Account

OUT = pathlib.Path("test_dev_account_discovery")
OUT.mkdir(parents=True, exist_ok=True)
INFO = "https://api.test.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MNEMONIC = "test test test test test test test test test test test junk"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def post(payload: dict[str, Any]) -> tuple[int, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        INFO,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            raw = response.read(2 * 1024 * 1024)
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read(2 * 1024 * 1024)
        status = exc.code
    try:
        return status, json.loads(raw)
    except Exception:
        return status, None


def ids_from_response(parsed: Any) -> dict[str, list[str]]:
    response = parsed.get("response") if isinstance(parsed, dict) else None
    out = {"owned": [], "managed": [], "delegated": []}
    if isinstance(response, list):
        out["owned"] = [str(value) for value in response]
    elif isinstance(response, dict):
        out["owned"] = [str(value) for value in response.get("subAccountIds", []) or []]
        out["managed"] = [str(value) for value in response.get("managedSubAccountIds", []) or []]
        out["delegated"] = [str(value) for value in response.get("delegatedSubAccountIds", []) or []]
    return out


def main() -> None:
    Account.enable_unaudited_hdwallet_features()
    results = []
    positives = []
    for index in range(20):
        acct = Account.from_mnemonic(MNEMONIC, account_path=f"m/44'/60'/0'/0/{index}")
        status, parsed = post(
            {"params": {"action": "getSubAccountIds", "walletAddress": acct.address, "includeDelegations": True}}
        )
        ids = ids_from_response(parsed)
        item = {
            "derivationIndex": index,
            "addressSha256": digest(acct.address.lower()),
            "httpStatus": status,
            "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
            "counts": {key: len(values) for key, values in ids.items()},
            "accountIdHashes": {key: sorted(digest(value) for value in values) for key, values in ids.items()},
        }
        results.append(item)
        if any(ids.values()):
            positives.append(
                {
                    "derivationIndex": index,
                    "address": acct.address,
                    "privateKey": "0x" + acct.key.hex(),
                    "ids": ids,
                }
            )
        time.sleep(0.2)

    # Positive keys are public deterministic development keys, not secrets. They are isolated in a
    # separate local-only JSON file for the follow-up workflow; the summary contains hashes only.
    summary = {
        "safety": "Unsigned test API discovery using the public Hardhat/Anvil mnemonic only.",
        "checked": len(results),
        "positiveCount": len(positives),
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (OUT / "public_dev_positive_accounts.json").write_text(
        json.dumps(positives, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps({"checked": len(results), "positiveCount": len(positives)}, indent=2))


if __name__ == "__main__":
    main()
