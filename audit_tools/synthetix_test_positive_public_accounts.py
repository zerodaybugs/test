#!/usr/bin/env python3
"""Enumerate public production deposit beneficiaries that also have test-API accounts.

All inputs are public Ethereum logs and unsigned account-discovery responses. The output retains
only the small test-positive subset, including public wallet addresses and off-chain test account
IDs, so those identities can be correlated with intentionally published development keys. No
signature, credential, account data, order, balance, or mutation is used.
"""
from __future__ import annotations

import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

from eth_utils import to_checksum_address

OUT = pathlib.Path("test_positive_public_accounts")
OUT.mkdir(parents=True, exist_ok=True)
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
TEST_INFO = "https://api.test.synthetix.io/v1/info"
DEPOSIT_PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
CREATION_BLOCK = 23_739_792
TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"


def post(url: str, payload: dict[str, Any]) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            return response.status, response.read(3 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(3 * 1024 * 1024)


def rpc(method: str, params: list[Any]) -> Any:
    errors = []
    for url in RPC_URLS:
        try:
            status, body = post(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            parsed = json.loads(body)
            if status < 400 and "error" not in parsed:
                return parsed["result"]
            errors.append(str(parsed.get("error")))
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def logs(start: int, end: int) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [{"address": DEPOSIT_PROXY, "fromBlock": hex(start), "toBlock": hex(end), "topics": [TOPIC]}],
        )
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return logs(start, middle) + logs(middle + 1, end)


def discover(wallet: str) -> tuple[int, dict[str, list[str]], str | None]:
    status, body = post(
        TEST_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}},
    )
    try:
        parsed = json.loads(body)
    except Exception:
        return status, {"owned": [], "managed": [], "delegated": []}, None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    values = {"owned": [], "managed": [], "delegated": []}
    if status == 200 and parsed.get("status") == "ok":
        if isinstance(response, list):
            values["owned"] = [str(v) for v in response]
        elif isinstance(response, dict):
            values["owned"] = [str(v) for v in response.get("subAccountIds", []) or []]
            values["managed"] = [str(v) for v in response.get("managedSubAccountIds", []) or []]
            values["delegated"] = [str(v) for v in response.get("delegatedSubAccountIds", []) or []]
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    return status, values, message


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    entries = logs(CREATION_BLOCK, latest)
    beneficiaries = sorted(
        {
            to_checksum_address("0x" + str(entry["topics"][2])[-40:])
            for entry in entries
            if len(entry.get("topics", [])) >= 3
        }
    )
    positives = []
    errors = []
    for index, wallet in enumerate(beneficiaries):
        status, values, message = discover(wallet)
        if any(values.values()):
            positives.append({"walletAddress": wallet, "testAccounts": values})
        if status != 200:
            errors.append({"walletAddress": wallet, "status": status, "message": message})
        if index + 1 < len(beneficiaries):
            time.sleep(0.22)
    output = {
        "safety": "Public Ethereum logs and unsigned test account discovery only.",
        "latestBlock": latest,
        "depositEventCount": len(entries),
        "beneficiaryCount": len(beneficiaries),
        "positiveCount": len(positives),
        "nonOkCount": len(errors),
        "positives": positives,
        "errors": errors,
    }
    (OUT / "public_test_positive_accounts.json").write_text(
        json.dumps(output, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps({key: output[key] for key in ("beneficiaryCount", "positiveCount", "nonOkCount")}, indent=2))


if __name__ == "__main__":
    main()
