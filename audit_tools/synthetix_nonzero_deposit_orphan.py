#!/usr/bin/env python3
"""Read-only reconstruction of the anomalous first non-zero Synthetix deposit event.

The historical correlation found one AssetDeposited event whose explicit subAccountId no longer
matches any owned/delegated/managed account for either depositor or beneficiary. This collector
fetches the exact public receipt/transaction/block, decodes all Deposit events in the transaction,
queries current unsigned account discovery, and compares surrounding non-zero deposits.

Public Ethereum JSON-RPC and unsigned Synthetix info API only. No signer, credential, trade request,
transaction, account mutation, or private data access.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

from eth_utils import to_checksum_address

OUT = pathlib.Path("synthetix_nonzero_deposit_orphan")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
INFO = "https://papi.synthetix.io/v1/info"
PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
TARGET_BLOCK = 24_265_381
TARGET_LOG_INDEX = 866
TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 4 * 1024 * 1024


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
    if len(body) > MAX_BODY:
        raise RuntimeError("response exceeds cap")
    return status, body


def rpc(method: str, params: list[Any]) -> Any:
    errors = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            parsed = json.loads(body)
            if status < 400 and "error" not in parsed:
                return parsed["result"]
            errors.append({"url": url, "status": status, "error": parsed.get("error")})
        except Exception as exc:  # noqa: BLE001
            errors.append({"url": url, "error": type(exc).__name__})
    raise RuntimeError(f"RPC failed {method}: {errors}")


def decode_address(topic: str) -> str:
    return to_checksum_address("0x" + topic[-40:])


def decode_event(log: dict[str, Any]) -> dict[str, Any]:
    topics = log.get("topics", [])
    data = str(log.get("data", "0x"))[2:]
    if len(topics) < 4 or len(data) < 128:
        raise ValueError("unexpected AssetDeposited encoding")
    amount = int(data[:64], 16)
    subaccount_id = int(data[64:128], 16)
    return {
        "blockNumber": int(log["blockNumber"], 16),
        "transactionIndex": int(log["transactionIndex"], 16),
        "logIndex": int(log["logIndex"], 16),
        "transactionHash": log["transactionHash"],
        "depositor": decode_address(topics[1]),
        "beneficiary": decode_address(topics[2]),
        "token": decode_address(topics[3]),
        "amountRaw": str(amount),
        "subAccountId": str(subaccount_id),
        "removed": bool(log.get("removed", False)),
    }


def discover(wallet: str) -> dict[str, Any]:
    status, body = post_json(
        INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}},
    )
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    roles = {"owned": [], "managed": [], "delegated": []}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            roles["owned"] = [str(x) for x in response]
        elif isinstance(response, dict):
            roles["owned"] = [str(x) for x in (response.get("subAccountIds") or [])]
            roles["managed"] = [str(x) for x in (response.get("managedSubAccountIds") or [])]
            roles["delegated"] = [str(x) for x in (response.get("delegatedSubAccountIds") or [])]
    error = parsed.get("error") if isinstance(parsed, dict) else None
    return {
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error.get("code") if isinstance(error, dict) else None,
        "roles": roles,
        "bodySha256": sha(body),
    }


def eth_call(to: str, data: str, block: str = "latest") -> str | None:
    try:
        return rpc("eth_call", [{"to": to, "data": data}, block])
    except Exception:
        return None


def main() -> None:
    logs = rpc(
        "eth_getLogs",
        [{
            "address": PROXY,
            "fromBlock": hex(TARGET_BLOCK - 1),
            "toBlock": hex(TARGET_BLOCK + 1),
            "topics": [TOPIC],
        }],
    )
    decoded = [decode_event(log) for log in logs]
    target = next(
        (item for item in decoded if item["blockNumber"] == TARGET_BLOCK and item["logIndex"] == TARGET_LOG_INDEX),
        None,
    )
    if target is None:
        raise RuntimeError(f"target log not found among {len(decoded)} AssetDeposited logs")

    tx = rpc("eth_getTransactionByHash", [target["transactionHash"]])
    receipt = rpc("eth_getTransactionReceipt", [target["transactionHash"]])
    block = rpc("eth_getBlockByNumber", [hex(TARGET_BLOCK), False])
    tx_deposit_events = [
        decode_event(log)
        for log in receipt.get("logs", [])
        if str(log.get("address", "")).lower() == PROXY.lower()
        and log.get("topics")
        and str(log["topics"][0]).lower() == TOPIC.lower()
    ]

    beneficiary_discovery = discover(target["beneficiary"])
    depositor_discovery = (
        beneficiary_discovery if target["depositor"].lower() == target["beneficiary"].lower()
        else discover(target["depositor"])
    )

    target_id = target["subAccountId"]
    current_matches = {
        "beneficiary": {
            role: target_id in values for role, values in beneficiary_discovery["roles"].items()
        },
        "depositor": {
            role: target_id in values for role, values in depositor_discovery["roles"].items()
        },
    }

    token_decimals = None
    decimals_result = eth_call(target["token"], "0x313ce567")
    if decimals_result and decimals_result != "0x":
        token_decimals = int(decimals_result, 16)
    amount_normalized = None
    if token_decimals is not None:
        amount_normalized = int(target["amountRaw"]) / (10 ** token_decimals)

    # Compare all explicit non-zero deposits by the same beneficiary over the proxy lifetime.
    latest = int(rpc("eth_blockNumber", []), 16)
    beneficiary_topic = "0x" + "0" * 24 + target["beneficiary"][2:].lower()
    beneficiary_logs = rpc(
        "eth_getLogs",
        [{
            "address": PROXY,
            "fromBlock": hex(23_739_792),
            "toBlock": hex(latest),
            "topics": [TOPIC, None, beneficiary_topic],
        }],
    )
    beneficiary_events = [decode_event(log) for log in beneficiary_logs]
    nonzero_for_beneficiary = [item for item in beneficiary_events if item["subAccountId"] != "0"]

    output = {
        "safety": "Public Ethereum RPC and unsigned account discovery only; no signer or state mutation.",
        "target": target,
        "targetAmountNormalized": amount_normalized,
        "tokenDecimals": token_decimals,
        "targetTransaction": {
            "hash": tx.get("hash"),
            "from": tx.get("from"),
            "to": tx.get("to"),
            "nonce": int(tx.get("nonce", "0x0"), 16),
            "input": tx.get("input"),
            "inputSha256": sha(tx.get("input", "")),
            "value": str(int(tx.get("value", "0x0"), 16)),
            "transactionIndex": int(tx.get("transactionIndex", "0x0"), 16),
        },
        "receipt": {
            "status": int(receipt.get("status", "0x0"), 16),
            "gasUsed": str(int(receipt.get("gasUsed", "0x0"), 16)),
            "contractAddress": receipt.get("contractAddress"),
            "logCount": len(receipt.get("logs", [])),
            "depositEventCount": len(tx_deposit_events),
            "depositEvents": tx_deposit_events,
        },
        "block": {
            "number": TARGET_BLOCK,
            "timestamp": int(block["timestamp"], 16),
            "transactionCount": len(block.get("transactions", [])),
        },
        "beneficiaryDiscovery": beneficiary_discovery,
        "depositorDiscovery": depositor_discovery,
        "targetIdCurrentMatches": current_matches,
        "beneficiaryDepositEventCount": len(beneficiary_events),
        "beneficiaryNonZeroDepositEventCount": len(nonzero_for_beneficiary),
        "beneficiaryNonZeroDeposits": nonzero_for_beneficiary,
        "targetIdIsDecimalOne": target_id == "1",
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "targetTransactionHash": target["transactionHash"],
        "targetSubAccountId": target_id,
        "targetAmountRaw": target["amountRaw"],
        "targetAmountNormalized": amount_normalized,
        "token": target["token"],
        "beneficiary": target["beneficiary"],
        "currentRoleCounts": {k: len(v) for k, v in beneficiary_discovery["roles"].items()},
        "currentMatches": current_matches,
        "beneficiaryNonZeroDepositEventCount": len(nonzero_for_beneficiary),
    }, indent=2))


if __name__ == "__main__":
    main()
