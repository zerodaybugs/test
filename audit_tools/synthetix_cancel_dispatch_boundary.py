#!/usr/bin/env python3
"""Low-noise EIP-712 dispatcher differential for Synthetix cancelOrders.

The production API uses one outer action (`cancelOrders`) for two distinct signed
primary types: CancelOrders(orderIds) and CancelOrdersByCloid(clientOrderIds).
This probe checks whether verification and dispatch normalize the same field set.

Safety properties:
- deterministic synthetic EOA only;
- preflight confirms zero owned, managed, and delegated Synthetix accounts;
- deliberately nonexistent source account and order identifiers;
- therefore no cancellation can execute;
- only response metadata, hashes, schemas, and redacted errors are retained.
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

OUT = pathlib.Path("cancel_dispatch_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
PRIVATE_KEY = "0x" + "88" * 32
ACCOUNT = Account.from_key(PRIVATE_KEY)
SUBACCOUNT_ID = 999_999_937
ORDER_A = 9_100_001
ORDER_B = 9_100_003
CLOID_A = "0x" + "11" * 16
CLOID_B = "0x" + "22" * 16
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
DOMAIN = {
    "name": "Synthetix",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
}
CANCEL_IDS_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "CancelOrders": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "orderIds", "type": "uint256[]"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}
CANCEL_CLOIDS_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "CancelOrdersByCloid": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "clientOrderIds", "type": "string[]"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}
SUBACCOUNT_ACTION_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "SubAccountAction": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "action", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{7,}\b", "<number>", text)
    return text[:600]


def post_bytes(url: str, body: bytes, timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(MAX_BODY + 1)
            if len(response_body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, response_body, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read(MAX_BODY + 1),
            dict(exc.headers.items()) if exc.headers else {},
            time.monotonic() - started,
        )


def post_json(url: str, payload: dict[str, Any]) -> tuple[int, bytes, dict[str, str], float]:
    return post_bytes(url, json.dumps(payload, separators=(",", ":")).encode())


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if not isinstance(response, dict):
        return None
    recognized = False
    count = 0
    for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
        values = response.get(key)
        if isinstance(values, list):
            recognized = True
            count += len(values)
    return count if recognized else None


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def sign_ids(nonce: int, expires_after: int, order_ids: list[int]) -> dict[str, Any]:
    message = {
        "subAccountId": SUBACCOUNT_ID,
        "orderIds": order_ids,
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    encoded = encode_typed_data(
        full_message={
            "types": CANCEL_IDS_TYPES,
            "primaryType": "CancelOrders",
            "domain": DOMAIN,
            "message": message,
        }
    )
    return format_signature(ACCOUNT.sign_message(encoded))


def sign_cloids(nonce: int, expires_after: int, client_order_ids: list[str]) -> dict[str, Any]:
    message = {
        "subAccountId": SUBACCOUNT_ID,
        "clientOrderIds": client_order_ids,
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    encoded = encode_typed_data(
        full_message={
            "types": CANCEL_CLOIDS_TYPES,
            "primaryType": "CancelOrdersByCloid",
            "domain": DOMAIN,
            "message": message,
        }
    )
    return format_signature(ACCOUNT.sign_message(encoded))


def sign_generic(nonce: int, expires_after: int) -> dict[str, Any]:
    message = {
        "subAccountId": SUBACCOUNT_ID,
        "action": "cancelOrders",
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    encoded = encode_typed_data(
        full_message={
            "types": SUBACCOUNT_ACTION_TYPES,
            "primaryType": "SubAccountAction",
            "domain": DOMAIN,
            "message": message,
        }
    )
    return format_signature(ACCOUNT.sign_message(encoded))


def corrupt(signature: dict[str, Any]) -> dict[str, Any]:
    value = int(signature["s"], 16) ^ 1
    return {"v": signature["v"], "r": signature["r"], "s": "0x" + format(value, "064x")}


def envelope(
    signature: dict[str, Any],
    nonce: int,
    expires_after: int,
    *,
    order_ids: Any | None = None,
    client_order_ids: Any | None = None,
    action: str = "cancelOrders",
    source_key: str = "subaccountId",
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "action": action,
        source_key: str(SUBACCOUNT_ID),
        "walletAddress": ACCOUNT.address,
    }
    if order_ids is not None:
        params["orderIds"] = order_ids
    if client_order_ids is not None:
        params["clientOrderIds"] = client_order_ids
    return {
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": params,
    }


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(str(error_message)) if error_message is not None else None,
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "requestId": (
            parsed.get("request_id") if isinstance(parsed, dict) else None
        ) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def raw_duplicate_field_body(nonce: int, expires_after: int) -> bytes:
    signature = sign_ids(nonce, expires_after, [ORDER_A])
    return (
        "{"
        '"signature":' + json.dumps(signature, separators=(",", ":")) + ","
        f'"nonce":{nonce},"expiresAfter":{expires_after},'
        '"params":{'
        '"action":"cancelOrders",'
        f'"subaccountId":"{SUBACCOUNT_ID}",'
        f'"walletAddress":"{ACCOUNT.address}",'
        f'"orderIds":[{ORDER_A}],'
        f'"orderIds":[{ORDER_B}]'
        "}}"
    ).encode()


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": (
            "Deterministic zero-account EOA and deliberately nonexistent account/order IDs only; "
            "no cancellation can execute."
        ),
        "syntheticAddress": ACCOUNT.address,
        "subaccountIdSha256": digest(str(SUBACCOUNT_ID)),
        "tests": [],
    }

    status, body, headers, elapsed = post_json(
        PAPI_INFO,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": ACCOUNT.address,
                "includeDelegations": True,
            }
        },
    )
    preflight = summarize("synthetic_account_preflight", status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    count = account_count(response)
    preflight["accountCount"] = count
    evidence["tests"].append(preflight)

    if count != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic EOA was not confirmed to own/manage/delegate zero accounts."
    else:
        cases: list[tuple[str, dict[str, Any] | bytes]] = []

        def add(
            name: str,
            signer: str,
            *,
            signed_ids: list[int] | None = None,
            signed_cloids: list[str] | None = None,
            wire_ids: Any | None = None,
            wire_cloids: Any | None = None,
            corrupt_sig: bool = False,
            source_key: str = "subaccountId",
        ) -> None:
            nonce = int(time.time() * 1000) + len(cases)
            expires_after = nonce + 120_000
            if signer == "ids":
                signature = sign_ids(nonce, expires_after, signed_ids or [ORDER_A])
            elif signer == "cloids":
                signature = sign_cloids(nonce, expires_after, signed_cloids or [CLOID_A])
            elif signer == "generic":
                signature = sign_generic(nonce, expires_after)
            else:
                raise ValueError(signer)
            if corrupt_sig:
                signature = corrupt(signature)
            cases.append(
                (
                    name,
                    envelope(
                        signature,
                        nonce,
                        expires_after,
                        order_ids=wire_ids,
                        client_order_ids=wire_cloids,
                        source_key=source_key,
                    ),
                )
            )

        add("corrupted_ids_signature_control", "ids", wire_ids=[str(ORDER_A)], corrupt_sig=True)
        add("correct_order_ids_primary_type", "ids", wire_ids=[str(ORDER_A)])
        add("correct_cloids_primary_type", "cloids", wire_cloids=[CLOID_A])
        add("ids_signature_wire_cloids_only", "ids", wire_cloids=[CLOID_A])
        add("cloids_signature_wire_ids_only", "cloids", wire_ids=[str(ORDER_A)])
        add("both_fields_sign_ids", "ids", wire_ids=[str(ORDER_A)], wire_cloids=[CLOID_B])
        add("both_fields_sign_cloids", "cloids", wire_ids=[str(ORDER_B)], wire_cloids=[CLOID_A])
        add("signed_ids_mismatch_wire_ids", "ids", signed_ids=[ORDER_A], wire_ids=[str(ORDER_B)])
        add("signed_cloids_mismatch_wire_cloids", "cloids", signed_cloids=[CLOID_A], wire_cloids=[CLOID_B])
        add("malformed_ids_valid_cloids_sign_cloids", "cloids", wire_ids=["AUDIT_NOT_UINT"], wire_cloids=[CLOID_A])
        add("valid_ids_malformed_cloids_sign_ids", "ids", wire_ids=[str(ORDER_A)], wire_cloids=[12345])
        add("generic_subaccount_action_replayed_as_cancel", "generic", wire_ids=[str(ORDER_A)])
        add("camel_case_source_correct_ids", "ids", wire_ids=[str(ORDER_A)], source_key="subAccountId")

        nonce = int(time.time() * 1000) + len(cases)
        cases.append(("duplicate_order_ids_json_key", raw_duplicate_field_body(nonce, nonce + 120_000)))

        for name, payload in cases:
            if isinstance(payload, bytes):
                status, body, headers, elapsed = post_bytes(PAPI_TRADE, payload)
            else:
                status, body, headers, elapsed = post_json(PAPI_TRADE, payload)
            evidence["tests"].append(summarize(name, status, body, headers, elapsed))
            time.sleep(0.65)

    tests = {item.get("name"): item for item in evidence["tests"]}
    baseline_ids = tests.get("correct_order_ids_primary_type", {})
    baseline_cloids = tests.get("correct_cloids_primary_type", {})
    evidence["differential"] = {
        "baselineIdsErrorCode": baseline_ids.get("errorCode"),
        "baselineCloidsErrorCode": baseline_cloids.get("errorCode"),
        "baselineIdsErrorHash": baseline_ids.get("errorMessageSha256"),
        "baselineCloidsErrorHash": baseline_cloids.get("errorMessageSha256"),
        "casesMatchingIdsBody": [
            item.get("name")
            for item in evidence["tests"]
            if item.get("bodySha256") == baseline_ids.get("bodySha256")
        ],
        "casesMatchingCloidsBody": [
            item.get("name")
            for item in evidence["tests"]
            if item.get("bodySha256") == baseline_cloids.get("bodySha256")
        ],
    }
    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps({
        "preflightAccountCount": tests.get("synthetic_account_preflight", {}).get("accountCount"),
        "differential": evidence["differential"],
        "cases": [
            {
                "name": item.get("name"),
                "httpStatus": item.get("httpStatus"),
                "errorCode": item.get("errorCode"),
                "errorMessageRedacted": item.get("errorMessageRedacted"),
            }
            for item in evidence["tests"]
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
