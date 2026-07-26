#!/usr/bin/env python3
"""Controlled EIP-712 primary-type boundary matrix for Synthetix write actions.

Safety constraints:
- deterministic synthetic EOAs only;
- preflight confirms the signer owns/manages/delegates zero Synthetix accounts;
- deliberately nonexistent valid-range source and destination subaccount IDs;
- fixed low-noise request matrix;
- no real account, order, position, ticket, delegate, collateral, or funds are used;
- no write can execute because the signer has no source account;
- response bodies are reduced to status/error metadata, hashes, schemas, and recovered addresses.

Goal: determine whether a cached long-lived generic SubAccountAction signature, especially
one for a read action such as getPositions, can be replayed against any write handler that
should require an action-specific EIP-712 primary type binding every financial parameter.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from eth_account import Account
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("generic_write_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 3 * 1024 * 1024

SIGNER = Account.from_key("0x" + "b1" * 32)
DELEGATE = Account.from_key("0x" + "b2" * 32)
SOURCE_ID = 8_410_000_000_000_001
DESTINATION_ID = 8_410_000_000_000_003
READ_ACTION = "getPositions"
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
TRUNCATED_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{3,8}\.\.\.[a-fA-F0-9]{3,8}")
DELEGATE_EXPIRES_AT = int(time.time()) + 30 * 86400

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
GENERIC_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "SubAccountAction": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "action", "type": "string"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}

ORDER_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "Order": [
        {"name": "symbol", "type": "string"},
        {"name": "side", "type": "string"},
        {"name": "orderType", "type": "string"},
        {"name": "price", "type": "string"},
        {"name": "triggerPrice", "type": "string"},
        {"name": "quantity", "type": "string"},
        {"name": "reduceOnly", "type": "bool"},
        {"name": "isTriggerMarket", "type": "bool"},
        {"name": "clientOrderId", "type": "string"},
        {"name": "closePosition", "type": "bool"},
    ],
    "PlaceOrders": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "orders", "type": "Order[]"},
        {"name": "grouping", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "ModifyOrder": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "orderId", "type": "uint256"},
        {"name": "price", "type": "string"},
        {"name": "quantity", "type": "string"},
        {"name": "triggerPrice", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "CancelOrders": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "orderIds", "type": "uint256[]"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}

SIMPLE_TYPES: dict[str, list[dict[str, str]]] = {
    "CancelAllOrders": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbols", "type": "string[]"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "WithdrawCollateral": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "amount", "type": "string"},
        {"name": "destination", "type": "address"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "UpdateLeverage": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "leverage", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "CreateSubaccount": [
        {"name": "masterSubAccountId", "type": "uint256"},
        {"name": "name", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "TransferCollateral": [
        {"name": "amount", "type": "string"},
        {"name": "expiresAfter", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "to", "type": "uint256"},
    ],
    "VoluntaryCollateralExchange": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "sourceAsset", "type": "string"},
        {"name": "targetUSDTAmount", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "UpdateSubAccountName": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "name", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "AddDelegatedSigner": [
        {"name": "delegateAddress", "type": "address"},
        {"name": "subAccountId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
        {"name": "expiresAt", "type": "uint256"},
        {"name": "permissions", "type": "string[]"},
    ],
    "RemoveDelegatedSigner": [
        {"name": "delegateAddress", "type": "address"},
        {"name": "subAccountId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "RemoveAllDelegatedSigners": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "ScheduleCancel": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "timeoutSeconds", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    body = json.dumps(payload, separators=(",", ":")).encode()
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


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        total = 0
        recognized = False
        for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
            values = response.get(key)
            if isinstance(values, list):
                recognized = True
                total += len(values)
        return total if recognized else None
    return None


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def signature_hex(signature: dict[str, Any]) -> str:
    return (
        "0x"
        + str(signature["r"])[2:].rjust(64, "0")
        + str(signature["s"])[2:].rjust(64, "0")
        + format(int(signature["v"]), "02x")
    )


def typed_types(primary_type: str) -> dict[str, Any]:
    if primary_type in {"PlaceOrders", "ModifyOrder", "CancelOrders"}:
        return ORDER_TYPES
    return {"EIP712Domain": DOMAIN_FIELDS, primary_type: SIMPLE_TYPES[primary_type]}


@dataclass(frozen=True)
class ActionCase:
    wire_action: str
    primary_type: str
    signed_fields: Callable[[int, int], dict[str, Any]]
    wire_params: Callable[[int], dict[str, Any]]


ORDER = {
    "symbol": "BTC-USDT",
    "side": "buy",
    "orderType": "limitGtc",
    "price": "1",
    "triggerPrice": "",
    "quantity": "0.001",
    "reduceOnly": False,
    "isTriggerMarket": False,
    "clientOrderId": "0x" + "ab" * 16,
    "closePosition": False,
}

ACTIONS: list[ActionCase] = [
    ActionCase(
        "placeOrders",
        "PlaceOrders",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "orders": [ORDER], "grouping": "na", "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "placeOrders", "subAccountId": str(SOURCE_ID), "orders": [ORDER], "grouping": "na"},
    ),
    ActionCase(
        "modifyOrder",
        "ModifyOrder",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "orderId": 1, "price": "1", "quantity": "0.001", "triggerPrice": "", "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "modifyOrder", "subAccountId": str(SOURCE_ID), "orderId": "1", "price": "1", "quantity": "0.001", "triggerPrice": ""},
    ),
    ActionCase(
        "cancelOrders",
        "CancelOrders",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "orderIds": [1], "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "cancelOrders", "subAccountId": str(SOURCE_ID), "orderIds": ["1"]},
    ),
    ActionCase(
        "cancelAllOrders",
        "CancelAllOrders",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "symbols": [], "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "cancelAllOrders", "subAccountId": str(SOURCE_ID), "symbols": []},
    ),
    ActionCase(
        "withdrawCollateral",
        "WithdrawCollateral",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "symbol": "USDT", "amount": "1", "destination": SIGNER.address, "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "withdrawCollateral", "subAccountId": str(SOURCE_ID), "symbol": "USDT", "amount": "1", "destination": SIGNER.address},
    ),
    ActionCase(
        "updateLeverage",
        "UpdateLeverage",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "symbol": "BTC-USDT", "leverage": "1", "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "updateLeverage", "subAccountId": str(SOURCE_ID), "symbol": "BTC-USDT", "leverage": "1"},
    ),
    ActionCase(
        "createSubaccount",
        "CreateSubaccount",
        lambda nonce, expiry: {"masterSubAccountId": SOURCE_ID, "name": "audit", "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "createSubaccount", "subAccountId": str(SOURCE_ID), "name": "audit"},
    ),
    ActionCase(
        "transferCollateral",
        "TransferCollateral",
        lambda nonce, expiry: {"amount": "1", "expiresAfter": expiry, "nonce": nonce, "subAccountId": SOURCE_ID, "symbol": "USDT", "to": DESTINATION_ID},
        lambda now: {"action": "transferCollateral", "subAccountId": str(SOURCE_ID), "symbol": "USDT", "amount": "1", "to": str(DESTINATION_ID)},
    ),
    ActionCase(
        "voluntaryCollateralExchange",
        "VoluntaryCollateralExchange",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "sourceAsset": "WETH", "targetUSDTAmount": "1", "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "voluntaryCollateralExchange", "subAccountId": str(SOURCE_ID), "sourceAsset": "WETH", "targetUSDTAmount": "1"},
    ),
    ActionCase(
        "updateSubAccountName",
        "UpdateSubAccountName",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "name": "audit", "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "updateSubAccountName", "subAccountId": str(SOURCE_ID), "name": "audit"},
    ),
    ActionCase(
        "addDelegatedSigner",
        "AddDelegatedSigner",
        lambda nonce, expiry: {"delegateAddress": DELEGATE.address, "subAccountId": SOURCE_ID, "nonce": nonce, "expiresAfter": expiry, "expiresAt": DELEGATE_EXPIRES_AT, "permissions": ["trading"]},
        lambda now: {"action": "addDelegatedSigner", "subAccountId": str(SOURCE_ID), "walletAddress": DELEGATE.address, "permissions": ["trading"], "expiresAt": DELEGATE_EXPIRES_AT},
    ),
    ActionCase(
        "removeDelegatedSigner",
        "RemoveDelegatedSigner",
        lambda nonce, expiry: {"delegateAddress": DELEGATE.address, "subAccountId": SOURCE_ID, "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "removeDelegatedSigner", "subAccountId": str(SOURCE_ID), "walletAddress": DELEGATE.address},
    ),
    ActionCase(
        "removeAllDelegatedSigners",
        "RemoveAllDelegatedSigners",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "removeAllDelegatedSigners", "subAccountId": str(SOURCE_ID)},
    ),
    ActionCase(
        "scheduleCancel",
        "ScheduleCancel",
        lambda nonce, expiry: {"subAccountId": SOURCE_ID, "timeoutSeconds": 60, "nonce": nonce, "expiresAfter": expiry},
        lambda now: {"action": "scheduleCancel", "subAccountId": str(SOURCE_ID), "timeoutSeconds": 60},
    ),
]


def now_seconds() -> int:
    return int(time.time())


def sign_specific(action: ActionCase, nonce: int, expiry: int) -> tuple[dict[str, Any], dict[str, Any]]:
    message = action.signed_fields(nonce, expiry)
    encoded = encode_typed_data(
        full_message={
            "types": typed_types(action.primary_type),
            "primaryType": action.primary_type,
            "domain": DOMAIN,
            "message": message,
        }
    )
    return format_signature(SIGNER.sign_message(encoded)), message


def sign_generic(action_name: str, expiry: int) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": GENERIC_TYPES,
            "primaryType": "SubAccountAction",
            "domain": DOMAIN,
            "message": {"subAccountId": SOURCE_ID, "action": action_name, "expiresAfter": expiry},
        }
    )
    return format_signature(SIGNER.sign_message(encoded))


def recover_as_specific(action: ActionCase, signature: dict[str, Any], nonce: int, expiry: int) -> str:
    message = action.signed_fields(nonce, expiry)
    encoded = encode_typed_data(
        full_message={
            "types": typed_types(action.primary_type),
            "primaryType": action.primary_type,
            "domain": DOMAIN,
            "message": message,
        }
    )
    return Account.recover_message(encoded, signature=signature_hex(signature))


def make_envelope(
    action: ActionCase,
    signature: dict[str, Any],
    expiry: int,
    nonce: int | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "params": action.wire_params(now_seconds()),
        "signature": signature,
        "expiresAfter": expiry,
    }
    if nonce is not None:
        payload["nonce"] = nonce
    return payload


def summarize(
    name: str,
    action: ActionCase,
    status: int,
    body: bytes,
    headers: dict[str, str],
    elapsed: float,
    expected_wrong_recovery: str | None,
) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    raw = str(error_message) if error_message is not None else ""
    addresses = [value for value in ADDRESS_RE.findall(raw)]
    truncated_addresses = [value for value in TRUNCATED_ADDRESS_RE.findall(raw)]
    lowered = {value.lower() for value in addresses}

    def mentions(address: str | None) -> bool:
        if not address:
            return False
        address_lower = address.lower()
        truncated = f"0x{address_lower[2:5]}...{address_lower[-3:]}"
        raw_lower = raw.lower()
        return address_lower in lowered or address_lower in raw_lower or truncated in raw_lower

    response = parsed.get("response") if isinstance(parsed, dict) else None
    return {
        "name": name,
        "wireAction": action.wire_action,
        "primaryType": action.primary_type,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorCategory": error.get("category") if isinstance(error, dict) else None,
        "errorMessageRedacted": ADDRESS_RE.sub("<address>", raw)[:1000] if raw else None,
        "errorMessageSha256": digest(raw) if raw else None,
        "recoveredAddresses": addresses,
        "truncatedRecoveredAddresses": truncated_addresses,
        "mentionsSyntheticSigner": mentions(SIGNER.address),
        "mentionsExpectedWrongRecovery": mentions(expected_wrong_recovery),
        "expectedWrongRecovery": expected_wrong_recovery,
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "rateLimit": parsed.get("rateLimit") if isinstance(parsed, dict) and isinstance(parsed.get("rateLimit"), dict) else None,
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def run_case(
    action: ActionCase,
    case_name: str,
    signature: dict[str, Any],
    expiry: int,
    nonce: int | None,
    expected_wrong_recovery: str | None,
) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(PAPI_TRADE, make_envelope(action, signature, expiry, nonce))
    return summarize(case_name, action, status, body, headers, elapsed, expected_wrong_recovery)


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": (
            "Deterministic zero-account signer and deliberately nonexistent valid-range account IDs only. "
            "No real account or state can be affected."
        ),
        "syntheticSigner": SIGNER.address,
        "syntheticDelegate": DELEGATE.address,
        "sourceSubaccountIdSha256": digest(str(SOURCE_ID)),
        "destinationSubaccountIdSha256": digest(str(DESTINATION_ID)),
        "readAction": READ_ACTION,
        "tests": [],
    }

    status, body, headers, elapsed = post_json(
        PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": SIGNER.address, "includeDelegations": True}},
    )
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    preflight = {
        "name": "synthetic_account_preflight",
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "accountCount": account_count(response),
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "elapsedMs": round(elapsed * 1000, 2),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }
    evidence["tests"].append(preflight)
    if preflight["accountCount"] != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic signer was not confirmed to own/manage/delegate zero accounts."
        (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        raise RuntimeError(evidence["abortReason"])

    nonce_seed = int(time.time() * 1_000_000)
    for action_index, action in enumerate(ACTIONS):
        action_results: list[dict[str, Any]] = []
        base_nonce = nonce_seed + action_index * 20

        baseline_nonce = base_nonce + 1
        baseline_expiry = now_seconds() + 3600
        baseline_signature, _ = sign_specific(action, baseline_nonce, baseline_expiry)
        action_results.append(
            run_case(action, "specific_baseline", baseline_signature, baseline_expiry, baseline_nonce, SIGNER.address)
        )
        time.sleep(0.22)

        read_nonce = base_nonce + 2
        read_expiry = now_seconds() + 365 * 86400
        read_signature = sign_generic(READ_ACTION, read_expiry)
        read_wrong = recover_as_specific(action, read_signature, read_nonce, read_expiry)
        action_results.append(
            run_case(action, "generic_read_with_nonce", read_signature, read_expiry, read_nonce, read_wrong)
        )
        time.sleep(0.22)

        action_results.append(
            run_case(action, "generic_read_without_nonce", read_signature, read_expiry, None, None)
        )
        time.sleep(0.22)

        same_nonce = base_nonce + 3
        same_expiry = now_seconds() + 365 * 86400
        same_signature = sign_generic(action.wire_action, same_expiry)
        same_wrong = recover_as_specific(action, same_signature, same_nonce, same_expiry)
        action_results.append(
            run_case(action, "generic_same_write_with_nonce", same_signature, same_expiry, same_nonce, same_wrong)
        )
        time.sleep(0.22)

        action_results.append(
            run_case(action, "generic_same_write_without_nonce", same_signature, same_expiry, None, None)
        )
        time.sleep(0.22)

        evidence["tests"].append({
            "action": action.wire_action,
            "primaryType": action.primary_type,
            "results": action_results,
        })

    action_groups = [item for item in evidence["tests"] if isinstance(item, dict) and "results" in item]
    baseline_valid_actions = [
        item["action"]
        for item in action_groups
        if any(
            result["name"] == "specific_baseline"
            and result["errorCode"] == "UNAUTHORIZED"
            and result["mentionsSyntheticSigner"]
            for result in item["results"]
        )
    ]
    read_replay_acceptances = [
        {"action": item["action"], "case": result["name"], "result": result}
        for item in action_groups
        for result in item["results"]
        if result["name"].startswith("generic_read") and result["mentionsSyntheticSigner"]
    ]
    same_write_generic_acceptances = [
        {"action": item["action"], "case": result["name"], "result": result}
        for item in action_groups
        for result in item["results"]
        if result["name"].startswith("generic_same_write") and result["mentionsSyntheticSigner"]
    ]
    unexpected_successes = [
        {"action": item["action"], "case": result["name"], "result": result}
        for item in action_groups
        for result in item["results"]
        if result["httpStatus"] == 200 and result["apiStatus"] == "ok"
    ]
    predicted_wrong_matches = [
        {"action": item["action"], "case": result["name"], "expectedWrongRecovery": result["expectedWrongRecovery"]}
        for item in action_groups
        for result in item["results"]
        if result["mentionsExpectedWrongRecovery"]
    ]

    evidence["analysis"] = {
        "actionCount": len(action_groups),
        "requestCountExcludingPreflight": sum(len(item["results"]) for item in action_groups),
        "baselineValidActionCount": len(baseline_valid_actions),
        "baselineValidActions": baseline_valid_actions,
        "readReplayAcceptanceCount": len(read_replay_acceptances),
        "readReplayAcceptances": read_replay_acceptances,
        "sameWriteGenericAcceptanceCount": len(same_write_generic_acceptances),
        "sameWriteGenericAcceptances": same_write_generic_acceptances,
        "unexpectedSuccessCount": len(unexpected_successes),
        "unexpectedSuccesses": unexpected_successes,
        "predictedWrongRecoveryMatchCount": len(predicted_wrong_matches),
        "predictedWrongRecoveryMatches": predicted_wrong_matches,
        "unexpectedAcceptance": bool(read_replay_acceptances or same_write_generic_acceptances or unexpected_successes),
    }

    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence["analysis"], indent=2))


if __name__ == "__main__":
    main()
