#!/usr/bin/env python3
"""Controlled EIP-712 primary-type and field-binding probe for Synthetix PAPI.

Safety constraints:
- deterministic synthetic EOA only;
- preflight confirms that EOA has no Synthetix subaccounts;
- a deliberately nonexistent high subaccount ID is used;
- only a minimal positive withdrawal amount and the synthetic EOA as destination;
- every signature is produced by synthetic keys controlled by this probe;
- no real account, credential, balance, position, order, or reward is touched;
- only status/error metadata is retained.
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

OUT = pathlib.Path("primary_type_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
PRIVATE_KEY = "0x" + "55" * 32
ACCOUNT = Account.from_key(PRIVATE_KEY)
ALT_DESTINATION = Account.from_key("0x" + "56" * 32).address
TARGET_SUBACCOUNT_ID = 999_999_999_999_999_937
TRANSMITTED_AMOUNT = "1"
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

WITHDRAW_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "WithdrawCollateral": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "amount", "type": "string"},
        {"name": "destination", "type": "address"},
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
UPDATE_LEVERAGE_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "UpdateLeverage": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "leverage", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "User-Agent": UA,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
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
        "errorMessage": str(error_message)[:500] if error_message is not None else None,
        "responseSchema": schema(response),
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "bodyBytes": len(body),
        "requestId": headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def sign(types: dict[str, Any], primary_type: str, message: dict[str, Any]) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": types,
            "primaryType": primary_type,
            "domain": DOMAIN,
            "message": message,
        }
    )
    return format_signature(ACCOUNT.sign_message(encoded))


def corrupt(signature: dict[str, Any]) -> dict[str, Any]:
    value = int(signature["s"], 16) ^ 1
    return {"v": signature["v"], "r": signature["r"], "s": "0x" + format(value, "064x")}


def withdraw_envelope(nonce: int, expires_after: int, signature: dict[str, Any]) -> dict[str, Any]:
    return {
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": "withdrawCollateral",
            "subaccountId": str(TARGET_SUBACCOUNT_ID),
            "walletAddress": ACCOUNT.address,
            "symbol": "USDT",
            "amount": TRANSMITTED_AMOUNT,
            "destination": ACCOUNT.address,
        },
    }


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        total = 0
        recognized = False
        for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
            value = response.get(key)
            if isinstance(value, list):
                recognized = True
                total += len(value)
        return total if recognized else None
    return None


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": (
            "Synthetic empty EOA, deliberately nonexistent high subaccount ID, minimal positive amount, "
            "and synthetic own destination only. No real user or funds are involved."
        ),
        "syntheticAddress": ACCOUNT.address,
        "targetSubaccountIdSha256": hashlib.sha256(str(TARGET_SUBACCOUNT_ID).encode()).hexdigest(),
        "transmittedAmount": TRANSMITTED_AMOUNT,
        "domain": DOMAIN,
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
        evidence["abortReason"] = "Synthetic EOA was not confirmed to have zero Synthetix accounts."
    else:
        base_nonce = int(time.time() * 1000)
        cases: list[tuple[str, dict[str, Any]]] = []

        missing_nonce = base_nonce
        missing_expiry = missing_nonce + 60_000
        missing = withdraw_envelope(
            missing_nonce,
            missing_expiry,
            {"v": 27, "r": "0x" + "00" * 32, "s": "0x" + "00" * 32},
        )
        missing.pop("signature")
        cases.append(("missing_signature_control", missing))

        nonce = base_nonce + 10
        expiry = nonce + 60_000
        message = {
            "subAccountId": TARGET_SUBACCOUNT_ID,
            "symbol": "USDT",
            "amount": TRANSMITTED_AMOUNT,
            "destination": ACCOUNT.address,
            "nonce": nonce,
            "expiresAfter": expiry,
        }
        correct_signature = sign(WITHDRAW_TYPES, "WithdrawCollateral", message)
        cases.append(("corrupted_withdraw_signature", withdraw_envelope(nonce, expiry, corrupt(correct_signature))))

        nonce = base_nonce + 20
        expiry = nonce + 60_000
        message = {
            "subAccountId": TARGET_SUBACCOUNT_ID,
            "symbol": "USDT",
            "amount": TRANSMITTED_AMOUNT,
            "destination": ACCOUNT.address,
            "nonce": nonce,
            "expiresAfter": expiry,
        }
        cases.append(
            (
                "correct_withdraw_primary_type",
                withdraw_envelope(nonce, expiry, sign(WITHDRAW_TYPES, "WithdrawCollateral", message)),
            )
        )

        nonce = base_nonce + 30
        expiry = nonce + 60_000
        message = {
            "subAccountId": TARGET_SUBACCOUNT_ID,
            "symbol": "USDT",
            "amount": "2",
            "destination": ACCOUNT.address,
            "nonce": nonce,
            "expiresAfter": expiry,
        }
        cases.append(
            (
                "signed_amount_mismatch",
                withdraw_envelope(nonce, expiry, sign(WITHDRAW_TYPES, "WithdrawCollateral", message)),
            )
        )

        nonce = base_nonce + 40
        expiry = nonce + 60_000
        message = {
            "subAccountId": TARGET_SUBACCOUNT_ID,
            "symbol": "USDT",
            "amount": TRANSMITTED_AMOUNT,
            "destination": ALT_DESTINATION,
            "nonce": nonce,
            "expiresAfter": expiry,
        }
        cases.append(
            (
                "signed_destination_mismatch",
                withdraw_envelope(nonce, expiry, sign(WITHDRAW_TYPES, "WithdrawCollateral", message)),
            )
        )

        nonce = base_nonce + 50
        expiry = nonce + 60_000
        message = {
            "subAccountId": TARGET_SUBACCOUNT_ID,
            "symbol": "USDT",
            "leverage": "1",
            "nonce": nonce,
            "expiresAfter": expiry,
        }
        cases.append(
            (
                "wrong_update_leverage_primary_type",
                withdraw_envelope(nonce, expiry, sign(UPDATE_LEVERAGE_TYPES, "UpdateLeverage", message)),
            )
        )

        nonce = base_nonce + 60
        expiry = nonce + 60_000
        message = {
            "subAccountId": TARGET_SUBACCOUNT_ID,
            "action": "withdrawCollateral",
            "nonce": nonce,
            "expiresAfter": expiry,
        }
        cases.append(
            (
                "generic_same_action_primary_type",
                withdraw_envelope(nonce, expiry, sign(SUBACCOUNT_ACTION_TYPES, "SubAccountAction", message)),
            )
        )

        nonce = base_nonce + 70
        expiry = nonce + 60_000
        message = {
            "subAccountId": TARGET_SUBACCOUNT_ID,
            "action": "getPositions",
            "nonce": nonce,
            "expiresAfter": expiry,
        }
        cases.append(
            (
                "generic_read_action_replayed_as_withdraw",
                withdraw_envelope(nonce, expiry, sign(SUBACCOUNT_ACTION_TYPES, "SubAccountAction", message)),
            )
        )

        for name, payload in cases:
            status, body, headers, elapsed = post_json(PAPI_TRADE, payload)
            evidence["tests"].append(summarize(name, status, body, headers, elapsed))
            time.sleep(0.65)

        by_name = {item["name"]: item for item in evidence["tests"]}
        correct = by_name["correct_withdraw_primary_type"]
        evidence["comparisons"] = {
            name: {
                "sameHttpStatusAsCorrect": item["httpStatus"] == correct["httpStatus"],
                "sameApiStatusAsCorrect": item["apiStatus"] == correct["apiStatus"],
                "sameErrorCodeAsCorrect": item["errorCode"] == correct["errorCode"],
                "sameErrorMessageAsCorrect": item["errorMessage"] == correct["errorMessage"],
                "sameBodyHashAsCorrect": item["bodySha256"] == correct["bodySha256"],
            }
            for name, item in by_name.items()
            if name not in {"synthetic_account_preflight", "correct_withdraw_primary_type"}
        }

    (OUT / "result.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
