#!/usr/bin/env python3
"""Low-noise EIP-712 / wire-field alias probe for Synthetix transferCollateral.

Safety properties:
- deterministic synthetic EOA only;
- preflight confirms the EOA owns/manages/delegates zero Synthetix accounts;
- deliberately nonexistent source and destination IDs;
- fixed 14-request differential matrix;
- no real account, credential, balance, order, or position is used;
- a transfer cannot execute because the signer has no source account;
- only response status/error metadata and hashes are retained.
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

OUT = pathlib.Path("transfer_alias_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
PRIVATE_KEY = "0x" + "77" * 32
ACCOUNT = Account.from_key(PRIVATE_KEY)
SOURCE_A = 9_832_451_907_612_340_731
SOURCE_B = 9_832_451_907_612_340_733
DEST_A = 9_832_451_907_612_340_737
DEST_B = 9_832_451_907_612_340_739
AMOUNT = "1"
SYMBOL = "USDT"
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
TRANSFER_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "TransferCollateral": [
        {"name": "amount", "type": "string"},
        {"name": "expiresAfter", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "to", "type": "uint256"},
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
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:500]


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


def sign_transfer(source_id: int, destination_id: int, amount: str, nonce: int, expires_after: int) -> dict[str, Any]:
    full_message = {
        "types": TRANSFER_TYPES,
        "primaryType": "TransferCollateral",
        "domain": DOMAIN,
        "message": {
            "amount": amount,
            "expiresAfter": expires_after,
            "nonce": nonce,
            "subAccountId": source_id,
            "symbol": SYMBOL,
            "to": destination_id,
        },
    }
    return format_signature(ACCOUNT.sign_message(encode_typed_data(full_message=full_message)))


def corrupt(signature: dict[str, Any]) -> dict[str, Any]:
    value = int(signature["s"], 16) ^ 1
    return {"v": signature["v"], "r": signature["r"], "s": "0x" + format(value, "064x")}


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


def envelope(
    *,
    source_signed: int,
    destination_signed: int,
    source_wire_key: str = "subAccountId",
    source_wire_value: Any | None = None,
    to_wire: Any | None = None,
    destination_alias: Any | None = None,
    amount_wire: str = AMOUNT,
    amount_signed: str = AMOUNT,
    corrupt_signature: bool = False,
    extra_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign_transfer(source_signed, destination_signed, amount_signed, nonce, expires_after)
    if corrupt_signature:
        signature = corrupt(signature)
    params: dict[str, Any] = {
        "action": "transferCollateral",
        source_wire_key: source_signed if source_wire_value is None else source_wire_value,
        "symbol": SYMBOL,
        "amount": amount_wire,
    }
    if to_wire is not None:
        params["to"] = to_wire
    if destination_alias is not None:
        params["destinationSubAccountId"] = destination_alias
    if extra_params:
        params.update(extra_params)
    return {
        "params": params,
        "nonce": nonce,
        "signature": signature,
        "expiresAfter": expires_after,
    }


def duplicate_to_body(*, first_to: int, second_to: int, signed_to: int) -> bytes:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign_transfer(SOURCE_A, signed_to, AMOUNT, nonce, expires_after)
    # Intentionally raw JSON to preserve duplicate keys. All IDs are nonexistent and the signer owns zero accounts.
    return (
        "{"
        '"params":{'
        '"action":"transferCollateral",'
        f'"subAccountId":"{SOURCE_A}",'
        f'"to":"{first_to}",'
        f'"to":"{second_to}",'
        f'"symbol":"{SYMBOL}",'
        f'"amount":"{AMOUNT}"'
        "},"
        f'"nonce":{nonce},'
        '"signature":'
        + json.dumps(signature, separators=(",", ":"))
        + ","
        f'"expiresAfter":{expires_after}'
        "}"
    ).encode()


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": (
            "Synthetic zero-account EOA and deliberately nonexistent account IDs only. "
            "No valid source account exists, therefore no transfer can execute."
        ),
        "syntheticAddress": ACCOUNT.address,
        "sourceIdsSha256": [digest(str(SOURCE_A)), digest(str(SOURCE_B))],
        "destinationIdsSha256": [digest(str(DEST_A)), digest(str(DEST_B))],
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
        cases: list[tuple[str, dict[str, Any] | bytes]] = [
            (
                "corrupted_signature_control",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    to_wire=str(DEST_A),
                    corrupt_signature=True,
                ),
            ),
            (
                "frontend_to_only",
                envelope(source_signed=SOURCE_A, destination_signed=DEST_A, to_wire=str(DEST_A)),
            ),
            (
                "docs_destination_only",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    destination_alias=str(DEST_A),
                ),
            ),
            (
                "both_destination_fields_same",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    to_wire=str(DEST_A),
                    destination_alias=str(DEST_A),
                ),
            ),
            (
                "conflict_sign_to",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    to_wire=str(DEST_A),
                    destination_alias=str(DEST_B),
                ),
            ),
            (
                "conflict_sign_destination_alias",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_B,
                    to_wire=str(DEST_A),
                    destination_alias=str(DEST_B),
                ),
            ),
            (
                "malformed_to_valid_destination_alias",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    to_wire="AUDIT_NOT_UINT",
                    destination_alias=str(DEST_A),
                ),
            ),
            (
                "valid_to_malformed_destination_alias",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    to_wire=str(DEST_A),
                    destination_alias="AUDIT_NOT_UINT",
                ),
            ),
            (
                "lowercase_source_key_only",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    source_wire_key="subaccountId",
                    to_wire=str(DEST_A),
                ),
            ),
            (
                "both_source_keys_same",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    to_wire=str(DEST_A),
                    extra_params={"subaccountId": str(SOURCE_A)},
                ),
            ),
            (
                "source_key_conflict_sign_camel",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    to_wire=str(DEST_A),
                    extra_params={"subaccountId": str(SOURCE_B)},
                ),
            ),
            (
                "source_key_conflict_sign_lower",
                envelope(
                    source_signed=SOURCE_B,
                    destination_signed=DEST_A,
                    source_wire_key="subaccountId",
                    source_wire_value=str(SOURCE_B),
                    to_wire=str(DEST_A),
                    extra_params={"subAccountId": str(SOURCE_A)},
                ),
            ),
            (
                "amount_mismatch_control",
                envelope(
                    source_signed=SOURCE_A,
                    destination_signed=DEST_A,
                    to_wire=str(DEST_A),
                    amount_wire=AMOUNT,
                    amount_signed="2",
                ),
            ),
            (
                "duplicate_to_sign_first",
                duplicate_to_body(first_to=DEST_A, second_to=DEST_B, signed_to=DEST_A),
            ),
            (
                "duplicate_to_sign_second",
                duplicate_to_body(first_to=DEST_A, second_to=DEST_B, signed_to=DEST_B),
            ),
        ]

        for index, (name, payload) in enumerate(cases):
            if isinstance(payload, bytes):
                status, body, headers, elapsed = post_bytes(PAPI_TRADE, payload)
            else:
                status, body, headers, elapsed = post_json(PAPI_TRADE, payload)
            evidence["tests"].append(summarize(name, status, body, headers, elapsed))
            if index + 1 < len(cases):
                time.sleep(0.8)

    tests = evidence["tests"]
    evidence["responseEquivalenceGroups"] = {}
    for item in tests:
        key = "|".join(
            str(item.get(field))
            for field in ("httpStatus", "errorCode", "errorMessageSha256", "bodySha256")
        )
        evidence["responseEquivalenceGroups"].setdefault(key, []).append(item.get("name"))

    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "preflightAccountCount": count,
                "cases": [
                    {
                        "name": item.get("name"),
                        "status": item.get("httpStatus"),
                        "errorCode": item.get("errorCode"),
                        "error": item.get("errorMessageRedacted"),
                    }
                    for item in evidence["tests"]
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
