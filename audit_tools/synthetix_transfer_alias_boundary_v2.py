#!/usr/bin/env python3
"""Corrected low-noise transferCollateral wire-field differential.

Uses only a deterministic EOA confirmed to have zero Synthetix accounts and
nonexistent source/destination IDs. Therefore no transfer can execute. The
probe records only redacted status/error metadata.
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

OUT = pathlib.Path("transfer_alias_boundary_v2")
OUT.mkdir(parents=True, exist_ok=True)
INFO = "https://papi.synthetix.io/v1/info"
TRADE = "https://papi.synthetix.io/v1/trade"
ACCOUNT = Account.from_key("0x" + "77" * 32)
SOURCE = 9_832_451_907_612_340_731
DEST_A = 9_832_451_907_612_340_737
DEST_B = 9_832_451_907_612_340_739
AMOUNT = "1"
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
TYPES = {
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


def sha(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:500]


def post(url: str, body: bytes) -> tuple[int, bytes, dict[str, str], float]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, data, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1), dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


def post_json(url: str, value: dict[str, Any]) -> tuple[int, bytes, dict[str, str], float]:
    return post(url, json.dumps(value, separators=(",", ":")).encode())


def parse(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def signature(destination: int, nonce: int, expires_after: int, amount: str = AMOUNT) -> dict[str, Any]:
    message = {
        "types": TYPES,
        "primaryType": "TransferCollateral",
        "domain": DOMAIN,
        "message": {
            "amount": amount,
            "expiresAfter": expires_after,
            "nonce": nonce,
            "subAccountId": SOURCE,
            "symbol": "USDT",
            "to": destination,
        },
    }
    signed = ACCOUNT.sign_message(encode_typed_data(full_message=message))
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def corrupt(sig: dict[str, Any]) -> dict[str, Any]:
    return {**sig, "s": "0x" + format(int(sig["s"], 16) ^ 1, "064x")}


def make_case(
    *,
    signed_destination: int,
    to_value: Any | None = None,
    destination_alias: Any | None = None,
    signed_amount: str = AMOUNT,
    wire_amount: str = AMOUNT,
    corrupt_sig: bool = False,
) -> dict[str, Any]:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    sig = signature(signed_destination, nonce, expires_after, signed_amount)
    if corrupt_sig:
        sig = corrupt(sig)
    params: dict[str, Any] = {
        "action": "transferCollateral",
        "subAccountId": str(SOURCE),
        "symbol": "USDT",
        "amount": wire_amount,
    }
    if to_value is not None:
        params["to"] = to_value
    if destination_alias is not None:
        params["destinationSubAccountId"] = destination_alias
    return {"params": params, "nonce": nonce, "signature": sig, "expiresAfter": expires_after}


def duplicate_to_body(first: int, second: int, signed_destination: int) -> bytes:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    sig = signature(signed_destination, nonce, expires_after)
    return (
        "{"
        '"params":{'
        '"action":"transferCollateral",'
        f'"subAccountId":"{SOURCE}",'
        f'"to":"{first}",'
        f'"to":"{second}",'
        '"symbol":"USDT",'
        f'"amount":"{AMOUNT}"'
        "},"
        f'"nonce":{nonce},'
        '"signature":' + json.dumps(sig, separators=(",", ":")) + ","
        f'"expiresAfter":{expires_after}'
        "}"
    ).encode()


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    value = parse(body)
    error = value.get("error") if isinstance(value, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    return {
        "name": name,
        "httpStatus": status,
        "apiStatus": value.get("status") if isinstance(value, dict) else None,
        "errorCode": code,
        "errorMessageRedacted": redact(message),
        "errorMessageSha256": sha(str(message)) if message is not None else None,
        "bodySha256": sha(body),
        "bodyBytes": len(body),
        "elapsedMs": round(elapsed * 1000, 2),
        "requestId": (value.get("request_id") if isinstance(value, dict) else None)
        or headers.get("X-Request-Id")
        or headers.get("x-request-id"),
    }


def account_count(value: Any) -> int | None:
    if isinstance(value, list):
        return len(value)
    if not isinstance(value, dict):
        return None
    total = 0
    seen = False
    for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
        items = value.get(key)
        if isinstance(items, list):
            seen = True
            total += len(items)
    return total if seen else None


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": "Synthetic zero-account EOA and nonexistent IDs only; no transfer can execute.",
        "syntheticAddress": ACCOUNT.address,
        "sourceIdSha256": sha(str(SOURCE)),
        "destinationIdSha256": [sha(str(DEST_A)), sha(str(DEST_B))],
        "tests": [],
    }

    status, body, headers, elapsed = post_json(
        INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": ACCOUNT.address, "includeDelegations": True}},
    )
    preflight = summarize("synthetic_account_preflight", status, body, headers, elapsed)
    parsed = parse(body)
    count = account_count(parsed.get("response") if isinstance(parsed, dict) else None)
    preflight["accountCount"] = count
    evidence["tests"].append(preflight)

    if count != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic EOA was not confirmed to have zero accounts."
    else:
        cases: list[tuple[str, dict[str, Any] | bytes]] = [
            ("corrupted_signature_control", make_case(signed_destination=DEST_A, to_value=str(DEST_A), corrupt_sig=True)),
            ("frontend_to_only", make_case(signed_destination=DEST_A, to_value=str(DEST_A))),
            ("docs_destination_only", make_case(signed_destination=DEST_A, destination_alias=str(DEST_A))),
            ("both_fields_same", make_case(signed_destination=DEST_A, to_value=str(DEST_A), destination_alias=str(DEST_A))),
            ("conflict_sign_to", make_case(signed_destination=DEST_A, to_value=str(DEST_A), destination_alias=str(DEST_B))),
            ("conflict_sign_destination_alias", make_case(signed_destination=DEST_B, to_value=str(DEST_A), destination_alias=str(DEST_B))),
            ("malformed_to_valid_destination", make_case(signed_destination=DEST_A, to_value="AUDIT_NOT_UINT", destination_alias=str(DEST_A))),
            ("valid_to_malformed_destination", make_case(signed_destination=DEST_A, to_value=str(DEST_A), destination_alias="AUDIT_NOT_UINT")),
            ("amount_mismatch_control", make_case(signed_destination=DEST_A, to_value=str(DEST_A), signed_amount="2", wire_amount=AMOUNT)),
            ("to_numeric_wire", make_case(signed_destination=DEST_A, to_value=DEST_A)),
            ("destination_numeric_wire", make_case(signed_destination=DEST_A, destination_alias=DEST_A)),
            ("duplicate_to_sign_first", duplicate_to_body(DEST_A, DEST_B, DEST_A)),
            ("duplicate_to_sign_second", duplicate_to_body(DEST_A, DEST_B, DEST_B)),
        ]
        for index, (name, payload) in enumerate(cases):
            if isinstance(payload, bytes):
                status, body, headers, elapsed = post(TRADE, payload)
            else:
                status, body, headers, elapsed = post_json(TRADE, payload)
            evidence["tests"].append(summarize(name, status, body, headers, elapsed))
            if index + 1 < len(cases):
                time.sleep(0.8)

    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps({
        "accountCount": count,
        "cases": [
            {
                "name": item.get("name"),
                "httpStatus": item.get("httpStatus"),
                "errorCode": item.get("errorCode"),
                "error": item.get("errorMessageRedacted"),
            }
            for item in evidence["tests"]
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
