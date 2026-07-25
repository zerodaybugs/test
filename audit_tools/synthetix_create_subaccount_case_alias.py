#!/usr/bin/env python3
"""Controlled createSubaccount source-account alias differential.

The docs use `params.subAccountId`; the official Python SDK emits
`params.subaccountId`; EIP-712 signs `masterSubAccountId`. The probe uses only
a deterministic signer confirmed to own/manage/delegate zero Synthetix
accounts and deliberately nonexistent valid-range IDs, so no account can be
created. It retains only redacted response metadata.
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

OUT = pathlib.Path("create_subaccount_case_alias")
OUT.mkdir(parents=True, exist_ok=True)
INFO = "https://papi.synthetix.io/v1/info"
TRADE = "https://papi.synthetix.io/v1/trade"
SIGNER = Account.from_key("0x" + "dd" * 32)
SOURCE_A = 7_932_451_907_612_340_731
SOURCE_B = 7_932_451_907_612_340_733
NAME_A = "AUDIT_ALIAS_A"
NAME_B = "AUDIT_ALIAS_B"
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
    "CreateSubaccount": [
        {"name": "masterSubAccountId", "type": "uint256"},
        {"name": "name", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}


def sha(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


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


def post_json(url: str, payload: dict[str, Any]) -> tuple[int, bytes, dict[str, str], float]:
    return post(url, json.dumps(payload, separators=(",", ":")).encode())


def parse(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if not isinstance(response, dict):
        return None
    total, recognized = 0, False
    for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
        values = response.get(key)
        if isinstance(values, list):
            recognized = True
            total += len(values)
    return total if recognized else None


def sign(source: int, name: str, nonce: int, expires_after: int) -> dict[str, Any]:
    typed = {
        "types": TYPES,
        "primaryType": "CreateSubaccount",
        "domain": DOMAIN,
        "message": {
            "masterSubAccountId": source,
            "name": name,
            "nonce": nonce,
            "expiresAfter": expires_after,
        },
    }
    signed = SIGNER.sign_message(encode_typed_data(full_message=typed))
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def raw_request(
    pairs: list[tuple[str, Any]],
    signed_source: int,
    signed_name: str = NAME_A,
    wire_name: str = NAME_A,
    *,
    corrupt: bool = False,
) -> bytes:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign(signed_source, signed_name, nonce, expires_after)
    if corrupt:
        signature["s"] = "0x" + format(int(signature["s"], 16) ^ 1, "064x")
    params_pairs: list[tuple[str, Any]] = [
        ("action", "createSubaccount"),
        *pairs,
        ("walletAddress", SIGNER.address),
        ("name", wire_name),
    ]
    params_json = "{" + ",".join(json.dumps(key) + ":" + json.dumps(value) for key, value in params_pairs) + "}"
    return (
        "{"
        '"params":' + params_json + ","
        f'"nonce":{nonce},'
        f'"expiresAfter":{expires_after},'
        '"signature":' + json.dumps(signature, separators=(",", ":"))
        + "}"
    ).encode()


def wallet_hint(message: Any) -> str | None:
    if message is None:
        return None
    match = re.search(r"wallet\s+(0x[0-9a-fA-F]{3})\.\.\.([0-9a-fA-F]{3})", str(message))
    if not match:
        return None
    raw = SIGNER.address[2:].lower()
    return "signer" if raw.startswith(match.group(1)[2:].lower()) and raw.endswith(match.group(2).lower()) else "other"


def redact(message: Any) -> str | None:
    if message is None:
        return None
    text = str(message)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:600]


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    return {
        "name": name,
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": code,
        "errorMessageRedacted": redact(message),
        "errorMessageSha256": sha(str(message)) if message is not None else None,
        "walletHint": wallet_hint(message),
        "bodySha256": sha(body),
        "bodyBytes": len(body),
        "elapsedMs": round(elapsed * 1000, 2),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None)
        or headers.get("X-Request-Id")
        or headers.get("x-request-id"),
    }


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": "Synthetic zero-account signer and nonexistent IDs only; no subaccount can be created.",
        "signer": SIGNER.address,
        "sourceHashes": [sha(str(SOURCE_A)), sha(str(SOURCE_B))],
        "tests": [],
    }
    status, body, headers, elapsed = post_json(
        INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": SIGNER.address, "includeDelegations": True}},
    )
    preflight = summarize("synthetic_account_preflight", status, body, headers, elapsed)
    parsed = parse(body)
    count = account_count(parsed.get("response") if isinstance(parsed, dict) else None)
    preflight["accountCount"] = count
    evidence["tests"].append(preflight)

    if count != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic signer was not confirmed to have zero accounts."
    else:
        cases: list[tuple[str, list[tuple[str, Any]], int, str, str, bool]] = [
            ("corrupted_camel_control", [("subAccountId", str(SOURCE_A))], SOURCE_A, NAME_A, NAME_A, True),
            ("camel_only", [("subAccountId", str(SOURCE_A))], SOURCE_A, NAME_A, NAME_A, False),
            ("lower_only", [("subaccountId", str(SOURCE_A))], SOURCE_A, NAME_A, NAME_A, False),
            ("both_same", [("subAccountId", str(SOURCE_A)), ("subaccountId", str(SOURCE_A))], SOURCE_A, NAME_A, NAME_A, False),
            ("camel_a_lower_b_sign_a", [("subAccountId", str(SOURCE_A)), ("subaccountId", str(SOURCE_B))], SOURCE_A, NAME_A, NAME_A, False),
            ("camel_a_lower_b_sign_b", [("subAccountId", str(SOURCE_A)), ("subaccountId", str(SOURCE_B))], SOURCE_B, NAME_A, NAME_A, False),
            ("lower_b_camel_a_sign_a", [("subaccountId", str(SOURCE_B)), ("subAccountId", str(SOURCE_A))], SOURCE_A, NAME_A, NAME_A, False),
            ("lower_b_camel_a_sign_b", [("subaccountId", str(SOURCE_B)), ("subAccountId", str(SOURCE_A))], SOURCE_B, NAME_A, NAME_A, False),
            ("camel_a_lower_zero", [("subAccountId", str(SOURCE_A)), ("subaccountId", "0")], SOURCE_A, NAME_A, NAME_A, False),
            ("lower_zero_camel_a", [("subaccountId", "0"), ("subAccountId", str(SOURCE_A))], SOURCE_A, NAME_A, NAME_A, False),
            ("camel_a_lower_bad", [("subAccountId", str(SOURCE_A)), ("subaccountId", "AUDIT_NOT_UINT")], SOURCE_A, NAME_A, NAME_A, False),
            ("lower_bad_camel_a", [("subaccountId", "AUDIT_NOT_UINT"), ("subAccountId", str(SOURCE_A))], SOURCE_A, NAME_A, NAME_A, False),
            ("duplicate_camel_sign_first", [("subAccountId", str(SOURCE_A)), ("subAccountId", str(SOURCE_B))], SOURCE_A, NAME_A, NAME_A, False),
            ("duplicate_camel_sign_second", [("subAccountId", str(SOURCE_A)), ("subAccountId", str(SOURCE_B))], SOURCE_B, NAME_A, NAME_A, False),
            ("signed_name_mismatch", [("subAccountId", str(SOURCE_A))], SOURCE_A, NAME_B, NAME_A, False),
            ("empty_name", [("subAccountId", str(SOURCE_A))], SOURCE_A, "", "", False),
        ]
        for index, (name, pairs, signed_source, signed_name, wire_name, corrupt) in enumerate(cases):
            payload = raw_request(
                pairs,
                signed_source,
                signed_name=signed_name,
                wire_name=wire_name,
                corrupt=corrupt,
            )
            status, body, headers, elapsed = post(TRADE, payload)
            evidence["tests"].append(summarize(name, status, body, headers, elapsed))
            if index + 1 < len(cases):
                time.sleep(0.8)

    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps({
        "accountCount": count,
        "cases": [
            {
                "name": item.get("name"),
                "status": item.get("httpStatus"),
                "code": item.get("errorCode"),
                "walletHint": item.get("walletHint"),
                "error": item.get("errorMessageRedacted"),
            }
            for item in evidence["tests"]
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
