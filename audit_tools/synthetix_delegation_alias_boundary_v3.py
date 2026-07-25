#!/usr/bin/env python3
"""Corrected standalone addDelegatedSigner envelope differential.

Uses only a deterministic signer confirmed to have zero Synthetix accounts,
synthetic delegate EOAs, and nonexistent valid-range account IDs. Therefore no
delegation can execute. Only redacted response metadata is retained.
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

OUT = pathlib.Path("delegation_alias_boundary_v3")
OUT.mkdir(parents=True, exist_ok=True)
INFO = "https://papi.synthetix.io/v1/info"
TRADE = "https://papi.synthetix.io/v1/trade"
SIGNER = Account.from_key("0x" + "88" * 32)
DELEGATE_A = Account.from_key("0x" + "99" * 32)
DELEGATE_B = Account.from_key("0x" + "aa" * 32)
UNRELATED = Account.from_key("0x" + "bb" * 32)
SOURCE_A = 8_432_451_907_612_340_731
SOURCE_B = 8_432_451_907_612_340_733
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
    "AddDelegatedSigner": [
        {"name": "delegateAddress", "type": "address"},
        {"name": "subAccountId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
        {"name": "expiresAt", "type": "uint256"},
        {"name": "permissions", "type": "string[]"},
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
    return text[:600]


def wallet_hint(value: Any) -> str | None:
    if value is None:
        return None
    match = re.search(r"wallet\s+(0x[0-9a-fA-F]{3})\.\.\.([0-9a-fA-F]{3})", str(value))
    if not match:
        return None
    prefix, suffix = match.group(1)[2:].lower(), match.group(2).lower()
    for name, account in {
        "signer": SIGNER,
        "delegate_a": DELEGATE_A,
        "delegate_b": DELEGATE_B,
        "unrelated": UNRELATED,
    }.items():
        raw = account.address[2:].lower()
        if raw.startswith(prefix) and raw.endswith(suffix):
            return name
    return "other"


def post_bytes(url: str, body: bytes) -> tuple[int, bytes, dict[str, str], float]:
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
    return post_bytes(url, json.dumps(payload, separators=(",", ":")).encode())


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


def sign_add(source: int, delegate: str, permissions: list[str], expires_at: int, nonce: int, expires_after: int) -> dict[str, Any]:
    typed = {
        "types": TYPES,
        "primaryType": "AddDelegatedSigner",
        "domain": DOMAIN,
        "message": {
            "delegateAddress": delegate,
            "subAccountId": source,
            "nonce": nonce,
            "expiresAfter": expires_after,
            "expiresAt": expires_at,
            "permissions": permissions,
        },
    }
    signed = SIGNER.sign_message(encode_typed_data(full_message=typed))
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def corrupt(signature: dict[str, Any]) -> dict[str, Any]:
    return {**signature, "s": "0x" + format(int(signature["s"], 16) ^ 1, "064x")}


def request(
    *,
    signed_source: int = SOURCE_A,
    signed_delegate: str = DELEGATE_A.address,
    signed_permissions: list[str] | None = None,
    signed_expires_at: int = 0,
    params_source: Any | None = str(SOURCE_A),
    params_wallet: Any | None = DELEGATE_A.address,
    params_delegate: Any | None = None,
    wire_permissions: list[str] | None = None,
    wire_expires_at: Any | None = 0,
    top_source: Any | None = None,
    top_wallet: Any | None = None,
    corrupt_signature: bool = False,
) -> dict[str, Any]:
    permissions = list(signed_permissions or ["session"])
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign_add(signed_source, signed_delegate, permissions, signed_expires_at, nonce, expires_after)
    if corrupt_signature:
        signature = corrupt(signature)
    params: dict[str, Any] = {"action": "addDelegatedSigner"}
    if params_source is not None:
        params["subAccountId"] = params_source
    if params_wallet is not None:
        params["walletAddress"] = params_wallet
    if params_delegate is not None:
        params["delegateAddress"] = params_delegate
    params["permissions"] = list(wire_permissions if wire_permissions is not None else permissions)
    if wire_expires_at is not None:
        params["expiresAt"] = wire_expires_at
    payload: dict[str, Any] = {
        "params": params,
        "nonce": nonce,
        "expiresAfter": expires_after,
        "signature": signature,
    }
    if top_source is not None:
        payload["subaccountId"] = top_source
    if top_wallet is not None:
        payload["walletAddress"] = top_wallet
    return payload


def duplicate_wallet(first: str, second: str, signed_delegate: str) -> bytes:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign_add(SOURCE_A, signed_delegate, ["session"], 0, nonce, expires_after)
    prefix = (
        "{"
        '"params":{'
        '"action":"addDelegatedSigner",'
        f'"subAccountId":"{SOURCE_A}",'
        f'"walletAddress":"{first}",'
        f'"walletAddress":"{second}",'
        '"permissions":["session"],'
        '"expiresAt":0'
        "},"
        f'"nonce":{nonce},'
        f'"expiresAfter":{expires_after},'
        '"signature":'
    )
    return (prefix + json.dumps(signature, separators=(",", ":")) + "}").encode()


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
        "safety": "Synthetic zero-account signer/delegates and nonexistent IDs only; no delegation can execute.",
        "signer": SIGNER.address,
        "delegates": [DELEGATE_A.address, DELEGATE_B.address],
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
        future = int(time.time() * 1000) + 30 * 24 * 60 * 60 * 1000
        cases: list[tuple[str, dict[str, Any] | bytes]] = [
            ("corrupted_docs_control", request(corrupt_signature=True)),
            ("docs_shape_baseline", request()),
            ("sdk_shape_baseline", request(params_source=None, top_source=str(SOURCE_A), top_wallet=SIGNER.address)),
            ("hybrid_same", request(top_source=str(SOURCE_A), top_wallet=SIGNER.address)),
            ("sdk_top_wallet_unrelated", request(params_source=None, top_source=str(SOURCE_A), top_wallet=UNRELATED.address)),
            ("sdk_top_wallet_omitted", request(params_source=None, top_source=str(SOURCE_A))),
            ("delegate_alias_only", request(params_wallet=None, params_delegate=DELEGATE_A.address)),
            ("both_delegate_fields_sign_wallet", request(params_delegate=DELEGATE_B.address, signed_delegate=DELEGATE_A.address)),
            ("both_delegate_fields_sign_alias", request(params_delegate=DELEGATE_B.address, signed_delegate=DELEGATE_B.address)),
            ("malformed_wallet_valid_alias", request(params_wallet="AUDIT_NOT_ADDRESS", params_delegate=DELEGATE_A.address)),
            ("valid_wallet_malformed_alias", request(params_delegate="AUDIT_NOT_ADDRESS")),
            ("permission_escalation", request(signed_permissions=["session"], wire_permissions=["delegate"])),
            ("permission_downgrade", request(signed_permissions=["delegate"], wire_permissions=["session"])),
            ("expiry_extension", request(signed_expires_at=future, wire_expires_at=0)),
            ("expiry_shortening", request(signed_expires_at=0, wire_expires_at=future)),
            ("source_conflict_sign_params", request(signed_source=SOURCE_A, top_source=str(SOURCE_B), top_wallet=SIGNER.address)),
            ("source_conflict_sign_top", request(signed_source=SOURCE_B, top_source=str(SOURCE_B), top_wallet=SIGNER.address)),
            ("params_source_zero_top_valid", request(params_source="0", top_source=str(SOURCE_A), top_wallet=SIGNER.address)),
            ("params_source_valid_top_zero", request(top_source="0", top_wallet=SIGNER.address)),
            ("top_wallet_delegate_docs_shape", request(top_wallet=DELEGATE_A.address)),
            ("duplicate_wallet_sign_first", duplicate_wallet(DELEGATE_A.address, DELEGATE_B.address, DELEGATE_A.address)),
            ("duplicate_wallet_sign_second", duplicate_wallet(DELEGATE_A.address, DELEGATE_B.address, DELEGATE_B.address)),
            ("legacy_trading_permission", request(signed_permissions=["trading"], wire_permissions=["trading"])),
        ]
        for index, (name, payload) in enumerate(cases):
            if isinstance(payload, bytes):
                status, body, headers, elapsed = post_bytes(TRADE, payload)
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
