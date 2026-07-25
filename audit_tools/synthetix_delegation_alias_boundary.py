#!/usr/bin/env python3
"""Controlled addDelegatedSigner EIP-712 / wire-envelope differential.

Safety properties:
- deterministic synthetic signer only;
- preflight confirms the signer owns/manages/delegates zero Synthetix accounts;
- deliberately nonexistent, valid-range subaccount IDs;
- all delegate addresses are deterministic synthetic EOAs controlled by this probe;
- no real account, credential, balance, order, or position is used;
- no delegation can be created because the signer has no source account;
- only redacted response status/error metadata is retained.
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

OUT = pathlib.Path("delegation_alias_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
SIGNER = Account.from_key("0x" + "88" * 32)
DELEGATE_A = Account.from_key("0x" + "99" * 32)
DELEGATE_B = Account.from_key("0x" + "aa" * 32)
UNRELATED = Account.from_key("0x" + "bb" * 32)
SOURCE_A = 8_432_451_907_612_340_731
SOURCE_B = 8_432_451_907_612_340_733
PERMISSION_SESSION = ["session"]
PERMISSION_DELEGATE = ["delegate"]
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
ADD_TYPES = {
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
    return text[:600]


def address_hint(message: Any) -> str | None:
    if message is None:
        return None
    text = str(message)
    match = re.search(r"wallet\s+(0x[0-9a-fA-F]{3})\.\.\.([0-9a-fA-F]{3})", text)
    if not match:
        return None
    prefix = match.group(1)[2:].lower()
    suffix = match.group(2).lower()
    candidates = {
        "signer": SIGNER.address,
        "delegate_a": DELEGATE_A.address,
        "delegate_b": DELEGATE_B.address,
        "unrelated": UNRELATED.address,
    }
    for name, address in candidates.items():
        raw = address[2:].lower()
        if raw.startswith(prefix) and raw.endswith(suffix):
            return name
    return "other"


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


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if not isinstance(response, dict):
        return None
    total = 0
    recognized = False
    for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
        value = response.get(key)
        if isinstance(value, list):
            recognized = True
            total += len(value)
    return total if recognized else None


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def sign_add(
    *,
    source_id: int,
    delegate_address: str,
    permissions: list[str],
    expires_at: int,
    nonce: int,
    expires_after: int,
) -> dict[str, Any]:
    full_message = {
        "types": ADD_TYPES,
        "primaryType": "AddDelegatedSigner",
        "domain": DOMAIN,
        "message": {
            "delegateAddress": delegate_address,
            "subAccountId": source_id,
            "nonce": nonce,
            "expiresAfter": expires_after,
            "expiresAt": expires_at,
            "permissions": permissions,
        },
    }
    return format_signature(SIGNER.sign_message(encode_typed_data(full_message=full_message)))


def corrupt(signature: dict[str, Any]) -> dict[str, Any]:
    value = int(signature["s"], 16) ^ 1
    return {"v": signature["v"], "r": signature["r"], "s": "0x" + format(value, "064x")}


def build(
    *,
    signed_source: int = SOURCE_A,
    signed_delegate: str = DELEGATE_A.address,
    signed_permissions: list[str] | None = None,
    signed_expires_at: int = 0,
    params_source: Any | None = str(SOURCE_A),
    params_wallet: Any | None = DELEGATE_A.address,
    params_delegate_alias: Any | None = None,
    wire_permissions: list[str] | None = None,
    wire_expires_at: Any | None = 0,
    top_source: Any | None = None,
    top_wallet: Any | None = None,
    corrupt_sig: bool = False,
    extra_params: dict[str, Any] | None = None,
    extra_top: dict[str, Any] | None = None,
) -> dict[str, Any]:
    permissions = list(signed_permissions or PERMISSION_SESSION)
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign_add(
        source_id=signed_source,
        delegate_address=signed_delegate,
        permissions=permissions,
        expires_at=signed_expires_at,
        nonce=nonce,
        expires_after=expires_after,
    )
    if corrupt_sig:
        signature = corrupt(signature)

    params: dict[str, Any] = {"action": "addDelegatedSigner"}
    if params_source is not None:
        params["subAccountId"] = params_source
    if params_wallet is not None:
        params["walletAddress"] = params_wallet
    if params_delegate_alias is not None:
        params["delegateAddress"] = params_delegate_alias
    params["permissions"] = list(wire_permissions if wire_permissions is not None else permissions)
    if wire_expires_at is not None:
        params["expiresAt"] = wire_expires_at
    if extra_params:
        params.update(extra_params)

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
    if extra_top:
        payload.update(extra_top)
    return payload


def duplicate_wallet_body(*, first: str, second: str, signed_delegate: str) -> bytes:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign_add(
        source_id=SOURCE_A,
        delegate_address=signed_delegate,
        permissions=PERMISSION_SESSION,
        expires_at=0,
        nonce=nonce,
        expires_after=expires_after,
    )
    return (
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
        '"signature":' + json.dumps(signature, separators=(",", ":"))
        "}"
    ).encode()


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    return {
        "name": name,
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": sha(str(error_message)) if error_message is not None else None,
        "walletHint": address_hint(error_message),
        "responseType": type(response).__name__ if response is not None else None,
        "bodySha256": sha(body),
        "bodyBytes": len(body),
        "elapsedMs": round(elapsed * 1000, 2),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None)
        or headers.get("X-Request-Id")
        or headers.get("x-request-id"),
    }


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": "Synthetic zero-account signer, synthetic delegates and nonexistent account IDs only; no delegation can execute.",
        "syntheticSigner": SIGNER.address,
        "syntheticDelegates": [DELEGATE_A.address, DELEGATE_B.address],
        "sourceIdsSha256": [sha(str(SOURCE_A)), sha(str(SOURCE_B))],
        "tests": [],
    }

    status, body, headers, elapsed = post_json(
        PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": SIGNER.address, "includeDelegations": True}},
    )
    preflight = summarize("synthetic_account_preflight", status, body, headers, elapsed)
    parsed = parse_json(body)
    count = account_count(parsed.get("response") if isinstance(parsed, dict) else None)
    preflight["accountCount"] = count
    evidence["tests"].append(preflight)

    if count != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic signer was not confirmed to have zero accounts."
    else:
        future = int(time.time() * 1000) + 30 * 24 * 60 * 60 * 1000
        cases: list[tuple[str, dict[str, Any] | bytes]] = [
            ("corrupted_docs_control", build(corrupt_sig=True)),
            ("docs_shape_baseline", build()),
            (
                "sdk_shape_baseline",
                build(
                    params_source=None,
                    top_source=str(SOURCE_A),
                    top_wallet=SIGNER.address,
                ),
            ),
            (
                "hybrid_same",
                build(top_source=str(SOURCE_A), top_wallet=SIGNER.address),
            ),
            (
                "sdk_top_wallet_unrelated",
                build(params_source=None, top_source=str(SOURCE_A), top_wallet=UNRELATED.address),
            ),
            (
                "sdk_top_wallet_omitted",
                build(params_source=None, top_source=str(SOURCE_A), top_wallet=None),
            ),
            (
                "delegate_alias_only",
                build(params_wallet=None, params_delegate_alias=DELEGATE_A.address),
            ),
            (
                "both_delegate_fields_conflict_sign_wallet",
                build(params_wallet=DELEGATE_A.address, params_delegate_alias=DELEGATE_B.address, signed_delegate=DELEGATE_A.address),
            ),
            (
                "both_delegate_fields_conflict_sign_alias",
                build(params_wallet=DELEGATE_A.address, params_delegate_alias=DELEGATE_B.address, signed_delegate=DELEGATE_B.address),
            ),
            (
                "malformed_wallet_valid_alias",
                build(params_wallet="AUDIT_NOT_ADDRESS", params_delegate_alias=DELEGATE_A.address),
            ),
            (
                "valid_wallet_malformed_alias",
                build(params_wallet=DELEGATE_A.address, params_delegate_alias="AUDIT_NOT_ADDRESS"),
            ),
            (
                "permission_escalation_attempt",
                build(signed_permissions=PERMISSION_SESSION, wire_permissions=PERMISSION_DELEGATE),
            ),
            (
                "permission_downgrade_control",
                build(signed_permissions=PERMISSION_DELEGATE, wire_permissions=PERMISSION_SESSION),
            ),
            (
                "expiry_extension_attempt",
                build(signed_expires_at=future, wire_expires_at=0),
            ),
            (
                "expiry_shortening_control",
                build(signed_expires_at=0, wire_expires_at=future),
            ),
            (
                "source_conflict_sign_params",
                build(signed_source=SOURCE_A, params_source=str(SOURCE_A), top_source=str(SOURCE_B), top_wallet=SIGNER.address),
            ),
            (
                "source_conflict_sign_top",
                build(signed_source=SOURCE_B, params_source=str(SOURCE_A), top_source=str(SOURCE_B), top_wallet=SIGNER.address),
            ),
            (
                "params_source_zero_top_valid",
                build(signed_source=SOURCE_A, params_source="0", top_source=str(SOURCE_A), top_wallet=SIGNER.address),
            ),
            (
                "params_source_valid_top_zero",
                build(signed_source=SOURCE_A, params_source=str(SOURCE_A), top_source="0", top_wallet=SIGNER.address),
            ),
            (
                "top_wallet_delegate_a_docs_shape",
                build(top_wallet=DELEGATE_A.address),
            ),
            (
                "duplicate_wallet_sign_first",
                duplicate_wallet_body(first=DELEGATE_A.address, second=DELEGATE_B.address, signed_delegate=DELEGATE_A.address),
            ),
            (
                "duplicate_wallet_sign_second",
                duplicate_wallet_body(first=DELEGATE_A.address, second=DELEGATE_B.address, signed_delegate=DELEGATE_B.address),
            ),
            (
                "legacy_trading_permission",
                build(signed_permissions=["trading"], wire_permissions=["trading"]),
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

    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "accountCount": count,
                "cases": [
                    {
                        "name": item.get("name"),
                        "httpStatus": item.get("httpStatus"),
                        "errorCode": item.get("errorCode"),
                        "walletHint": item.get("walletHint"),
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
