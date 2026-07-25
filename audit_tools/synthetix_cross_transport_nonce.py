#!/usr/bin/env python3
"""Synthetic REST/WebSocket nonce-sharing and validation-order probe for Synthetix PAPI.

Safety constraints:
- deterministic EOAs confirmed to own/manage/delegate zero accounts;
- deliberately nonexistent valid-range subaccount ID;
- `updateLeverage` only; no funds can move;
- WebSocket `post` is sent without successful account auth, so no mutation can execute;
- identical signed envelopes are compared across REST and WS;
- fixed low-noise sequence, redacted metadata only.

Goals:
1. determine whether unauthenticated WS `post` reaches request-signature/nonce validation;
2. determine whether REST and WS share the same consumed-nonce store.
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
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
import websockets

OUT = pathlib.Path("cross_transport_nonce")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
WS_TRADE = "wss://papi.synthetix.io/v1/ws/trade"
SIGNER_WR = Account.from_key("0x" + "a2" * 32)
SIGNER_RW = Account.from_key("0x" + "a3" * 32)
SIGNER_CTRL = Account.from_key("0x" + "a4" * 32)
TARGET_ACCOUNT = 8_600_000_000_000_001
SYMBOL = "BTC-USDT"
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

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
    "UpdateLeverage": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "leverage", "type": "string"},
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
    text = ADDRESS_RE.sub("<address>", str(value))
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:800]


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
        return exc.code, exc.read(MAX_BODY + 1), dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


def parse_json(value: bytes | str) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
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
    return {"v": signed.v, "r": "0x" + format(signed.r, "064x"), "s": "0x" + format(signed.s, "064x")}


def envelope(account: Any, nonce: int) -> dict[str, Any]:
    expires_after = nonce + 300_000
    message = {
        "subAccountId": TARGET_ACCOUNT,
        "symbol": SYMBOL,
        "leverage": "1",
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    encoded = encode_typed_data(full_message={"types": TYPES, "primaryType": "UpdateLeverage", "domain": DOMAIN, "message": message})
    return {
        "signature": format_signature(account.sign_message(encoded)),
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": "updateLeverage",
            "subaccountId": str(TARGET_ACCOUNT),
            "walletAddress": account.address,
            "symbol": SYMBOL,
            "leverage": "1",
        },
    }


def summarize_rest(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    raw = str(message) if message is not None else ""
    return {
        "name": name,
        "transport": "rest",
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error.get("code") if isinstance(error, dict) else None,
        "errorMessageRedacted": redact(message),
        "errorMessageSha256": digest(raw) if raw else None,
        "nonceUsedSignal": bool(re.search(r"nonce.*used|already used|duplicate nonce", raw, re.I)),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def summarize_ws(name: str, raw: str | None, error: Exception | None, elapsed: float) -> dict[str, Any]:
    if raw is None:
        return {
            "name": name,
            "transport": "websocket",
            "connected": False if error else True,
            "elapsedMs": round(elapsed * 1000, 2),
            "errorType": type(error).__name__ if error else "Timeout",
            "errorSha256": digest(str(error)) if error else None,
            "nonceUsedSignal": False,
        }
    parsed = parse_json(raw)
    result = parsed.get("result") if isinstance(parsed, dict) else None
    error_obj = parsed.get("error") if isinstance(parsed, dict) else None
    message = None
    code = None
    if isinstance(error_obj, dict):
        message = error_obj.get("message")
        code = error_obj.get("code")
    elif error_obj is not None:
        message = error_obj
    if message is None and isinstance(result, dict):
        inner_error = result.get("error")
        if isinstance(inner_error, dict):
            message = inner_error.get("message")
            code = code or inner_error.get("code")
        elif inner_error is not None:
            message = inner_error
        if message is None:
            message = result.get("message")
            code = code or result.get("code")
    raw_message = str(message) if message is not None else ""
    return {
        "name": name,
        "transport": "websocket",
        "connected": True,
        "elapsedMs": round(elapsed * 1000, 2),
        "topLevelKeys": sorted(parsed.keys()) if isinstance(parsed, dict) else None,
        "status": parsed.get("status") if isinstance(parsed, dict) else None,
        "resultSchema": schema(result),
        "errorCode": code,
        "errorMessageRedacted": redact(message),
        "errorMessageSha256": digest(raw_message) if raw_message else None,
        "nonceUsedSignal": bool(re.search(r"nonce.*used|already used|duplicate nonce", raw_message, re.I)),
        "bodySha256": digest(raw),
        "bodyBytes": len(raw.encode()),
    }


async def ws_post(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    ws_params = {**payload["params"], "signature": payload["signature"], "nonce": payload["nonce"], "expiresAfter": payload["expiresAfter"]}
    message = json.dumps({"id": "1", "method": "post", "params": ws_params}, separators=(",", ":"))
    started = time.monotonic()
    try:
        async with websockets.connect(WS_TRADE, additional_headers={"User-Agent": UA}, ping_interval=None, close_timeout=5) as ws:
            await ws.send(message)
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=8)
                return summarize_ws(name, raw, None, time.monotonic() - started)
            except asyncio.TimeoutError as exc:
                return summarize_ws(name, None, exc, time.monotonic() - started)
    except Exception as exc:  # noqa: BLE001
        return summarize_ws(name, None, exc, time.monotonic() - started)


def preflight(account: Any, label: str) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(PAPI_INFO, {"params": {"action": "getSubAccountIds", "walletAddress": account.address, "includeDelegations": True}})
    item = summarize_rest(f"preflight_{label}", status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    item["accountCount"] = account_count(response)
    return item


async def main() -> None:
    evidence: dict[str, Any] = {
        "safety": "Three zero-account synthetic EOAs, one nonexistent account, updateLeverage only, and no successful WS authentication. No mutation can execute.",
        "targetAccountSha256": digest(str(TARGET_ACCOUNT)),
        "tests": [],
    }
    for label, signer in (("wr", SIGNER_WR), ("rw", SIGNER_RW), ("ctrl", SIGNER_CTRL)):
        item = preflight(signer, label)
        evidence["tests"].append(item)
        time.sleep(0.3)
    if any(item.get("accountCount") != 0 for item in evidence["tests"]):
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic signers were not all confirmed to have zero accounts."
    else:
        base_nonce = int(time.time() * 1000) + 40_000

        wr_payload = envelope(SIGNER_WR, base_nonce)
        evidence["tests"].append(await ws_post("ws_first_wr", wr_payload))
        await asyncio.sleep(0.5)
        status, body, headers, elapsed = post_json(PAPI_TRADE, wr_payload)
        evidence["tests"].append(summarize_rest("rest_second_exact_wr", status, body, headers, elapsed))
        await asyncio.sleep(0.6)

        rw_payload = envelope(SIGNER_RW, base_nonce + 1)
        status, body, headers, elapsed = post_json(PAPI_TRADE, rw_payload)
        evidence["tests"].append(summarize_rest("rest_first_rw", status, body, headers, elapsed))
        await asyncio.sleep(0.5)
        evidence["tests"].append(await ws_post("ws_second_exact_rw", rw_payload))
        await asyncio.sleep(0.6)

        ctrl_payload = envelope(SIGNER_CTRL, base_nonce + 2)
        evidence["tests"].append(await ws_post("ws_control_first", ctrl_payload))
        await asyncio.sleep(0.5)
        evidence["tests"].append(await ws_post("ws_control_local_replay", ctrl_payload))
        await asyncio.sleep(0.5)
        status, body, headers, elapsed = post_json(PAPI_TRADE, ctrl_payload)
        evidence["tests"].append(summarize_rest("rest_after_ws_control", status, body, headers, elapsed))

    by_name = {item["name"]: item for item in evidence["tests"]}
    evidence["summary"] = {
        "testCount": len(evidence["tests"]),
        "probeAborted": bool(evidence.get("probeAborted")),
        "wsFirstConsumedForRest": bool(by_name.get("rest_second_exact_wr", {}).get("nonceUsedSignal")),
        "restFirstVisibleToWs": bool(by_name.get("ws_second_exact_rw", {}).get("nonceUsedSignal")),
        "wsLocalReplayNonceSignal": bool(by_name.get("ws_control_local_replay", {}).get("nonceUsedSignal")),
        "restAfterWsControlNonceSignal": bool(by_name.get("rest_after_ws_control", {}).get("nonceUsedSignal")),
        "caseMatrix": [
            {key: item.get(key) for key in ("name", "transport", "connected", "accountCount", "httpStatus", "apiStatus", "status", "errorCode", "errorMessageRedacted", "errorMessageSha256", "nonceUsedSignal", "bodySha256")}
            for item in evidence["tests"]
        ],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(evidence["summary"], indent=2), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__":
    asyncio.run(main())
