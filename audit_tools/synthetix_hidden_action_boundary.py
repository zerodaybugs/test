#!/usr/bin/env python3
"""Low-noise validation-boundary probe for documented-but-unlinked Synthetix trade actions.

Safety constraints:
- deterministic synthetic EOA confirmed to own/manage/delegate zero accounts;
- deliberately nonexistent valid-range subaccount ID;
- fixed malformed/invalid-signature requests only;
- no valid signature is sent for write actions, so no state change can execute;
- `getPortfolio` uses a valid synthetic generic read signature;
- output contains only redacted errors, schemas and hashes.
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

OUT = pathlib.Path("hidden_action_boundary")
OUT.mkdir(parents=True, exist_ok=True)
PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
ACCOUNT = Account.from_key("0x" + "96" * 32)
SUBACCOUNT_ID = 8_400_000_000_000_001
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": "0x0000000000000000000000000000000000000000"}
SUBACTION_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "SubAccountAction": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "action", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}
ZERO_SIGNATURE = {"v": 27, "r": "0x" + "00" * 32, "s": "0x" + "00" * 32}


def digest(value: str | bytes) -> str:
    if isinstance(value, str): value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None: return None
    text = ADDRESS_RE.sub("<address>", str(value))
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:1200]


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=body, headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_body = response.read(MAX_BODY + 1)
            if len(response_body) > MAX_BODY: raise ValueError("response too large")
            return response.status, response_body, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1), dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


def parse_json(body: bytes) -> Any:
    try: return json.loads(body)
    except Exception: return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4: return type(value).__name__
    if isinstance(value, dict): return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list): return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def account_count(response: Any) -> int | None:
    if isinstance(response, list): return len(response)
    if isinstance(response, dict):
        recognized, total = False, 0
        for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
            values = response.get(key)
            if isinstance(values, list): recognized, total = True, total + len(values)
        return total if recognized else None
    return None


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    raw = str(error_message) if error_message is not None else ""
    addresses = [value.lower() for value in ADDRESS_RE.findall(raw)]
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorCategory": error.get("category") if isinstance(error, dict) else None,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(raw) if raw else None,
        "mentionsSyntheticSigner": ACCOUNT.address.lower() in addresses,
        "responseSchema": schema(response),
        "rateLimit": parsed.get("rateLimit") if isinstance(parsed, dict) and isinstance(parsed.get("rateLimit"), dict) else None,
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def base_envelope(action: str, params: dict[str, Any], nonce: int, *, signature: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "signature": signature if signature is not None else ZERO_SIGNATURE,
        "nonce": nonce,
        "expiresAfter": nonce + 300_000,
        "params": {"action": action, **params},
    }


def get_portfolio_envelope(nonce: int) -> dict[str, Any]:
    expires_after = nonce + 300_000
    encoded = encode_typed_data(full_message={
        "types": SUBACTION_TYPES,
        "primaryType": "SubAccountAction",
        "domain": DOMAIN,
        "message": {"subAccountId": SUBACCOUNT_ID, "action": "getPortfolio", "nonce": nonce, "expiresAfter": expires_after},
    })
    signed = ACCOUNT.sign_message(encoded)
    signature = {"v": signed.v, "r": "0x" + format(signed.r, "064x"), "s": "0x" + format(signed.s, "064x")}
    return base_envelope("getPortfolio", {"subaccountId": str(SUBACCOUNT_ID), "walletAddress": ACCOUNT.address}, nonce, signature=signature)


def main() -> None:
    evidence: dict[str, Any] = {"safety": "Synthetic zero-account signer and invalid signatures only for write actions; no mutation can execute.", "syntheticAddress": ACCOUNT.address, "subaccountIdSha256": digest(str(SUBACCOUNT_ID)), "tests": []}
    status, body, headers, elapsed = post_json(PAPI_INFO, {"params": {"action": "getSubAccountIds", "walletAddress": ACCOUNT.address, "includeDelegations": True}})
    preflight = summarize("synthetic_account_preflight", status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    preflight["accountCount"] = account_count(response)
    evidence["tests"].append(preflight)
    if preflight.get("accountCount") != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic signer was not confirmed to have zero accounts."
    else:
        n = int(time.time() * 1000) + 5_000
        cases: list[tuple[str, dict[str, Any]]] = [
            ("getPortfolio_valid_generic_signature", get_portfolio_envelope(n)),
            ("modifyOrderBatch_minimal", {"params": {"action": "modifyOrderBatch"}}),
            ("modifyOrderBatch_source_only", base_envelope("modifyOrderBatch", {"subAccountId": str(SUBACCOUNT_ID)}, n + 1)),
            ("modifyOrderBatch_orders_empty", base_envelope("modifyOrderBatch", {"subAccountId": str(SUBACCOUNT_ID), "orders": []}, n + 2)),
            ("modifyOrderBatch_modifications_empty", base_envelope("modifyOrderBatch", {"subAccountId": str(SUBACCOUNT_ID), "modifications": []}, n + 3)),
            ("modifyOrderBatch_updates_empty", base_envelope("modifyOrderBatch", {"subAccountId": str(SUBACCOUNT_ID), "updates": []}, n + 4)),
            ("placeIsolatedOrder_minimal", {"params": {"action": "placeIsolatedOrder"}}),
            ("placeIsolatedOrder_candidate", base_envelope("placeIsolatedOrder", {"subAccountId": str(SUBACCOUNT_ID), "symbol": "BTC-USDT", "side": "buy", "orderType": "limitGtc", "price": "1", "quantity": "0.001", "leverage": "1", "margin": "1"}, n + 5)),
            ("placeIsolatedOrder_nested_order", base_envelope("placeIsolatedOrder", {"subAccountId": str(SUBACCOUNT_ID), "order": {"symbol": "BTC-USDT", "side": "buy", "orderType": "limitGtc", "price": "1", "quantity": "0.001", "reduceOnly": False}}, n + 6)),
            ("updateIsolatedMargin_minimal", {"params": {"action": "updateIsolatedMargin"}}),
            ("updateIsolatedMargin_symbol_amount", base_envelope("updateIsolatedMargin", {"subAccountId": str(SUBACCOUNT_ID), "symbol": "BTC-USDT", "amount": "1"}, n + 7)),
            ("updateIsolatedMargin_position_delta", base_envelope("updateIsolatedMargin", {"subAccountId": str(SUBACCOUNT_ID), "positionId": "1", "marginDelta": "1"}, n + 8)),
            ("updateIsolatedMargin_asset_delta", base_envelope("updateIsolatedMargin", {"subAccountId": str(SUBACCOUNT_ID), "asset": "BTC-USDT", "delta": "1"}, n + 9)),
        ]
        for index, (name, payload) in enumerate(cases):
            status, body, headers, elapsed = post_json(PAPI_TRADE, payload)
            evidence["tests"].append(summarize(name, status, body, headers, elapsed))
            if index + 1 < len(cases): time.sleep(0.45)
    evidence["summary"] = {
        "testCount": len(evidence["tests"]),
        "probeAborted": bool(evidence.get("probeAborted")),
        "supportedActionSignals": [
            item["name"] for item in evidence["tests"]
            if item["name"] != "synthetic_account_preflight"
            and "unsupported type" not in str(item.get("errorMessageRedacted") or "").lower()
            and "invalid request type" not in str(item.get("errorMessageRedacted") or "").lower()
            and item.get("httpStatus") != 404
        ],
        "caseMatrix": [{key: item.get(key) for key in ("name", "httpStatus", "apiStatus", "errorCode", "errorMessageRedacted", "mentionsSyntheticSigner", "rateLimit", "bodySha256")} for item in evidence["tests"]],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(evidence["summary"], indent=2), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__": main()
