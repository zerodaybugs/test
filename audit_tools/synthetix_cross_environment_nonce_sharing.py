#!/usr/bin/env python3
"""Synthetic cross-environment nonce-store sharing probe for Synthetix PAPI.

Safety constraints:
- three deterministic EOAs confirmed to own/manage/delegate zero accounts in both environments;
- one deliberately nonexistent valid-range subaccount ID;
- `updateLeverage` requests only, so no funds can move;
- identical signed envelopes are replayed across official production/test endpoints;
- no real account exists, therefore no state mutation can execute;
- fixed low-noise sequence and redacted metadata only.

Purpose: determine whether api.test.synthetix.io and papi.synthetix.io share the
same consumed-nonce store for the production-fixed EIP-712 domain.
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

OUT = pathlib.Path("cross_environment_nonce_sharing")
OUT.mkdir(parents=True, exist_ok=True)

PROD_INFO = "https://papi.synthetix.io/v1/info"
PROD_TRADE = "https://papi.synthetix.io/v1/trade"
TEST_INFO = "https://api.test.synthetix.io/v1/info"
TEST_TRADE = "https://api.test.synthetix.io/v1/trade"
SIGNER_TP = Account.from_key("0x" + "97" * 32)
SIGNER_PT = Account.from_key("0x" + "98" * 32)
SIGNER_CTRL = Account.from_key("0x" + "99" * 32)
TARGET_ACCOUNT = 8_500_000_000_000_001
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
        return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        recognized = False
        total = 0
        for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
            values = response.get(key)
            if isinstance(values, list):
                recognized = True
                total += len(values)
        return total if recognized else None
    return None


def summarize(name: str, env: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    raw = str(error_message) if error_message is not None else ""
    return {
        "name": name,
        "environment": env,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(raw) if raw else None,
        "nonceUsedSignal": bool(re.search(r"nonce.*used|already used|duplicate nonce", raw, re.I)),
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "requestId": (
            parsed.get("request_id") if isinstance(parsed, dict) else None
        ) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def envelope(account: Any, nonce: int, leverage: str = "1") -> dict[str, Any]:
    expires_after = nonce + 300_000
    message = {
        "subAccountId": TARGET_ACCOUNT,
        "symbol": SYMBOL,
        "leverage": leverage,
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    encoded = encode_typed_data(
        full_message={
            "types": TYPES,
            "primaryType": "UpdateLeverage",
            "domain": DOMAIN,
            "message": message,
        }
    )
    return {
        "signature": format_signature(account.sign_message(encoded)),
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": "updateLeverage",
            "subaccountId": str(TARGET_ACCOUNT),
            "walletAddress": account.address,
            "symbol": SYMBOL,
            "leverage": leverage,
        },
    }


def preflight(account: Any, env: str, url: str) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(
        url,
        {"params": {"action": "getSubAccountIds", "walletAddress": account.address, "includeDelegations": True}},
    )
    item = summarize(f"preflight_{env}", env, status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    item["accountCount"] = account_count(response)
    return item


def send(name: str, env: str, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(url, payload)
    return summarize(name, env, status, body, headers, elapsed)


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": "Three deterministic zero-account EOAs and one nonexistent account; identical updateLeverage envelopes only. No account state can mutate.",
        "targetAccountSha256": digest(str(TARGET_ACCOUNT)),
        "tests": [],
    }

    signers = (("tp", SIGNER_TP), ("pt", SIGNER_PT), ("ctrl", SIGNER_CTRL))
    preflight_ok = True
    for label, signer in signers:
        for env, url in (("prod", PROD_INFO), ("test", TEST_INFO)):
            item = preflight(signer, env, url)
            item["signerLabel"] = label
            evidence["tests"].append(item)
            if item.get("accountCount") != 0:
                preflight_ok = False
            time.sleep(0.25)

    if not preflight_ok:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "All synthetic signers were not confirmed to have zero accounts in both environments."
    else:
        base_nonce = int(time.time() * 1000) + 20_000

        payload_tp = envelope(SIGNER_TP, base_nonce)
        evidence["tests"].append(send("test_first_tp", "test", TEST_TRADE, payload_tp))
        time.sleep(0.5)
        evidence["tests"].append(send("prod_second_exact_tp", "prod", PROD_TRADE, payload_tp))
        time.sleep(0.6)

        payload_pt = envelope(SIGNER_PT, base_nonce + 1)
        evidence["tests"].append(send("prod_first_pt", "prod", PROD_TRADE, payload_pt))
        time.sleep(0.5)
        evidence["tests"].append(send("test_second_exact_pt", "test", TEST_TRADE, payload_pt))
        time.sleep(0.6)

        payload_ctrl_prod = envelope(SIGNER_CTRL, base_nonce + 2)
        payload_ctrl_test = envelope(SIGNER_CTRL, base_nonce + 3)
        evidence["tests"].append(send("prod_control_unique_nonce", "prod", PROD_TRADE, payload_ctrl_prod))
        time.sleep(0.5)
        evidence["tests"].append(send("test_control_different_nonce", "test", TEST_TRADE, payload_ctrl_test))
        time.sleep(0.6)

        # Endpoint-local exact replay controls establish that each environment consumes its own nonce.
        evidence["tests"].append(send("prod_local_replay_control", "prod", PROD_TRADE, payload_ctrl_prod))
        time.sleep(0.5)
        evidence["tests"].append(send("test_local_replay_control", "test", TEST_TRADE, payload_ctrl_test))

    by_name = {item["name"]: item for item in evidence["tests"]}
    evidence["summary"] = {
        "testCount": len(evidence["tests"]),
        "probeAborted": bool(evidence.get("probeAborted")),
        "testThenProdSharedNonceSignal": bool(by_name.get("prod_second_exact_tp", {}).get("nonceUsedSignal")),
        "prodThenTestSharedNonceSignal": bool(by_name.get("test_second_exact_pt", {}).get("nonceUsedSignal")),
        "prodLocalReplaySignal": bool(by_name.get("prod_local_replay_control", {}).get("nonceUsedSignal")),
        "testLocalReplaySignal": bool(by_name.get("test_local_replay_control", {}).get("nonceUsedSignal")),
        "directionalPairs": {
            "testThenProd": {
                "first": {k: by_name.get("test_first_tp", {}).get(k) for k in ("httpStatus", "errorCode", "errorMessageSha256", "nonceUsedSignal")},
                "second": {k: by_name.get("prod_second_exact_tp", {}).get(k) for k in ("httpStatus", "errorCode", "errorMessageSha256", "nonceUsedSignal")},
            },
            "prodThenTest": {
                "first": {k: by_name.get("prod_first_pt", {}).get(k) for k in ("httpStatus", "errorCode", "errorMessageSha256", "nonceUsedSignal")},
                "second": {k: by_name.get("test_second_exact_pt", {}).get(k) for k in ("httpStatus", "errorCode", "errorMessageSha256", "nonceUsedSignal")},
            },
        },
        "caseMatrix": [
            {key: item.get(key) for key in ("name", "environment", "signerLabel", "accountCount", "httpStatus", "apiStatus", "errorCode", "errorMessageSha256", "nonceUsedSignal", "bodySha256")}
            for item in evidence["tests"]
        ],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(evidence["summary"], indent=2), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__":
    main()
