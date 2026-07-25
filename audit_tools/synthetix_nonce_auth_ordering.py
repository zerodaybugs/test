#!/usr/bin/env python3
"""Synthetic nonce/auth ordering differential for Synthetix PAPI.

Safety constraints:
- two deterministic synthetic EOAs only;
- preflight confirms both own/manage/delegate zero Synthetix accounts;
- two deliberately nonexistent valid-range subaccount IDs;
- `updateLeverage` requests only, so no funds can move;
- no valid account exists, therefore no request can mutate protocol state;
- fixed low-noise request sequence;
- only redacted response metadata, hashes and recovered-address comparisons retained.

Purpose: determine whether nonce state is checked or consumed before account authorization,
and whether one unauthorised signer can poison nonce state shared by another signer/account.
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

OUT = pathlib.Path("nonce_auth_ordering")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
SIGNER_A = Account.from_key("0x" + "91" * 32)
SIGNER_B = Account.from_key("0x" + "92" * 32)
ACCOUNT_X = 8_100_000_000_000_001
ACCOUNT_Y = 8_100_000_000_000_003
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
    text = str(value)
    text = ADDRESS_RE.sub("<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:700]


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


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def sign(account: Any, subaccount_id: int, nonce: int, expires_after: int, leverage: str) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": TYPES,
            "primaryType": "UpdateLeverage",
            "domain": DOMAIN,
            "message": {
                "subAccountId": subaccount_id,
                "symbol": SYMBOL,
                "leverage": leverage,
                "nonce": nonce,
                "expiresAfter": expires_after,
            },
        }
    )
    return format_signature(account.sign_message(encoded))


def corrupt(signature: dict[str, Any]) -> dict[str, Any]:
    value = int(signature["s"], 16) ^ 1
    return {"v": signature["v"], "r": signature["r"], "s": "0x" + format(value, "064x")}


def envelope(
    account: Any,
    subaccount_id: int,
    nonce: int,
    *,
    leverage: str = "1",
    corrupt_signature: bool = False,
) -> dict[str, Any]:
    expires_after = nonce + 300_000
    signature = sign(account, subaccount_id, nonce, expires_after, leverage)
    if corrupt_signature:
        signature = corrupt(signature)
    return {
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": "updateLeverage",
            "subaccountId": str(subaccount_id),
            "walletAddress": account.address,
            "symbol": SYMBOL,
            "leverage": leverage,
        },
    }


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    raw = str(error_message) if error_message is not None else ""
    addresses = [item.lower() for item in ADDRESS_RE.findall(raw)]
    headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}
    rate_headers = {
        key: value
        for key, value in headers_lower.items()
        if "rate" in key or "limit" in key or "retry" in key
    }
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(raw) if raw else None,
        "errorAddressesSha256": sorted(digest(item) for item in addresses),
        "mentionsSignerA": SIGNER_A.address.lower() in addresses,
        "mentionsSignerB": SIGNER_B.address.lower() in addresses,
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "rateLimitHeaders": rate_headers,
        "requestId": (
            parsed.get("request_id") if isinstance(parsed, dict) else None
        ) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def preflight(account: Any, name: str) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(
        PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": account.address, "includeDelegations": True}},
    )
    item = summarize(name, status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    item["accountCount"] = account_count(response)
    return item


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": (
            "Two deterministic zero-account EOAs, two nonexistent valid-range subaccount IDs, and updateLeverage only. "
            "No request can mutate an existing account or move funds."
        ),
        "signerA": SIGNER_A.address,
        "signerB": SIGNER_B.address,
        "accountXSha256": digest(str(ACCOUNT_X)),
        "accountYSha256": digest(str(ACCOUNT_Y)),
        "tests": [],
    }
    pre_a = preflight(SIGNER_A, "preflight_signer_a")
    time.sleep(0.4)
    pre_b = preflight(SIGNER_B, "preflight_signer_b")
    evidence["tests"].extend([pre_a, pre_b])
    if pre_a.get("accountCount") != 0 or pre_b.get("accountCount") != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic signers were not both confirmed to have zero accounts."
    else:
        base_nonce = int(time.time() * 1000) + 5_000
        high_nonce = 8_900_000_000_000_000
        first_payload = envelope(SIGNER_A, ACCOUNT_X, base_nonce)
        cases: list[tuple[str, dict[str, Any]]] = [
            ("corrupted_signature_control", envelope(SIGNER_A, ACCOUNT_X, base_nonce - 10, corrupt_signature=True)),
            ("first_nonce_n", first_payload),
            ("exact_replay_nonce_n", first_payload),
            ("lower_nonce_after_n", envelope(SIGNER_A, ACCOUNT_X, base_nonce - 1)),
            ("higher_nonce_after_n", envelope(SIGNER_A, ACCOUNT_X, base_nonce + 1)),
            ("same_nonce_different_signed_payload", envelope(SIGNER_A, ACCOUNT_X, base_nonce, leverage="2")),
            ("different_signer_same_account_same_nonce", envelope(SIGNER_B, ACCOUNT_X, base_nonce)),
            ("same_signer_different_account_same_nonce", envelope(SIGNER_A, ACCOUNT_Y, base_nonce)),
            ("high_nonce_unauthorized_signer_a_account_x", envelope(SIGNER_A, ACCOUNT_X, high_nonce)),
            ("ordinary_nonce_after_high_same_signer_account", envelope(SIGNER_A, ACCOUNT_X, base_nonce + 2)),
            ("ordinary_nonce_after_high_other_signer_same_account", envelope(SIGNER_B, ACCOUNT_X, base_nonce + 2)),
            ("ordinary_nonce_after_high_same_signer_other_account", envelope(SIGNER_A, ACCOUNT_Y, base_nonce + 2)),
        ]
        for index, (name, payload) in enumerate(cases):
            status, body, headers, elapsed = post_json(PAPI_TRADE, payload)
            evidence["tests"].append(summarize(name, status, body, headers, elapsed))
            if index + 1 < len(cases):
                time.sleep(0.65)

    by_name = {item["name"]: item for item in evidence["tests"]}
    baseline = by_name.get("first_nonce_n", {})
    baseline_tuple = (
        baseline.get("httpStatus"),
        baseline.get("apiStatus"),
        baseline.get("errorCode"),
        baseline.get("errorMessageSha256"),
    )
    comparisons: dict[str, Any] = {}
    for name in (
        "exact_replay_nonce_n",
        "lower_nonce_after_n",
        "higher_nonce_after_n",
        "same_nonce_different_signed_payload",
        "different_signer_same_account_same_nonce",
        "same_signer_different_account_same_nonce",
        "ordinary_nonce_after_high_same_signer_account",
        "ordinary_nonce_after_high_other_signer_same_account",
        "ordinary_nonce_after_high_same_signer_other_account",
    ):
        item = by_name.get(name, {})
        current = (item.get("httpStatus"), item.get("apiStatus"), item.get("errorCode"), item.get("errorMessageSha256"))
        comparisons[name] = {
            "sameAsFirstUnauthorizedResponse": current == baseline_tuple,
            "tuple": current,
        }
    nonce_signals = [
        item["name"]
        for item in evidence["tests"]
        if re.search(r"nonce|already used|stale|sequence|too low|too high", str(item.get("errorMessageRedacted") or ""), re.I)
    ]
    evidence["summary"] = {
        "testCount": len(evidence["tests"]),
        "probeAborted": bool(evidence.get("probeAborted")),
        "firstUnauthorizedTuple": baseline_tuple,
        "comparisons": comparisons,
        "casesWithNonceRelatedErrorText": nonce_signals,
        "distinctErrorMessageHashes": sorted({
            item.get("errorMessageSha256") for item in evidence["tests"] if item.get("errorMessageSha256")
        }),
        "caseMatrix": [
            {
                key: item.get(key)
                for key in (
                    "name", "httpStatus", "apiStatus", "errorCode", "errorMessageSha256",
                    "mentionsSignerA", "mentionsSignerB", "bodySha256", "rateLimitHeaders"
                )
            }
            for item in evidence["tests"]
        ],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(evidence["summary"], indent=2), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__":
    main()
