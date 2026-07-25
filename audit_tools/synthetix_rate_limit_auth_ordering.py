#!/usr/bin/env python3
"""Synthetic per-subaccount rate-limit versus authorization ordering probe.

Safety constraints:
- two deterministic EOAs confirmed to own/manage/delegate zero Synthetix accounts;
- two deliberately nonexistent valid-range subaccount IDs;
- signed `getBalanceUpdates` reads only (documented cost: 100 tokens);
- fixed request sequence below the documented 10,000-token per-IP window;
- no real account, credential, position, order, balance or funds are touched;
- only redacted errors, hashes and the documented top-level rateLimit snapshot retained.

Purpose: determine whether an unauthorised signer can debit a target subaccount's token
bucket before ownership/permission verification, including across different signers.
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

OUT = pathlib.Path("rate_limit_auth_ordering")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
SIGNER_A = Account.from_key("0x" + "93" * 32)
SIGNER_B = Account.from_key("0x" + "94" * 32)
ACCOUNT_X = 8_200_000_000_000_001
ACCOUNT_Y = 8_200_000_000_000_003
ACTION = "getBalanceUpdates"
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
    "SubAccountAction": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "action", "type": "string"},
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


def envelope(account: Any, subaccount_id: int, nonce: int) -> dict[str, Any]:
    expires_after = nonce + 300_000
    encoded = encode_typed_data(
        full_message={
            "types": TYPES,
            "primaryType": "SubAccountAction",
            "domain": DOMAIN,
            "message": {
                "subAccountId": subaccount_id,
                "action": ACTION,
                "nonce": nonce,
                "expiresAfter": expires_after,
            },
        }
    )
    signature = format_signature(account.sign_message(encoded))
    return {
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": ACTION,
            "subaccountId": str(subaccount_id),
            "walletAddress": account.address,
        },
    }


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    rate_limit = parsed.get("rateLimit") if isinstance(parsed, dict) else None
    raw = str(error_message) if error_message is not None else ""
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorCategory": error.get("category") if isinstance(error, dict) else None,
        "errorRetryable": error.get("retryable") if isinstance(error, dict) else None,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(raw) if raw else None,
        "responseSchema": schema(response),
        "rateLimit": rate_limit if isinstance(rate_limit, dict) else None,
        "bodySha256": digest(body),
        "bodyBytes": len(body),
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
            "Two deterministic zero-account EOAs, two nonexistent valid-range subaccount IDs, and signed read-only getBalanceUpdates requests. "
            "No real subaccount bucket or account state is touched."
        ),
        "documentedActionCost": 100,
        "documentedPerIpCap": 10_000,
        "signerA": SIGNER_A.address,
        "signerB": SIGNER_B.address,
        "accountXSha256": digest(str(ACCOUNT_X)),
        "accountYSha256": digest(str(ACCOUNT_Y)),
        "tests": [],
    }
    pre_a = preflight(SIGNER_A, "preflight_signer_a")
    time.sleep(0.35)
    pre_b = preflight(SIGNER_B, "preflight_signer_b")
    evidence["tests"].extend([pre_a, pre_b])
    if pre_a.get("accountCount") != 0 or pre_b.get("accountCount") != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic signers were not both confirmed to have zero accounts."
    else:
        base_nonce = int(time.time() * 1000) + 10_000
        sequence: list[tuple[str, Any, int]] = [
            ("control_y_before_burn_signer_a", SIGNER_A, ACCOUNT_Y),
        ]
        for index in range(1, 13):
            signer = SIGNER_A if index % 2 else SIGNER_B
            sequence.append((f"burn_x_{index:02d}_{'a' if signer is SIGNER_A else 'b'}", signer, ACCOUNT_X))
        sequence.extend(
            [
                ("control_y_after_burn_signer_b", SIGNER_B, ACCOUNT_Y),
                ("post_burn_x_signer_a", SIGNER_A, ACCOUNT_X),
            ]
        )
        for index, (name, signer, target) in enumerate(sequence):
            nonce = base_nonce + index
            status, body, headers, elapsed = post_json(PAPI_TRADE, envelope(signer, target, nonce))
            item = summarize(name, status, body, headers, elapsed)
            item["target"] = "X" if target == ACCOUNT_X else "Y"
            item["signer"] = "A" if signer is SIGNER_A else "B"
            evidence["tests"].append(item)
            if index + 1 < len(sequence):
                time.sleep(0.12)

    x_items = [item for item in evidence["tests"] if item.get("target") == "X"]
    y_items = [item for item in evidence["tests"] if item.get("target") == "Y"]
    snapshots_x = [item.get("rateLimit") for item in x_items if item.get("rateLimit")]
    snapshots_y = [item.get("rateLimit") for item in y_items if item.get("rateLimit")]
    remaining_x = [snapshot.get("remainingTokens") for snapshot in snapshots_x if isinstance(snapshot.get("remainingTokens"), int)]
    remaining_y = [snapshot.get("remainingTokens") for snapshot in snapshots_y if isinstance(snapshot.get("remainingTokens"), int)]
    evidence["summary"] = {
        "testCount": len(evidence["tests"]),
        "probeAborted": bool(evidence.get("probeAborted")),
        "xRateLimitSnapshots": snapshots_x,
        "yRateLimitSnapshots": snapshots_y,
        "xRemainingTokens": remaining_x,
        "yRemainingTokens": remaining_y,
        "xRateLimitedCases": [item["name"] for item in x_items if item.get("httpStatus") == 429 or item.get("errorCode") == "RATE_LIMIT_EXCEEDED"],
        "yRateLimitedCases": [item["name"] for item in y_items if item.get("httpStatus") == 429 or item.get("errorCode") == "RATE_LIMIT_EXCEEDED"],
        "crossSignerSharedXSequence": [
            {
                "name": item.get("name"),
                "signer": item.get("signer"),
                "httpStatus": item.get("httpStatus"),
                "errorCode": item.get("errorCode"),
                "rateLimit": item.get("rateLimit"),
            }
            for item in x_items
        ],
        "caseMatrix": [
            {
                key: item.get(key)
                for key in (
                    "name", "target", "signer", "httpStatus", "apiStatus", "errorCode",
                    "errorMessageSha256", "rateLimit", "bodySha256"
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
