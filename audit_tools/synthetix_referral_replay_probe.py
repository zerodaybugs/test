#!/usr/bin/env python3
"""Controlled referral-claim replay boundary probe for Synthetix PAPI.

The probe uses a deterministic synthetic EOA that has no exchange subaccount,
referral codes, balances, or rewards. It first verifies that empty state through
public read endpoints, then submits only two identical signed claim requests.
No real user identity, credential, balance, or reward is touched.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("referral_replay_probe")
OUT.mkdir(parents=True, exist_ok=True)

PAPI = "https://papi.synthetix.io/v1/"
PRIVATE_KEY = "0x" + "44" * 32
ACCOUNT = Account.from_key(PRIVATE_KEY)
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024

DOMAIN = {
    "name": "Synthetix",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
}
TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "ClaimReferralPayout": [
        {"name": "expiresAfter", "type": "uint256"},
    ],
}


def request(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: int = 45,
) -> tuple[int, bytes, dict[str, str], float]:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, body, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        return exc.code, body, dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(val, depth + 1) for key, val in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorMessage": str(error_message)[:500] if error_message is not None else None,
        "responseSchema": schema(response),
        "response": response,
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "bodyBytes": len(body),
        "retryAfter": headers.get("Retry-After"),
        "requestId": headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def info_request(params: dict[str, Any]) -> tuple[int, bytes, dict[str, str], float]:
    return request(PAPI + "info", method="POST", payload={"params": params})


def sign_claim(expires_after: int) -> str:
    message = encode_typed_data(
        full_message={
            "types": TYPES,
            "primaryType": "ClaimReferralPayout",
            "domain": DOMAIN,
            "message": {"expiresAfter": expires_after},
        }
    )
    signed = ACCOUNT.sign_message(message)
    return "0x" + format(signed.r, "064x") + format(signed.s, "064x") + format(signed.v, "02x")


def claim_payload(expires_after: int, signature: str) -> dict[str, Any]:
    # Matches the production frontend envelope exactly: signature is inside params,
    # and the signed message contains only expiresAfter.
    return {
        "params": {
            "action": "claimReferral",
            "expiresAfter": expires_after,
            "signature": signature,
        }
    }


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": (
            "Synthetic deterministic EOA only. The probe verifies the address has no "
            "subaccounts or referral codes before sending two identical claim requests."
        ),
        "syntheticAddress": ACCOUNT.address,
        "frontendType": TYPES["ClaimReferralPayout"],
        "domain": DOMAIN,
        "checks": [],
    }

    status, body, headers, elapsed = info_request(
        {
            "action": "getSubAccountIds",
            "walletAddress": ACCOUNT.address,
            "includeDelegations": True,
        }
    )
    account_check = summarize("synthetic_account_ids", status, body, headers, elapsed)
    evidence["checks"].append(account_check)

    referee_url = PAPI + "referral/referrals/referee/" + ACCOUNT.address.lower()
    status, body, headers, elapsed = request(referee_url)
    referee_check = summarize("synthetic_referee_record", status, body, headers, elapsed)
    evidence["checks"].append(referee_check)

    codes_url = PAPI + "referral/referrals/referrer/" + ACCOUNT.address.lower() + "/codes"
    status, body, headers, elapsed = request(codes_url)
    codes_check = summarize("synthetic_referrer_codes", status, body, headers, elapsed)
    evidence["checks"].append(codes_check)

    account_response = account_check.get("response")
    if isinstance(account_response, list):
        account_count = len(account_response)
    elif isinstance(account_response, dict):
        account_count = sum(
            len(account_response.get(key) or [])
            for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds")
            if isinstance(account_response.get(key) or [], list)
        )
    else:
        account_count = -1

    codes_response = codes_check.get("response")
    # The public referral endpoint may return its payload at the top level rather than
    # under PAPI's response wrapper. Use the parsed body for the safety gate as well.
    _, codes_raw, _, _ = request(codes_url)
    codes_parsed = parse_json(codes_raw)
    code_count = None
    if isinstance(codes_parsed, dict):
        value = codes_parsed.get("count")
        if isinstance(value, int):
            code_count = value
        elif isinstance(codes_parsed.get("codes"), list):
            code_count = len(codes_parsed["codes"])

    safety_gate = account_count == 0 and code_count == 0
    evidence["precondition"] = {
        "accountCount": account_count,
        "referrerCodeCount": code_count,
        "emptySyntheticIdentityConfirmed": safety_gate,
    }

    if not safety_gate:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic address was not confirmed empty; no claim request sent."
    else:
        expires_after = int(time.time()) + 240
        signature = sign_claim(expires_after)
        payload = claim_payload(expires_after, signature)
        evidence["signedClaim"] = {
            "expiresAfter": expires_after,
            "signatureSha256": hashlib.sha256(signature.encode()).hexdigest(),
            "payloadSha256": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
        }

        for name in ("first_identical_claim", "second_identical_claim"):
            status, body, headers, elapsed = request(PAPI + "trade", method="POST", payload=payload)
            evidence["checks"].append(summarize(name, status, body, headers, elapsed))
            time.sleep(0.75)

        first = next(item for item in evidence["checks"] if item["name"] == "first_identical_claim")
        second = next(item for item in evidence["checks"] if item["name"] == "second_identical_claim")
        evidence["replayComparison"] = {
            "sameHttpStatus": first["httpStatus"] == second["httpStatus"],
            "sameApiStatus": first["apiStatus"] == second["apiStatus"],
            "sameErrorCode": first["errorCode"] == second["errorCode"],
            "sameErrorMessage": first["errorMessage"] == second["errorMessage"],
            "sameResponse": first["response"] == second["response"],
            "sameBodyHash": first["bodySha256"] == second["bodySha256"],
        }

    (OUT / "result.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
