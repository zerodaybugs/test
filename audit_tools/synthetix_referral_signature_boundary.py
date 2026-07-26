#!/usr/bin/env python3
"""Controlled Synthetix referral signature/replay boundary matrix.

Safety constraints:
- deterministic synthetic EOA only;
- unsigned account discovery confirms it owns/manages/delegates zero Synthetix accounts;
- a randomized, almost certainly nonexistent referral code is used;
- the signer has no referral reward or production account;
- fixed low-noise request matrix, no real identity/funds/account;
- results retain only status/error metadata, hashes, schemas and recovered addresses.

The matrix tests ApplyReferral/ClaimReferralPayout cross-primary-type reuse, signed/wire
referral-code substitution, expiry substitution, exact replay, and a two-request concurrent
claim. It cannot transfer funds because the synthetic signer has no referral balance.
"""
from __future__ import annotations

import concurrent.futures
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

OUT = pathlib.Path("referral_signature_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 3 * 1024 * 1024
SIGNER = Account.from_key("0x" + "c1" * 32)
CODE_A = "AUDIT" + hashlib.sha256(b"synthetix-referral-a").hexdigest()[:12].upper()
CODE_B = "AUDIT" + hashlib.sha256(b"synthetix-referral-b").hexdigest()[:12].upper()
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
TRUNCATED_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{3,8}\.\.\.[a-fA-F0-9]{3,8}")

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
APPLY_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "ApplyReferral": [
        {"name": "referralCode", "type": "string"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}
CLAIM_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "ClaimReferralPayout": [
        {"name": "expiresAfter", "type": "uint256"},
    ],
}


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=raw,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, body, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1), dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
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
        found = False
        total = 0
        for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
            values = response.get(key)
            if isinstance(values, list):
                found = True
                total += len(values)
        return total if found else None
    return None


def format_signature(signed: Any) -> str:
    return "0x" + format(signed.r, "064x") + format(signed.s, "064x") + format(signed.v, "02x")


def sign_apply(code: str, expiry: int) -> str:
    encoded = encode_typed_data(full_message={
        "types": APPLY_TYPES,
        "primaryType": "ApplyReferral",
        "domain": DOMAIN,
        "message": {"referralCode": code, "expiresAfter": expiry},
    })
    return format_signature(SIGNER.sign_message(encoded))


def sign_claim(expiry: int) -> str:
    encoded = encode_typed_data(full_message={
        "types": CLAIM_TYPES,
        "primaryType": "ClaimReferralPayout",
        "domain": DOMAIN,
        "message": {"expiresAfter": expiry},
    })
    return format_signature(SIGNER.sign_message(encoded))


def recover_apply(signature: str, code: str, expiry: int) -> str:
    encoded = encode_typed_data(full_message={
        "types": APPLY_TYPES,
        "primaryType": "ApplyReferral",
        "domain": DOMAIN,
        "message": {"referralCode": code, "expiresAfter": expiry},
    })
    return Account.recover_message(encoded, signature=signature)


def recover_claim(signature: str, expiry: int) -> str:
    encoded = encode_typed_data(full_message={
        "types": CLAIM_TYPES,
        "primaryType": "ClaimReferralPayout",
        "domain": DOMAIN,
        "message": {"expiresAfter": expiry},
    })
    return Account.recover_message(encoded, signature=signature)


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float, expected: str | None) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    raw = str(error_message) if error_message is not None else ""
    addresses = ADDRESS_RE.findall(raw)
    truncated = TRUNCATED_ADDRESS_RE.findall(raw)
    expected_lower = expected.lower() if expected else None
    truncated_expected = f"0x{expected_lower[2:5]}...{expected_lower[-3:]}" if expected_lower else None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorCategory": error.get("category") if isinstance(error, dict) else None,
        "errorMessageRedacted": ADDRESS_RE.sub("<address>", raw)[:1000] if raw else None,
        "errorMessageSha256": digest(raw) if raw else None,
        "recoveredAddresses": addresses,
        "truncatedRecoveredAddresses": truncated,
        "expectedRecovery": expected,
        "mentionsExpectedRecovery": bool(expected_lower and (expected_lower in raw.lower() or truncated_expected in raw.lower())),
        "mentionsSyntheticSigner": SIGNER.address.lower() in raw.lower() or f"0x{SIGNER.address.lower()[2:5]}...{SIGNER.address.lower()[-3:]}" in raw.lower(),
        "responseSchema": schema(response),
        "responseCount": len(response) if isinstance(response, (list, dict)) else None,
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def send(name: str, params: dict[str, Any], expected: str | None) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(PAPI_TRADE, {"params": params})
    return summarize(name, status, body, headers, elapsed, expected)


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": "Synthetic zero-account EOA and randomized nonexistent referral codes only; no real account, reward or funds.",
        "syntheticSigner": SIGNER.address,
        "codeASha256": digest(CODE_A),
        "codeBSha256": digest(CODE_B),
        "tests": [],
    }

    status, body, headers, elapsed = post_json(PAPI_INFO, {
        "params": {"action": "getSubAccountIds", "walletAddress": SIGNER.address, "includeDelegations": True}
    })
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    preflight = {
        "name": "synthetic_account_preflight",
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "accountCount": account_count(response),
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "elapsedMs": round(elapsed * 1000, 2),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }
    evidence["tests"].append(preflight)
    if preflight["accountCount"] != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic signer was not confirmed to own/manage/delegate zero accounts."
        (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        raise RuntimeError(evidence["abortReason"])

    now = int(time.time())
    expiry_a = now + 240
    expiry_b = now + 480
    apply_sig = sign_apply(CODE_A, expiry_a)
    claim_sig = sign_claim(expiry_a)

    cases: list[tuple[str, dict[str, Any], str | None]] = [
        ("apply_correct", {"action": "applyReferral", "referralCode": CODE_A, "expiresAfter": expiry_a, "signature": apply_sig}, SIGNER.address),
        ("apply_code_substitution", {"action": "applyReferral", "referralCode": CODE_B, "expiresAfter": expiry_a, "signature": apply_sig}, recover_apply(apply_sig, CODE_B, expiry_a)),
        ("apply_expiry_substitution", {"action": "applyReferral", "referralCode": CODE_A, "expiresAfter": expiry_b, "signature": apply_sig}, recover_apply(apply_sig, CODE_A, expiry_b)),
        ("apply_with_claim_signature", {"action": "applyReferral", "referralCode": CODE_A, "expiresAfter": expiry_a, "signature": claim_sig}, recover_apply(claim_sig, CODE_A, expiry_a)),
        ("claim_correct_first", {"action": "claimReferral", "expiresAfter": expiry_a, "signature": claim_sig}, SIGNER.address),
        ("claim_exact_replay", {"action": "claimReferral", "expiresAfter": expiry_a, "signature": claim_sig}, SIGNER.address),
        ("claim_expiry_substitution", {"action": "claimReferral", "expiresAfter": expiry_b, "signature": claim_sig}, recover_claim(claim_sig, expiry_b)),
        ("claim_with_apply_signature", {"action": "claimReferral", "expiresAfter": expiry_a, "signature": apply_sig}, recover_claim(apply_sig, expiry_a)),
        ("claim_expired", {"action": "claimReferral", "expiresAfter": now - 60, "signature": sign_claim(now - 60)}, SIGNER.address),
        ("claim_far_future", {"action": "claimReferral", "expiresAfter": now + 86400, "signature": sign_claim(now + 86400)}, SIGNER.address),
    ]

    for name, params, expected in cases:
        evidence["tests"].append(send(name, params, expected))
        time.sleep(0.25)

    concurrent_expiry = int(time.time()) + 240
    concurrent_signature = sign_claim(concurrent_expiry)
    concurrent_params = {"action": "claimReferral", "expiresAfter": concurrent_expiry, "signature": concurrent_signature}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(send, f"claim_concurrent_{index+1}", concurrent_params, SIGNER.address) for index in range(2)]
        concurrent_results = [future.result() for future in futures]
    evidence["tests"].extend(concurrent_results)

    result_tests = [item for item in evidence["tests"] if item.get("name") != "synthetic_account_preflight"]
    evidence["analysis"] = {
        "requestCountExcludingPreflight": len(result_tests),
        "unexpectedSuccessCount": sum(item.get("httpStatus") == 200 and item.get("apiStatus") == "ok" for item in result_tests),
        "unexpectedSuccesses": [item for item in result_tests if item.get("httpStatus") == 200 and item.get("apiStatus") == "ok"],
        "crossTypeOrSubstitutionAcceptedCount": sum(
            item.get("name") in {"apply_code_substitution", "apply_expiry_substitution", "apply_with_claim_signature", "claim_expiry_substitution", "claim_with_apply_signature"}
            and item.get("mentionsSyntheticSigner")
            for item in result_tests
        ),
        "correctSignatureRecoveryCount": sum(
            item.get("name") in {"apply_correct", "claim_correct_first", "claim_exact_replay", "claim_expired", "claim_far_future", "claim_concurrent_1", "claim_concurrent_2"}
            and item.get("mentionsSyntheticSigner")
            for item in result_tests
        ),
        "concurrentResults": concurrent_results,
    }

    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence["analysis"], indent=2))


if __name__ == "__main__":
    main()
