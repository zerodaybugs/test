#!/usr/bin/env python3
"""Controlled Synthetix EIP-712 domain-separation and signature-malleability probe.

Safety constraints:
- deterministic synthetic EOA confirmed to own/manage/delegate zero accounts;
- deliberately nonexistent valid-range subaccount ID;
- only withdrawCollateral requests that cannot pass account authorization;
- no real account, balance, destination, credential, or fund can be touched;
- fixed low-noise matrix; response bodies are reduced to hashes and redacted metadata.
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

OUT = pathlib.Path("eip712_domain_malleability")
OUT.mkdir(parents=True, exist_ok=True)

INFO = "https://papi.synthetix.io/v1/info"
TRADE = "https://papi.synthetix.io/v1/trade"
PRIVATE_KEY = "0x" + "b7" * 32
ACCOUNT = Account.from_key(PRIVATE_KEY)
SUBACCOUNT_ID = 8_734_910_284_155_203
SYMBOL = "USDT"
AMOUNT = "1"
DESTINATION = ACCOUNT.address
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HEX_RE = re.compile(r"0x[a-fA-F0-9]{64,}")
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

CANONICAL_DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
WITHDRAW_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "symbol", "type": "string"},
    {"name": "amount", "type": "string"},
    {"name": "destination", "type": "address"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
CANONICAL_DOMAIN = {
    "name": "Synthetix",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
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
    text = HEX_RE.sub("<hex>", text)
    text = re.sub(r"\b\d{10,}\b", "<number>", text)
    return text[:900]


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
            status = response.status
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        response_body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
    if len(response_body) > MAX_BODY:
        raise RuntimeError("response too large")
    return status, response_body, headers, time.monotonic() - started


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


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


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_category = error.get("category") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    addresses = [address.lower() for address in ADDRESS_RE.findall(str(error_message or ""))]
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorCategory": error_category,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(str(error_message)) if error_message is not None else None,
        "errorAddressHashes": sorted(digest(address) for address in addresses),
        "mentionsSyntheticSigner": ACCOUNT.address.lower() in addresses,
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None)
        or headers.get("X-Request-Id")
        or headers.get("x-request-id"),
    }


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": int(signed.v),
        "r": "0x" + format(int(signed.r), "064x"),
        "s": "0x" + format(int(signed.s), "064x"),
    }


def sign_with_domain(
    nonce: int,
    expires_after: int,
    *,
    domain: dict[str, Any],
    domain_fields: list[dict[str, str]],
) -> dict[str, Any]:
    message = {
        "subAccountId": SUBACCOUNT_ID,
        "symbol": SYMBOL,
        "amount": AMOUNT,
        "destination": DESTINATION,
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    full_message = {
        "types": {
            "EIP712Domain": domain_fields,
            "WithdrawCollateral": WITHDRAW_FIELDS,
        },
        "primaryType": "WithdrawCollateral",
        "domain": domain,
        "message": message,
    }
    return format_signature(ACCOUNT.sign_message(encode_typed_data(full_message=full_message)))


def envelope(signature: dict[str, Any], nonce: int, expires_after: int) -> dict[str, Any]:
    return {
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": "withdrawCollateral",
            "subaccountId": str(SUBACCOUNT_ID),
            "walletAddress": ACCOUNT.address,
            "symbol": SYMBOL,
            "amount": AMOUNT,
            "destination": DESTINATION,
        },
    }


def high_s_variant(signature: dict[str, Any]) -> dict[str, Any]:
    s = int(str(signature["s"]), 16)
    high_s = SECP256K1_N - s
    v = int(signature["v"])
    if v in (27, 28):
        flipped_v = 55 - v
    elif v in (0, 1):
        flipped_v = 1 - v
    else:
        raise ValueError(f"unsupported recovery id {v}")
    return {
        "v": flipped_v,
        "r": signature["r"],
        "s": "0x" + format(high_s, "064x"),
    }


def v_zero_one_variant(signature: dict[str, Any]) -> dict[str, Any]:
    v = int(signature["v"])
    normalized = v - 27 if v in (27, 28) else v
    return {"v": normalized, "r": signature["r"], "s": signature["s"]}


def run_request(name: str, payload: dict[str, Any]) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(TRADE, payload)
    return summarize(name, status, body, headers, elapsed)


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": (
            "Deterministic zero-account EOA and deliberately nonexistent subaccount only. "
            "All write requests must fail account authorization before any state change."
        ),
        "syntheticAddress": ACCOUNT.address,
        "subaccountIdSha256": digest(str(SUBACCOUNT_ID)),
        "tests": [],
    }

    status, body, headers, elapsed = post_json(
        INFO,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": ACCOUNT.address,
                "includeDelegations": True,
            }
        },
    )
    preflight = summarize("synthetic_account_preflight", status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    preflight["accountCount"] = account_count(response)
    evidence["tests"].append(preflight)
    if preflight["accountCount"] != 0:
        evidence["aborted"] = True
        evidence["abortReason"] = "Synthetic EOA was not confirmed to own/manage/delegate zero accounts."
        (OUT / "summary.json").write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
        raise RuntimeError(evidence["abortReason"])

    domain_cases: list[tuple[str, dict[str, Any], list[dict[str, str]]]] = [
        ("canonical_domain", dict(CANONICAL_DOMAIN), list(CANONICAL_DOMAIN_FIELDS)),
        ("name_lowercase", {**CANONICAL_DOMAIN, "name": "synthetix"}, list(CANONICAL_DOMAIN_FIELDS)),
        ("name_empty", {**CANONICAL_DOMAIN, "name": ""}, list(CANONICAL_DOMAIN_FIELDS)),
        ("version_two", {**CANONICAL_DOMAIN, "version": "2"}, list(CANONICAL_DOMAIN_FIELDS)),
        ("chain_id_ten", {**CANONICAL_DOMAIN, "chainId": 10}, list(CANONICAL_DOMAIN_FIELDS)),
        ("chain_id_base", {**CANONICAL_DOMAIN, "chainId": 8453}, list(CANONICAL_DOMAIN_FIELDS)),
        (
            "verifying_contract_deposit",
            {**CANONICAL_DOMAIN, "verifyingContract": "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"},
            list(CANONICAL_DOMAIN_FIELDS),
        ),
        (
            "verifying_contract_arbitrary",
            {**CANONICAL_DOMAIN, "verifyingContract": "0x1111111111111111111111111111111111111111"},
            list(CANONICAL_DOMAIN_FIELDS),
        ),
        (
            "domain_without_verifying_contract",
            {key: value for key, value in CANONICAL_DOMAIN.items() if key != "verifyingContract"},
            [field for field in CANONICAL_DOMAIN_FIELDS if field["name"] != "verifyingContract"],
        ),
        (
            "domain_field_order_reversed",
            dict(CANONICAL_DOMAIN),
            list(reversed(CANONICAL_DOMAIN_FIELDS)),
        ),
    ]

    domain_results: list[dict[str, Any]] = []
    base_nonce = int(time.time() * 1000)
    for index, (name, domain, fields) in enumerate(domain_cases):
        nonce = base_nonce + index + 1
        expires_after = nonce + 300_000
        signature = sign_with_domain(nonce, expires_after, domain=domain, domain_fields=fields)
        item = run_request(name, envelope(signature, nonce, expires_after))
        item["domainFingerprint"] = digest(json.dumps({"domain": domain, "fields": fields}, sort_keys=True))
        domain_results.append(item)
        time.sleep(0.15)
    evidence["domainSeparation"] = domain_results

    # Exact replay control: unauthorized canonical request consumes signer nonce.
    nonce = base_nonce + 100
    expires_after = nonce + 300_000
    canonical_signature = sign_with_domain(
        nonce, expires_after, domain=dict(CANONICAL_DOMAIN), domain_fields=list(CANONICAL_DOMAIN_FIELDS)
    )
    replay_first = run_request("exact_replay_first", envelope(canonical_signature, nonce, expires_after))
    replay_second = run_request("exact_replay_second", envelope(canonical_signature, nonce, expires_after))
    evidence["exactReplay"] = [replay_first, replay_second]

    # Low-s first, mathematically equivalent high-s second.
    nonce = base_nonce + 200
    expires_after = nonce + 300_000
    low_signature = sign_with_domain(
        nonce, expires_after, domain=dict(CANONICAL_DOMAIN), domain_fields=list(CANONICAL_DOMAIN_FIELDS)
    )
    high_signature = high_s_variant(low_signature)
    evidence["lowThenHighS"] = [
        run_request("low_s_first", envelope(low_signature, nonce, expires_after)),
        run_request("high_s_equivalent_second", envelope(high_signature, nonce, expires_after)),
    ]

    # High-s first, canonical low-s second on a fresh nonce.
    nonce = base_nonce + 300
    expires_after = nonce + 300_000
    low_signature = sign_with_domain(
        nonce, expires_after, domain=dict(CANONICAL_DOMAIN), domain_fields=list(CANONICAL_DOMAIN_FIELDS)
    )
    high_signature = high_s_variant(low_signature)
    evidence["highThenLowS"] = [
        run_request("high_s_equivalent_first", envelope(high_signature, nonce, expires_after)),
        run_request("low_s_second", envelope(low_signature, nonce, expires_after)),
    ]

    # v=0/1 representation control on a fresh nonce.
    nonce = base_nonce + 400
    expires_after = nonce + 300_000
    canonical_signature = sign_with_domain(
        nonce, expires_after, domain=dict(CANONICAL_DOMAIN), domain_fields=list(CANONICAL_DOMAIN_FIELDS)
    )
    normalized_signature = v_zero_one_variant(canonical_signature)
    evidence["vNormalization"] = [
        run_request("v_zero_one_first", envelope(normalized_signature, nonce, expires_after)),
        run_request("v_27_28_second", envelope(canonical_signature, nonce, expires_after)),
    ]

    canonical = next(item for item in domain_results if item["name"] == "canonical_domain")
    wrong_domain_mentions_signer = [
        item["name"]
        for item in domain_results
        if item["name"] != "canonical_domain" and item.get("mentionsSyntheticSigner")
    ]
    evidence["summary"] = {
        "canonicalReachedSyntheticSignerAuthorization": bool(canonical.get("mentionsSyntheticSigner")),
        "wrongDomainCasesMentioningSyntheticSigner": wrong_domain_mentions_signer,
        "exactReplaySecondErrorCode": replay_second.get("errorCode"),
        "lowThenHighSecondErrorCode": evidence["lowThenHighS"][1].get("errorCode"),
        "highThenLowFirstMentionsSyntheticSigner": evidence["highThenLowS"][0].get("mentionsSyntheticSigner"),
        "highThenLowSecondErrorCode": evidence["highThenLowS"][1].get("errorCode"),
        "vZeroOneFirstMentionsSyntheticSigner": evidence["vNormalization"][0].get("mentionsSyntheticSigner"),
        "v2728SecondErrorCode": evidence["vNormalization"][1].get("errorCode"),
    }

    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
