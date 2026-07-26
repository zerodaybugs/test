#!/usr/bin/env python3
"""Read-only discovery of one public referral code plus non-mutating signature controls.

The script reads the public referral-team endpoint, extracts up to 20 public Ethereum
addresses, and queries the public referrer-code endpoint until one existing code is found.
It then sends only invalid or expired ApplyReferral requests for that valid code: missing
signature, malformed signature, and an expired correctly signed message. These controls
cannot apply the code. ClaimReferralPayout controls use a zero-account synthetic EOA and
cover missing/malformed/other-signer signatures; the signer has no payout balance.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("referral_valid_code_controls")
OUT.mkdir(parents=True, exist_ok=True)
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 3 * 1024 * 1024
TEAMS_URL = "https://exchange.synthetix.io/api/referral-teams"
PAPI_BASE = "https://papi.synthetix.io/v1/"
PAPI_TRADE = PAPI_BASE + "trade"
SIGNER = Account.from_key("0x" + "c3" * 32)
OTHER = Account.from_key("0x" + "c4" * 32)
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": "0x0000000000000000000000000000000000000000"}
APPLY_TYPES = {"EIP712Domain": DOMAIN_FIELDS, "ApplyReferral": [{"name": "referralCode", "type": "string"}, {"name": "expiresAfter", "type": "uint256"}]}
CLAIM_TYPES = {"EIP712Domain": DOMAIN_FIELDS, "ClaimReferralPayout": [{"name": "expiresAfter", "type": "uint256"}]}


def digest(value: bytes | str) -> str:
    if isinstance(value, str): value = value.encode()
    return hashlib.sha256(value).hexdigest()


def request(url: str, payload: dict[str, Any] | None = None, timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    raw = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=raw, headers={"User-Agent": UA, "Accept": "application/json", "Content-Type": "application/json"}, method="GET" if raw is None else "POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            return response.status, body, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1), dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


def parse(body: bytes) -> Any:
    try: return json.loads(body)
    except Exception: return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4: return type(value).__name__
    if isinstance(value, dict): return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list): return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def collect_addresses(value: Any, output: list[str]) -> None:
    if len(output) >= 20: return
    if isinstance(value, dict):
        for item in value.values(): collect_addresses(item, output)
    elif isinstance(value, list):
        for item in value: collect_addresses(item, output)
    elif isinstance(value, str):
        for address in ADDRESS_RE.findall(value):
            address = address.lower()
            if address not in output: output.append(address)
            if len(output) >= 20: return


def format_signature(signed: Any) -> str:
    return "0x" + format(signed.r, "064x") + format(signed.s, "064x") + format(signed.v, "02x")


def sign_apply(account: Any, code: str, expiry: int) -> str:
    encoded = encode_typed_data(full_message={"types": APPLY_TYPES, "primaryType": "ApplyReferral", "domain": DOMAIN, "message": {"referralCode": code, "expiresAfter": expiry}})
    return format_signature(account.sign_message(encoded))


def sign_claim(account: Any, expiry: int) -> str:
    encoded = encode_typed_data(full_message={"types": CLAIM_TYPES, "primaryType": "ClaimReferralPayout", "domain": DOMAIN, "message": {"expiresAfter": expiry}})
    return format_signature(account.sign_message(encoded))


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    return {
        "name": name,
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error.get("code") if isinstance(error, dict) else None,
        "errorCategory": error.get("category") if isinstance(error, dict) else None,
        "errorMessage": ADDRESS_RE.sub("<address>", str(message))[:1000] if message is not None else None,
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "elapsedMs": round(elapsed * 1000, 2),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def main() -> None:
    evidence: dict[str, Any] = {"safety": "Public reads plus invalid/expired synthetic referral controls only; no referral can be applied and no payout balance exists.", "tests": []}
    status, body, headers, elapsed = request(TEAMS_URL)
    teams = parse(body)
    evidence["tests"].append({"name": "public_referral_teams", "httpStatus": status, "bodySha256": digest(body), "bodyBytes": len(body), "responseSchema": schema(teams), "elapsedMs": round(elapsed*1000,2)})
    addresses: list[str] = []
    collect_addresses(teams, addresses)
    selected_code = None
    selected_address = None
    code_queries = []
    for address in addresses:
        url = PAPI_BASE + "referral/referrals/referrer/" + urllib.parse.quote(address) + "/codes"
        s, b, h, e = request(url)
        parsed = parse(b)
        codes: list[str] = []
        if isinstance(parsed, dict):
            for key in ("codes", "referral_codes"):
                value = parsed.get(key)
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str): codes.append(item)
                        elif isinstance(item, dict):
                            for ck in ("code", "referral_code"):
                                if isinstance(item.get(ck), str): codes.append(item[ck])
        code_queries.append({"addressSha256": digest(address), "httpStatus": s, "bodySha256": digest(b), "bodyBytes": len(b), "responseSchema": schema(parsed), "codeCount": len(codes)})
        if codes:
            selected_code = codes[0]
            selected_address = address
            break
        time.sleep(0.2)
    evidence["publicCodeDiscovery"] = {"addressCount": len(addresses), "queries": code_queries, "found": selected_code is not None, "selectedAddressSha256": digest(selected_address) if selected_address else None, "selectedCodeSha256": digest(selected_code) if selected_code else None}

    now = int(time.time())
    if selected_code:
        expired = now - 60
        apply_controls = [
            ("apply_valid_code_missing_signature", {"action": "applyReferral", "referralCode": selected_code, "expiresAfter": now + 240}),
            ("apply_valid_code_malformed_signature", {"action": "applyReferral", "referralCode": selected_code, "expiresAfter": now + 240, "signature": "0x00"}),
            ("apply_valid_code_expired_correct_signature", {"action": "applyReferral", "referralCode": selected_code, "expiresAfter": expired, "signature": sign_apply(SIGNER, selected_code, expired)}),
        ]
        for name, params in apply_controls:
            s,b,h,e=request(PAPI_TRADE,{"params":params}); evidence["tests"].append(summarize(name,s,b,h,e)); time.sleep(0.25)

    claim_expiry = now + 240
    claim_controls = [
        ("claim_missing_signature", {"action":"claimReferral","expiresAfter":claim_expiry}),
        ("claim_malformed_signature", {"action":"claimReferral","expiresAfter":claim_expiry,"signature":"0x00"}),
        ("claim_other_signer_signature", {"action":"claimReferral","expiresAfter":claim_expiry,"signature":sign_claim(OTHER,claim_expiry)}),
        ("claim_correct_zero_balance_signature", {"action":"claimReferral","expiresAfter":claim_expiry,"signature":sign_claim(SIGNER,claim_expiry)}),
    ]
    for name, params in claim_controls:
        s,b,h,e=request(PAPI_TRADE,{"params":params}); evidence["tests"].append(summarize(name,s,b,h,e)); time.sleep(0.25)

    evidence["analysis"] = {
        "publicValidCodeFound": selected_code is not None,
        "validationControlCount": sum(item.get("name","").startswith(("apply_","claim_")) for item in evidence["tests"]),
        "unexpectedSuccesses": [item for item in evidence["tests"] if item.get("apiStatus") == "ok" and item.get("name","").startswith(("apply_","claim_"))],
    }
    (OUT / "summary.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(json.dumps(evidence["analysis"], indent=2))


if __name__ == "__main__": main()
