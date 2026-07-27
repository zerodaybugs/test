#!/usr/bin/env python3
"""Check whether rejected Synthetix write requests leave observable authorization side effects.

Authorized bug-bounty safety constraints:
- two deterministic synthetic EOAs confirmed to own/manage/delegate zero accounts;
- one deliberately nonexistent valid-range subaccount/master-account ID;
- the only write requests are expected to fail account authorization;
- no public or private victim account ID, balance, order, or position is used;
- postconditions are checked through unsigned discovery and an authenticated read signed by the
  synthetic delegate itself;
- no blockchain transaction is signed or broadcast.

The probe targets failure atomicity because prior synthetic tests showed nonce state may be consumed
before ownership authorization. It asks whether an unauthorized `addDelegatedSigner` or
`createSubaccount` request can similarly commit a delegation/account record despite returning an
error. Any created record would refer only to the deliberately nonexistent source ID or the
synthetic wallet.
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

OUT = pathlib.Path("synthetix_failed_write_atomicity")
OUT.mkdir(parents=True, exist_ok=True)

INFO = "https://papi.synthetix.io/v1/info"
TRADE = "https://papi.synthetix.io/v1/trade"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
ZERO = "0x0000000000000000000000000000000000000000"
DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
ATTACKER = Account.from_key("0x" + "91" * 32)
DELEGATE = Account.from_key("0x" + "92" * 32)
NONEXISTENT_ID = 8_300_000_000_091_337
UNIQUE_NAME = "zdb-atomicity-" + hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:12]
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HEX_RE = re.compile(r"0x[a-fA-F0-9]{64,}")


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> Any:
    if value is None:
        return None
    text = str(value)
    text = ADDRESS_RE.sub("<address>", text)
    text = HEX_RE.sub("<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:1500]


def post(url: str, payload: dict[str, Any]) -> tuple[int, bytes, float]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            raw = response.read(MAX_BODY + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_BODY + 1)
        status = exc.code
    elapsed = time.monotonic() - started
    if len(raw) > MAX_BODY:
        raise RuntimeError("response exceeds safety cap")
    return status, raw, elapsed


def parse(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return None


def response_summary(status: int, raw: bytes, elapsed: float) -> dict[str, Any]:
    parsed = parse(raw)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    return {
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error.get("code") if isinstance(error, dict) else None,
        "messageRedacted": redact(message),
        "responseSchema": schema(response),
        "bodySha256": sha(raw),
        "bodyBytes": len(raw),
    }


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def sign(account: Any, primary: str, types: dict[str, Any], message: dict[str, Any]) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": {k: v for k, v in types.items() if k != "EIP712Domain"},
            "primaryType": primary,
            "domain": DOMAIN,
            "message": message,
        }
    )
    signed = account.sign_message(encoded)
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def discover(wallet: str) -> tuple[dict[str, list[str]], dict[str, Any]]:
    status, raw, elapsed = post(
        INFO,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": wallet,
                "includeDelegations": True,
            }
        },
    )
    parsed = parse(raw)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    roles = {"owned": [], "managed": [], "delegated": []}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            roles["owned"] = [str(x) for x in response]
        elif isinstance(response, dict):
            roles["owned"] = [str(x) for x in (response.get("subAccountIds") or [])]
            roles["managed"] = [str(x) for x in (response.get("managedSubAccountIds") or [])]
            roles["delegated"] = [str(x) for x in (response.get("delegatedSubAccountIds") or [])]
    summary = response_summary(status, raw, elapsed)
    summary["counts"] = {role: len(values) for role, values in roles.items()}
    summary["idSha256"] = {role: sorted(sha(value) for value in values) for role, values in roles.items()}
    return roles, summary


def add_delegated_signer() -> tuple[dict[str, Any], dict[str, Any]]:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 60_000
    expires_at = nonce + 7 * 24 * 60 * 60 * 1000
    message = {
        "delegateAddress": DELEGATE.address,
        "subAccountId": NONEXISTENT_ID,
        "nonce": nonce,
        "expiresAfter": expires_after,
        "expiresAt": expires_at,
        "permissions": ["session"],
    }
    types = {
        "EIP712Domain": DOMAIN_FIELDS,
        "AddDelegatedSigner": [
            {"name": "delegateAddress", "type": "address"},
            {"name": "subAccountId", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
            {"name": "expiresAfter", "type": "uint256"},
            {"name": "expiresAt", "type": "uint256"},
            {"name": "permissions", "type": "string[]"},
        ],
    }
    payload = {
        "signature": sign(ATTACKER, "AddDelegatedSigner", types, message),
        "nonce": nonce,
        "expiresAfter": expires_after,
        "subaccountId": str(NONEXISTENT_ID),
        "walletAddress": ATTACKER.address,
        "params": {
            "action": "addDelegatedSigner",
            "walletAddress": DELEGATE.address,
            "expiresAt": expires_at,
            "permissions": ["session"],
        },
    }
    status, raw, elapsed = post(TRADE, payload)
    return payload, response_summary(status, raw, elapsed)


def create_subaccount() -> tuple[dict[str, Any], dict[str, Any]]:
    nonce = int(time.time() * 1000) + 11
    expires_after = nonce + 60_000
    message = {
        "masterSubAccountId": NONEXISTENT_ID,
        "name": UNIQUE_NAME,
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    types = {
        "EIP712Domain": DOMAIN_FIELDS,
        "CreateSubaccount": [
            {"name": "masterSubAccountId", "type": "uint256"},
            {"name": "name", "type": "string"},
            {"name": "nonce", "type": "uint256"},
            {"name": "expiresAfter", "type": "uint256"},
        ],
    }
    payload = {
        "signature": sign(ATTACKER, "CreateSubaccount", types, message),
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": "createSubaccount",
            "subaccountId": str(NONEXISTENT_ID),
            "walletAddress": ATTACKER.address,
            "name": UNIQUE_NAME,
        },
    }
    status, raw, elapsed = post(TRADE, payload)
    return payload, response_summary(status, raw, elapsed)


def delegate_centric_query() -> dict[str, Any]:
    expires_after = 0
    message = {
        "subAccountId": NONEXISTENT_ID,
        "action": "getDelegationsForDelegate",
        "expiresAfter": expires_after,
    }
    types = {
        "EIP712Domain": DOMAIN_FIELDS,
        "SubAccountAction": [
            {"name": "subAccountId", "type": "uint256"},
            {"name": "action", "type": "string"},
            {"name": "expiresAfter", "type": "uint256"},
        ],
    }
    payload = {
        "signature": sign(DELEGATE, "SubAccountAction", types, message),
        "expiresAfter": expires_after,
        "params": {
            "action": "getDelegationsForDelegate",
            "subAccountId": str(NONEXISTENT_ID),
        },
    }
    status, raw, elapsed = post(TRADE, payload)
    parsed = parse(raw)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    accounts = response.get("delegatedAccounts") if isinstance(response, dict) else None
    result = response_summary(status, raw, elapsed)
    result["delegatedAccountCount"] = len(accounts) if isinstance(accounts, list) else None
    result["containsTargetId"] = any(
        str(item.get("subAccountId")) == str(NONEXISTENT_ID)
        for item in accounts
        if isinstance(item, dict)
    ) if isinstance(accounts, list) else False
    return result


def main() -> None:
    attacker_before_roles, attacker_before = discover(ATTACKER.address)
    delegate_before_roles, delegate_before = discover(DELEGATE.address)
    if any(attacker_before_roles.values()) or any(delegate_before_roles.values()):
        raise RuntimeError("Synthetic identity preflight is not empty")

    delegate_read_before = delegate_centric_query()

    _, add_result = add_delegated_signer()
    time.sleep(0.8)
    _, create_result = create_subaccount()
    time.sleep(1.5)

    attacker_after_roles, attacker_after = discover(ATTACKER.address)
    delegate_after_roles, delegate_after = discover(DELEGATE.address)
    delegate_read_after = delegate_centric_query()

    target_hash = sha(str(NONEXISTENT_ID))
    unauthorized_delegation_observed = (
        str(NONEXISTENT_ID) in delegate_after_roles["delegated"]
        or delegate_read_after.get("containsTargetId") is True
    )
    unauthorized_account_observed = any(
        value not in set(attacker_before_roles[role])
        for role in attacker_after_roles
        for value in attacker_after_roles[role]
    )

    summary = {
        "safety": "Synthetic zero-account identities and a nonexistent source ID only; no victim or chain state touched.",
        "syntheticAttackerAddressSha256": sha(ATTACKER.address.lower()),
        "syntheticDelegateAddressSha256": sha(DELEGATE.address.lower()),
        "nonexistentTargetIdSha256": target_hash,
        "uniqueNameSha256": sha(UNIQUE_NAME),
        "preflight": {
            "attacker": attacker_before,
            "delegate": delegate_before,
            "delegateCentricRead": delegate_read_before,
        },
        "rejectedWrites": {
            "addDelegatedSigner": add_result,
            "createSubaccount": create_result,
        },
        "postflight": {
            "attacker": attacker_after,
            "delegate": delegate_after,
            "delegateCentricRead": delegate_read_after,
        },
        "unauthorizedDelegationObserved": unauthorized_delegation_observed,
        "unauthorizedAccountObserved": unauthorized_account_observed,
        "verdict": (
            "FAILED_WRITE_LEFT_AUTHORIZATION_SIDE_EFFECT"
            if unauthorized_delegation_observed or unauthorized_account_observed
            else "REJECTED_WRITES_ATOMIC_FOR_OBSERVABLE_AUTHORIZATION_STATE"
        ),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "addDelegatedSigner": add_result,
        "createSubaccount": create_result,
        "attackerCountsBefore": attacker_before["counts"],
        "attackerCountsAfter": attacker_after["counts"],
        "delegateCountsBefore": delegate_before["counts"],
        "delegateCountsAfter": delegate_after["counts"],
        "delegateReadBefore": delegate_read_before,
        "delegateReadAfter": delegate_read_after,
        "unauthorizedDelegationObserved": unauthorized_delegation_observed,
        "unauthorizedAccountObserved": unauthorized_account_observed,
        "verdict": summary["verdict"],
    }, indent=2))


if __name__ == "__main__":
    main()
