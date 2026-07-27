#!/usr/bin/env python3
"""Infer the production EIP-712 boundary for the documented legacy exchangeCollateral action.

Authorized safety design:
- deterministic synthetic EOA proven to own/manage/delegate zero accounts;
- deliberately nonexistent valid-range account ID;
- fresh nonces; every request must fail account authorization before any state change;
- no victim identifier, balance, order, position, transaction, or blockchain write;
- artifact contains only hashes, status classes, and redacted messages.

The current documentation describes `exchangeCollateral(fromSymbol,toSymbol,fromAmount)` but omits
its EIP-712 type, while the current SDK exposes a separate
`voluntaryCollateralExchange(sourceAsset,targetUSDTAmount)` typed action. This matrix determines
whether the legacy route is live, which signature schema it accepts, and whether wire fields are
cryptographically bound or normalized across the two handlers.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import pathlib
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("synthetix_legacy_exchange_signature")
OUT.mkdir(parents=True, exist_ok=True)
INFO = "https://papi.synthetix.io/v1/info"
TRADE = "https://papi.synthetix.io/v1/trade"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
DELAY = 0.28
ACCOUNT = Account.from_key("0x" + "a4" * 32)
SUBACCOUNT = 8_300_000_000_040_001
OTHER_ACCOUNT = 8_300_000_000_040_002
ZERO = "0x0000000000000000000000000000000000000000"
DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HEX_RE = re.compile(r"0x[a-fA-F0-9]{64,}")
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


def sha(value: str | bytes) -> str:
    if isinstance(value, str): value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None: return None
    text = ADDRESS_RE.sub("<address>", str(value))
    text = HEX_RE.sub("<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:1400]


def post(url: str, payload: dict[str, Any]) -> tuple[int, bytes, float]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(url, data=body, headers={
        "User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"
    }, method="POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw, status = response.read(MAX_BODY + 1), response.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(MAX_BODY + 1), exc.code
    if len(raw) > MAX_BODY: raise RuntimeError("response exceeds cap")
    return status, raw, time.monotonic() - started


def parsed(raw: bytes) -> Any:
    try: return json.loads(raw)
    except Exception: return None


def account_count(response: Any) -> int | None:
    if isinstance(response, list): return len(response)
    if isinstance(response, dict):
        seen, count = False, 0
        for key in ("subAccountIds", "managedSubAccountIds", "delegatedSubAccountIds"):
            value = response.get(key)
            if isinstance(value, list): seen, count = True, count + len(value)
        return count if seen else None
    return None


def sign(primary: str, fields: list[dict[str, str]], message: dict[str, Any]) -> dict[str, Any]:
    encoded = encode_typed_data(full_message={
        "types": {primary: fields}, "primaryType": primary, "domain": DOMAIN, "message": message
    })
    signed = ACCOUNT.sign_message(encoded)
    return {"v": signed.v, "r": "0x" + format(signed.r, "064x"), "s": "0x" + format(signed.s, "064x")}


def legacy_message(nonce: int) -> dict[str, Any]:
    return {
        "subAccountId": SUBACCOUNT,
        "fromSymbol": "WETH",
        "toSymbol": "USDT",
        "fromAmount": "1",
        "nonce": nonce,
        "expiresAfter": nonce + 60_000,
    }


def wire(nonce: int, signature: dict[str, Any], *, action: str = "exchangeCollateral",
         overrides: dict[str, Any] | None = None, top: dict[str, Any] | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {
        "action": action,
        "subAccountId": str(SUBACCOUNT),
        "walletAddress": ACCOUNT.address,
        "fromSymbol": "WETH",
        "toSymbol": "USDT",
        "fromAmount": "1",
    }
    if overrides: params.update(overrides)
    result: dict[str, Any] = {
        "params": params, "nonce": nonce, "expiresAfter": nonce + 60_000, "signature": signature
    }
    if top: result.update(top)
    return result


@dataclass(frozen=True)
class Candidate:
    name: str
    primary: str
    fields: tuple[tuple[str, str], ...]
    message_kind: str = "legacy"
    action: str = "exchangeCollateral"
    overrides: tuple[tuple[str, Any], ...] = ()


def f(*pairs: tuple[str, str]) -> tuple[tuple[str, str], ...]: return tuple(pairs)


SEMANTIC = f(
    ("subAccountId", "uint256"), ("fromSymbol", "string"), ("toSymbol", "string"),
    ("fromAmount", "string"), ("nonce", "uint256"), ("expiresAfter", "uint256")
)
CANDIDATES: list[Candidate] = [
    Candidate("ExchangeCollateral_semantic", "ExchangeCollateral", SEMANTIC),
    Candidate("CollateralExchange_semantic", "CollateralExchange", SEMANTIC),
    Candidate("VoluntaryCollateralExchange_legacy_fields", "VoluntaryCollateralExchange", SEMANTIC),
    Candidate("ExchangeCollateral_no_nonce", "ExchangeCollateral", f(
        ("subAccountId","uint256"),("fromSymbol","string"),("toSymbol","string"),
        ("fromAmount","string"),("expiresAfter","uint256"))),
    Candidate("SubAccountAction_with_nonce", "SubAccountAction", f(
        ("subAccountId","uint256"),("action","string"),("nonce","uint256"),("expiresAfter","uint256")), "generic"),
    Candidate("SubAccountAction_no_nonce", "SubAccountAction", f(
        ("subAccountId","uint256"),("action","string"),("expiresAfter","uint256")), "generic_no_nonce"),
]

# Plausible action-specific field orders. TransferCollateral uses a non-semantic order, so do not
# assume the documented order is authoritative.
orders = [
    ["subAccountId","fromSymbol","toSymbol","fromAmount","nonce","expiresAfter"],
    ["subAccountId","fromAmount","fromSymbol","toSymbol","nonce","expiresAfter"],
    ["fromAmount","expiresAfter","fromSymbol","nonce","subAccountId","toSymbol"],
    ["fromAmount","fromSymbol","toSymbol","subAccountId","nonce","expiresAfter"],
    ["fromSymbol","toSymbol","fromAmount","subAccountId","nonce","expiresAfter"],
    ["subAccountId","fromSymbol","toSymbol","fromAmount","expiresAfter","nonce"],
]
types = {"subAccountId":"uint256","fromSymbol":"string","toSymbol":"string","fromAmount":"string","nonce":"uint256","expiresAfter":"uint256"}
for index, order in enumerate(orders):
    fields = tuple((name, types[name]) for name in order)
    CANDIDATES.append(Candidate(f"ExchangeCollateral_order_{index}", "ExchangeCollateral", fields))

# Cross-handler candidates: current VCE type while invoking legacy wire, and legacy type against
# current action/wire aliases.
VCE_FIELDS = f(
    ("subAccountId","uint256"),("sourceAsset","string"),("targetUSDTAmount","string"),
    ("nonce","uint256"),("expiresAfter","uint256")
)
CANDIDATES += [
    Candidate("VCE_signature_legacy_action", "VoluntaryCollateralExchange", VCE_FIELDS, "vce", "exchangeCollateral"),
    Candidate("VCE_signature_current_action", "VoluntaryCollateralExchange", VCE_FIELDS, "vce", "voluntaryCollateralExchange"),
    Candidate("Exchange_signature_current_action", "ExchangeCollateral", SEMANTIC, "legacy", "voluntaryCollateralExchange"),
]


def build(candidate: Candidate, nonce: int) -> dict[str, Any]:
    fields = [{"name": name, "type": typ} for name, typ in candidate.fields]
    if candidate.message_kind == "generic":
        message = {"subAccountId": SUBACCOUNT, "action": candidate.action, "nonce": nonce, "expiresAfter": nonce + 60_000}
    elif candidate.message_kind == "generic_no_nonce":
        message = {"subAccountId": SUBACCOUNT, "action": candidate.action, "expiresAfter": nonce + 60_000}
    elif candidate.message_kind == "vce":
        message = {"subAccountId": SUBACCOUNT, "sourceAsset": "WETH", "targetUSDTAmount": "1", "nonce": nonce, "expiresAfter": nonce + 60_000}
    else:
        full = legacy_message(nonce)
        message = {name: full[name] for name, _ in candidate.fields}
    signature = sign(candidate.primary, fields, message)
    overrides = dict(candidate.overrides)
    if candidate.message_kind == "vce" and candidate.action == "voluntaryCollateralExchange":
        overrides.update({"sourceAsset":"WETH","targetUSDTAmount":"1"})
    return wire(nonce, signature, action=candidate.action, overrides=overrides)


def summarize(name: str, status: int, raw: bytes, elapsed: float) -> dict[str, Any]:
    data = parsed(raw)
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict): code, message = error.get("code"), error.get("message") or error.get("error")
    else: code, message = None, error
    text = str(message) if message is not None else ""
    return {
        "name": name, "httpStatus": status, "elapsedMs": round(elapsed*1000,2),
        "apiStatus": data.get("status") if isinstance(data, dict) else None,
        "errorCode": code, "messageRedacted": redact(message),
        "messageSha256": sha(text) if text else None,
        "mentionsSyntheticSigner": ACCOUNT.address[:6].lower() in text.lower() or ACCOUNT.address[-4:].lower() in text.lower(),
        "bodySha256": sha(raw), "bodyBytes": len(raw),
    }


def main() -> None:
    status, raw, _ = post(INFO, {"params":{"action":"getSubAccountIds","walletAddress":ACCOUNT.address,"includeDelegations":True}})
    data = parsed(raw); response = data.get("response") if isinstance(data, dict) else None
    count = account_count(response)
    if status != 200 or count != 0: raise RuntimeError(f"preflight failed status={status} count={count}")

    base_nonce = int(time.time()*1000)
    results = []
    for index, candidate in enumerate(CANDIDATES):
        nonce = base_nonce + index*10 + 1
        results.append(summarize(candidate.name, *post(TRADE, build(candidate, nonce))))
        if index + 1 < len(CANDIDATES): time.sleep(DELAY)

    # Once an accepted schema reaches account authorization, repeat it with material wire mutations.
    accepted = [item["name"] for item in results if item["httpStatus"] in (401,403) and item["errorCode"] in ("UNAUTHORIZED","FORBIDDEN")]
    mutation_results = []
    by_name = {c.name:c for c in CANDIDATES}
    for candidate_name in accepted[:4]:
        candidate = by_name[candidate_name]
        for suffix, overrides in (
            ("wire_amount_large", {"fromAmount":"1000000"}),
            ("wire_source_USDT", {"fromSymbol":"USDT"}),
            ("wire_target_WETH", {"toSymbol":"WETH"}),
            ("wire_other_account", {"subAccountId":str(OTHER_ACCOUNT)}),
            ("mixed_vce_fields", {"sourceAsset":"USDT","targetUSDTAmount":"1000000"}),
        ):
            nonce = base_nonce + 10_000 + len(mutation_results)*10 + 1
            payload = build(candidate, nonce)
            payload["params"].update(overrides)
            mutation_results.append(summarize(candidate_name+"__"+suffix, *post(TRADE, payload)))
            time.sleep(DELAY)

    output = {
        "safety":"Synthetic zero-account signer and nonexistent account IDs; no request can mutate state.",
        "candidateCount":len(results), "acceptedAuthorizationStageCandidates":accepted,
        "candidateResults":results, "mutationResults":mutation_results,
    }
    (OUT/"summary.json").write_text(json.dumps(output,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps({
        "candidateCount":len(results), "acceptedAuthorizationStageCandidates":accepted,
        "statuses":{item["name"]:item["httpStatus"] for item in results},
        "mutationStatuses":{item["name"]:item["httpStatus"] for item in mutation_results},
    },indent=2))


if __name__ == "__main__": main()
