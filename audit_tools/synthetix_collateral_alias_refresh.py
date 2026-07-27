#!/usr/bin/env python3
"""Synthetic, non-mutating Synthetix PAPI dispatcher differential.

Safety:
- deterministic EOA verified to own/manage/delegate zero accounts;
- deliberately nonexistent source/destination account IDs;
- fresh nonces and tiny fixed values;
- every write request must fail account authorization before mutation;
- no victim identifier, credential, balance, order, or blockchain transaction.

The main target is the unsigned wire `action` selector around
VoluntaryCollateralExchange. The signed EIP-712 message does not contain the
wire action string, so an active alias or verifier/handler schema split could
execute different business logic under a valid signature.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from eth_account import Account
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("synthetix_collateral_alias_refresh")
OUT.mkdir(parents=True, exist_ok=True)

TRADE = "https://papi.synthetix.io/v1/trade"
INFO = "https://papi.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
ACCOUNT = Account.from_key("0x" + "f1" * 32)
SOURCE = 8_300_000_000_030_001
DESTINATION = 8_300_000_000_030_101
ZERO = "0x0000000000000000000000000000000000000000"
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HEX_RE = re.compile(r"0x[a-fA-F0-9]{64,}")
MAX_BODY = 2 * 1024 * 1024
DELAY = 0.32

DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
VCE_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "sourceAsset", "type": "string"},
    {"name": "targetUSDTAmount", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
SUBACTION_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "action", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
TRANSFER_FIELDS = [
    {"name": "amount", "type": "string"},
    {"name": "expiresAfter", "type": "uint256"},
    {"name": "nonce", "type": "uint256"},
    {"name": "subAccountId", "type": "uint256"},
    {"name": "symbol", "type": "string"},
    {"name": "to", "type": "uint256"},
]


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = ADDRESS_RE.sub("<address>", str(value))
    text = HEX_RE.sub("<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:1400]


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
    if len(raw) > MAX_BODY:
        raise RuntimeError("response exceeds safety cap")
    return status, raw, time.monotonic() - started


def sign(primary: str, fields: list[dict[str, str]], message: dict[str, Any]) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": {"EIP712Domain": DOMAIN_FIELDS, primary: fields},
            "primaryType": primary,
            "domain": DOMAIN,
            "message": message,
        }
    )
    signed = ACCOUNT.sign_message(encoded)
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def vce_request(
    nonce: int,
    *,
    wire_action: str = "voluntaryCollateralExchange",
    primary: str = "VoluntaryCollateralExchange",
    signed_source: str = "WETH",
    signed_amount: str = "1",
    params: dict[str, Any] | None = None,
    include_canonical: bool = True,
) -> dict[str, Any]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": SOURCE,
        "sourceAsset": signed_source,
        "targetUSDTAmount": signed_amount,
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    sig = sign(primary, VCE_FIELDS, message)
    wire = {
        "action": wire_action,
        "subaccountId": str(SOURCE),
        "walletAddress": ACCOUNT.address,
    }
    if include_canonical:
        wire.update({"sourceAsset": signed_source, "targetUSDTAmount": signed_amount})
    if params:
        wire.update(params)
    return {"signature": sig, "nonce": nonce, "expiresAfter": expiry, "params": wire}


def generic_request(nonce: int, action: str, params: dict[str, Any]) -> dict[str, Any]:
    expiry = nonce + 60_000
    message = {"subAccountId": SOURCE, "action": action, "nonce": nonce, "expiresAfter": expiry}
    sig = sign("SubAccountAction", SUBACTION_FIELDS, message)
    wire = {"action": action, "subaccountId": str(SOURCE), "walletAddress": ACCOUNT.address, **params}
    return {"signature": sig, "nonce": nonce, "expiresAfter": expiry, "params": wire}


def transfer_signature_on_action(nonce: int, action: str, params: dict[str, Any]) -> dict[str, Any]:
    expiry = nonce + 60_000
    message = {
        "amount": "1",
        "expiresAfter": expiry,
        "nonce": nonce,
        "subAccountId": SOURCE,
        "symbol": "WETH",
        "to": DESTINATION,
    }
    sig = sign("TransferCollateral", TRANSFER_FIELDS, message)
    wire = {
        "action": action,
        "subaccountId": str(SOURCE),
        "walletAddress": ACCOUNT.address,
        "sourceAsset": "WETH",
        "targetUSDTAmount": "1",
        **params,
    }
    return {"signature": sig, "nonce": nonce, "expiresAfter": expiry, "params": wire}


@dataclass(frozen=True)
class Case:
    name: str
    build: Callable[[int], dict[str, Any]]


CASES = [
    Case("canonical_vce", lambda n: vce_request(n)),
    Case("action_exchangeCollateral", lambda n: vce_request(n, wire_action="exchangeCollateral")),
    Case("action_collateralExchange", lambda n: vce_request(n, wire_action="collateralExchange")),
    Case("action_convertCollateral", lambda n: vce_request(n, wire_action="convertCollateral")),
    Case("action_voluntaryExchangeCollateral", lambda n: vce_request(n, wire_action="voluntaryExchangeCollateral")),
    Case("action_case_variant", lambda n: vce_request(n, wire_action="VoluntaryCollateralExchange")),
    Case("alternate_primary_exchange", lambda n: vce_request(n, primary="ExchangeCollateral")),
    Case("alternate_primary_collateral", lambda n: vce_request(n, primary="CollateralExchange")),
    Case("missing_source_with_symbol", lambda n: vce_request(n, include_canonical=False, params={"symbol": "WETH", "targetUSDTAmount": "1"})),
    Case("missing_source_with_fromAsset", lambda n: vce_request(n, include_canonical=False, params={"fromAsset": "WETH", "targetUSDTAmount": "1"})),
    Case("missing_amount_with_amount", lambda n: vce_request(n, include_canonical=False, params={"sourceAsset": "WETH", "amount": "1"})),
    Case("missing_amount_with_targetAmount", lambda n: vce_request(n, include_canonical=False, params={"sourceAsset": "WETH", "targetAmount": "1"})),
    Case("source_conflict_symbol", lambda n: vce_request(n, params={"symbol": "USDT"})),
    Case("source_conflict_fromAsset", lambda n: vce_request(n, params={"fromAsset": "USDT"})),
    Case("amount_conflict_amount", lambda n: vce_request(n, params={"amount": "999999"})),
    Case("amount_conflict_targetAmount", lambda n: vce_request(n, params={"targetAmount": "999999"})),
    Case("account_alias_conflict", lambda n: vce_request(n, params={"subAccountId": str(SOURCE + 1)})),
    Case("generic_signature_vce", lambda n: generic_request(n, "voluntaryCollateralExchange", {"sourceAsset": "WETH", "targetUSDTAmount": "1"})),
    Case("transfer_signature_vce", lambda n: transfer_signature_on_action(n, "voluntaryCollateralExchange", {})),
    Case("hidden_modifyOrderBatch", lambda n: generic_request(n, "modifyOrderBatch", {"orders": []})),
    Case("hidden_placeIsolatedOrder", lambda n: generic_request(n, "placeIsolatedOrder", {"symbol": "BTC-USDT", "side": "buy", "quantity": "0.001", "price": "1"})),
    Case("hidden_updateIsolatedMargin", lambda n: generic_request(n, "updateIsolatedMargin", {"symbol": "BTC-USDT", "amount": "1"})),
    Case("hidden_exchangeCollateral", lambda n: generic_request(n, "exchangeCollateral", {"sourceAsset": "WETH", "targetUSDTAmount": "1"})),
]


def parse_result(name: str, status: int, raw: bytes, elapsed: float) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error, dict):
        code = error.get("code")
        message = error.get("message") or error.get("error")
    else:
        code = None
        message = error
    text = str(message or "")
    abbr = ACCOUNT.address[:6].lower()
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": code,
        "messageRedacted": redact(message),
        "messageSha256": digest(text) if text else None,
        "mentionsSyntheticSigner": abbr in text.lower(),
        "bodySha256": digest(raw),
        "bodyBytes": len(raw),
    }


def main() -> None:
    status, raw, _ = post(INFO, {"params": {"action": "getSubAccountIds", "walletAddress": ACCOUNT.address, "includeDelegations": True}})
    parsed = json.loads(raw)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    if isinstance(response, list):
        count = len(response)
    elif isinstance(response, dict):
        count = sum(len(response.get(k) or []) for k in ("subAccountIds", "managedSubAccountIds", "delegatedSubAccountIds"))
    else:
        count = None
    if status != 200 or count != 0:
        raise RuntimeError(f"synthetic preflight failed: status={status}, count={count}")

    base = int(time.time() * 1000)
    results = []
    for index, case in enumerate(CASES):
        nonce = base + index * 10 + 1
        results.append(parse_result(case.name, *post(TRADE, case.build(nonce))))
        if index + 1 < len(CASES):
            time.sleep(DELAY)

    canonical = next(item for item in results if item["name"] == "canonical_vce")
    same_stage = []
    different_stage = []
    signer_recovered = []
    successful = []
    for item in results:
        if item["mentionsSyntheticSigner"]:
            signer_recovered.append(item["name"])
        if 200 <= item["httpStatus"] < 300:
            successful.append(item["name"])
        if item["name"] == "canonical_vce":
            continue
        key = (item["httpStatus"], item["errorCode"], item["messageSha256"])
        baseline_key = (canonical["httpStatus"], canonical["errorCode"], canonical["messageSha256"])
        (same_stage if key == baseline_key else different_stage).append(item["name"])

    summary = {
        "safety": "Synthetic zero-account signer and nonexistent account IDs; no request can mutate state.",
        "syntheticAccountCount": count,
        "caseCount": len(results),
        "canonical": canonical,
        "sameAsCanonical": same_stage,
        "differentValidationStage": different_stage,
        "syntheticSignerRecovered": signer_recovered,
        "successfulResponses": successful,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("caseCount", "sameAsCanonical", "differentValidationStage", "syntheticSignerRecovered", "successfulResponses")}, indent=2))


if __name__ == "__main__":
    main()
