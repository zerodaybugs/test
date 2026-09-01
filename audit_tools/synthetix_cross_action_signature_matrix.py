#!/usr/bin/env python3
"""Targeted cross-action EIP-712 signature differential for Synthetix PAPI.

Safety constraints:
- deterministic EOA confirmed to own/manage/delegate zero accounts;
- deliberately nonexistent source/destination subaccount IDs;
- fresh nonce per request and tiny fixed values;
- every write must fail account authorization before state mutation;
- no victim identifier, balance, order, credential, or blockchain transaction.

Most action-specific EIP-712 messages do not include the outer wire `action` selector.
This matrix checks whether a valid signature for one primary type can be accepted by a
second high-impact handler because of schema overlap, alias normalization, or envelope
routing differences.
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
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("synthetix_cross_action_signature_matrix")
OUT.mkdir(parents=True, exist_ok=True)

TRADE = "https://papi.synthetix.io/v1/trade"
INFO = "https://papi.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
ACCOUNT = Account.from_key("0x" + "f2" * 32)
SOURCE = 8_300_000_000_040_001
DESTINATION = 8_300_000_000_040_101
DELEGATE = Account.from_key("0x" + "f3" * 32).address
ZERO = "0x0000000000000000000000000000000000000000"
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HEX_RE = re.compile(r"0x[a-fA-F0-9]{64,}")
MAX_BODY = 2 * 1024 * 1024
DELAY = 0.30

DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
TYPES: dict[str, list[dict[str, str]]] = {
    "WithdrawCollateral": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "amount", "type": "string"},
        {"name": "destination", "type": "address"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "TransferCollateral": [
        {"name": "amount", "type": "string"},
        {"name": "expiresAfter", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "to", "type": "uint256"},
    ],
    "VoluntaryCollateralExchange": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "sourceAsset", "type": "string"},
        {"name": "targetUSDTAmount", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "CreateSubaccount": [
        {"name": "masterSubAccountId", "type": "uint256"},
        {"name": "name", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "UpdateSubAccountName": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "name", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "AddDelegatedSigner": [
        {"name": "delegateAddress", "type": "address"},
        {"name": "subAccountId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
        {"name": "expiresAt", "type": "uint256"},
        {"name": "permissions", "type": "string[]"},
    ],
    "RemoveDelegatedSigner": [
        {"name": "delegateAddress", "type": "address"},
        {"name": "subAccountId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "RemoveAllDelegatedSigners": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "CancelAllOrders": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbols", "type": "string[]"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "ScheduleCancel": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "timeoutSeconds", "type": "uint256"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
    "UpdateLeverage": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "leverage", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}

ACTION_TO_PRIMARY = {
    "withdrawCollateral": "WithdrawCollateral",
    "transferCollateral": "TransferCollateral",
    "voluntaryCollateralExchange": "VoluntaryCollateralExchange",
    "createSubaccount": "CreateSubaccount",
    "updateSubAccountName": "UpdateSubAccountName",
    "addDelegatedSigner": "AddDelegatedSigner",
    "removeDelegatedSigner": "RemoveDelegatedSigner",
    "removeAllDelegatedSigners": "RemoveAllDelegatedSigners",
    "cancelAllOrders": "CancelAllOrders",
    "scheduleCancel": "ScheduleCancel",
    "updateLeverage": "UpdateLeverage",
}


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


def sign(primary: str, message: dict[str, Any]) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": {"EIP712Domain": DOMAIN_FIELDS, primary: TYPES[primary]},
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


def message_for(primary: str, nonce: int) -> tuple[dict[str, Any], int]:
    expiry = nonce + 60_000
    common = {"nonce": nonce, "expiresAfter": expiry}
    messages = {
        "WithdrawCollateral": {"subAccountId": SOURCE, "symbol": "USDT", "amount": "1", "destination": ACCOUNT.address, **common},
        "TransferCollateral": {"amount": "1", "expiresAfter": expiry, "nonce": nonce, "subAccountId": SOURCE, "symbol": "USDT", "to": DESTINATION},
        "VoluntaryCollateralExchange": {"subAccountId": SOURCE, "sourceAsset": "WETH", "targetUSDTAmount": "1", **common},
        "CreateSubaccount": {"masterSubAccountId": SOURCE, "name": "", **common},
        "UpdateSubAccountName": {"subAccountId": SOURCE, "name": "", **common},
        "AddDelegatedSigner": {"delegateAddress": DELEGATE, "subAccountId": SOURCE, "nonce": nonce, "expiresAfter": expiry, "expiresAt": expiry + 86_400_000, "permissions": ["session"]},
        "RemoveDelegatedSigner": {"delegateAddress": DELEGATE, "subAccountId": SOURCE, **common},
        "RemoveAllDelegatedSigners": {"subAccountId": SOURCE, **common},
        "CancelAllOrders": {"subAccountId": SOURCE, "symbols": [], **common},
        "ScheduleCancel": {"subAccountId": SOURCE, "timeoutSeconds": 60, **common},
        "UpdateLeverage": {"subAccountId": SOURCE, "symbol": "BTC-USDT", "leverage": "1", **common},
    }
    return messages[primary], expiry


def target_params(action: str) -> dict[str, Any]:
    return {
        "withdrawCollateral": {"symbol": "USDT", "amount": "1", "destination": ACCOUNT.address},
        "transferCollateral": {"symbol": "USDT", "amount": "1", "to": str(DESTINATION)},
        "voluntaryCollateralExchange": {"sourceAsset": "WETH", "targetUSDTAmount": "1"},
        "createSubaccount": {"name": ""},
        "updateSubAccountName": {"name": ""},
        "addDelegatedSigner": {"walletAddress": DELEGATE, "expiresAt": 0, "permissions": ["session"]},
        "removeDelegatedSigner": {"walletAddress": DELEGATE},
        "removeAllDelegatedSigners": {},
        "cancelAllOrders": {"symbols": []},
        "scheduleCancel": {"timeoutSeconds": 60},
        "updateLeverage": {"symbol": "BTC-USDT", "leverage": "1"},
    }[action]


def envelope(source_primary: str, target_action: str, nonce: int) -> dict[str, Any]:
    message, expiry = message_for(source_primary, nonce)
    sig = sign(source_primary, message)
    params = {"action": target_action, **target_params(target_action)}
    if target_action in {"addDelegatedSigner", "removeDelegatedSigner"}:
        return {
            "signature": sig,
            "nonce": nonce,
            "expiresAfter": expiry,
            "subaccountId": str(SOURCE),
            "walletAddress": ACCOUNT.address,
            "params": params,
        }
    params.update({"subaccountId": str(SOURCE), "walletAddress": ACCOUNT.address})
    return {"signature": sig, "nonce": nonce, "expiresAfter": expiry, "params": params}


@dataclass(frozen=True)
class Case:
    name: str
    source_primary: str
    target_action: str
    canonical: bool = False


CANONICAL_CASES = [
    Case(f"canonical_{action}", primary, action, True)
    for action, primary in ACTION_TO_PRIMARY.items()
]
CROSS_CASES = [
    Case("withdraw_to_transfer", "WithdrawCollateral", "transferCollateral"),
    Case("transfer_to_withdraw", "TransferCollateral", "withdrawCollateral"),
    Case("vce_to_withdraw", "VoluntaryCollateralExchange", "withdrawCollateral"),
    Case("withdraw_to_vce", "WithdrawCollateral", "voluntaryCollateralExchange"),
    Case("transfer_to_vce", "TransferCollateral", "voluntaryCollateralExchange"),
    Case("vce_to_transfer", "VoluntaryCollateralExchange", "transferCollateral"),
    Case("update_name_to_create", "UpdateSubAccountName", "createSubaccount"),
    Case("create_to_update_name", "CreateSubaccount", "updateSubAccountName"),
    Case("add_delegate_to_remove", "AddDelegatedSigner", "removeDelegatedSigner"),
    Case("remove_delegate_to_add", "RemoveDelegatedSigner", "addDelegatedSigner"),
    Case("remove_all_to_cancel_all", "RemoveAllDelegatedSigners", "cancelAllOrders"),
    Case("cancel_all_to_remove_all", "CancelAllOrders", "removeAllDelegatedSigners"),
    Case("schedule_to_leverage", "ScheduleCancel", "updateLeverage"),
    Case("leverage_to_schedule", "UpdateLeverage", "scheduleCancel"),
    Case("add_delegate_to_remove_all", "AddDelegatedSigner", "removeAllDelegatedSigners"),
    Case("remove_all_to_add_delegate", "RemoveAllDelegatedSigners", "addDelegatedSigner"),
    Case("update_name_to_remove_all", "UpdateSubAccountName", "removeAllDelegatedSigners"),
    Case("remove_all_to_update_name", "RemoveAllDelegatedSigners", "updateSubAccountName"),
    Case("create_to_remove_all", "CreateSubaccount", "removeAllDelegatedSigners"),
    Case("remove_all_to_create", "RemoveAllDelegatedSigners", "createSubaccount"),
]
CASES = CANONICAL_CASES + CROSS_CASES


def parse_result(case: Case, status: int, raw: bytes, elapsed: float) -> dict[str, Any]:
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
    return {
        "name": case.name,
        "sourcePrimary": case.source_primary,
        "targetAction": case.target_action,
        "canonical": case.canonical,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": code,
        "messageRedacted": redact(message),
        "messageSha256": digest(text) if text else None,
        "mentionsSyntheticSigner": ACCOUNT.address[:6].lower() in text.lower(),
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
        results.append(parse_result(case, *post(TRADE, envelope(case.source_primary, case.target_action, nonce))))
        if index + 1 < len(CASES):
            time.sleep(DELAY)

    canonical_by_action = {item["targetAction"]: item for item in results if item["canonical"]}
    suspicious = []
    for item in results:
        if item["canonical"]:
            continue
        baseline = canonical_by_action[item["targetAction"]]
        exact_stage = (
            item["httpStatus"] == baseline["httpStatus"]
            and item["errorCode"] == baseline["errorCode"]
            and item["messageSha256"] == baseline["messageSha256"]
        )
        same_signer_stage = item["mentionsSyntheticSigner"] and baseline["mentionsSyntheticSigner"]
        item["matchesTargetCanonicalExactly"] = exact_stage
        item["reachesTargetCanonicalSignerStage"] = same_signer_stage
        if exact_stage or same_signer_stage or 200 <= item["httpStatus"] < 300:
            suspicious.append(item["name"])

    summary = {
        "safety": "Synthetic zero-account signer and nonexistent account IDs; no request can mutate state.",
        "syntheticAccountCount": count,
        "caseCount": len(results),
        "canonicalByAction": canonical_by_action,
        "suspiciousCrossActionCases": suspicious,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"caseCount": len(results), "suspiciousCrossActionCases": suspicious}, indent=2))


if __name__ == "__main__":
    main()
