#!/usr/bin/env python3
"""Controlled collateral-exchange alias and verifier/handler differential for Synthetix PAPI.

Safety:
- deterministic synthetic EOA confirmed to own/manage/delegate zero accounts;
- deliberately nonexistent valid-range source account ID;
- every request uses a fresh nonce and cannot pass ownership authorization;
- no victim identity, balance, order, position, withdrawal, transaction, or state mutation;
- response artifacts retain only hashes, status classes, and redacted error metadata.

Goal:
Map whether legacy/current action names, primary types, field aliases, or hidden write names are
normalized differently between the EIP-712 verifier, action dispatcher, and business handler.
A material split could permit a correctly signed harmless collateral exchange to execute a different
source asset, amount, account, or action.
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

OUT = pathlib.Path("synthetix_collateral_exchange_dispatch")
OUT.mkdir(parents=True, exist_ok=True)

INFO_URL = "https://papi.synthetix.io/v1/info"
TRADE_URL = "https://papi.synthetix.io/v1/trade"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
DELAY = 0.30

ACCOUNT = Account.from_key("0x" + "93" * 32)
SOURCE_ACCOUNT = 8_300_000_000_030_001
OTHER_ACCOUNT = 8_300_000_000_030_002
ZERO = "0x0000000000000000000000000000000000000000"

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
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HEX_RE = re.compile(r"0x[a-fA-F0-9]{64,}")


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = ADDRESS_RE.sub("<address>", text)
    text = HEX_RE.sub("<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:1500]


def post(url: str, payload: dict[str, Any]) -> tuple[int, bytes, float]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read(MAX_BODY + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_BODY + 1)
        status = exc.code
    elapsed = time.monotonic() - started
    if len(raw) > MAX_BODY:
        raise RuntimeError("response exceeds safety cap")
    return status, raw, elapsed


def parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return None


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        found = False
        count = 0
        for key in ("subAccountIds", "managedSubAccountIds", "delegatedSubAccountIds"):
            value = response.get(key)
            if isinstance(value, list):
                found = True
                count += len(value)
        return count if found else None
    return None


def sign(primary: str, fields: list[dict[str, str]], message: dict[str, Any]) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": {primary: fields},
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


def base_message(nonce: int, *, source: str = "WETH", amount: str = "1") -> dict[str, Any]:
    return {
        "subAccountId": SOURCE_ACCOUNT,
        "sourceAsset": source,
        "targetUSDTAmount": amount,
        "nonce": nonce,
        "expiresAfter": nonce + 60_000,
    }


def request_from(
    nonce: int,
    *,
    primary: str = "VoluntaryCollateralExchange",
    fields: list[dict[str, str]] = VCE_FIELDS,
    signed_source: str = "WETH",
    signed_amount: str = "1",
    action: str = "voluntaryCollateralExchange",
    params_override: dict[str, Any] | None = None,
    remove_params: tuple[str, ...] = (),
    top_override: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if primary == "SubAccountAction":
        message = {
            "subAccountId": SOURCE_ACCOUNT,
            "action": action,
            "nonce": nonce,
            "expiresAfter": nonce + 60_000,
        }
    else:
        message = base_message(nonce, source=signed_source, amount=signed_amount)
    signature = sign(primary, fields, message)
    params: dict[str, Any] = {
        "action": action,
        "subaccountId": str(SOURCE_ACCOUNT),
        "walletAddress": ACCOUNT.address,
        "sourceAsset": signed_source,
        "targetUSDTAmount": signed_amount,
    }
    if params_override:
        params.update(params_override)
    for key in remove_params:
        params.pop(key, None)
    payload: dict[str, Any] = {
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": nonce + 60_000,
        "params": params,
    }
    if top_override:
        payload.update(top_override)
    return payload


@dataclass(frozen=True)
class Case:
    name: str
    build: Callable[[int], dict[str, Any]]


CASES = [
    Case("canonical", lambda n: request_from(n)),
    # Action aliases with a canonical VCE signature.
    Case("action_exchangeCollateral", lambda n: request_from(n, action="exchangeCollateral")),
    Case("action_collateralExchange", lambda n: request_from(n, action="collateralExchange")),
    Case("action_voluntaryExchange", lambda n: request_from(n, action="voluntaryExchange")),
    # Alternate primary types with identical fields.
    Case("primary_ExchangeCollateral_action_exchange", lambda n: request_from(n, primary="ExchangeCollateral", action="exchangeCollateral")),
    Case("primary_ExchangeCollateral_action_canonical", lambda n: request_from(n, primary="ExchangeCollateral")),
    Case("primary_CollateralExchange_action_exchange", lambda n: request_from(n, primary="CollateralExchange", action="exchangeCollateral")),
    # Generic cached-capability crossover.
    Case("generic_canonical_action", lambda n: request_from(n, primary="SubAccountAction", fields=SUBACTION_FIELDS)),
    Case("generic_exchange_action", lambda n: request_from(n, primary="SubAccountAction", fields=SUBACTION_FIELDS, action="exchangeCollateral")),
    # Signed-vs-wire substitutions.
    Case("source_signed_WETH_wire_USDT", lambda n: request_from(n, signed_source="WETH", params_override={"sourceAsset": "USDT"})),
    Case("source_signed_USDT_wire_WETH", lambda n: request_from(n, signed_source="USDT", params_override={"sourceAsset": "WETH"})),
    Case("amount_signed_1_wire_large", lambda n: request_from(n, signed_amount="1", params_override={"targetUSDTAmount": "1000000"})),
    Case("amount_signed_large_wire_1", lambda n: request_from(n, signed_amount="1000000", params_override={"targetUSDTAmount": "1"})),
    Case("account_signed_A_wire_B", lambda n: request_from(n, params_override={"subaccountId": str(OTHER_ACCOUNT)})),
    # Potential legacy/new aliases and conflicts.
    Case("sourceSymbol_only", lambda n: request_from(n, params_override={"sourceSymbol": "WETH"}, remove_params=("sourceAsset",))),
    Case("sourceAsset_and_sourceSymbol_conflict", lambda n: request_from(n, params_override={"sourceSymbol": "USDT"})),
    Case("targetAmount_only", lambda n: request_from(n, params_override={"targetAmount": "1"}, remove_params=("targetUSDTAmount",))),
    Case("targetUSDTAmount_and_targetAmount_conflict", lambda n: request_from(n, params_override={"targetAmount": "1000000"})),
    Case("targetUsdtAmount_case_alias", lambda n: request_from(n, params_override={"targetUsdtAmount": "1"}, remove_params=("targetUSDTAmount",))),
    Case("subAccountId_only", lambda n: request_from(n, params_override={"subAccountId": str(SOURCE_ACCOUNT)}, remove_params=("subaccountId",))),
    Case("subaccount_alias_conflict", lambda n: request_from(n, params_override={"subAccountId": str(OTHER_ACCOUNT)})),
    # Type/format boundaries.
    Case("target_amount_number", lambda n: request_from(n, params_override={"targetUSDTAmount": 1})),
    Case("source_asset_lowercase", lambda n: request_from(n, params_override={"sourceAsset": "weth"})),
    Case("source_asset_null", lambda n: request_from(n, params_override={"sourceAsset": None})),
    Case("target_amount_null", lambda n: request_from(n, params_override={"targetUSDTAmount": None})),
    # Current documentation/rate-limit names that have appeared outside the SDK.
    Case("hidden_placeIsolatedOrder_generic", lambda n: request_from(n, primary="SubAccountAction", fields=SUBACTION_FIELDS, action="placeIsolatedOrder", remove_params=("sourceAsset", "targetUSDTAmount"))),
    Case("hidden_modifyOrderBatch_generic", lambda n: request_from(n, primary="SubAccountAction", fields=SUBACTION_FIELDS, action="modifyOrderBatch", remove_params=("sourceAsset", "targetUSDTAmount"))),
    Case("hidden_updateIsolatedMargin_generic", lambda n: request_from(n, primary="SubAccountAction", fields=SUBACTION_FIELDS, action="updateIsolatedMargin", remove_params=("sourceAsset", "targetUSDTAmount"))),
]


def summarize(name: str, status: int, raw: bytes, elapsed: float) -> dict[str, Any]:
    parsed = parse_json(raw)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error, dict):
        code = error.get("code")
        message = error.get("message") or error.get("error")
    else:
        code = None
        message = error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    message_text = str(message) if message is not None else ""
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": code,
        "messageRedacted": redact(message),
        "messageSha256": sha(message_text) if message_text else None,
        "responseType": type(response).__name__ if response is not None else None,
        "responseSha256": sha(json.dumps(response, sort_keys=True, default=str)) if response is not None else None,
        "bodySha256": sha(raw),
        "bodyBytes": len(raw),
    }


def main() -> None:
    status, raw, _ = post(
        INFO_URL,
        {"params": {"action": "getSubAccountIds", "walletAddress": ACCOUNT.address, "includeDelegations": True}},
    )
    parsed = parse_json(raw)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    count = account_count(response)
    if status != 200 or count != 0:
        raise RuntimeError(f"synthetic signer preflight failed: status={status}, accountCount={count}")

    base_nonce = int(time.time() * 1000)
    results: list[dict[str, Any]] = []
    for index, case in enumerate(CASES):
        nonce = base_nonce + index * 10 + 1
        payload = case.build(nonce)
        results.append(summarize(case.name, *post(TRADE_URL, payload)))
        if index + 1 < len(CASES):
            time.sleep(DELAY)

    baseline = next(item for item in results if item["name"] == "canonical")
    exact_baseline = []
    stage_changes = []
    for item in results:
        if item["name"] == "canonical":
            continue
        same = (
            item["httpStatus"] == baseline["httpStatus"]
            and item["apiStatus"] == baseline["apiStatus"]
            and item["errorCode"] == baseline["errorCode"]
            and item["messageSha256"] == baseline["messageSha256"]
        )
        (exact_baseline if same else stage_changes).append(item["name"])

    output = {
        "safety": "Synthetic zero-account signer, nonexistent account IDs, fresh nonces; no request can pass ownership or mutate state.",
        "caseCount": len(results),
        "syntheticAccountCount": count,
        "baseline": baseline,
        "casesMatchingCanonicalAuthorizationFingerprint": exact_baseline,
        "casesChangingValidationOrDispatchStage": stage_changes,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "caseCount": output["caseCount"],
        "baseline": baseline,
        "matchingCanonical": exact_baseline,
        "stageChanges": stage_changes,
        "statuses": {item["name"]: item["httpStatus"] for item in results},
    }, indent=2))


if __name__ == "__main__":
    main()
