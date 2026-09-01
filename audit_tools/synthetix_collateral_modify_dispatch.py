#!/usr/bin/env python3
"""Controlled Synthetix PAPI dispatcher/signature differential.

Safety constraints:
- deterministic synthetic EOA confirmed to own/manage/delegate zero accounts;
- deliberately nonexistent valid-range subaccount and order identifiers;
- every request uses a fresh nonce and therefore cannot pass ownership;
- no real account, balance, order, position, credential, or transaction is used;
- output retains only redacted response metadata and hashes.

Targets two high-value migration boundaries:
1. The docs expose both exchangeCollateral and voluntaryCollateralExchange with different wire shapes,
   while the Python SDK only implements VoluntaryCollateralExchange and includes a lowercase
   subaccountId that the docs say is omitted from params.
2. Current third-party SDK documentation advertises modify-by-client-order-id in addition to the
   documented modify-by-venue-order-id path. A verifier/dispatcher split could modify the wrong order.
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

OUT = pathlib.Path("synthetix_collateral_modify_dispatch")
OUT.mkdir(parents=True, exist_ok=True)

TRADE = "https://papi.synthetix.io/v1/trade"
INFO = "https://papi.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
ACCOUNT = Account.from_key("0x" + "d3" * 32)
A = 8_300_000_000_071_001
B = 8_300_000_000_071_002
ORDER_A = 8_300_000_000_071_101
ORDER_B = 8_300_000_000_071_102
CLOID_A = "0x" + "ab" * 16
CLOID_B = "0x" + "cd" * 16
ZERO = "0x0000000000000000000000000000000000000000"
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
HEX_RE = re.compile(r"0x[a-fA-F0-9]{64,}")
MAX_BODY = 2 * 1024 * 1024

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}

VOLUNTARY_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "sourceAsset", "type": "string"},
    {"name": "targetUSDTAmount", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
EXCHANGE_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "fromSymbol", "type": "string"},
    {"name": "toSymbol", "type": "string"},
    {"name": "fromAmount", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
MODIFY_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "orderId", "type": "uint256"},
    {"name": "price", "type": "string"},
    {"name": "quantity", "type": "string"},
    {"name": "triggerPrice", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
MODIFY_CLOID_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "clientOrderId", "type": "string"},
    {"name": "price", "type": "string"},
    {"name": "quantity", "type": "string"},
    {"name": "triggerPrice", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
GENERIC_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "action", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]


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
    return text[:1200]


def abbrev(address: str) -> str:
    return address[:5] + "..." + address[-3:]


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


def envelope(signature: dict[str, Any], nonce: int, expiry: int, params: dict[str, Any], **top: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": expiry,
        "params": params,
    }
    result.update(top)
    return result


def voluntary_signed(nonce: int, account: int = A, source: str = "WETH", target: str = "1") -> tuple[dict[str, Any], int]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": account,
        "sourceAsset": source,
        "targetUSDTAmount": target,
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    return sign("VoluntaryCollateralExchange", VOLUNTARY_FIELDS, message), expiry


def exchange_signed(nonce: int, account: int = A, source: str = "WETH", target: str = "USDT", amount: str = "0.0001") -> tuple[dict[str, Any], int]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": account,
        "fromSymbol": source,
        "toSymbol": target,
        "fromAmount": amount,
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    return sign("ExchangeCollateral", EXCHANGE_FIELDS, message), expiry


def modify_signed(nonce: int, order_id: int = ORDER_A) -> tuple[dict[str, Any], int]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": A,
        "orderId": order_id,
        "price": "1",
        "quantity": "",
        "triggerPrice": "",
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    return sign("ModifyOrder", MODIFY_FIELDS, message), expiry


def modify_cloid_signed(nonce: int, cloid: str = CLOID_A) -> tuple[dict[str, Any], int]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": A,
        "clientOrderId": cloid,
        "price": "1",
        "quantity": "",
        "triggerPrice": "",
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    return sign("ModifyOrderByCloid", MODIFY_CLOID_FIELDS, message), expiry


def generic_signed(nonce: int, action: str) -> tuple[dict[str, Any], int]:
    expiry = nonce + 60_000
    message = {"subAccountId": A, "action": action, "nonce": nonce, "expiresAfter": expiry}
    return sign("SubAccountAction", GENERIC_FIELDS, message), expiry


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    build: Callable[[int], dict[str, Any]]


def vcase(params: dict[str, Any], *, top: dict[str, Any] | None = None, signed_source: str = "WETH", signed_target: str = "1") -> Callable[[int], dict[str, Any]]:
    def build(nonce: int) -> dict[str, Any]:
        sig, expiry = voluntary_signed(nonce, source=signed_source, target=signed_target)
        return envelope(sig, nonce, expiry, params, **(top or {}))
    return build


def ecase(params: dict[str, Any], *, top: dict[str, Any] | None = None) -> Callable[[int], dict[str, Any]]:
    def build(nonce: int) -> dict[str, Any]:
        sig, expiry = exchange_signed(nonce)
        return envelope(sig, nonce, expiry, params, **(top or {}))
    return build


def mcase(params: dict[str, Any], *, cloid: bool = False) -> Callable[[int], dict[str, Any]]:
    def build(nonce: int) -> dict[str, Any]:
        sig, expiry = modify_cloid_signed(nonce) if cloid else modify_signed(nonce)
        return envelope(sig, nonce, expiry, params)
    return build


def gcase(action: str, params: dict[str, Any]) -> Callable[[int], dict[str, Any]]:
    def build(nonce: int) -> dict[str, Any]:
        sig, expiry = generic_signed(nonce, action)
        return envelope(sig, nonce, expiry, params)
    return build


VBASE = {"action": "voluntaryCollateralExchange", "subaccountId": str(A), "walletAddress": ACCOUNT.address, "sourceAsset": "WETH", "targetUSDTAmount": "1"}
EBASE = {"action": "exchangeCollateral", "subAccountId": str(A), "walletAddress": ACCOUNT.address, "fromSymbol": "WETH", "toSymbol": "USDT", "fromAmount": "0.0001"}
MBASE = {"action": "modifyOrder", "subAccountId": str(A), "walletAddress": ACCOUNT.address, "orderId": str(ORDER_A), "price": "1"}
MCBASE = {"action": "modifyOrder", "subAccountId": str(A), "walletAddress": ACCOUNT.address, "clientOrderId": CLOID_A, "price": "1"}

CASES = [
    Case("voluntary_sdk_lower_account", "voluntary", vcase(dict(VBASE))),
    Case("voluntary_docs_no_account_no_wallet", "voluntary", vcase({"action": "voluntaryCollateralExchange", "sourceAsset": "WETH", "targetUSDTAmount": "1"})),
    Case("voluntary_docs_no_account_with_wallet", "voluntary", vcase({"action": "voluntaryCollateralExchange", "walletAddress": ACCOUNT.address, "sourceAsset": "WETH", "targetUSDTAmount": "1"})),
    Case("voluntary_camel_account", "voluntary", vcase({**VBASE, "subaccountId": None, "subAccountId": str(A)})),
    Case("voluntary_top_lower_account", "voluntary", vcase({"action": "voluntaryCollateralExchange", "walletAddress": ACCOUNT.address, "sourceAsset": "WETH", "targetUSDTAmount": "1"}, top={"subaccountId": str(A)})),
    Case("voluntary_top_camel_account", "voluntary", vcase({"action": "voluntaryCollateralExchange", "walletAddress": ACCOUNT.address, "sourceAsset": "WETH", "targetUSDTAmount": "1"}, top={"subAccountId": str(A)})),
    Case("voluntary_lower_account_mismatch", "voluntary", vcase({**VBASE, "subaccountId": str(B)})),
    Case("voluntary_camel_account_mismatch", "voluntary", vcase({"action": "voluntaryCollateralExchange", "subAccountId": str(B), "walletAddress": ACCOUNT.address, "sourceAsset": "WETH", "targetUSDTAmount": "1"})),
    Case("voluntary_top_account_mismatch", "voluntary", vcase({"action": "voluntaryCollateralExchange", "walletAddress": ACCOUNT.address, "sourceAsset": "WETH", "targetUSDTAmount": "1"}, top={"subaccountId": str(B)})),
    Case("voluntary_dual_lower_signed_camel_other", "voluntary", vcase({**VBASE, "subAccountId": str(B)})),
    Case("voluntary_dual_lower_other_camel_signed", "voluntary", vcase({**VBASE, "subaccountId": str(B), "subAccountId": str(A)})),
    Case("voluntary_action_exchange_same_fields", "voluntary", vcase({**VBASE, "action": "exchangeCollateral"})),
    Case("voluntary_action_exchange_exchange_fields", "voluntary", vcase({"action": "exchangeCollateral", "subAccountId": str(A), "walletAddress": ACCOUNT.address, "fromSymbol": "WETH", "toSymbol": "USDT", "fromAmount": "0.0001"})),
    Case("voluntary_target_mismatch", "voluntary", vcase({**VBASE, "targetUSDTAmount": "1000000"})),
    Case("voluntary_source_mismatch", "voluntary", vcase({**VBASE, "sourceAsset": "cbBTC"})),
    Case("voluntary_missing_target", "voluntary", vcase({k: v for k, v in VBASE.items() if k != "targetUSDTAmount"})),
    Case("voluntary_missing_source", "voluntary", vcase({k: v for k, v in VBASE.items() if k != "sourceAsset"})),

    Case("exchange_canonical_camel", "exchange", ecase(dict(EBASE))),
    Case("exchange_lower_account", "exchange", ecase({**EBASE, "subAccountId": None, "subaccountId": str(A)})),
    Case("exchange_no_wallet", "exchange", ecase({k: v for k, v in EBASE.items() if k != "walletAddress"})),
    Case("exchange_action_voluntary_exchange_fields", "exchange", ecase({**EBASE, "action": "voluntaryCollateralExchange"})),
    Case("exchange_action_voluntary_translated_fields", "exchange", ecase({"action": "voluntaryCollateralExchange", "subaccountId": str(A), "walletAddress": ACCOUNT.address, "sourceAsset": "WETH", "targetUSDTAmount": "1"})),
    Case("exchange_account_mismatch", "exchange", ecase({**EBASE, "subAccountId": str(B)})),
    Case("exchange_amount_mismatch", "exchange", ecase({**EBASE, "fromAmount": "1000000"})),
    Case("exchange_to_symbol_mismatch", "exchange", ecase({**EBASE, "toSymbol": "cbBTC"})),
    Case("exchange_from_symbol_mismatch", "exchange", ecase({**EBASE, "fromSymbol": "cbBTC"})),
    Case("exchange_dual_account_conflict", "exchange", ecase({**EBASE, "subaccountId": str(B)})),

    Case("modify_orderid_canonical", "modify-order", mcase(dict(MBASE))),
    Case("modify_cloid_canonical", "modify-cloid", mcase(dict(MCBASE), cloid=True)),
    Case("modify_cloid_upper_ID_alias", "modify-cloid", mcase({**MCBASE, "clientOrderId": None, "clientOrderID": CLOID_A}, cloid=True)),
    Case("modify_order_signature_wire_cloid_only", "modify-order", mcase({"action": "modifyOrder", "subAccountId": str(A), "walletAddress": ACCOUNT.address, "clientOrderId": CLOID_A, "price": "1"})),
    Case("modify_cloid_signature_wire_order_only", "modify-cloid", mcase(dict(MBASE), cloid=True)),
    Case("modify_order_signature_both_fields", "modify-order", mcase({**MBASE, "clientOrderId": CLOID_B})),
    Case("modify_cloid_signature_both_fields", "modify-cloid", mcase({**MCBASE, "orderId": str(ORDER_B)}, cloid=True)),
    Case("modify_orderid_mismatch", "modify-order", mcase({**MBASE, "orderId": str(ORDER_B)})),
    Case("modify_cloid_mismatch", "modify-cloid", mcase({**MCBASE, "clientOrderId": CLOID_B}, cloid=True)),
    Case("modify_cloid_action_alias", "modify-cloid", mcase({**MCBASE, "action": "modifyOrderByCloid"}, cloid=True)),
    Case("modify_client_order_action_alias", "modify-cloid", mcase({**MCBASE, "action": "modifyOrderByClientOrderId"}, cloid=True)),

    Case("hidden_modify_order_batch", "hidden", gcase("modifyOrderBatch", {"action": "modifyOrderBatch", "subAccountId": str(A), "walletAddress": ACCOUNT.address, "orders": []})),
    Case("hidden_place_isolated_order", "hidden", gcase("placeIsolatedOrder", {"action": "placeIsolatedOrder", "subAccountId": str(A), "walletAddress": ACCOUNT.address, "symbol": "BTC-USDT"})),
    Case("hidden_update_isolated_margin", "hidden", gcase("updateIsolatedMargin", {"action": "updateIsolatedMargin", "subAccountId": str(A), "walletAddress": ACCOUNT.address, "symbol": "BTC-USDT", "amount": "1"})),
]


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        seen = False
        total = 0
        for key in ("subAccountIds", "managedSubAccountIds", "delegatedSubAccountIds"):
            value = response.get(key)
            if isinstance(value, list):
                seen = True
                total += len(value)
        return total if seen else None
    return None


def summarize(case: Case, status: int, raw: bytes, elapsed: float) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    code = error.get("code") if isinstance(error, dict) else None
    text = str(message or "")
    return {
        "name": case.name,
        "family": case.family,
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": code,
        "messageRedacted": redact(message),
        "messageSha256": sha(text) if text else None,
        "mentionsSyntheticSigner": abbrev(ACCOUNT.address).lower() in text.lower(),
        "bodySha256": sha(raw),
        "bodyBytes": len(raw),
        "elapsedMs": round(elapsed * 1000, 2),
    }


def main() -> None:
    status, raw, _ = post(INFO, {"params": {"action": "getSubAccountIds", "walletAddress": ACCOUNT.address, "includeDelegations": True}})
    parsed = json.loads(raw)
    count = account_count(parsed.get("response") if isinstance(parsed, dict) else None)
    if status != 200 or count != 0:
        raise RuntimeError(f"synthetic signer preflight failed: status={status}, count={count}")

    base_nonce = int(time.time() * 1000)
    results: list[dict[str, Any]] = []
    for index, case in enumerate(CASES):
        payload = case.build(base_nonce + index * 11 + 1)
        results.append(summarize(case, *post(TRADE, payload)))
        if index + 1 < len(CASES):
            time.sleep(0.32)

    families: dict[str, dict[str, Any]] = {}
    for family in sorted({item["family"] for item in results}):
        items = [item for item in results if item["family"] == family]
        families[family] = {
            "caseCount": len(items),
            "httpStatuses": sorted({item["httpStatus"] for item in items}),
            "errorCodes": sorted({str(item["errorCode"]) for item in items}),
            "syntheticSignerRecoveryCases": [item["name"] for item in items if item["mentionsSyntheticSigner"]],
            "uniqueMessageCount": len({item["messageSha256"] for item in items}),
        }

    output = {
        "safety": "Deterministic zero-account signer and nonexistent identifiers; no request can pass ownership or mutate state.",
        "syntheticAddress": ACCOUNT.address,
        "syntheticAddressAbbreviation": abbrev(ACCOUNT.address),
        "syntheticAccountCount": count,
        "caseCount": len(results),
        "families": families,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"caseCount": len(results), "families": families}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
