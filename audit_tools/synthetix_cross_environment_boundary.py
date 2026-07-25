#!/usr/bin/env python3
"""Read-only/synthetic production-versus-test boundary differential for Synthetix APIs.

Safety constraints:
- official `*.synthetix.io` hosts only;
- public info/status requests, public Ethereum receipts, and synthetic zero-account signatures only;
- deliberately nonexistent valid-range subaccount ID for all signed requests;
- no real credential, order, position, balance, or state-changing request can execute;
- public participant identities and account IDs are hashed before persistence.

Goals:
1. fingerprint supported action sets on `api.test.synthetix.io`;
2. determine whether production EIP-712 signatures are verified identically by the test API;
3. determine whether public production account IDs are mirrored by the test environment.
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

OUT = pathlib.Path("cross_environment_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PROD_INFO = "https://papi.synthetix.io/v1/info"
PROD_TRADE = "https://papi.synthetix.io/v1/trade"
PROD_STATUS = "https://papi.synthetix.io/v1/exchange/status"
TEST_INFO = "https://api.test.synthetix.io/v1/info"
TEST_TRADE = "https://api.test.synthetix.io/v1/trade"
TEST_STATUS = "https://api.test.synthetix.io/v1/status"
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
DEPOSIT_PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
ASSET_DEPOSITED_TOPIC = "0x8d9f8eed9603fe0e069574aaf008e644885b52d54ba86f026277ac9db1c2d08a"
DEPOSIT_TX_HASHES = (
    "0xb8099b559a99ef2e5122c7b37e2288cd21c90ab4a9cd282ebd556fac21c8618c",
    "0xff4a76000616a7bd6e7eec8dc8dd5ddc3aad54d61ae14e096b22721d1d4993fa",
    "0xff49e1668459cf9d6740fa406bb6e1714495451614bf7a0cbba287fd012d0406",
    "0x2bcf6ce3cd19759da83c531db0c37756af79371e4acd0c5e94e870c0485cd0dc",
)
SYNTHETIC = Account.from_key("0x" + "95" * 32)
TARGET_ACCOUNT = 8_300_000_000_000_001
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
SUBACTION_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "SubAccountAction": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "action", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}
LEVERAGE_TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "UpdateLeverage": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "symbol", "type": "string"},
        {"name": "leverage", "type": "string"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = ADDRESS_RE.sub("<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:900]


def http_json(
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    method: str | None = None,
    timeout: int = 45,
) -> tuple[int, bytes, dict[str, str], float]:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method=method or ("POST" if data is not None else "GET"),
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


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    raw = str(error_message) if error_message is not None else ""
    addresses = [value.lower() for value in ADDRESS_RE.findall(raw)]
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorCategory": error.get("category") if isinstance(error, dict) else None,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(raw) if raw else None,
        "errorAddressesSha256": sorted(digest(value) for value in addresses),
        "mentionsSyntheticSigner": SYNTHETIC.address.lower() in addresses,
        "responseSchema": schema(response),
        "responseCount": len(response) if isinstance(response, list) else None,
        "rateLimit": parsed.get("rateLimit") if isinstance(parsed, dict) and isinstance(parsed.get("rateLimit"), dict) else None,
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "server": headers.get("Server"),
        "requestId": (
            parsed.get("request_id") if isinstance(parsed, dict) else None
        ) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            status, body, _, _ = http_json(url, payload=payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                errors.append(str(parsed.get("error")))
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def beneficiary_from_receipt(tx_hash: str) -> str | None:
    receipt = rpc("eth_getTransactionReceipt", [tx_hash])
    if not isinstance(receipt, dict):
        return None
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        if (
            str(log.get("address", "")).lower() == DEPOSIT_PROXY.lower()
            and len(topics) >= 3
            and str(topics[0]).lower() == ASSET_DEPOSITED_TOPIC.lower()
        ):
            return "0x" + str(topics[2])[-40:]
    return None


def account_ids(url: str, wallet: str) -> tuple[dict[str, set[str]], dict[str, Any]]:
    status, body, headers, elapsed = http_json(
        url,
        payload={"params": {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}},
    )
    item = summarize("getSubAccountIds", status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    sets = {"owned": set(), "delegated": set(), "managed": set()}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            sets["owned"] = {str(value) for value in response}
        elif isinstance(response, dict):
            sets["owned"] = {str(value) for value in response.get("subAccountIds", []) or []}
            sets["delegated"] = {str(value) for value in response.get("delegatedSubAccountIds", []) or []}
            sets["managed"] = {str(value) for value in response.get("managedSubAccountIds", []) or []}
    item["counts"] = {key: len(value) for key, value in sets.items()}
    return sets, item


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def generic_payload(action: str, nonce: int) -> dict[str, Any]:
    expires_after = nonce + 300_000
    encoded = encode_typed_data(
        full_message={
            "types": SUBACTION_TYPES,
            "primaryType": "SubAccountAction",
            "domain": DOMAIN,
            "message": {
                "subAccountId": TARGET_ACCOUNT,
                "action": action,
                "nonce": nonce,
                "expiresAfter": expires_after,
            },
        }
    )
    return {
        "signature": format_signature(SYNTHETIC.sign_message(encoded)),
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": action,
            "subaccountId": str(TARGET_ACCOUNT),
            "walletAddress": SYNTHETIC.address,
        },
    }


def leverage_payload(nonce: int) -> dict[str, Any]:
    expires_after = nonce + 300_000
    message = {
        "subAccountId": TARGET_ACCOUNT,
        "symbol": "BTC-USDT",
        "leverage": "1",
        "nonce": nonce,
        "expiresAfter": expires_after,
    }
    encoded = encode_typed_data(
        full_message={
            "types": LEVERAGE_TYPES,
            "primaryType": "UpdateLeverage",
            "domain": DOMAIN,
            "message": message,
        }
    )
    return {
        "signature": format_signature(SYNTHETIC.sign_message(encoded)),
        "nonce": nonce,
        "expiresAfter": expires_after,
        "params": {
            "action": "updateLeverage",
            "subaccountId": str(TARGET_ACCOUNT),
            "walletAddress": SYNTHETIC.address,
            "symbol": "BTC-USDT",
            "leverage": "1",
        },
    }


def run_post(name: str, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    status, body, headers, elapsed = http_json(url, payload=payload)
    return summarize(name, status, body, headers, elapsed)


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": "Official hosts, public reads, public Ethereum receipts and a zero-account synthetic signer only; no state-changing request can execute.",
        "syntheticAddress": SYNTHETIC.address,
        "targetAccountSha256": digest(str(TARGET_ACCOUNT)),
        "publicActionMatrix": [],
        "signedBoundary": [],
        "accountCorrelation": [],
        "statusRoutes": [],
    }

    for name, url in (("production_status", PROD_STATUS), ("test_status", TEST_STATUS)):
        status, body, headers, elapsed = http_json(url)
        evidence["statusRoutes"].append(summarize(name, status, body, headers, elapsed))
        time.sleep(0.25)

    info_cases: list[tuple[str, dict[str, Any]]] = [
        ("getMarkets", {"params": {"action": "getMarkets"}}),
        ("getMarketPrices", {"params": {"action": "getMarketPrices"}}),
        ("getAssets", {"params": {"action": "getAssets"}}),
        ("getMids", {"params": {"action": "getMids"}}),
        ("getOpenInterest", {"params": {"action": "getOpenInterest"}}),
        ("getCollaterals", {"params": {"action": "getCollaterals"}}),
        ("getFundingRate", {"params": {"action": "getFundingRate", "symbol": "BTC-USDT"}}),
        ("getOrderbook", {"params": {"action": "getOrderbook", "symbol": "BTC-USDT", "depth": 10}}),
        ("getSubAccountIds", {"params": {"action": "getSubAccountIds", "walletAddress": SYNTHETIC.address, "includeDelegations": True}}),
    ]
    for action, payload in info_cases:
        for env, url in (("prod", PROD_INFO), ("test", TEST_INFO)):
            evidence["publicActionMatrix"].append(run_post(f"{env}_{action}", url, payload))
            time.sleep(0.25)

    base_nonce = int(time.time() * 1000) + 5_000
    signed_cases = [
        ("getPositions", generic_payload("getPositions", base_nonce)),
        ("getOpenOrders", generic_payload("getOpenOrders", base_nonce + 1)),
        ("getPortfolio", generic_payload("getPortfolio", base_nonce + 2)),
        ("updateLeverage", leverage_payload(base_nonce + 3)),
    ]
    for action, payload in signed_cases:
        for env, url in (("prod", PROD_TRADE), ("test", TEST_TRADE)):
            evidence["signedBoundary"].append(run_post(f"{env}_{action}", url, payload))
            time.sleep(0.4)

    seen_wallets: set[str] = set()
    for tx_hash in DEPOSIT_TX_HASHES:
        wallet = beneficiary_from_receipt(tx_hash)
        if not wallet or wallet.lower() in seen_wallets:
            continue
        seen_wallets.add(wallet.lower())
        prod_sets, prod_meta = account_ids(PROD_INFO, wallet)
        time.sleep(0.35)
        test_sets, test_meta = account_ids(TEST_INFO, wallet)
        intersection = {
            key: prod_sets[key] & test_sets[key]
            for key in ("owned", "delegated", "managed")
        }
        evidence["accountCorrelation"].append(
            {
                "walletSha256": digest(wallet.lower()),
                "txHashSha256": digest(tx_hash),
                "production": prod_meta,
                "test": test_meta,
                "intersectionCounts": {key: len(value) for key, value in intersection.items()},
                "intersectionIdsSha256": {
                    key: sorted(digest(value) for value in values)
                    for key, values in intersection.items()
                },
            }
        )
        time.sleep(0.4)

    def supported(items: list[dict[str, Any]], prefix: str) -> list[str]:
        out: list[str] = []
        for item in items:
            if not str(item.get("name", "")).startswith(prefix):
                continue
            message = str(item.get("errorMessageRedacted") or "").lower()
            if item.get("httpStatus") != 404 and "unsupported type" not in message and "invalid request type" not in message:
                out.append(str(item.get("name")))
        return out

    signed_by_name = {item["name"]: item for item in evidence["signedBoundary"]}
    signature_pairs: dict[str, Any] = {}
    for action, _ in signed_cases:
        prod = signed_by_name.get(f"prod_{action}", {})
        test = signed_by_name.get(f"test_{action}", {})
        signature_pairs[action] = {
            "productionStatus": prod.get("httpStatus"),
            "testStatus": test.get("httpStatus"),
            "productionMentionsSyntheticSigner": prod.get("mentionsSyntheticSigner"),
            "testMentionsSyntheticSigner": test.get("mentionsSyntheticSigner"),
            "productionErrorCode": prod.get("errorCode"),
            "testErrorCode": test.get("errorCode"),
        }

    evidence["summary"] = {
        "testSupportedPublicCases": supported(evidence["publicActionMatrix"], "test_"),
        "testSupportedSignedCases": supported(evidence["signedBoundary"], "test_"),
        "signaturePairs": signature_pairs,
        "correlatedWalletCount": len(evidence["accountCorrelation"]),
        "walletsWithAnyCrossEnvironmentAccountIdIntersection": sum(
            any(value > 0 for value in item["intersectionCounts"].values())
            for item in evidence["accountCorrelation"]
        ),
        "totalIntersectionCounts": {
            key: sum(item["intersectionCounts"][key] for item in evidence["accountCorrelation"])
            for key in ("owned", "delegated", "managed")
        },
        "caseMatrix": [
            {
                key: item.get(key)
                for key in (
                    "name", "httpStatus", "apiStatus", "errorCode", "errorMessageSha256",
                    "mentionsSyntheticSigner", "responseSchema", "bodySha256"
                )
            }
            for item in evidence["publicActionMatrix"] + evidence["signedBoundary"] + evidence["statusRoutes"]
        ],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(evidence["summary"], indent=2), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__":
    main()
