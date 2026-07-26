#!/usr/bin/env python3
"""Validate whether api.synthetix.io and papi.synthetix.io form a replay boundary.

Safety constraints:
- deterministic synthetic EOAs confirmed to own/manage/delegate zero accounts;
- deliberately nonexistent valid-range subaccount IDs for all signed requests;
- only updateLeverage is used as a write-shaped action, so account authorization must fail;
- public Ethereum receipts and unsigned account-discovery queries only for correlation;
- no real signature, credential, account ID, balance, order, or state mutation;
- raw public wallet/account identifiers are hashed before persistence.
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

OUT = pathlib.Path("api_alias_replay")
OUT.mkdir(parents=True, exist_ok=True)

HOSTS = {
    "papi": "https://papi.synthetix.io",
    "api": "https://api.synthetix.io",
}
INFO_PATH = "/v1/info"
TRADE_PATH = "/v1/trade"
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
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 3 * 1024 * 1024
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
TARGET_ACCOUNT = 8_300_000_000_000_731

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
UPDATE_TYPES = {
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
    text = ADDRESS_RE.sub("<address>", str(value))
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:1000]


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    body = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise RuntimeError("response too large")
            return response.status, data, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_BODY + 1)
        return exc.code, data, dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


def get_url(url: str, timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"}, method="GET")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise RuntimeError("response too large")
            return response.status, data, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_BODY + 1)
        return exc.code, data, dict(exc.headers.items()) if exc.headers else {}, time.monotonic() - started


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


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float, signer: str | None = None) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    raw_message = str(error_message) if error_message is not None else ""
    addresses = [item.lower() for item in ADDRESS_RE.findall(raw_message)]
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorCategory": error.get("category") if isinstance(error, dict) else None,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(raw_message) if raw_message else None,
        "mentionsExpectedSigner": signer.lower() in addresses if signer else None,
        "responseSchema": schema(response),
        "responseCount": len(response) if isinstance(response, (list, dict)) else None,
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "contentType": headers.get("Content-Type"),
        "server": headers.get("Server"),
        "requestId": (parsed.get("request_id") if isinstance(parsed, dict) else None)
        or (parsed.get("requestId") if isinstance(parsed, dict) else None)
        or headers.get("X-Request-Id")
        or headers.get("x-request-id"),
    }


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for base in RPC_URLS:
        try:
            status, body, _, _ = post_json(base, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                errors.append(str(parsed.get("error")))
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError("RPC failed: " + " | ".join(errors))


def public_beneficiaries() -> list[str]:
    values: list[str] = []
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
                address = to_checksum_address("0x" + str(topics[2])[-40:])
                if address not in values:
                    values.append(address)
    return values[:4]


def parse_account_sets(parsed: Any) -> dict[str, set[str]]:
    result = {"owned": set(), "delegated": set(), "managed": set()}
    if not isinstance(parsed, dict) or parsed.get("status") != "ok":
        return result
    response = parsed.get("response")
    if isinstance(response, list):
        result["owned"] = {str(v) for v in response}
    elif isinstance(response, dict):
        result["owned"] = {str(v) for v in response.get("subAccountIds", []) or []}
        result["delegated"] = {str(v) for v in response.get("delegatedSubAccountIds", []) or []}
        result["managed"] = {str(v) for v in response.get("managedSubAccountIds", []) or []}
    return result


def discover(host_key: str, wallet: str) -> tuple[dict[str, set[str]], dict[str, Any]]:
    base = HOSTS[host_key]
    variants = [
        ("wrapped", {"params": {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}}),
        ("flat", {"action": "getSubAccountIds", "walletAddress": wallet, "includeDelegations": True}),
    ]
    attempts: list[dict[str, Any]] = []
    best_sets = {"owned": set(), "delegated": set(), "managed": set()}
    for variant, payload in variants:
        status, body, headers, elapsed = post_json(base + INFO_PATH, payload)
        item = summarize(f"{host_key}_{variant}", status, body, headers, elapsed)
        parsed = parse_json(body)
        sets = parse_account_sets(parsed)
        item["counts"] = {k: len(v) for k, v in sets.items()}
        attempts.append(item)
        if any(sets.values()):
            best_sets = sets
            break
        if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
            best_sets = sets
            break
        time.sleep(0.12)
    return best_sets, {"attempts": attempts, "counts": {k: len(v) for k, v in best_sets.items()}}


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def signed_update(account: Any, nonce: int) -> dict[str, Any]:
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
            "types": UPDATE_TYPES,
            "primaryType": "UpdateLeverage",
            "domain": DOMAIN,
            "message": message,
        }
    )
    signed = account.sign_message(encoded)
    return {
        "params": {
            "action": "updateLeverage",
            "subAccountId": str(TARGET_ACCOUNT),
            "walletAddress": account.address,
            "symbol": "BTC-USDT",
            "leverage": "1",
        },
        "nonce": nonce,
        "signature": format_signature(signed),
        "expiresAfter": expires_after,
    }


def send_trade(host_key: str, name: str, payload: dict[str, Any], signer: str) -> dict[str, Any]:
    status, body, headers, elapsed = post_json(HOSTS[host_key] + TRADE_PATH, payload)
    return summarize(name, status, body, headers, elapsed, signer=signer)


def run_sequence(first: str, second: str, key_byte: str, offset: int) -> dict[str, Any]:
    account = Account.from_key("0x" + key_byte * 32)
    nonce = int(time.time() * 1000) + offset
    payload = signed_update(account, nonce)
    synthetic_sets: dict[str, Any] = {}
    for host in HOSTS:
        sets, meta = discover(host, account.address)
        synthetic_sets[host] = {"counts": {k: len(v) for k, v in sets.items()}, "meta": meta}
    tests = []
    tests.append(send_trade(first, f"first_{first}", payload, account.address))
    time.sleep(0.25)
    tests.append(send_trade(second, f"second_{second}", payload, account.address))
    time.sleep(0.25)
    tests.append(send_trade(first, f"replay_{first}", payload, account.address))
    time.sleep(0.25)
    tests.append(send_trade(second, f"replay_{second}", payload, account.address))
    return {
        "order": [first, second, first, second],
        "signerSha256": digest(account.address.lower()),
        "targetSubaccountSha256": digest(str(TARGET_ACCOUNT)),
        "nonceSha256": digest(str(nonce)),
        "syntheticAccountDiscovery": synthetic_sets,
        "tests": tests,
    }


def main() -> None:
    root_probes: dict[str, Any] = {}
    for name, base in HOSTS.items():
        status, body, headers, elapsed = get_url(base + "/")
        root_probes[name] = summarize(f"{name}_root", status, body, headers, elapsed)

    participants = public_beneficiaries()
    correlations: list[dict[str, Any]] = []
    overlap_events = 0
    for wallet in participants:
        per_host: dict[str, Any] = {}
        sets_by_host: dict[str, dict[str, set[str]]] = {}
        for host in HOSTS:
            sets, meta = discover(host, wallet)
            sets_by_host[host] = sets
            per_host[host] = {
                "counts": {k: len(v) for k, v in sets.items()},
                "metadata": meta,
            }
            time.sleep(0.12)
        all_papi = set().union(*sets_by_host["papi"].values())
        all_api = set().union(*sets_by_host["api"].values())
        overlap = all_papi & all_api
        if overlap:
            overlap_events += 1
        correlations.append(
            {
                "walletSha256": digest(wallet.lower()),
                "hosts": per_host,
                "unionCountPapi": len(all_papi),
                "unionCountApi": len(all_api),
                "intersectionCount": len(overlap),
                "intersectionIdHashes": sorted(digest(value) for value in overlap),
            }
        )

    sequences = [
        run_sequence("api", "papi", "b1", 101),
        run_sequence("papi", "api", "b2", 202),
    ]

    output = {
        "safety": "Synthetic zero-account signers and nonexistent target account only; public reads; no real state can mutate.",
        "hosts": HOSTS,
        "rootProbes": root_probes,
        "publicParticipantCount": len(participants),
        "publicAccountOverlapParticipantCount": overlap_events,
        "publicAccountCorrelations": correlations,
        "sequences": sequences,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "publicParticipantCount": len(participants),
                "publicAccountOverlapParticipantCount": overlap_events,
                "rootStatuses": {k: v["httpStatus"] for k, v in root_probes.items()},
                "sequenceErrors": [
                    [(item["httpStatus"], item["errorCode"], item["errorMessageRedacted"]) for item in seq["tests"]]
                    for seq in sequences
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
