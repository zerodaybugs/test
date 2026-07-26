#!/usr/bin/env python3
"""Passive current-state drift collector for the in-scope Synthetix assets.

Safety properties:
- public HTTPS GET requests to the three in-scope websites only;
- public Ethereum JSON-RPC reads only;
- no wallet connection, signature, transaction, credential, account ID or mutation;
- same-origin JavaScript graph collection with strict file/byte caps;
- output contains only public deployment metadata and public source assets.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from typing import Any

from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address

OUT = pathlib.Path("synthetix_deployment_drift")
ASSETS = OUT / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; authorized-passive-security-review/1.0)"
MAX_HTTP_BODY = 20 * 1024 * 1024
MAX_GRAPH_FILES = 350
MAX_GRAPH_BYTES = 35 * 1024 * 1024

SITES = {
    "exchange": "https://exchange.synthetix.io/",
    "root": "https://www.synthetix.io/",
    "governance": "https://governance.synthetix.io/",
}
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)

DEPOSIT_PROXY = to_checksum_address("0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B")
PERMISSIONS_PROXY = to_checksum_address("0x45F91031b33Da2585932c8f1cdFF0faa6cD329ae")
LENS = to_checksum_address("0x99E61877aF9Bc6805BCc3813F655D94Ed5f3782A")
EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BASELINE = {
    "exchangeRelease": "v4-frontend@20260714",
    "depositImplementation": "0xff6611190b48cc920ef3c5dcbd356bf2c20d731f",
    "permissionsImplementation": "0xf06e7b50a214d8437221baadd04e0878f232db5e",
}

ROLE_NAMES = (
    "DEFAULT_ADMIN_ROLE",
    "OWNER_ROLE",
    "MANAGER_ROLE",
    "RELAYER_ROLE",
    "WATCHER_ROLE",
    "TELLER_ROLE",
    "GUARDIAN_ROLE",
    "AUTHORIZED_TRADER_ROLE",
)

INTEREST_PATTERNS = {
    "sessionHandoff": rb"sessionHandoff",
    "privateKey": rb"privateKey",
    "exportPrivateKey": rb"exportPrivateKey",
    "importPrivateKey": rb"importPrivateKey",
    "postMessage": rb"postMessage",
    "eventOrigin": rb"event\.origin",
    "sentry": rb"sentry|Sentry",
    "posthog": rb"posthog|PostHog",
    "beneficiary": rb"beneficiary",
    "subAccountId": rb"subAccountId",
    "withdrawCollateral": rb"withdrawCollateral",
    "addDelegatedSigner": rb"addDelegatedSigner",
    "WETH": rb"WETH",
    "USDT": rb"USDT",
}


def sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def http_get(url: str, timeout: int = 45) -> tuple[int, bytes, dict[str, str], str, float]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "*/*"},
        method="GET",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_HTTP_BODY + 1)
            if len(body) > MAX_HTTP_BODY:
                raise ValueError("response too large")
            return response.status, body, dict(response.headers.items()), response.geturl(), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_HTTP_BODY + 1)
        return exc.code, body, dict(exc.headers.items()) if exc.headers else {}, exc.geturl(), time.monotonic() - started


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_HTTP_BODY + 1)
            if len(body) > MAX_HTTP_BODY:
                raise ValueError("response too large")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_HTTP_BODY + 1)


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                errors.append(f"{url}:{status}:{parsed.get('error')}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}:{type(exc).__name__}")
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def eth_call(to: str, signature: str, arg_types: list[str] | None = None, args: list[Any] | None = None) -> bytes:
    data = selector(signature)
    if arg_types:
        data += encode(arg_types, args or [])
    raw = rpc("eth_call", [{"to": to, "data": "0x" + data.hex()}, "latest"])
    return bytes.fromhex(raw.removeprefix("0x"))


def storage_address(proxy: str, slot: str) -> str:
    raw = rpc("eth_getStorageAt", [proxy, slot, "latest"])
    return to_checksum_address("0x" + raw[-40:])


def code_snapshot(address: str) -> dict[str, Any]:
    code_hex = rpc("eth_getCode", [address, "latest"])
    code = bytes.fromhex(code_hex.removeprefix("0x"))
    eip7702_target = None
    if len(code) == 23 and code[:3] == b"\xef\x01\x00":
        eip7702_target = to_checksum_address("0x" + code[3:].hex())
    return {
        "address": to_checksum_address(address),
        "codeBytes": len(code),
        "codeSha256": sha256(code),
        "eip7702DelegationTarget": eip7702_target,
    }


def role_value(contract: str, name: str) -> bytes:
    if name == "DEFAULT_ADMIN_ROLE":
        return b"\x00" * 32
    raw = eth_call(contract, f"{name}()")
    if len(raw) < 32:
        raise ValueError(f"short role value for {name}")
    return raw[-32:]


def role_members(contract: str, role: bytes) -> list[str]:
    count_raw = eth_call(contract, "getRoleMemberCount(bytes32)", ["bytes32"], [role])
    count = int.from_bytes(count_raw[-32:], "big")
    if count > 100:
        raise ValueError(f"unexpected role member count {count}")
    result: list[str] = []
    for index in range(count):
        raw = eth_call(contract, "getRoleMember(bytes32,uint256)", ["bytes32", "uint256"], [role, index])
        result.append(to_checksum_address("0x" + raw[-20:].hex()))
    return result


def try_safe_snapshot(address: str) -> dict[str, Any] | None:
    try:
        owners_raw = eth_call(address, "getOwners()")
        owners = list(decode(["address[]"], owners_raw)[0])
        threshold_raw = eth_call(address, "getThreshold()")
        threshold = int.from_bytes(threshold_raw[-32:], "big")
        return {
            "address": to_checksum_address(address),
            "threshold": threshold,
            "owners": [to_checksum_address(owner) for owner in owners],
        }
    except Exception:
        return None


def extract_urls(base_url: str, body: bytes) -> set[str]:
    text = body.decode("utf-8", "ignore")
    candidates: set[str] = set()
    patterns = (
        r"(?:src|href)=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']",
        r"(?:import\s*\(|from\s*)[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']",
        r"[\"']((?:\./|/)[^\"']+\.js(?:\?[^\"']*)?)[\"']",
    )
    for pattern in patterns:
        for value in re.findall(pattern, text):
            resolved = urllib.parse.urljoin(base_url, value)
            if urllib.parse.urlparse(resolved).scheme in {"http", "https"}:
                candidates.add(resolved)
    return candidates


def asset_name(site: str, url: str, digest: str) -> pathlib.Path:
    parsed = urllib.parse.urlparse(url)
    suffix = pathlib.Path(parsed.path).suffix or ".bin"
    return ASSETS / f"{site}_{digest[:20]}{suffix}"


def collect_site(site: str, start_url: str) -> dict[str, Any]:
    start_status, start_body, start_headers, final_url, elapsed = http_get(start_url)
    origin = f"{urllib.parse.urlparse(final_url).scheme}://{urllib.parse.urlparse(final_url).netloc}"
    queue: deque[str] = deque(sorted(extract_urls(final_url, start_body)))
    seen: set[str] = set()
    manifest: list[dict[str, Any]] = []
    total_bytes = 0

    html_digest = sha256(start_body)
    html_path = asset_name(site + "_html", final_url, html_digest)
    html_path.write_bytes(start_body)
    manifest.append({
        "url": final_url,
        "status": start_status,
        "contentType": start_headers.get("Content-Type"),
        "bytes": len(start_body),
        "sha256": html_digest,
        "savedAs": str(html_path.relative_to(OUT)),
    })
    total_bytes += len(start_body)

    while queue and len(seen) < MAX_GRAPH_FILES and total_bytes < MAX_GRAPH_BYTES:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        parsed = urllib.parse.urlparse(url)
        if f"{parsed.scheme}://{parsed.netloc}" != origin:
            continue
        try:
            status, body, headers, resolved, item_elapsed = http_get(url)
        except Exception as exc:  # noqa: BLE001
            manifest.append({"url": url, "errorType": type(exc).__name__})
            continue
        digest_value = sha256(body)
        saved = asset_name(site, resolved, digest_value)
        saved.write_bytes(body)
        item = {
            "url": resolved,
            "status": status,
            "contentType": headers.get("Content-Type"),
            "bytes": len(body),
            "sha256": digest_value,
            "elapsedMs": round(item_elapsed * 1000, 2),
            "savedAs": str(saved.relative_to(OUT)),
        }
        if body:
            item["interestCounts"] = {
                key: len(re.findall(pattern, body, flags=re.IGNORECASE))
                for key, pattern in INTEREST_PATTERNS.items()
                if re.search(pattern, body, flags=re.IGNORECASE)
            }
        manifest.append(item)
        total_bytes += len(body)
        if status == 200 and len(body) <= 8 * 1024 * 1024:
            for child in sorted(extract_urls(resolved, body)):
                if child not in seen:
                    queue.append(child)

    aggregate_interest: dict[str, int] = {}
    for item in manifest:
        for key, count in item.get("interestCounts", {}).items():
            aggregate_interest[key] = aggregate_interest.get(key, 0) + int(count)

    all_text = start_body.decode("utf-8", "ignore")
    for item in manifest:
        saved_as = item.get("savedAs")
        if saved_as and str(saved_as).endswith(".js"):
            try:
                all_text += "\n" + (OUT / saved_as).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass
    releases = sorted(set(re.findall(r"(?:v4-frontend|synthetix[-_a-zA-Z0-9]*)@\d{8,}", all_text)))
    commit_like = sorted(set(re.findall(r"\b[a-f0-9]{40}\b", all_text)))[:200]
    return {
        "requestedUrl": start_url,
        "finalUrl": final_url,
        "status": start_status,
        "elapsedMs": round(elapsed * 1000, 2),
        "origin": origin,
        "assetCount": len(manifest),
        "assetBytes": total_bytes,
        "releases": releases,
        "commitLikeValues": commit_like,
        "aggregateInterestCounts": aggregate_interest,
        "graphTruncated": bool(queue) or len(seen) >= MAX_GRAPH_FILES or total_bytes >= MAX_GRAPH_BYTES,
        "manifest": manifest,
    }


def main() -> None:
    block = int(rpc("eth_blockNumber", []), 16)
    block_data = rpc("eth_getBlockByNumber", [hex(block), False])
    block_timestamp = int(block_data["timestamp"], 16)

    implementation = {
        "deposit": storage_address(DEPOSIT_PROXY, EIP1967_IMPLEMENTATION_SLOT),
        "permissions": storage_address(PERMISSIONS_PROXY, EIP1967_IMPLEMENTATION_SLOT),
        "lens": LENS,
    }
    implementation_code = {name: code_snapshot(address) for name, address in implementation.items()}

    role_records: dict[str, Any] = {}
    all_role_addresses: set[str] = set()
    for name in ROLE_NAMES:
        try:
            role = role_value(DEPOSIT_PROXY, name)
            members = role_members(DEPOSIT_PROXY, role)
            role_records[name] = {"role": "0x" + role.hex(), "members": members}
            all_role_addresses.update(members)
        except Exception as exc:  # noqa: BLE001
            role_records[name] = {"errorType": type(exc).__name__, "errorSha256": sha256(str(exc))}

    address_code = {address: code_snapshot(address) for address in sorted(all_role_addresses)}
    safes: dict[str, Any] = {}
    owner_addresses: set[str] = set()
    for address in sorted(all_role_addresses):
        snapshot = try_safe_snapshot(address)
        if snapshot:
            safes[address] = snapshot
            owner_addresses.update(snapshot["owners"])
    safe_owner_code = {address: code_snapshot(address) for address in sorted(owner_addresses)}

    sites: dict[str, Any] = {}
    for name, url in SITES.items():
        try:
            sites[name] = collect_site(name, url)
        except Exception as exc:  # noqa: BLE001
            sites[name] = {"errorType": type(exc).__name__, "errorSha256": sha256(str(exc))}

    exchange_releases = sites.get("exchange", {}).get("releases", [])
    alerts: list[dict[str, Any]] = []
    if BASELINE["exchangeRelease"] not in exchange_releases:
        alerts.append({"type": "exchange_release_drift", "baseline": BASELINE["exchangeRelease"], "current": exchange_releases})
    if implementation["deposit"].lower() != BASELINE["depositImplementation"]:
        alerts.append({"type": "deposit_implementation_drift", "baseline": BASELINE["depositImplementation"], "current": implementation["deposit"]})
    if implementation["permissions"].lower() != BASELINE["permissionsImplementation"]:
        alerts.append({"type": "permissions_implementation_drift", "baseline": BASELINE["permissionsImplementation"], "current": implementation["permissions"]})
    for category, records in (("role", address_code), ("safe_owner", safe_owner_code)):
        for address, record in records.items():
            if record.get("eip7702DelegationTarget"):
                alerts.append({"type": "eip7702_delegation", "category": category, "address": address, "target": record["eip7702DelegationTarget"]})

    summary = {
        "safety": "Public HTTPS GETs to in-scope websites and public Ethereum RPC reads only; no signatures or mutations.",
        "snapshotBlock": block,
        "snapshotTimestamp": block_timestamp,
        "baseline": BASELINE,
        "implementation": implementation,
        "implementationCode": implementation_code,
        "roles": role_records,
        "roleAddressCode": address_code,
        "safeSnapshots": safes,
        "safeOwnerCode": safe_owner_code,
        "sites": sites,
        "alerts": alerts,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (OUT / "manifest.json").write_text(
        json.dumps({name: value.get("manifest", []) for name, value in sites.items()}, indent=2),
        encoding="utf-8",
    )
    print(json.dumps({
        "snapshotBlock": block,
        "implementation": implementation,
        "roleAddressCount": len(address_code),
        "safeOwnerCount": len(safe_owner_code),
        "siteSummary": {
            name: {
                "status": value.get("status"),
                "assetCount": value.get("assetCount"),
                "assetBytes": value.get("assetBytes"),
                "releases": value.get("releases"),
                "graphTruncated": value.get("graphTruncated"),
                "errorType": value.get("errorType"),
            }
            for name, value in sites.items()
        },
        "alerts": alerts,
    }, indent=2))


if __name__ == "__main__":
    main()
