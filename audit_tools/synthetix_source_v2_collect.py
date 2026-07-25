#!/usr/bin/env python3
"""Collect exact verified source artifacts for the in-scope Synthetix contracts.

Read-only operations only:
- Ethereum JSON-RPC eth_getStorageAt / eth_getCode;
- Sourcify v2 contract lookup GET requests.
No transaction is signed, proposed, or broadcast.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("synthetix_source_v2")
OUT.mkdir(parents=True, exist_ok=True)

CHAIN_ID = 1
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 100 * 1024 * 1024

TARGETS = {
    "deposit_proxy": "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B",
    "deposit_expected_implementation": "0xff6611190b48Cc920EF3c5DCbD356bF2C20D731F",
    "permissions_registry_proxy": "0x45F91031b33Da2585932c8f1cdFF0faa6cD329ae",
    "deposit_lens": "0x99E61877aF9Bc6805BCc3813F655D94Ed5f3782A",
}


def get_bytes(url: str, timeout: int = 90) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json,*/*;q=0.5"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError(f"response exceeds {MAX_BODY} bytes")
        return body


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError(f"response exceeds {MAX_BODY} bytes")
        return json.loads(body)


def rpc(method: str, params: list[Any]) -> Any:
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            parsed = post_json(url, payload)
            if "error" in parsed:
                error = parsed.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                errors.append(f"{url}: code={code}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}")
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def decode_storage_address(raw: str) -> str:
    value = raw.removeprefix("0x").rjust(64, "0")
    return "0x" + value[-40:]


def code_hash(address: str) -> dict[str, Any]:
    code = rpc("eth_getCode", [address, "latest"])
    body = bytes.fromhex(code.removeprefix("0x")) if code not in ("0x", "") else b""
    return {
        "address": address,
        "codeBytes": len(body),
        "codeSha256": hashlib.sha256(body).hexdigest() if body else None,
    }


def sourcify_lookup(address: str) -> tuple[int | None, dict[str, Any] | None, str | None]:
    url = f"https://sourcify.dev/server/v2/contract/{CHAIN_ID}/{address}?fields=all"
    try:
        raw = get_bytes(url)
        return 200, json.loads(raw), None
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        return exc.code, None, body.decode("utf-8", errors="replace")[:2000]
    except Exception as exc:  # noqa: BLE001
        return None, None, f"{type(exc).__name__}: {exc}"


def sanitize_path(value: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value.replace("\\", "/"))
    safe_parts = [part for part in path.parts if part not in ("", ".", "..", "/")]
    return pathlib.PurePosixPath(*safe_parts) if safe_parts else pathlib.PurePosixPath("unknown.sol")


def collect_source_entries(node: Any, location: str = "root") -> list[tuple[str, str, str]]:
    """Return (logical_path, content, JSON-location) source entries from any v2 response shape."""
    found: list[tuple[str, str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            child_location = f"{location}.{key}"
            if key == "sources" and isinstance(value, dict):
                for logical_path, item in value.items():
                    if isinstance(item, dict) and isinstance(item.get("content"), str):
                        found.append((str(logical_path), item["content"], child_location))
                    elif isinstance(item, str):
                        found.append((str(logical_path), item, child_location))
            found.extend(collect_source_entries(value, child_location))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(collect_source_entries(value, f"{location}[{index}]"))
    return found


def write_contract(label: str, address: str) -> dict[str, Any]:
    target_dir = OUT / label
    target_dir.mkdir(parents=True, exist_ok=True)
    status, data, error = sourcify_lookup(address)
    record: dict[str, Any] = {
        "label": label,
        "address": address,
        "lookupStatus": status,
        "lookupError": error,
        "code": code_hash(address),
        "sourceFiles": [],
    }
    if data is None:
        (target_dir / "lookup_error.txt").write_text(error or "unknown lookup failure", encoding="utf-8")
        return record

    raw_json = json.dumps(data, indent=2, sort_keys=True)
    (target_dir / "contract_all_fields.json").write_text(raw_json, encoding="utf-8")
    record["allFieldsSha256"] = hashlib.sha256(raw_json.encode()).hexdigest()
    record["match"] = data.get("match")
    record["creationMatch"] = data.get("creationMatch")
    record["runtimeMatch"] = data.get("runtimeMatch")
    record["verifiedAt"] = data.get("verifiedAt")

    dedup: dict[tuple[str, str], tuple[str, str, str]] = {}
    for logical_path, content, location in collect_source_entries(data):
        digest = hashlib.sha256(content.encode()).hexdigest()
        dedup[(logical_path, digest)] = (logical_path, content, location)

    for index, (logical_path, content, location) in enumerate(dedup.values()):
        relative = sanitize_path(logical_path)
        output_path = target_dir / "sources" / relative
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists() and output_path.read_text(encoding="utf-8") != content:
            output_path = output_path.with_name(f"{output_path.stem}__{index}{output_path.suffix}")
        output_path.write_text(content, encoding="utf-8")
        record["sourceFiles"].append(
            {
                "logicalPath": logical_path,
                "outputPath": str(output_path),
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "bytes": len(content.encode()),
                "jsonLocation": location,
            }
        )
    return record


def main() -> None:
    live_deposit_impl = decode_storage_address(
        rpc("eth_getStorageAt", [TARGETS["deposit_proxy"], EIP1967_IMPL_SLOT, "latest"])
    )
    live_registry_impl = decode_storage_address(
        rpc("eth_getStorageAt", [TARGETS["permissions_registry_proxy"], EIP1967_IMPL_SLOT, "latest"])
    )

    addresses = {
        **TARGETS,
        "deposit_live_implementation": live_deposit_impl,
        "permissions_registry_live_implementation": live_registry_impl,
    }

    # Avoid duplicate downloads while retaining every logical label in the manifest.
    by_address: dict[str, dict[str, Any]] = {}
    records: list[dict[str, Any]] = []
    for label, address in addresses.items():
        key = address.lower()
        if key not in by_address:
            by_address[key] = write_contract(label, address)
        records.append({"label": label, "address": address, "artifactLabel": by_address[key]["label"]})

    result = {
        "safety": "Ethereum read-only RPC and Sourcify GET requests only; no transaction signed or broadcast.",
        "chainId": CHAIN_ID,
        "eip1967ImplementationSlot": EIP1967_IMPL_SLOT,
        "liveDepositImplementation": live_deposit_impl,
        "expectedDepositImplementation": TARGETS["deposit_expected_implementation"],
        "depositImplementationMatchesExpected": live_deposit_impl.lower()
        == TARGETS["deposit_expected_implementation"].lower(),
        "livePermissionsRegistryImplementation": live_registry_impl,
        "labels": records,
        "contracts": list(by_address.values()),
    }
    manifest = json.dumps(result, indent=2, sort_keys=True)
    (OUT / "manifest.json").write_text(manifest, encoding="utf-8")
    print(
        json.dumps(
            {
                "liveDepositImplementation": live_deposit_impl,
                "livePermissionsRegistryImplementation": live_registry_impl,
                "uniqueContracts": len(by_address),
                "sourceFileCounts": {
                    record["label"]: len(record.get("sourceFiles", [])) for record in by_address.values()
                },
                "lookupStatuses": {
                    record["label"]: record.get("lookupStatus") for record in by_address.values()
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
