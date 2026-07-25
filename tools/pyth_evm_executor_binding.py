#!/usr/bin/env python3
"""Read-only binding of a compiled UUPS runtime to a live BSC deployment.

The helper performs eth_getStorageAt, eth_getCode, eth_getBlockByNumber and
eth_call only. It never signs or broadcasts a transaction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.request
from pathlib import Path
from typing import Any

IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
DEFAULT_RPCS = [
    "https://bsc-dataseed.binance.org",
    "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed.bnbchain.org",
]


def rpc(url: str, method: str, params: list[Any], request_id: int) -> Any:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()
    errors: list[str] = []
    for attempt in range(4):
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "pyth-readonly-source-binding/7.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                value = json.load(response)
            if "error" in value:
                raise RuntimeError(value["error"])
            return value["result"]
        except Exception as exc:  # Public providers can transiently fail.
            errors.append(repr(exc))
            if attempt < 3:
                time.sleep(1 + attempt)
    raise RuntimeError({"rpc": url, "method": method, "errors": errors})


def strip_cbor(bytecode: bytes) -> bytes:
    """Remove the terminal Solidity CBOR metadata section when it is well formed."""
    if len(bytecode) < 2:
        return bytecode
    size = int.from_bytes(bytecode[-2:], "big")
    if size + 2 > len(bytecode):
        return bytecode
    return bytecode[: -(size + 2)]


def zero_ranges(bytecode: bytes, ranges: list[dict[str, int]]) -> bytes:
    result = bytearray(bytecode)
    for item in ranges:
        start = item["start"]
        length = item["length"]
        if start < 0 or length <= 0 or start + length > len(result):
            raise ValueError(
                {"invalid_range": item, "runtime_length": len(result)}
            )
        result[start : start + length] = bytes(length)
    return bytes(result)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_abi_string(value: str) -> str | None:
    try:
        raw = bytes.fromhex(value.removeprefix("0x"))
        if len(raw) < 64:
            return None
        offset = int.from_bytes(raw[:32], "big")
        if offset + 32 > len(raw):
            return None
        length = int.from_bytes(raw[offset : offset + 32], "big")
        payload = raw[offset + 32 : offset + 32 + length]
        return payload.decode("utf-8", "strict")
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--rpc", action="append", dest="rpcs")
    args = parser.parse_args()

    artifact_path = Path(args.artifact)
    output_dir = Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)
    proxy = args.proxy.lower()
    rpcs = args.rpcs or DEFAULT_RPCS

    artifact = json.loads(artifact_path.read_text())
    deployed = artifact["deployedBytecode"]
    compiled = bytes.fromhex(deployed["object"].removeprefix("0x"))
    immutable_ranges = sorted(
        [
            {"start": int(ref["start"]), "length": int(ref["length"])}
            for refs in deployed.get("immutableReferences", {}).values()
            for ref in refs
        ],
        key=lambda item: (item["start"], item["length"]),
    )
    compiled_normalized = zero_ranges(compiled, immutable_ranges)

    rows: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, url in enumerate(rpcs):
        try:
            base = 1000 + index * 20
            implementation_word = rpc(
                url, "eth_getStorageAt", [proxy, IMPLEMENTATION_SLOT, "latest"], base
            )
            implementation = "0x" + implementation_word[-40:]
            runtime_hex = rpc(
                url, "eth_getCode", [implementation, "latest"], base + 1
            ).lower()
            proxy_hex = rpc(url, "eth_getCode", [proxy, "latest"], base + 2).lower()
            block = rpc(
                url, "eth_getBlockByNumber", ["latest", False], base + 3
            )
            version_raw = rpc(
                url,
                "eth_call",
                [{"to": proxy, "data": "0x54fd4d50"}, "latest"],
                base + 4,
            )

            runtime = bytes.fromhex(runtime_hex.removeprefix("0x"))
            proxy_runtime = bytes.fromhex(proxy_hex.removeprefix("0x"))
            immutable_values = [
                "0x" + runtime[r["start"] : r["start"] + r["length"]].hex()
                for r in immutable_ranges
            ]
            normalized = zero_ranges(runtime, immutable_ranges)
            rows.append(
                {
                    "rpc": url,
                    "implementation": implementation.lower(),
                    "implementation_word": implementation_word.lower(),
                    "implementation_runtime_hex": runtime_hex,
                    "proxy_runtime_hex": proxy_hex,
                    "latest_block": block,
                    "version_raw": version_raw,
                    "version": decode_abi_string(version_raw),
                    "runtime_bytes": len(runtime),
                    "runtime_sha256": sha256(runtime),
                    "proxy_runtime_bytes": len(proxy_runtime),
                    "proxy_runtime_sha256": sha256(proxy_runtime),
                    "immutable_values": immutable_values,
                    "normalized_full_sha256": sha256(normalized),
                    "normalized_stripped_sha256": sha256(strip_cbor(normalized)),
                }
            )
        except Exception as exc:
            failures.append({"rpc": url, "error": repr(exc)})

    successful_provider_count = len(rows)
    providers_identical = successful_provider_count >= 2 and (
        len({row["implementation"] for row in rows}) == 1
        and len({row["implementation_runtime_hex"] for row in rows}) == 1
        and len({row["proxy_runtime_hex"] for row in rows}) == 1
    )
    implementation_nonzero = all(
        int(row["implementation"], 16) != 0 for row in rows
    ) if rows else False
    runtime_nonempty = all(row["runtime_bytes"] > 0 for row in rows) if rows else False
    immutable_values_are_live_implementation = bool(immutable_ranges) and all(
        all(
            (int(value, 16) & ((1 << 160) - 1))
            == int(row["implementation"], 16)
            for value in row["immutable_values"]
        )
        for row in rows
    )
    full_normalized_runtime_match = bool(rows) and all(
        zero_ranges(
            bytes.fromhex(row["implementation_runtime_hex"].removeprefix("0x")),
            immutable_ranges,
        )
        == compiled_normalized
        for row in rows
    )
    cbor_stripped_normalized_runtime_match = bool(rows) and all(
        strip_cbor(
            zero_ranges(
                bytes.fromhex(
                    row["implementation_runtime_hex"].removeprefix("0x")
                ),
                immutable_ranges,
            )
        )
        == strip_cbor(compiled_normalized)
        for row in rows
    )

    result = {
        "mode": "BSC_READ_ONLY_ETH_GETSTORAGEAT_ETH_GETCODE_ETH_CALL",
        "signed_or_broadcast_transactions": 0,
        "proxy": proxy,
        "artifact": str(artifact_path),
        "immutable_references": immutable_ranges,
        "successful_provider_count": successful_provider_count,
        "provider_failures": failures,
        "compiled_runtime_bytes": len(compiled),
        "compiled_runtime_sha256": sha256(compiled),
        "compiled_normalized_full_sha256": sha256(compiled_normalized),
        "compiled_normalized_stripped_sha256": sha256(
            strip_cbor(compiled_normalized)
        ),
        "providers_identical": providers_identical,
        "implementation_nonzero": implementation_nonzero,
        "implementation_runtime_nonempty": runtime_nonempty,
        "immutable_values_are_live_implementation": immutable_values_are_live_implementation,
        "full_normalized_runtime_match": full_normalized_runtime_match,
        "cbor_stripped_normalized_runtime_match": cbor_stripped_normalized_runtime_match,
        "rows": rows,
    }
    (output_dir / "SOURCE_DEPLOYMENT_BINDING.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )

    markers = [
        "PYTH_EVM_EXECUTOR_IMMUTABLE_AWARE_BINDING_CAPTURED",
        "PUBLIC_CHAIN_MODE=READ_ONLY",
        "SIGNED_OR_BROADCAST_TRANSACTIONS=0",
        f"SUCCESSFUL_PROVIDER_COUNT={successful_provider_count}",
        f"PROVIDERS_IDENTICAL={str(providers_identical).lower()}",
        f"IMPLEMENTATION_NONZERO={str(implementation_nonzero).lower()}",
        f"IMPLEMENTATION_RUNTIME_NONEMPTY={str(runtime_nonempty).lower()}",
        "IMMUTABLE_VALUES_ARE_LIVE_IMPLEMENTATION="
        + str(immutable_values_are_live_implementation).lower(),
        f"FULL_NORMALIZED_RUNTIME_MATCH={str(full_normalized_runtime_match).lower()}",
        "CBOR_STRIPPED_NORMALIZED_RUNTIME_MATCH="
        + str(cbor_stripped_normalized_runtime_match).lower(),
        "EXECUTOR_IMPLEMENTATION="
        + (rows[0]["implementation"] if rows else "MISSING"),
    ]
    (output_dir / "BINDING_MARKERS.txt").write_text("\n".join(markers) + "\n")
    print("\n".join(markers))

    required = (
        successful_provider_count >= 2
        and providers_identical
        and implementation_nonzero
        and runtime_nonempty
        and immutable_values_are_live_implementation
        and cbor_stripped_normalized_runtime_match
    )
    return 0 if required else 1


if __name__ == "__main__":
    raise SystemExit(main())
