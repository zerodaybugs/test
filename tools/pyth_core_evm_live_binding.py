#!/usr/bin/env python3
"""Read-only exact-source binding for the public Pyth Core EVM proxy."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import time
import urllib.request
from typing import Any

IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
RPCS = [
    "https://bsc-dataseed.binance.org",
    "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed.bnbchain.org",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rpc(url: str, method: str, params: list[Any], request_id: int) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
    errors: list[str] = []
    for attempt in range(5):
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "content-type": "application/json",
                "accept": "application/json",
                "user-agent": "pyth-core-readonly-binding/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                obj = json.load(response)
            if "error" in obj:
                raise RuntimeError(obj["error"])
            return obj["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
            if attempt < 4:
                time.sleep(attempt + 1)
    raise RuntimeError({"rpc": url, "method": method, "errors": errors})


def get_json(url: str) -> Any:
    errors: list[str] = []
    for attempt in range(5):
        request = urllib.request.Request(
            url,
            headers={"accept": "application/json", "user-agent": "pyth-core-readonly-binding/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
            if attempt < 4:
                time.sleep(attempt + 1)
    raise RuntimeError({"url": url, "errors": errors})


def strip_cbor(runtime: bytes) -> bytes:
    if len(runtime) < 2:
        return runtime
    size = int.from_bytes(runtime[-2:], "big") + 2
    return runtime[:-size] if size <= len(runtime) else runtime


def fetch_verified_standard_json(implementation: str, out: pathlib.Path) -> tuple[dict[str, Any], str]:
    legacy_url = (
        "https://optimism.blockscout.com/api?module=contract&action=getsourcecode&address=" + implementation
    )
    response = get_json(legacy_url)
    (out / "blockscout-source-response.json").write_text(
        json.dumps(response, indent=2, sort_keys=True) + "\n"
    )
    rows = response.get("result", []) if isinstance(response, dict) else []
    if not rows or not isinstance(rows[0], dict):
        raise RuntimeError({"invalid_blockscout_response": response})
    row = rows[0]
    source = str(row.get("SourceCode") or "").strip()
    compiler = str(row.get("CompilerVersion") or "")
    if not source or not compiler:
        raise RuntimeError({"missing_source_or_compiler": row})
    if source.startswith("{{") and source.endswith("}}"):
        source = source[1:-1]
    standard = json.loads(source)
    if not isinstance(standard, dict) or "sources" not in standard:
        raise RuntimeError("verified source is not Solidity standard JSON")
    standard.setdefault("language", "Solidity")
    settings = standard.setdefault("settings", {})
    settings["outputSelection"] = {
        "*": {"*": ["evm.deployedBytecode.object", "metadata"]}
    }
    return standard, compiler


def compiler_semver(value: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+)", value)
    if not match:
        raise RuntimeError({"invalid_compiler_version": value})
    return match.group(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--solc", required=True)
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    proxy = args.proxy.lower()

    rows: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, url in enumerate(RPCS):
        try:
            chain_id = rpc(url, "eth_chainId", [], 100 + index * 10)
            block = rpc(url, "eth_getBlockByNumber", ["latest", False], 101 + index * 10)
            word = rpc(url, "eth_getStorageAt", [proxy, IMPLEMENTATION_SLOT, "latest"], 102 + index * 10)
            implementation = ("0x" + word[-40:]).lower()
            proxy_code = rpc(url, "eth_getCode", [proxy, "latest"], 103 + index * 10).lower()
            implementation_code = rpc(
                url, "eth_getCode", [implementation, "latest"], 104 + index * 10
            ).lower()
            rows.append(
                {
                    "rpc": url,
                    "chain_id": chain_id,
                    "latest_block_number": block.get("number"),
                    "latest_block_hash": block.get("hash"),
                    "implementation": implementation,
                    "proxy_code_hex": proxy_code,
                    "implementation_code_hex": implementation_code,
                    "proxy_code_sha256": sha256(bytes.fromhex(proxy_code.removeprefix("0x"))),
                    "implementation_code_sha256": sha256(
                        bytes.fromhex(implementation_code.removeprefix("0x"))
                    ),
                }
            )
        except Exception as exc:  # noqa: BLE001
            failures.append({"rpc": url, "error": repr(exc)})

    if len(rows) < 2:
        raise RuntimeError({"successful_provider_count": len(rows), "failures": failures})
    providers_identical = (
        len({row["implementation"] for row in rows}) == 1
        and len({row["proxy_code_hex"] for row in rows}) == 1
        and len({row["implementation_code_hex"] for row in rows}) == 1
    )
    implementation = rows[0]["implementation"]
    live = bytes.fromhex(rows[0]["implementation_code_hex"].removeprefix("0x"))
    if int(implementation, 16) == 0 or not live:
        raise RuntimeError("implementation is zero or has empty runtime")

    standard, explorer_compiler = fetch_verified_standard_json(implementation, out)
    if compiler_semver(explorer_compiler) != "0.8.4":
        raise RuntimeError({"unexpected_compiler": explorer_compiler})
    (out / "standard-json-input.json").write_text(
        json.dumps(standard, indent=2, sort_keys=True) + "\n"
    )

    completed = subprocess.run(
        [args.solc, "--standard-json"],
        input=json.dumps(standard).encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    (out / "solc-output.json").write_bytes(completed.stdout)
    (out / "solc-stderr.txt").write_bytes(completed.stderr)
    if completed.returncode != 0:
        raise RuntimeError({"solc_returncode": completed.returncode})
    compiled_json = json.loads(completed.stdout)
    fatal = [item for item in compiled_json.get("errors", []) if item.get("severity") == "error"]
    if fatal:
        raise RuntimeError({"solc_errors": fatal})

    candidates: list[tuple[str, str, str]] = []
    for source_name, contracts in compiled_json.get("contracts", {}).items():
        for contract_name, artifact in contracts.items():
            object_hex = artifact.get("evm", {}).get("deployedBytecode", {}).get("object", "")
            if contract_name == "PythUpgradable" and object_hex:
                candidates.append((source_name, contract_name, object_hex))
    if len(candidates) != 1:
        raise RuntimeError({"PythUpgradable_candidates": [(a, b) for a, b, _ in candidates]})
    source_name, contract_name, object_hex = candidates[0]
    compiled = bytes.fromhex(object_hex.removeprefix("0x"))
    full_match = compiled == live
    stripped_match = strip_cbor(compiled) == strip_cbor(live)

    result = {
        "mode": "BSC_READ_ONLY_SOURCE_DEPLOYMENT_BINDING",
        "signed_or_broadcast_transactions": 0,
        "proxy": proxy,
        "implementation_slot": IMPLEMENTATION_SLOT,
        "implementation": implementation,
        "successful_provider_count": len(rows),
        "provider_failures": failures,
        "providers_identical": providers_identical,
        "explorer_compiler_version": explorer_compiler,
        "compiled_source_name": source_name,
        "compiled_contract_name": contract_name,
        "live_runtime_bytes": len(live),
        "compiled_runtime_bytes": len(compiled),
        "live_runtime_sha256": sha256(live),
        "compiled_runtime_sha256": sha256(compiled),
        "live_stripped_sha256": sha256(strip_cbor(live)),
        "compiled_stripped_sha256": sha256(strip_cbor(compiled)),
        "full_runtime_match": full_match,
        "cbor_stripped_runtime_match": stripped_match,
        "rows": rows,
    }
    (out / "SOURCE_DEPLOYMENT_BINDING.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    markers = [
        "PYTH_CORE_EVM_SOURCE_DEPLOYMENT_BINDING_CAPTURED",
        "PUBLIC_CHAIN_MODE=READ_ONLY",
        "SIGNED_OR_BROADCAST_TRANSACTIONS=0",
        f"SUCCESSFUL_PROVIDER_COUNT={len(rows)}",
        f"PROVIDERS_IDENTICAL={str(providers_identical).lower()}",
        f"IMPLEMENTATION_NONZERO={str(int(implementation, 16) != 0).lower()}",
        f"IMPLEMENTATION_RUNTIME_NONEMPTY={str(bool(live)).lower()}",
        f"FULL_RUNTIME_MATCH={str(full_match).lower()}",
        f"CBOR_STRIPPED_RUNTIME_MATCH={str(stripped_match).lower()}",
        f"IMPLEMENTATION={implementation}",
        f"COMPILER_VERSION={explorer_compiler}",
    ]
    (out / "BINDING_MARKERS.txt").write_text("\n".join(markers) + "\n")
    print("\n".join(markers))
    if not providers_identical or not stripped_match:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
