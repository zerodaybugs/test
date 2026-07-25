#!/usr/bin/env python3
"""Read-only exact-source binding for the public Pyth Core EVM proxy.

Security properties:
- Queries public BSC RPC endpoints only.
- Pins all providers to one common block before reading proxy/implementation state.
- Resolves the EIP-1967 implementation slot.
- Reconstructs Solidity standard JSON from public Blockscout verified-source data,
  including every additional source and the explorer compiler settings.
- Compiles with the caller-supplied exact solc binary and compares runtime code.
- Never signs or broadcasts a transaction.
"""
from __future__ import annotations

import argparse
import copy
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
BLOCKSCOUT_LEGACY = (
    "https://optimism.blockscout.com/api?module=contract&action=getsourcecode&address="
)
EXPECTED_CONTRACT = "PythUpgradable"
EXPECTED_COMPILER = "0.8.4"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def rpc(url: str, method: str, params: list[Any], request_id: int) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()
    errors: list[str] = []
    for attempt in range(5):
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "content-type": "application/json",
                "accept": "application/json",
                "user-agent": "pyth-core-readonly-binding/2.0",
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
            headers={
                "accept": "application/json",
                "user-agent": "pyth-core-readonly-binding/2.0",
            },
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
    """Strip Solidity CBOR metadata using the terminal two-byte length field."""
    if len(runtime) < 2:
        return runtime
    size = int.from_bytes(runtime[-2:], "big") + 2
    if size <= 2 or size > len(runtime):
        return runtime
    return runtime[:-size]


def compiler_semver(value: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+)", value)
    if not match:
        raise RuntimeError({"invalid_compiler_version": value})
    return match.group(1)


def flatten_immutable_ranges(refs: dict[str, Any]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for entries in refs.values():
        if not isinstance(entries, list):
            raise RuntimeError({"invalid_immutable_references": refs})
        for entry in entries:
            start = int(entry["start"])
            length = int(entry["length"])
            if start < 0 or length <= 0:
                raise RuntimeError({"invalid_immutable_reference": entry})
            ranges.append((start, length))
    ranges.sort()
    previous_end = -1
    for start, length in ranges:
        if start < previous_end:
            raise RuntimeError({"overlapping_immutable_references": ranges})
        previous_end = start + length
    return ranges


def zero_ranges(data: bytes, ranges: list[tuple[int, int]]) -> bytes:
    normalized = bytearray(data)
    for start, length in ranges:
        end = start + length
        if end > len(normalized):
            raise RuntimeError(
                {"immutable_reference_out_of_bounds": [start, length, len(normalized)]}
            )
        normalized[start:end] = bytes(length)
    return bytes(normalized)


def validate_implementation_immutables(
    live: bytes, compiled: bytes, ranges: list[tuple[int, int]], implementation: str
) -> tuple[bool, bool, list[dict[str, Any]]]:
    expected_address_word = bytes(12) + bytes.fromhex(implementation.removeprefix("0x"))
    compiled_zero = True
    live_is_implementation = True
    evidence: list[dict[str, Any]] = []
    for start, length in ranges:
        live_value = live[start : start + length]
        compiled_value = compiled[start : start + length]
        compiled_zero = compiled_zero and compiled_value == bytes(length)
        live_is_implementation = (
            live_is_implementation
            and length == 32
            and live_value == expected_address_word
        )
        evidence.append(
            {
                "start": start,
                "length": length,
                "live_value": "0x" + live_value.hex(),
                "compiled_value": "0x" + compiled_value.hex(),
                "expected_live_implementation_word": "0x" + expected_address_word.hex(),
            }
        )
    return compiled_zero, live_is_implementation, evidence


def normalize_standard_json(row: dict[str, Any]) -> dict[str, Any]:
    """Create exact compiler input from Etherscan/Blockscout source metadata."""
    source = str(row.get("SourceCode") or "").strip()
    compiler = str(row.get("CompilerVersion") or "")
    if not source or not compiler:
        raise RuntimeError({"missing_source_or_compiler": sorted(row)})

    candidate = source[1:-1] if source.startswith("{{") and source.endswith("}}") else source
    standard: dict[str, Any] | None = None
    if candidate.startswith("{"):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict) and isinstance(parsed.get("sources"), dict):
                standard = parsed
        except json.JSONDecodeError:
            standard = None

    if standard is None:
        file_name = str(row.get("FileName") or "").strip()
        if not file_name:
            raise RuntimeError("verified source response lacks FileName")
        sources: dict[str, dict[str, str]] = {file_name: {"content": source}}
        for item in row.get("AdditionalSources") or []:
            if not isinstance(item, dict):
                raise RuntimeError({"invalid_additional_source": item})
            name = str(item.get("Filename") or item.get("FileName") or "").strip()
            content = str(item.get("SourceCode") or "")
            if not name or not content:
                raise RuntimeError({"incomplete_additional_source": sorted(item)})
            if name in sources and sources[name]["content"] != content:
                raise RuntimeError({"conflicting_source_unit": name})
            sources[name] = {"content": content}

        raw_settings = row.get("CompilerSettings")
        settings = copy.deepcopy(raw_settings) if isinstance(raw_settings, dict) else {}
        if "optimizer" not in settings:
            enabled = str(row.get("OptimizationUsed", "false")).lower() in {
                "1",
                "true",
                "yes",
            }
            runs = int(row.get("OptimizationRuns") or 200)
            settings["optimizer"] = {"enabled": enabled, "runs": runs}
        if row.get("EVMVersion") and "evmVersion" not in settings:
            settings["evmVersion"] = row["EVMVersion"]
        settings.setdefault("libraries", {})
        standard = {"language": "Solidity", "sources": sources, "settings": settings}

    standard.setdefault("language", "Solidity")
    settings = standard.setdefault("settings", {})
    settings["outputSelection"] = {
        "*": {
            "*": [
                "abi",
                "metadata",
                "evm.deployedBytecode.object",
                "evm.deployedBytecode.immutableReferences",
            ]
        }
    }
    return standard


def fetch_verified_standard_json(
    implementation: str, out: pathlib.Path
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    response = get_json(BLOCKSCOUT_LEGACY + implementation)
    write_json(out / "blockscout-source-response.json", response)
    rows = response.get("result", []) if isinstance(response, dict) else []
    if not rows or not isinstance(rows[0], dict):
        raise RuntimeError({"invalid_blockscout_response": response})
    row = rows[0]
    standard = normalize_standard_json(row)
    compiler = str(row.get("CompilerVersion") or "")
    manifest = {
        "address": row.get("Address"),
        "contract_name": row.get("ContractName"),
        "file_name": row.get("FileName"),
        "compiler_version": compiler,
        "compiler_settings": row.get("CompilerSettings"),
        "source_unit_count": len(standard.get("sources", {})),
        "source_units": sorted(standard.get("sources", {})),
    }
    write_json(out / "verified-source-manifest.json", manifest)
    return standard, compiler, row


def query_common_block() -> tuple[str, list[dict[str, Any]], list[dict[str, str]]]:
    heads: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, url in enumerate(RPCS):
        try:
            chain_id = rpc(url, "eth_chainId", [], 10 + index * 10)
            latest = rpc(url, "eth_getBlockByNumber", ["latest", False], 11 + index * 10)
            heads.append(
                {
                    "rpc": url,
                    "chain_id": chain_id,
                    "latest_block_number": latest.get("number"),
                    "latest_block_hash": latest.get("hash"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            failures.append({"rpc": url, "stage": "head", "error": repr(exc)})
    if len(heads) < 2:
        raise RuntimeError({"successful_head_provider_count": len(heads), "failures": failures})
    if len({row["chain_id"] for row in heads}) != 1:
        raise RuntimeError({"provider_chain_id_mismatch": heads})
    common_number = min(int(row["latest_block_number"], 16) for row in heads)
    return hex(common_number), heads, failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--solc", required=True)
    args = parser.parse_args()

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    proxy = args.proxy.lower()

    common_block, heads, failures = query_common_block()
    rows: list[dict[str, Any]] = []
    for index, head in enumerate(heads):
        url = str(head["rpc"])
        try:
            block = rpc(url, "eth_getBlockByNumber", [common_block, False], 100 + index * 10)
            if not block or str(block.get("number", "")).lower() != common_block.lower():
                raise RuntimeError({"missing_common_block": common_block, "block": block})
            word = rpc(
                url,
                "eth_getStorageAt",
                [proxy, IMPLEMENTATION_SLOT, common_block],
                101 + index * 10,
            )
            implementation = ("0x" + str(word)[-40:]).lower()
            proxy_code = str(
                rpc(url, "eth_getCode", [proxy, common_block], 102 + index * 10)
            ).lower()
            implementation_code = str(
                rpc(
                    url,
                    "eth_getCode",
                    [implementation, common_block],
                    103 + index * 10,
                )
            ).lower()
            rows.append(
                {
                    "rpc": url,
                    "chain_id": head["chain_id"],
                    "pinned_block_number": block.get("number"),
                    "pinned_block_hash": block.get("hash"),
                    "implementation": implementation,
                    "proxy_code_hex": proxy_code,
                    "implementation_code_hex": implementation_code,
                    "proxy_code_sha256": sha256(
                        bytes.fromhex(proxy_code.removeprefix("0x"))
                    ),
                    "implementation_code_sha256": sha256(
                        bytes.fromhex(implementation_code.removeprefix("0x"))
                    ),
                }
            )
        except Exception as exc:  # noqa: BLE001
            failures.append({"rpc": url, "stage": "pinned_state", "error": repr(exc)})

    if len(rows) < 2:
        raise RuntimeError({"successful_provider_count": len(rows), "failures": failures})
    providers_identical = (
        len({row["pinned_block_hash"] for row in rows}) == 1
        and len({row["implementation"] for row in rows}) == 1
        and len({row["proxy_code_hex"] for row in rows}) == 1
        and len({row["implementation_code_hex"] for row in rows}) == 1
    )
    implementation = rows[0]["implementation"]
    live = bytes.fromhex(rows[0]["implementation_code_hex"].removeprefix("0x"))
    if int(implementation, 16) == 0 or not live:
        raise RuntimeError("implementation is zero or has empty runtime")

    standard, explorer_compiler, explorer_row = fetch_verified_standard_json(
        implementation, out
    )
    if compiler_semver(explorer_compiler) != EXPECTED_COMPILER:
        raise RuntimeError({"unexpected_compiler": explorer_compiler})
    if str(explorer_row.get("ContractName") or "") != EXPECTED_CONTRACT:
        raise RuntimeError({"unexpected_contract": explorer_row.get("ContractName")})
    write_json(out / "standard-json-input.json", standard)

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
    fatal = [
        item
        for item in compiled_json.get("errors", [])
        if item.get("severity") == "error"
    ]
    if fatal:
        raise RuntimeError({"solc_errors": fatal})

    candidates: list[tuple[str, str, dict[str, Any]]] = []
    for source_name, contracts in compiled_json.get("contracts", {}).items():
        for contract_name, artifact in contracts.items():
            deployed = artifact.get("evm", {}).get("deployedBytecode", {})
            if contract_name == EXPECTED_CONTRACT and deployed.get("object"):
                candidates.append((source_name, contract_name, deployed))
    if len(candidates) != 1:
        raise RuntimeError(
            {
                "PythUpgradable_candidates": [
                    (source, contract) for source, contract, _ in candidates
                ]
            }
        )
    source_name, contract_name, deployed = candidates[0]
    object_hex = str(deployed["object"])
    if "__" in object_hex or re.search(r"\$[0-9a-fA-F]{34}\$", object_hex):
        raise RuntimeError("compiled runtime contains unresolved link references")
    compiled = bytes.fromhex(object_hex.removeprefix("0x"))
    immutable_refs = deployed.get("immutableReferences") or {}
    immutable_ranges = flatten_immutable_ranges(immutable_refs)
    compiled_placeholders_zero, live_immutables_are_implementation, immutable_evidence = (
        validate_implementation_immutables(
            live, compiled, immutable_ranges, implementation
        )
    )
    full_match = compiled == live
    stripped_live = strip_cbor(live)
    stripped_compiled = strip_cbor(compiled)
    stripped_match = stripped_compiled == stripped_live
    normalized_live = zero_ranges(live, immutable_ranges)
    normalized_compiled = zero_ranges(compiled, immutable_ranges)
    normalized_full_match = normalized_compiled == normalized_live
    stripped_normalized_live = strip_cbor(normalized_live)
    stripped_normalized_compiled = strip_cbor(normalized_compiled)
    stripped_normalized_match = (
        stripped_normalized_compiled == stripped_normalized_live
    )

    result = {
        "mode": "BSC_PINNED_BLOCK_READ_ONLY_SOURCE_DEPLOYMENT_BINDING",
        "signed_or_broadcast_transactions": 0,
        "proxy": proxy,
        "implementation_slot": IMPLEMENTATION_SLOT,
        "pinned_block_number": common_block,
        "pinned_block_hash": rows[0]["pinned_block_hash"],
        "implementation": implementation,
        "successful_provider_count": len(rows),
        "provider_failures": failures,
        "providers_identical": providers_identical,
        "explorer_compiler_version": explorer_compiler,
        "explorer_contract_name": explorer_row.get("ContractName"),
        "explorer_file_name": explorer_row.get("FileName"),
        "source_unit_count": len(standard.get("sources", {})),
        "compiled_source_name": source_name,
        "compiled_contract_name": contract_name,
        "immutable_references": immutable_refs,
        "immutable_reference_ranges": [
            {"start": start, "length": length}
            for start, length in immutable_ranges
        ],
        "immutable_reference_evidence": immutable_evidence,
        "compiled_immutable_placeholders_zero": compiled_placeholders_zero,
        "live_immutable_values_are_implementation": live_immutables_are_implementation,
        "live_runtime_bytes": len(live),
        "compiled_runtime_bytes": len(compiled),
        "live_runtime_sha256": sha256(live),
        "compiled_runtime_sha256": sha256(compiled),
        "live_stripped_bytes": len(stripped_live),
        "compiled_stripped_bytes": len(stripped_compiled),
        "live_stripped_sha256": sha256(stripped_live),
        "compiled_stripped_sha256": sha256(stripped_compiled),
        "full_runtime_match": full_match,
        "cbor_stripped_runtime_match": stripped_match,
        "normalized_full_runtime_match": normalized_full_match,
        "normalized_live_runtime_sha256": sha256(normalized_live),
        "normalized_compiled_runtime_sha256": sha256(normalized_compiled),
        "cbor_stripped_normalized_runtime_match": stripped_normalized_match,
        "cbor_stripped_normalized_live_sha256": sha256(stripped_normalized_live),
        "cbor_stripped_normalized_compiled_sha256": sha256(
            stripped_normalized_compiled
        ),
        "provider_heads": heads,
        "rows": rows,
    }
    write_json(out / "SOURCE_DEPLOYMENT_BINDING.json", result)
    markers = [
        "PYTH_CORE_EVM_SOURCE_DEPLOYMENT_BINDING_CAPTURED",
        "PUBLIC_CHAIN_MODE=READ_ONLY",
        "SIGNED_OR_BROADCAST_TRANSACTIONS=0",
        f"PINNED_BLOCK_NUMBER={common_block}",
        f"PINNED_BLOCK_HASH={rows[0]['pinned_block_hash']}",
        f"SUCCESSFUL_PROVIDER_COUNT={len(rows)}",
        f"PROVIDERS_IDENTICAL={str(providers_identical).lower()}",
        f"IMPLEMENTATION_NONZERO={str(int(implementation, 16) != 0).lower()}",
        f"IMPLEMENTATION_RUNTIME_NONEMPTY={str(bool(live)).lower()}",
        f"VERIFIED_SOURCE_UNIT_COUNT={len(standard.get('sources', {}))}",
        f"IMMUTABLE_REFERENCE_COUNT={len(immutable_ranges)}",
        f"COMPILED_IMMUTABLE_PLACEHOLDERS_ZERO={str(compiled_placeholders_zero).lower()}",
        f"IMMUTABLE_VALUES_ARE_LIVE_IMPLEMENTATION={str(live_immutables_are_implementation).lower()}",
        f"FULL_RUNTIME_MATCH={str(full_match).lower()}",
        f"CBOR_STRIPPED_RUNTIME_MATCH={str(stripped_match).lower()}",
        f"NORMALIZED_FULL_RUNTIME_MATCH={str(normalized_full_match).lower()}",
        f"CBOR_STRIPPED_NORMALIZED_RUNTIME_MATCH={str(stripped_normalized_match).lower()}",
        f"IMPLEMENTATION={implementation}",
        f"COMPILER_VERSION={explorer_compiler}",
    ]
    (out / "BINDING_MARKERS.txt").write_text("\n".join(markers) + "\n")
    print("\n".join(markers))
    if not (
        providers_identical
        and compiled_placeholders_zero
        and live_immutables_are_implementation
        and stripped_normalized_match
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
