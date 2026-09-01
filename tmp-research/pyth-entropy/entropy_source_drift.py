#!/usr/bin/env python3
"""Read-only exact-source/runtime binding across public Pyth Entropy mainnets."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import time
import urllib.request
from typing import Any

IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
PINNED_COMMIT = "4a596e7adff552afaf5687ce791764019f2d3719"
CONTRACTS_URL = f"https://raw.githubusercontent.com/pyth-network/pyth-crosschain/{PINNED_COMMIT}/contract_manager/src/store/contracts/EvmEntropyContracts.json"
CHAINS_URL = f"https://raw.githubusercontent.com/pyth-network/pyth-crosschain/{PINNED_COMMIT}/contract_manager/src/store/chains/EvmChains.json"
CHAINLIST_URL = "https://chainid.network/chains.json"


def get_json(url: str) -> Any:
    errors: list[str] = []
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, headers={"accept": "application/json", "user-agent": "pyth-entropy-binding/1.0"})
            with urllib.request.urlopen(req, timeout=60) as response:
                return json.load(response)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
            if attempt < 4:
                time.sleep(attempt + 1)
    raise RuntimeError({"url": url, "errors": errors})


def rpc(url: str, method: str, params: list[Any], request_id: int) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
    errors: list[str] = []
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, data=body, headers={"content-type": "application/json", "accept": "application/json", "user-agent": "pyth-entropy-binding/1.0"})
            with urllib.request.urlopen(req, timeout=45) as response:
                obj = json.load(response)
            if "error" in obj:
                raise RuntimeError(obj["error"])
            return obj["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
            if attempt < 3:
                time.sleep(attempt + 1)
    raise RuntimeError({"rpc": url, "method": method, "errors": errors})


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strip_cbor(runtime: bytes) -> bytes:
    if len(runtime) < 2:
        return runtime
    size = int.from_bytes(runtime[-2:], "big") + 2
    if size <= 2 or size > len(runtime):
        return runtime
    return runtime[:-size]


def flatten_immutables(refs: dict[str, Any]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for entries in refs.values():
        for entry in entries:
            ranges.append((int(entry["start"]), int(entry["length"])))
    ranges.sort()
    return ranges


def zero_ranges(data: bytes, ranges: list[tuple[int, int]]) -> bytes:
    out = bytearray(data)
    for start, length in ranges:
        if start + length > len(out):
            raise RuntimeError({"immutable_out_of_bounds": [start, length, len(out)]})
        out[start : start + length] = bytes(length)
    return bytes(out)


def load_artifact(path: pathlib.Path) -> tuple[bytes, list[tuple[int, int]]]:
    obj = json.loads(path.read_text())
    deployed = obj.get("deployedBytecode") or obj.get("bytecode", {}).get("deployedBytecode")
    if isinstance(deployed, str):
        hex_code = deployed
        refs = obj.get("immutableReferences", {})
    else:
        deployed = deployed or {}
        hex_code = deployed.get("object", "")
        refs = deployed.get("immutableReferences", {})
    if not hex_code:
        raise RuntimeError({"missing_deployed_bytecode": str(path)})
    return bytes.fromhex(hex_code.removeprefix("0x")), flatten_immutables(refs)


def normalize_rpc(url: str) -> str | None:
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None
    if "${" in url or "{API_KEY}" in url or "<" in url:
        return None
    return url


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    compiled, immutable_ranges = load_artifact(pathlib.Path(args.artifact))
    compiled_norm = zero_ranges(compiled, immutable_ranges)
    compiled_stripped = strip_cbor(compiled_norm)

    contracts = get_json(CONTRACTS_URL)
    chains = get_json(CHAINS_URL)
    chainlist = get_json(CHAINLIST_URL)
    chain_by_id = {row["id"]: row for row in chains if row.get("type") == "EvmChain"}
    chainlist_by_network = {int(row["chainId"]): row for row in chainlist if row.get("chainId") is not None}

    deployments: list[dict[str, Any]] = []
    for row in contracts:
        chain = chain_by_id.get(row.get("chain"))
        if not chain or not chain.get("mainnet"):
            continue
        deployments.append({"chain": row["chain"], "proxy": row["address"].lower(), "network_id": int(chain["networkId"]), "official_rpc": chain.get("rpcUrl")})

    results: list[dict[str, Any]] = []
    for index, dep in enumerate(sorted(deployments, key=lambda x: x["chain"])):
        endpoints: list[str] = []
        for candidate in [dep.get("official_rpc")]:
            value = normalize_rpc(candidate)
            if value and value not in endpoints:
                endpoints.append(value)
        chain_row = chainlist_by_network.get(dep["network_id"], {})
        for candidate in chain_row.get("rpc", [])[:8]:
            value = normalize_rpc(candidate)
            if value and value not in endpoints:
                endpoints.append(value)
        endpoint_rows: list[dict[str, Any]] = []
        for eidx, endpoint in enumerate(endpoints[:5]):
            try:
                chain_id = int(rpc(endpoint, "eth_chainId", [], 100000 + index * 100 + eidx * 10), 16)
                if chain_id != dep["network_id"]:
                    raise RuntimeError({"wrong_chain": chain_id})
                word = str(rpc(endpoint, "eth_getStorageAt", [dep["proxy"], IMPLEMENTATION_SLOT, "latest"], 100001 + index * 100 + eidx * 10))
                implementation = ("0x" + word[-40:]).lower()
                code_hex = str(rpc(endpoint, "eth_getCode", [implementation, "latest"], 100002 + index * 100 + eidx * 10))
                code = bytes.fromhex(code_hex.removeprefix("0x"))
                if int(implementation, 16) == 0 or not code:
                    raise RuntimeError({"empty_implementation": implementation})
                normalized = zero_ranges(code, immutable_ranges) if len(code) >= max((s + l for s, l in immutable_ranges), default=0) else code
                stripped = strip_cbor(normalized)
                endpoint_rows.append({
                    "endpoint": endpoint,
                    "completed": True,
                    "implementation": implementation,
                    "runtime_bytes": len(code),
                    "runtime_sha256": sha256(code),
                    "normalized_stripped_bytes": len(stripped),
                    "normalized_stripped_sha256": sha256(stripped),
                    "exact_current_source_match": stripped == compiled_stripped,
                    "code_hex": code_hex,
                })
            except Exception as exc:  # noqa: BLE001
                endpoint_rows.append({"endpoint": endpoint, "completed": False, "error": repr(exc)})
            if sum(bool(x.get("completed")) for x in endpoint_rows) >= 2:
                break

        completed = [x for x in endpoint_rows if x.get("completed")]
        provider_agreement = bool(completed) and len({(x["implementation"], x["runtime_sha256"]) for x in completed}) == 1
        current_match = bool(completed) and all(bool(x["exact_current_source_match"]) for x in completed)
        results.append({"deployment": dep, "endpoint_rows": endpoint_rows, "successful_endpoint_count": len(completed), "provider_agreement": provider_agreement, "exact_current_source_match": current_match})

    match = [r["deployment"]["chain"] for r in results if r["exact_current_source_match"]]
    mismatch = [r["deployment"]["chain"] for r in results if r["successful_endpoint_count"] and not r["exact_current_source_match"]]
    coverage = [r["deployment"]["chain"] for r in results if not r["successful_endpoint_count"]]
    summary = {
        "pinned_commit": PINNED_COMMIT,
        "compiled_runtime_bytes": len(compiled),
        "compiled_normalized_stripped_bytes": len(compiled_stripped),
        "compiled_normalized_stripped_sha256": sha256(compiled_stripped),
        "immutable_ranges": immutable_ranges,
        "deployment_count": len(results),
        "exact_match_count": len(match),
        "mismatch_count": len(mismatch),
        "coverage_issue_count": len(coverage),
        "exact_matches": match,
        "mismatches": mismatch,
        "coverage_issues": coverage,
        "signed_or_broadcast_transactions": 0,
    }
    (out / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "PYTH_ENTROPY_SOURCE_DRIFT.json").write_text(json.dumps({"summary": summary, "results": results}, indent=2, sort_keys=True) + "\n")
    print("PYTH_ENTROPY_SOURCE_DRIFT_COMPLETE " + json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
