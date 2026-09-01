#!/usr/bin/env python3
"""Legacy Pyth EVM Lazer signer/owner follow-up.

Reads the 100-element TrustedSignerInfo array from proxy storage slots 0..199,
matching the official contract-manager implementation for pre-0.2.0 contracts.
Only JSON-RPC read methods are used.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path("upstream")
OUT = Path("evidence/legacy_storage")
ZERO = "0x0000000000000000000000000000000000000000"
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
OWNER_SELECTOR = "0x8da5cb5b"
VERSION_SELECTOR = "0x54fd4d50"
GET_SIGNERS_SELECTOR = "0x1d9c68c3"

FALLBACKS = {
    "arbitrum": ["https://arb1.arbitrum.io/rpc"],
    "base": ["https://mainnet.base.org"],
    "bsc": ["https://bsc-rpc.publicnode.com"],
    "cronos": ["https://evm.cronos.org", "https://rpc.nodeflare.app/cronos/public"],
    "polygon": ["https://137.rpc.thirdweb.com"],
    "polynomial": ["https://8008.rpc.thirdweb.com"],
    "soneium": ["https://rpc.soneium.org/"],
}


def rpc(url: str, method: str, params: list[Any], timeout: int = 25) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    last: Exception | None = None
    for attempt in range(3):
        request = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "content-type": "application/json",
                "user-agent": "Pyth-authorized-read-only-storage-census/2026-07-30",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                value = json.loads(response.read())
            if not isinstance(value, dict):
                raise ValueError("non-object RPC response")
            return value
        except Exception as error:
            last = error
            time.sleep(0.5 * (attempt + 1))
    return {"error": {"message": type(last).__name__ if last else "RPC failure"}}


def rpc_batch10(
    url: str, calls: list[tuple[str, str, list[Any]]], timeout: int = 25
) -> dict[str, dict[str, Any]]:
    payload = [
        {"jsonrpc": "2.0", "id": index + 1, "method": method, "params": params}
        for index, (_, method, params) in enumerate(calls)
    ]
    encoded = json.dumps(payload, separators=(",", ":")).encode()
    try:
        request = urllib.request.Request(
            url,
            data=encoded,
            method="POST",
            headers={
                "content-type": "application/json",
                "user-agent": "Pyth-authorized-read-only-storage-census/2026-07-30",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
        if not isinstance(value, list) or len(value) != len(calls):
            raise ValueError("batch unsupported or incomplete")
        indexed = {
            int(item["id"]): item
            for item in value
            if isinstance(item, dict) and item.get("id") is not None
        }
        if set(indexed) != set(range(1, len(calls) + 1)):
            raise ValueError("batch IDs incomplete")
        return {
            name: indexed[index + 1]
            for index, (name, _, _) in enumerate(calls)
        }
    except Exception:
        return {
            name: rpc(url, method, params, timeout)
            for name, method, params in calls
        }


def result(item: Any) -> Any:
    return item.get("result") if isinstance(item, dict) else None


def word(value: str | None) -> int | None:
    if not value or value == "0x":
        return None
    return int(value, 16)


def address_from_word(value: str | None) -> str | None:
    number = word(value)
    if number is None:
        return None
    return f"0x{number & ((1 << 160) - 1):040x}"


def decode_string(value: str | None) -> str | None:
    if not value or value == "0x":
        return None
    body = value.removeprefix("0x")
    try:
        offset = int(body[:64], 16) * 2
        size = int(body[offset : offset + 64], 16)
        return bytes.fromhex(body[offset + 64 : offset + 64 + size * 2]).decode()
    except Exception:
        return None


def decode_getter(value: str | None) -> list[dict[str, Any]] | None:
    if value is None:
        return None
    if value == "0x":
        return []
    body = value.removeprefix("0x")
    try:
        offset = int(body[:64], 16) * 2
        count = int(body[offset : offset + 64], 16)
        base = offset + 64
        return [
            {
                "address": "0x" + body[base + i * 128 + 24 : base + i * 128 + 64].lower(),
                "expires_at": int(body[base + i * 128 + 64 : base + i * 128 + 128], 16),
            }
            for i in range(count)
        ]
    except Exception:
        return None


def code_meta(value: str | None) -> dict[str, Any]:
    if not value or value == "0x":
        return {"length": 0, "sha256": None}
    raw = bytes.fromhex(value.removeprefix("0x"))
    return {"length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def choose_rpc(chain_name: str, primary: str, expected: int) -> tuple[str | None, list[dict[str, Any]]]:
    attempts = []
    candidates = []
    for candidate in [primary, *FALLBACKS.get(chain_name, [])]:
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    for candidate in candidates:
        response = rpc(candidate, "eth_chainId", [])
        observed = result(response)
        observed_int = int(observed, 16) if isinstance(observed, str) else None
        attempts.append(
            {
                "rpc": candidate,
                "observed_chain_id": observed_int,
                "error": response.get("error") if isinstance(response, dict) else None,
            }
        )
        if observed_int == expected:
            return candidate, attempts
    return None, attempts


def read_storage_signers(url: str, address: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    slots: dict[int, str | None] = {}
    errors = []
    for start in range(0, 200, 10):
        calls = [
            (f"slot_{index}", "eth_getStorageAt", [address, hex(index), "latest"])
            for index in range(start, start + 10)
        ]
        responses = rpc_batch10(url, calls)
        for index in range(start, start + 10):
            item = responses[f"slot_{index}"]
            slots[index] = result(item)
            if result(item) is None:
                errors.append({"slot": index, "error": item.get("error")})
    signers = []
    for index in range(100):
        public_key = word(slots.get(2 * index))
        expires_at = word(slots.get(2 * index + 1))
        if public_key not in (None, 0):
            signers.append(
                {
                    "index": index,
                    "address": f"0x{public_key & ((1 << 160) - 1):040x}",
                    "expires_at": expires_at or 0,
                    "raw_public_key_slot": slots.get(2 * index),
                    "raw_expiry_slot": slots.get(2 * index + 1),
                }
            )
    return signers, {"slot_errors": errors, "slots_read": len(slots)}


def inspect(contract: dict[str, Any], chain: dict[str, Any]) -> dict[str, Any]:
    name = contract["chain"]
    address = contract["address"]
    expected = int(chain["networkId"])
    selected, attempts = choose_rpc(name, chain.get("rpcUrl", ""), expected)
    output: dict[str, Any] = {
        "chain": name,
        "address": address.lower(),
        "expected_chain_id": expected,
        "rpc_attempts": attempts,
        "selected_rpc": selected,
        "anomalies": [],
    }
    if selected is None:
        output["anomalies"].append("no_confirmed_rpc")
        return output

    base_calls = [
        ("code", "eth_getCode", [address, "latest"]),
        ("owner", "eth_call", [{"to": address, "data": OWNER_SELECTOR}, "latest"]),
        ("version", "eth_call", [{"to": address, "data": VERSION_SELECTOR}, "latest"]),
        ("getter", "eth_call", [{"to": address, "data": GET_SIGNERS_SELECTOR}, "latest"]),
        ("implementation", "eth_getStorageAt", [address, IMPL_SLOT, "latest"]),
        ("block_number", "eth_blockNumber", []),
    ]
    base = rpc_batch10(selected, base_calls)
    code = code_meta(result(base["code"]))
    owner = address_from_word(result(base["owner"]))
    version = decode_string(result(base["version"]))
    getter_signers = decode_getter(result(base["getter"]))
    implementation = address_from_word(result(base["implementation"]))
    block_number_hex = result(base["block_number"])
    block_number = int(block_number_hex, 16) if isinstance(block_number_hex, str) else None

    extra_calls = []
    if owner not in (None, ZERO):
        extra_calls.append(("owner_code", "eth_getCode", [owner, "latest"]))
    if implementation not in (None, ZERO):
        extra_calls.append(("implementation_code", "eth_getCode", [implementation, "latest"]))
    if block_number is not None:
        extra_calls.append(("block", "eth_getBlockByNumber", [hex(block_number), False]))
    extra = rpc_batch10(selected, extra_calls)
    block = result(extra.get("block", {}))
    timestamp = (
        int(block["timestamp"], 16)
        if isinstance(block, dict) and isinstance(block.get("timestamp"), str)
        else None
    )

    storage_signers, storage_meta = read_storage_signers(selected, address)
    normalized_storage = [
        {"address": item["address"], "expires_at": item["expires_at"]}
        for item in storage_signers
    ]
    getter_matches = (
        getter_signers == normalized_storage if getter_signers is not None else None
    )
    live = [
        item for item in normalized_storage
        if timestamp is not None and item["expires_at"] > timestamp
    ]

    output.update(
        {
            "proxy_code": code,
            "owner": owner,
            "owner_code": code_meta(result(extra.get("owner_code", {}))),
            "owner_is_contract": code_meta(result(extra.get("owner_code", {})))["length"] > 0,
            "version": version,
            "implementation": implementation,
            "implementation_code": code_meta(result(extra.get("implementation_code", {}))),
            "latest_block": block_number,
            "latest_timestamp": timestamp,
            "getter_signers": getter_signers,
            "storage_signers": storage_signers,
            "live_storage_signers": live,
            "getter_matches_storage": getter_matches,
            "storage_read": storage_meta,
            "raw_base": base,
            "raw_extra": extra,
        }
    )
    if code["length"] == 0:
        output["anomalies"].append("proxy_code_missing")
    if owner in (None, ZERO):
        output["anomalies"].append("owner_missing")
    if implementation in (None, ZERO):
        output["anomalies"].append("implementation_slot_missing")
    if implementation not in (None, ZERO) and output["implementation_code"]["length"] == 0:
        output["anomalies"].append("implementation_code_missing")
    if storage_meta["slot_errors"]:
        output["anomalies"].append("storage_slots_incomplete")
    if getter_matches is False:
        output["anomalies"].append("getter_storage_mismatch")
    if timestamp is not None and not live:
        output["anomalies"].append("no_live_storage_signer")
    return output


def main() -> None:
    contracts = json.loads(
        (ROOT / "contract_manager/src/store/contracts/EvmLazerContracts.json").read_text()
    )
    chains = json.loads(
        (ROOT / "contract_manager/src/store/chains/EvmChains.json").read_text()
    )
    by_id = {item["id"]: item for item in chains if item.get("type") == "EvmChain"}
    targets = [
        (contract, by_id[contract["chain"]])
        for contract in contracts
        if contract.get("chain") in by_id and by_id[contract["chain"]].get("mainnet") is True
    ]
    OUT.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(inspect, contract, chain) for contract, chain in targets]
        records = []
        for future, (contract, _) in zip(futures, targets):
            try:
                records.append(future.result())
            except Exception as error:
                records.append(
                    {
                        "chain": contract["chain"],
                        "address": contract["address"].lower(),
                        "anomalies": ["inspection_exception"],
                        "exception_type": type(error).__name__,
                    }
                )
    records.sort(key=lambda item: item["chain"])
    anomalies = [item for item in records if item.get("anomalies")]
    OUT.joinpath("results.json").write_text(json.dumps(records, indent=2, sort_keys=True))
    OUT.joinpath("anomalies.json").write_text(json.dumps(anomalies, indent=2, sort_keys=True))
    lines = [
        "# Pyth EVM legacy storage follow-up",
        "",
        f"Targets: {len(records)}",
        f"Targets with anomalies: {len(anomalies)}",
        "Public-chain transactions broadcast: 0",
        "",
        "| Chain | Version | Owner kind | Storage signers | Live | Getter match | Anomalies |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for item in records:
        lines.append(
            "| {chain} | {version} | {owner_kind} | {signers} | {live} | {match} | {anomalies} |".format(
                chain=item["chain"],
                version=item.get("version") or "N/A",
                owner_kind=("contract" if item.get("owner_is_contract") else "EOA/unknown"),
                signers=len(item.get("storage_signers", [])),
                live=len(item.get("live_storage_signers", [])),
                match=item.get("getter_matches_storage"),
                anomalies=", ".join(item.get("anomalies", [])) or "none",
            )
        )
    OUT.joinpath("SUMMARY.md").write_text("\n".join(lines) + "\n")
    print("LEGACY_STORAGE_COMPLETE")


if __name__ == "__main__":
    main()
