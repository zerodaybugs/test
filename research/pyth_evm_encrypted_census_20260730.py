#!/usr/bin/env python3
"""Read-only Pyth EVM Lazer deployment census.

The script only performs JSON-RPC read calls (`eth_call`, `eth_getCode`,
`eth_getStorageAt`, and block metadata reads). It never signs or broadcasts a
transaction. Output is intended to be encrypted by the calling workflow before
leaving the runner.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import subprocess
import time
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path("upstream")
OUT = Path("evidence")
RANDOM = "0x1111111111111111111111111111111111111111"
ZERO_ADDR = "0x0000000000000000000000000000000000000000"
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

SELECTOR = {
    "owner": "0x8da5cb5b",
    "version": "0x54fd4d50",
    "fee": "0xbac12f87",
    "signers": "0x1d9c68c3",
    "proxiable": "0x52d1902d",
    "initialize": "0xc4d66de8",
    "update_signer": "0x9feb088c",
    "transfer_ownership": "0xf2fde38b",
    "upgrade_to": "0x3659cfe6",
    "upgrade_to_and_call": "0x4f1ef286",
}


def enc_address(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64, "0")


def enc_uint(value: int) -> str:
    return f"{value:064x}"


def data(selector: str, *words: str) -> str:
    return selector + "".join(words)


def word_int(value: str | None, index: int = 0) -> int | None:
    if not value or value == "0x":
        return None
    body = value.removeprefix("0x")
    start = index * 64
    if len(body) < start + 64:
        return None
    return int(body[start : start + 64], 16)


def word_address(value: str | None, index: int = 0) -> str | None:
    number = word_int(value, index)
    if number is None:
        return None
    return f"0x{number & ((1 << 160) - 1):040x}"


def decode_string(value: str | None) -> str | None:
    if not value or value == "0x":
        return None
    body = value.removeprefix("0x")
    try:
        offset = int(body[:64], 16) * 2
        length = int(body[offset : offset + 64], 16)
        raw = bytes.fromhex(body[offset + 64 : offset + 64 + 2 * length])
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_signers(value: str | None) -> list[dict[str, Any]]:
    if not value or value == "0x":
        return []
    body = value.removeprefix("0x")
    try:
        offset = int(body[:64], 16) * 2
        count = int(body[offset : offset + 64], 16)
        base = offset + 64
        output: list[dict[str, Any]] = []
        for index in range(count):
            pos = base + 128 * index
            if len(body) < pos + 128:
                raise ValueError("short signer array")
            output.append(
                {
                    "address": "0x" + body[pos + 24 : pos + 64].lower(),
                    "expires_at": int(body[pos + 64 : pos + 128], 16),
                }
            )
        return output
    except Exception:
        return []


def code_metadata(code: str | None) -> dict[str, Any]:
    if not code or code == "0x":
        return {"length": 0, "sha256": None}
    raw = bytes.fromhex(code.removeprefix("0x"))
    return {"length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def rpc_post(url: str, payload: Any, timeout: int = 25) -> Any:
    encoded = json.dumps(payload, separators=(",", ":")).encode()
    last_error: Exception | None = None
    for attempt in range(3):
        request = urllib.request.Request(
            url,
            data=encoded,
            method="POST",
            headers={
                "content-type": "application/json",
                "user-agent": "Pyth-authorized-read-only-census/2026-07-30",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except Exception as error:  # provider heterogeneity is expected
            last_error = error
            time.sleep(0.5 * (attempt + 1))
    raise RuntimeError(type(last_error).__name__ if last_error else "unknown RPC error")


def rpc_batch(url: str, calls: list[tuple[str, str, list[Any]]]) -> dict[str, Any]:
    if not calls:
        return {}
    payload = [
        {"jsonrpc": "2.0", "id": index + 1, "method": method, "params": params}
        for index, (_, method, params) in enumerate(calls)
    ]
    try:
        response = rpc_post(url, payload)
        if not isinstance(response, list):
            raise ValueError("batch unsupported")
        indexed = {
            int(item.get("id")): item
            for item in response
            if isinstance(item, dict) and item.get("id") is not None
        }
        return {
            name: indexed.get(index + 1, {"error": {"message": "missing batch item"}})
            for index, (name, _, _) in enumerate(calls)
        }
    except Exception:
        output: dict[str, Any] = {}
        for index, (name, method, params) in enumerate(calls):
            try:
                output[name] = rpc_post(
                    url,
                    {"jsonrpc": "2.0", "id": index + 1, "method": method, "params": params},
                )
            except Exception as error:
                output[name] = {"error": {"message": type(error).__name__}}
        return output


def rpc_result(item: Any) -> Any:
    return item.get("result") if isinstance(item, dict) else None


def rpc_error(item: Any) -> str | None:
    if not isinstance(item, dict) or item.get("error") is None:
        return None
    error = item["error"]
    if isinstance(error, dict):
        return str(error.get("message", "RPC error"))
    return str(error)


def reverted(item: Any) -> bool:
    return isinstance(item, dict) and item.get("error") is not None


def inspect_target(contract: dict[str, Any], chain: dict[str, Any]) -> dict[str, Any]:
    chain_name = contract["chain"]
    address = contract["address"]
    url = chain.get("rpcUrl")
    record: dict[str, Any] = {
        "chain": chain_name,
        "address": address.lower(),
        "mainnet": bool(chain.get("mainnet")),
        "network_id_expected": chain.get("networkId"),
        "rpc": url,
        "anomalies": [],
        "critical_signals": [],
    }
    if not isinstance(url, str) or not url.startswith("http") or "${" in url:
        record["anomalies"].append("unusable_rpc_url")
        return record

    future = int(time.time()) + 86_400
    initialize = data(SELECTOR["initialize"], enc_address(RANDOM))
    update_signer = data(
        SELECTOR["update_signer"], enc_address(RANDOM), enc_uint(future)
    )
    transfer_owner = data(SELECTOR["transfer_ownership"], enc_address(RANDOM))
    upgrade_to = data(SELECTOR["upgrade_to"], enc_address(RANDOM))
    upgrade_to_and_call = data(
        SELECTOR["upgrade_to_and_call"],
        enc_address(RANDOM),
        enc_uint(64),
        enc_uint(0),
    )

    def call_tx(call_data: str, to: str = address) -> dict[str, str]:
        return {"from": RANDOM, "to": to, "data": call_data}

    primary_calls = [
        ("chain_id", "eth_chainId", []),
        ("block_number", "eth_blockNumber", []),
        ("proxy_code", "eth_getCode", [address, "latest"]),
        ("impl_slot", "eth_getStorageAt", [address, IMPL_SLOT, "latest"]),
        ("admin_slot", "eth_getStorageAt", [address, ADMIN_SLOT, "latest"]),
        ("owner", "eth_call", [{"to": address, "data": SELECTOR["owner"]}, "latest"]),
        ("version", "eth_call", [{"to": address, "data": SELECTOR["version"]}, "latest"]),
        ("fee", "eth_call", [{"to": address, "data": SELECTOR["fee"]}, "latest"]),
        ("signers", "eth_call", [{"to": address, "data": SELECTOR["signers"]}, "latest"]),
        ("proxy_proxiable", "eth_call", [{"to": address, "data": SELECTOR["proxiable"]}, "latest"]),
        ("sim_initialize", "eth_call", [call_tx(initialize), "latest"]),
        ("sim_update_signer", "eth_call", [call_tx(update_signer), "latest"]),
        ("sim_transfer_owner", "eth_call", [call_tx(transfer_owner), "latest"]),
        ("sim_upgrade_to", "eth_call", [call_tx(upgrade_to), "latest"]),
        ("sim_upgrade_to_and_call", "eth_call", [call_tx(upgrade_to_and_call), "latest"]),
    ]
    primary = rpc_batch(url, primary_calls)
    record["raw_primary"] = primary

    chain_value = rpc_result(primary["chain_id"])
    block_value = rpc_result(primary["block_number"])
    proxy_code = code_metadata(rpc_result(primary["proxy_code"]))
    implementation = word_address(rpc_result(primary["impl_slot"]))
    admin = word_address(rpc_result(primary["admin_slot"]))
    owner = word_address(rpc_result(primary["owner"]))
    version = decode_string(rpc_result(primary["version"]))
    fee = word_int(rpc_result(primary["fee"]))
    signers = decode_signers(rpc_result(primary["signers"]))

    record.update(
        {
            "network_id_observed": int(chain_value, 16)
            if isinstance(chain_value, str)
            else None,
            "latest_block": int(block_value, 16)
            if isinstance(block_value, str)
            else None,
            "proxy_code": proxy_code,
            "implementation": implementation,
            "admin": admin,
            "owner": owner,
            "version": version,
            "verification_fee": fee,
            "trusted_signers": signers,
            "simulations": {
                "initialize_reverted": reverted(primary["sim_initialize"]),
                "initialize_error": rpc_error(primary["sim_initialize"]),
                "update_reverted": reverted(primary["sim_update_signer"]),
                "update_error": rpc_error(primary["sim_update_signer"]),
                "transfer_reverted": reverted(primary["sim_transfer_owner"]),
                "transfer_error": rpc_error(primary["sim_transfer_owner"]),
                "upgrade_to_reverted": reverted(primary["sim_upgrade_to"]),
                "upgrade_to_error": rpc_error(primary["sim_upgrade_to"]),
                "upgrade_to_and_call_reverted": reverted(
                    primary["sim_upgrade_to_and_call"]
                ),
                "upgrade_to_and_call_error": rpc_error(
                    primary["sim_upgrade_to_and_call"]
                ),
            },
        }
    )

    secondary_calls: list[tuple[str, str, list[Any]]] = []
    if record["latest_block"] is not None:
        secondary_calls.append(
            ("block", "eth_getBlockByNumber", [hex(record["latest_block"]), False])
        )
    if implementation not in (None, ZERO_ADDR):
        secondary_calls.extend(
            [
                ("implementation_code", "eth_getCode", [implementation, "latest"]),
                (
                    "implementation_owner",
                    "eth_call",
                    [{"to": implementation, "data": SELECTOR["owner"]}, "latest"],
                ),
                (
                    "implementation_initialize",
                    "eth_call",
                    [call_tx(initialize, implementation), "latest"],
                ),
                (
                    "implementation_proxiable",
                    "eth_call",
                    [{"to": implementation, "data": SELECTOR["proxiable"]}, "latest"],
                ),
            ]
        )
    secondary = rpc_batch(url, secondary_calls)
    record["raw_secondary"] = secondary

    block = rpc_result(secondary.get("block", {}))
    block_timestamp = (
        int(block["timestamp"], 16)
        if isinstance(block, dict) and isinstance(block.get("timestamp"), str)
        else None
    )
    implementation_code = code_metadata(
        rpc_result(secondary.get("implementation_code", {}))
    )
    implementation_uuid = rpc_result(secondary.get("implementation_proxiable", {}))
    live_signers = (
        [entry for entry in signers if entry["expires_at"] > block_timestamp]
        if block_timestamp is not None
        else []
    )
    record.update(
        {
            "latest_timestamp": block_timestamp,
            "implementation_code": implementation_code,
            "implementation_owner": word_address(
                rpc_result(secondary.get("implementation_owner", {}))
            ),
            "implementation_initialize_reverted": reverted(
                secondary.get("implementation_initialize", {})
            ),
            "implementation_initialize_error": rpc_error(
                secondary.get("implementation_initialize", {})
            ),
            "implementation_proxiable_uuid": implementation_uuid,
            "live_trusted_signers": live_signers,
        }
    )

    has_proxy_code = proxy_code["length"] > 0
    has_implementation_code = implementation_code["length"] > 0
    checks: dict[str, bool | None] = {
        "rpc_responded": record["network_id_observed"] is not None,
        "chain_id_matches": record["network_id_observed"]
        == record["network_id_expected"],
        "proxy_has_code": has_proxy_code,
        "implementation_nonzero": implementation not in (None, ZERO_ADDR),
        "implementation_has_code": has_implementation_code,
        "owner_nonzero": owner not in (None, ZERO_ADDR),
        "version_expected": version == "0.2.0",
        "fee_expected": fee == 1,
        "signer_call_succeeded": rpc_result(primary["signers"]) is not None,
        "has_live_signer": len(live_signers) > 0
        if block_timestamp is not None and rpc_result(primary["signers"]) is not None
        else None,
        "proxy_initialize_blocked": reverted(primary["sim_initialize"])
        if has_proxy_code
        else None,
        "unauthorized_update_blocked": reverted(primary["sim_update_signer"])
        if has_proxy_code
        else None,
        "unauthorized_transfer_blocked": reverted(primary["sim_transfer_owner"])
        if has_proxy_code
        else None,
        "unauthorized_upgrade_blocked": (
            reverted(primary["sim_upgrade_to"])
            and reverted(primary["sim_upgrade_to_and_call"])
        )
        if has_proxy_code
        else None,
        "implementation_initialize_blocked": reverted(
            secondary.get("implementation_initialize", {})
        )
        if has_implementation_code
        else None,
        "implementation_uuid_expected": implementation_uuid is not None
        and implementation_uuid.lower() == IMPL_SLOT.lower()
        if has_implementation_code
        else None,
        "proxy_proxiable_blocked": reverted(primary["proxy_proxiable"])
        if has_proxy_code
        else None,
    }
    record["checks"] = checks
    for name, status in checks.items():
        if status is False:
            record["anomalies"].append(name)

    if has_proxy_code and not reverted(primary["sim_initialize"]):
        record["critical_signals"].append("proxy_initialize_succeeded")
    if has_proxy_code and not reverted(primary["sim_update_signer"]):
        record["critical_signals"].append("unauthorized_signer_update_succeeded")
    if has_proxy_code and not reverted(primary["sim_transfer_owner"]):
        record["critical_signals"].append("unauthorized_owner_transfer_succeeded")
    if has_proxy_code and (
        not reverted(primary["sim_upgrade_to"])
        or not reverted(primary["sim_upgrade_to_and_call"])
    ):
        record["critical_signals"].append("unauthorized_upgrade_succeeded")
    return record


def main() -> None:
    contracts = json.loads(
        (ROOT / "contract_manager/src/store/contracts/EvmLazerContracts.json").read_text()
    )
    chains = json.loads(
        (ROOT / "contract_manager/src/store/chains/EvmChains.json").read_text()
    )
    chain_by_id = {item["id"]: item for item in chains if item.get("type") == "EvmChain"}
    targets = [
        (contract, chain_by_id[contract["chain"]])
        for contract in contracts
        if contract.get("chain") in chain_by_id
        and chain_by_id[contract["chain"]].get("mainnet") is True
    ]

    OUT.joinpath("raw").mkdir(parents=True, exist_ok=True)
    OUT.joinpath("derived").mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(inspect_target, contract, chain) for contract, chain in targets]
        results = []
        for future, (contract, chain) in zip(futures, targets):
            try:
                results.append(future.result())
            except Exception as error:
                results.append(
                    {
                        "chain": contract["chain"],
                        "address": contract["address"].lower(),
                        "mainnet": True,
                        "anomalies": ["inspection_exception"],
                        "critical_signals": [],
                        "exception_type": type(error).__name__,
                    }
                )
    results.sort(key=lambda item: item["chain"])

    signer_groups: dict[tuple[tuple[str, int], ...], list[str]] = defaultdict(list)
    for item in results:
        key = tuple(
            (entry["address"], entry["expires_at"])
            for entry in item.get("trusted_signers", [])
        )
        signer_groups[key].append(item["chain"])

    anomalies = [
        {
            "chain": item["chain"],
            "address": item["address"],
            "anomalies": item.get("anomalies", []),
            "critical_signals": item.get("critical_signals", []),
        }
        for item in results
        if item.get("anomalies") or item.get("critical_signals")
    ]
    critical = [item for item in anomalies if item["critical_signals"]]
    source_commit = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
    ).strip()
    provenance = {
        "generated_at_unix": int(time.time()),
        "pyth_crosschain_commit": source_commit,
        "target_count": len(results),
        "mainnet_only": True,
        "read_only": True,
        "public_chain_transactions_signed": 0,
        "public_chain_transactions_broadcast": 0,
    }

    OUT.joinpath("raw/results.json").write_text(
        json.dumps(results, indent=2, sort_keys=True)
    )
    OUT.joinpath("derived/anomalies.json").write_text(
        json.dumps(anomalies, indent=2, sort_keys=True)
    )
    OUT.joinpath("derived/critical_signals.json").write_text(
        json.dumps(critical, indent=2, sort_keys=True)
    )
    OUT.joinpath("derived/signer_groups.json").write_text(
        json.dumps(
            [
                {"signers": list(signers), "chains": chain_names}
                for signers, chain_names in signer_groups.items()
            ],
            indent=2,
            sort_keys=True,
        )
    )
    OUT.joinpath("derived/provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True)
    )

    lines = [
        "# Pyth EVM Lazer mainnet census",
        "",
        f"Targets: {len(results)}",
        f"Targets with failed gates: {len(anomalies)}",
        f"Targets with takeover-class signals: {len(critical)}",
        "Public-chain transactions broadcast: 0",
        "",
        "| Chain | Code | Owner | Version | Live signers | Failed gates | Critical signals |",
        "|---|---:|---|---|---:|---|---|",
    ]
    for item in results:
        lines.append(
            "| {chain} | {code} | {owner} | {version} | {live} | {failed} | {critical} |".format(
                chain=item["chain"],
                code=item.get("proxy_code", {}).get("length", 0),
                owner=item.get("owner") or "N/A",
                version=item.get("version") or "N/A",
                live=len(item.get("live_trusted_signers", [])),
                failed=", ".join(item.get("anomalies", [])) or "none",
                critical=", ".join(item.get("critical_signals", [])) or "none",
            )
        )
    OUT.joinpath("derived/SUMMARY.md").write_text("\n".join(lines) + "\n")
    print("CENSUS_COMPLETE")


if __name__ == "__main__":
    main()
