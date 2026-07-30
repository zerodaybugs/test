#!/usr/bin/env python3
"""Read-only Pyth Crosschain EVM deployment census.

Authorized bug-bounty research only. The script sends JSON-RPC read calls and
eth_call simulations; it never signs or broadcasts a transaction.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from Crypto.Hash import keccak

STORE = Path("pyth-crosschain/contract_manager/src/store")
OUT = Path("evidence")
RAW = OUT / "raw"
RAW.mkdir(parents=True, exist_ok=True)

IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
ZERO_ADDRESS = "0x" + "00" * 20
ZERO_BYTES32 = "0x" + "00" * 32
EXPECTED_MAGIC = 0x97A6F304
RANDOM = "0x1111111111111111111111111111111111111111"

EXTRA_RPCS: dict[str, list[str]] = {
    "ethereum": ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com"],
    "base": ["https://mainnet.base.org", "https://base-rpc.publicnode.com"],
    "polygon": ["https://polygon-bor-rpc.publicnode.com"],
    "optimism": ["https://optimism-rpc.publicnode.com"],
    "arbitrum": ["https://arbitrum-one-rpc.publicnode.com"],
    "bsc": ["https://bsc-rpc.publicnode.com"],
    "avalanche": ["https://avalanche-c-chain-rpc.publicnode.com"],
    "gnosis": ["https://gnosis-rpc.publicnode.com"],
    "linea": ["https://linea-rpc.publicnode.com"],
    "scroll": ["https://scroll-rpc.publicnode.com"],
    "mantle": ["https://mantle-rpc.publicnode.com"],
    "soneium": ["https://rpc.soneium.org", "https://soneium-rpc.publicnode.com"],
}


def selector(signature: str) -> str:
    digest = keccak.new(digest_bits=256)
    digest.update(signature.encode())
    return "0x" + digest.hexdigest()[:8]


def request_json(url: str, payload: Any, timeout: int = 28) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            "user-agent": "Pyth-authorized-read-only-state-census/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except Exception as exc:  # fail closed and preserve transport evidence
        return {"transport_error": type(exc).__name__, "message": str(exc)}


def rpc(url: str, method: str, params: list[Any]) -> Any:
    return request_json(url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def result(obj: Any) -> Any:
    return obj.get("result") if isinstance(obj, dict) else None


def eth_call(url: str, to: str, data: str, from_address: str | None = None) -> Any:
    tx = {"to": to, "data": data}
    if from_address:
        tx["from"] = from_address
    return rpc(url, "eth_call", [tx, "latest"])


def call_signature(url: str, to: str, signature: str) -> Any:
    return eth_call(url, to, selector(signature))


def word(raw: Any, index: int = 0) -> int | None:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    body = raw[2:]
    start = index * 64
    if len(body) < start + 64:
        return None
    return int(body[start : start + 64], 16)


def address_word(raw: Any, index: int = 0) -> str | None:
    value = word(raw, index)
    return None if value is None else f"0x{value & ((1 << 160) - 1):040x}"


def code_length(raw: Any) -> int:
    return max(0, (len(raw) - 2) // 2) if isinstance(raw, str) and raw.startswith("0x") else 0


def decode_string(raw: Any) -> str | None:
    try:
        body = raw.removeprefix("0x")
        offset = int(body[:64], 16) * 2
        length = int(body[offset : offset + 64], 16)
        return bytes.fromhex(body[offset + 64 : offset + 64 + length * 2]).decode(errors="replace")
    except Exception:
        return None


def dynamic_array_length(raw: Any) -> int | None:
    try:
        body = raw.removeprefix("0x")
        offset = int(body[:64], 16) * 2
        return int(body[offset : offset + 64], 16)
    except Exception:
        return None


def encode_uint(value: int) -> str:
    return f"{value:064x}"


def encode_address(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def initializer_calldata() -> str:
    """ABI-encode a valid-looking initialize call with one data source."""
    signature = "initialize(address,uint16[],bytes32[],uint16,bytes32,uint64,uint256,uint256)"
    head = [
        encode_address(RANDOM),
        encode_uint(8 * 32),
        encode_uint(8 * 32 + 2 * 32),
        encode_uint(1),
        "11" * 32,
        encode_uint(0),
        encode_uint(60),
        encode_uint(1),
    ]
    chain_array = encode_uint(1) + encode_uint(1)
    address_array = encode_uint(1) + "22" * 32
    return selector(signature) + "".join(head) + chain_array + address_array


def probe(url: str, network_id: int) -> dict[str, Any]:
    chain = rpc(url, "eth_chainId", [])
    block = rpc(url, "eth_blockNumber", [])
    chain_result = result(chain)
    block_result = result(block)
    return {
        "url": url,
        "chain_id": chain,
        "block": block,
        "ok": isinstance(chain_result, str)
        and isinstance(block_result, str)
        and int(chain_result, 16) == network_id,
    }


def choose_rpc(chain_id: str, store_url: str | None, network_id: int) -> tuple[str | None, list[dict[str, Any]]]:
    urls: list[str] = []
    for url in [store_url, *EXTRA_RPCS.get(chain_id, [])]:
        if url and url not in urls:
            urls.append(url)
    probes = [probe(url, network_id) for url in urls]
    return next((item["url"] for item in probes if item["ok"]), None), probes


def main() -> None:
    chains = {entry["id"]: entry for entry in json.load(open(STORE / "chains/EvmChains.json"))}
    records = json.load(open(STORE / "contracts/EvmPriceFeedContracts.json"))
    revision = subprocess.check_output(
        ["git", "-C", "pyth-crosschain", "rev-parse", "HEAD"], text=True
    ).strip()

    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record in records:
        chain = chains.get(record["chain"])
        if not chain or not chain.get("mainnet"):
            continue
        key = (record["chain"], record["address"].lower())
        if key in seen:
            continue
        seen.add(key)
        targets.append(
            {
                "chain": record["chain"],
                "address": record["address"],
                "network_id": chain["networkId"],
                "store_rpc": chain.get("rpcUrl"),
            }
        )

    rows: list[dict[str, Any]] = []
    for index, target in enumerate(targets):
        url, probes = choose_rpc(
            target["chain"], target["store_rpc"], target["network_id"]
        )
        row: dict[str, Any] = {
            "target": target,
            "source_revision": revision,
            "rpc": url,
            "rpc_probes": probes,
            "raw": {},
            "decoded": {},
            "gates": {},
        }
        if not url:
            row["status"] = "RPC_UNAVAILABLE"
            rows.append(row)
            (RAW / f"{index:03d}_{target['chain']}_{target['address'][-6:]}.json").write_text(
                json.dumps(row, indent=2, sort_keys=True)
            )
            continue

        address = target["address"]
        raw = row["raw"]
        raw["code"] = rpc(url, "eth_getCode", [address, "latest"])
        raw["implementation"] = rpc(url, "eth_getStorageAt", [address, IMPL_SLOT, "latest"])
        raw["admin"] = rpc(url, "eth_getStorageAt", [address, ADMIN_SLOT, "latest"])
        signatures = {
            "wormhole": "wormhole()",
            "chain_id": "chainId()",
            "governance": "governanceDataSource()",
            "governance_index": "governanceDataSourceIndex()",
            "last_sequence": "lastExecutedGovernanceSequence()",
            "data_sources": "validDataSources()",
            "valid_period": "validTimePeriodSeconds()",
            "update_fee": "singleUpdateFeeInWei()",
            "transaction_fee": "transactionFeeInWei()",
            "owner": "owner()",
            "magic": "pythUpgradableMagic()",
            "version": "version()",
        }
        for name, signature in signatures.items():
            raw[name] = call_signature(url, address, signature)
        raw["initializer_simulation"] = eth_call(
            url, address, initializer_calldata(), RANDOM
        )

        decoded = row["decoded"]
        decoded["proxy_code_length"] = code_length(result(raw["code"]))
        decoded["implementation"] = address_word(result(raw["implementation"]))
        decoded["admin"] = address_word(result(raw["admin"]))
        decoded["wormhole"] = address_word(result(raw["wormhole"]))
        decoded["chain_id"] = word(result(raw["chain_id"]))
        decoded["governance_chain"] = word(result(raw["governance"]), 0)
        governance_raw = result(raw["governance"])
        decoded["governance_emitter"] = (
            "0x" + governance_raw.removeprefix("0x")[64:128]
            if isinstance(governance_raw, str)
            and len(governance_raw.removeprefix("0x")) >= 128
            else None
        )
        decoded["governance_index"] = word(result(raw["governance_index"]))
        decoded["last_sequence"] = word(result(raw["last_sequence"]))
        decoded["data_source_count"] = dynamic_array_length(result(raw["data_sources"]))
        decoded["valid_period"] = word(result(raw["valid_period"]))
        decoded["update_fee"] = word(result(raw["update_fee"]))
        decoded["transaction_fee"] = word(result(raw["transaction_fee"]))
        decoded["owner"] = address_word(result(raw["owner"]))
        decoded["magic"] = word(result(raw["magic"]))
        decoded["version"] = decode_string(result(raw["version"]))
        decoded["initializer_simulation_succeeded"] = result(
            raw["initializer_simulation"]
        ) is not None

        implementation = decoded["implementation"]
        if implementation and implementation != ZERO_ADDRESS:
            raw["implementation_code"] = rpc(
                url, "eth_getCode", [implementation, "latest"]
            )
            decoded["implementation_code_length"] = code_length(
                result(raw["implementation_code"])
            )
        else:
            decoded["implementation_code_length"] = 0

        wormhole = decoded["wormhole"]
        if wormhole and wormhole != ZERO_ADDRESS:
            raw["wormhole_code"] = rpc(url, "eth_getCode", [wormhole, "latest"])
            decoded["wormhole_code_length"] = code_length(result(raw["wormhole_code"]))
        else:
            decoded["wormhole_code_length"] = 0

        row["status"] = "OK"
        row["gates"] = {
            "proxy_has_code": decoded["proxy_code_length"] > 0,
            "implementation_nonzero": implementation not in (None, ZERO_ADDRESS),
            "implementation_has_code": decoded["implementation_code_length"] > 0,
            "admin_zero_for_uups": decoded["admin"] == ZERO_ADDRESS,
            "initializer_reverts": not decoded["initializer_simulation_succeeded"],
            "wormhole_nonzero": wormhole not in (None, ZERO_ADDRESS),
            "wormhole_has_code": decoded["wormhole_code_length"] > 0,
            "chain_id_positive": decoded["chain_id"] is not None
            and decoded["chain_id"] > 0,
            "governance_chain_nonzero": decoded["governance_chain"] is not None
            and decoded["governance_chain"] > 0,
            "governance_emitter_nonzero": decoded["governance_emitter"]
            not in (None, ZERO_BYTES32),
            "data_source_count_positive": decoded["data_source_count"] is not None
            and decoded["data_source_count"] > 0,
            "valid_period_positive": decoded["valid_period"] is not None
            and decoded["valid_period"] > 0,
            "owner_renounced": decoded["owner"] == ZERO_ADDRESS,
            "pyth_magic_matches": decoded["magic"] == EXPECTED_MAGIC,
        }
        rows.append(row)
        (RAW / f"{index:03d}_{target['chain']}_{target['address'][-6:]}.json").write_text(
            json.dumps(row, indent=2, sort_keys=True)
        )
        time.sleep(0.10)

    failures: list[dict[str, Any]] = []
    compact: list[dict[str, Any]] = []
    for row in rows:
        compact.append(
            {
                "chain": row["target"]["chain"],
                "address": row["target"]["address"],
                "rpc": row.get("rpc"),
                "status": row.get("status"),
                "decoded": row.get("decoded"),
                "gates": row.get("gates"),
            }
        )
        for gate, passed in (row.get("gates") or {}).items():
            if passed is False:
                failures.append(
                    {
                        "chain": row["target"]["chain"],
                        "address": row["target"]["address"],
                        "gate": gate,
                        "decoded": row.get("decoded"),
                    }
                )

    summary = {
        "source_revision": revision,
        "target_count": len(targets),
        "status_counts": dict(Counter(row.get("status") for row in rows)),
        "results": rows,
    }
    (OUT / "census.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    (OUT / "compact.json").write_text(json.dumps(compact, indent=2, sort_keys=True))
    (OUT / "gate_failures.json").write_text(
        json.dumps(failures, indent=2, sort_keys=True)
    )
    print(
        f"targets={len(targets)} "
        f"reachable={sum(row.get('status') == 'OK' for row in rows)} "
        f"failures={len(failures)}"
    )
    for failure in failures:
        print(failure["chain"], failure["address"], failure["gate"])


if __name__ == "__main__":
    main()
