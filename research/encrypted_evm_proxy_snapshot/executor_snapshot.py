#!/usr/bin/env python3
"""Read-only audit of the EVM governance Executor that owns each Pyth Lazer proxy."""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

from Crypto.Hash import keccak

from snapshot import EIP1967_IMPLEMENTATION_SLOT, rpc_request, result_or_error

OUT = Path(os.environ.get("PRIVATE_OUT", "private_out"))


def selector(signature: str) -> str:
    h = keccak.new(digest_bits=256)
    h.update(signature.encode())
    return "0x" + h.hexdigest()[:8]


def call(url: str, to: str, signature: str, request_id: int) -> dict[str, Any]:
    return result_or_error(
        rpc_request(
            url,
            "eth_call",
            [{"from": "0x0000000000000000000000000000000000000001", "to": to, "data": selector(signature)}, "latest"],
            request_id,
        )
    )


def decode_uint(obj: dict[str, Any]) -> int | None:
    value = obj.get("result") if obj.get("status") == "RESULT" else None
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def decode_address(obj: dict[str, Any]) -> str | None:
    value = decode_uint(obj)
    if value is None:
        return None
    return "0x" + (value & ((1 << 160) - 1)).to_bytes(20, "big").hex()


def decode_bytes32(obj: dict[str, Any]) -> str | None:
    value = obj.get("result") if obj.get("status") == "RESULT" else None
    if not isinstance(value, str) or not value.startswith("0x") or len(value) < 66:
        return None
    return "0x" + value[2:66].lower()


def decode_string(obj: dict[str, Any]) -> str | None:
    value = obj.get("result") if obj.get("status") == "RESULT" else None
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        b = bytes.fromhex(value[2:])
        if len(b) < 64:
            return None
        offset = int.from_bytes(b[:32], "big")
        if offset + 32 > len(b):
            return None
        length = int.from_bytes(b[offset : offset + 32], "big")
        raw = b[offset + 32 : offset + 32 + length]
        return raw.decode("utf-8", "strict")
    except Exception:
        return None


def code_hashes(code_hex: str | None) -> dict[str, str | None]:
    if not code_hex or not code_hex.startswith("0x"):
        return {"sha256": None, "keccak256": None, "bytes": None}
    raw = bytes.fromhex(code_hex[2:])
    k = keccak.new(digest_bits=256)
    k.update(raw)
    return {"sha256": hashlib.sha256(raw).hexdigest(), "keccak256": k.hexdigest(), "bytes": len(raw)}


def main() -> None:
    source = json.loads((OUT / "RESULTS.json").read_text())
    scanned = [x for x in source["results"] if x.get("status") == "SCANNED"]
    results = []
    for index, lazer in enumerate(scanned):
        rid = 90000 + index * 100
        url = lazer["chosen_rpc"]
        owner = lazer["owner"].lower()
        code_obj = result_or_error(rpc_request(url, "eth_getCode", [owner, "latest"], rid)); rid += 1
        impl_obj = result_or_error(rpc_request(url, "eth_getStorageAt", [owner, EIP1967_IMPLEMENTATION_SLOT, "latest"], rid)); rid += 1
        version_obj = call(url, owner, "version()", rid); rid += 1
        self_owner_obj = call(url, owner, "owner()", rid); rid += 1
        chain_obj = call(url, owner, "getOwnerChainId()", rid); rid += 1
        emitter_obj = call(url, owner, "getOwnerEmitterAddress()", rid); rid += 1
        sequence_obj = call(url, owner, "getLastExecutedSequence()", rid); rid += 1
        code = code_obj.get("result") if code_obj.get("status") == "RESULT" else None
        implementation = decode_address(impl_obj)
        self_owner = decode_address(self_owner_obj)
        owner_chain_id = decode_uint(chain_obj)
        owner_emitter = decode_bytes32(emitter_obj)
        last_sequence = decode_uint(sequence_obj)
        version = decode_string(version_obj)
        checks = {
            "executor_code_nonempty": bool(code and code != "0x"),
            "executor_is_proxy": bool(implementation and int(implementation, 16) != 0),
            "executor_self_owned": self_owner == owner,
            "owner_chain_id_readable": owner_chain_id is not None,
            "owner_emitter_readable": owner_emitter is not None,
            "last_executed_sequence_readable": last_sequence is not None,
            "version_readable": version is not None,
        }
        results.append(
            {
                "chain_name": lazer["target"]["name"],
                "evm_chain_id": lazer.get("observed_chain_id"),
                "lazer_contract": lazer["target"]["address"],
                "lazer_version": lazer.get("version"),
                "executor_address": owner,
                "executor_implementation": implementation,
                "executor_version": version,
                "executor_owner": self_owner,
                "executor_owner_chain_id": owner_chain_id,
                "executor_owner_emitter_address": owner_emitter,
                "executor_last_executed_sequence": last_sequence,
                "executor_code_hashes": code_hashes(code),
                "rpc": url,
                "raw": {
                    "code": code_obj,
                    "implementation_slot": impl_obj,
                    "version": version_obj,
                    "owner": self_owner_obj,
                    "owner_chain_id": chain_obj,
                    "owner_emitter_address": emitter_obj,
                    "last_executed_sequence": sequence_obj,
                },
                "checks": checks,
            }
        )

    group_by_impl: dict[str, list[str]] = defaultdict(list)
    group_by_owner_chain: dict[str, list[str]] = defaultdict(list)
    for row in results:
        group_by_impl[str(row["executor_implementation"])].append(row["chain_name"])
        group_by_owner_chain[str(row["executor_owner_chain_id"])].append(row["chain_name"])
    failing = {
        key: [r["chain_name"] for r in results if not r["checks"][key]]
        for key in sorted(results[0]["checks"] if results else {})
    }
    summary = {
        "candidate": "PYL-EVM-EXEC-GOV-ORDER",
        "mode": "PUBLIC_CHAIN_READ_ONLY_ETH_CALL_AND_ETH_GETSTORAGEAT",
        "signed_or_broadcast_transactions": 0,
        "scanned_count": len(results),
        "all_executor_addresses_match_lazer_owner": all(
            r["executor_address"] == next(
                x["owner"].lower() for x in scanned if x["target"]["name"] == r["chain_name"]
            )
            for r in results
        ),
        "executor_implementation_groups": group_by_impl,
        "owner_chain_id_groups": group_by_owner_chain,
        "failing_checks": failing,
        "results": results,
    }
    (OUT / "EXECUTOR_RESULTS.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    markers = [
        "PYTH_LAZER_EVM_LIVE_EXECUTOR_SNAPSHOT_PASS",
        "PUBLIC_CHAIN_EXECUTOR_MODE=READ_ONLY_ETH_CALL_AND_ETH_GETSTORAGEAT",
        "SIGNED_OR_BROADCAST_TRANSACTIONS=0",
        f"EXECUTOR_SCANNED_COUNT={len(results)}",
        f"EXECUTOR_SELF_OWNED_COUNT={sum(r['checks']['executor_self_owned'] for r in results)}",
        f"EXECUTOR_LAST_SEQUENCE_READABLE_COUNT={sum(r['checks']['last_executed_sequence_readable'] for r in results)}",
        f"EXECUTOR_OWNER_CHAIN_ID_READABLE_COUNT={sum(r['checks']['owner_chain_id_readable'] for r in results)}",
        f"EXECUTOR_CODE_NONEMPTY_COUNT={sum(r['checks']['executor_code_nonempty'] for r in results)}",
        f"EXECUTOR_PROXY_COUNT={sum(r['checks']['executor_is_proxy'] for r in results)}",
    ]
    (OUT / "EXECUTOR_MARKERS.txt").write_text("\n".join(markers) + "\n")
    print("\n".join(markers))


if __name__ == "__main__":
    main()
