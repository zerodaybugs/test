#!/usr/bin/env python3
"""Read-only raw-storage audit of Pyth Lazer EVM trusted-signer state."""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from Crypto.Hash import keccak

from snapshot import rpc_request, result_or_error

OUT = Path(os.environ.get("PRIVATE_OUT", "private_out"))
TRUSTED_SIGNERS_BASE_SLOT = 0
TRUSTED_SIGNER_COUNT = 100
VERIFICATION_FEE_SLOT = 200
TRUSTED_SIGNER_EXPIRY_MAPPING_SLOT = 201


def storage_word(url: str, address: str, slot: int | str, request_id: int) -> dict[str, Any]:
    slot_arg = hex(slot) if isinstance(slot, int) else slot
    return result_or_error(rpc_request(url, "eth_getStorageAt", [address, slot_arg, "latest"], request_id))


def word_int(obj: dict[str, Any]) -> int | None:
    value = obj.get("result") if obj.get("status") == "RESULT" else None
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def word_address(value: int) -> str:
    return "0x" + (value & ((1 << 160) - 1)).to_bytes(20, "big").hex()


def mapping_storage_slot(address: str, mapping_slot: int) -> str:
    key = bytes.fromhex(address.removeprefix("0x").rjust(64, "0"))
    slot = mapping_slot.to_bytes(32, "big")
    h = keccak.new(digest_bits=256)
    h.update(key + slot)
    return "0x" + h.hexdigest()


def scan_chain(item: dict[str, Any], id_base: int) -> dict[str, Any]:
    target = item["target"]
    name = target["name"]
    url = item["chosen_rpc"]
    address = target["address"]
    latest_timestamp = int(item.get("latest_block", {}).get("timestamp") or 0)
    request_id = id_base

    signers: list[dict[str, Any]] = []
    stale_expiry_slots: list[dict[str, Any]] = []
    read_errors: list[dict[str, Any]] = []

    for index in range(TRUSTED_SIGNER_COUNT):
        pub_slot_index = TRUSTED_SIGNERS_BASE_SLOT + index * 2
        expiry_slot_index = pub_slot_index + 1
        pub_obj = storage_word(url, address, pub_slot_index, request_id)
        request_id += 1
        expiry_obj = storage_word(url, address, expiry_slot_index, request_id)
        request_id += 1
        pub_value = word_int(pub_obj)
        expiry_value = word_int(expiry_obj)
        if pub_value is None or expiry_value is None:
            read_errors.append(
                {
                    "index": index,
                    "pubkey_slot": pub_obj,
                    "expiry_slot": expiry_obj,
                }
            )
            continue
        if pub_value == 0:
            if expiry_value != 0:
                stale_expiry_slots.append(
                    {
                        "index": index,
                        "expiry": expiry_value,
                        "expiry_slot": expiry_slot_index,
                    }
                )
            continue

        signer = word_address(pub_value)
        map_slot = mapping_storage_slot(signer, TRUSTED_SIGNER_EXPIRY_MAPPING_SLOT)
        map_obj = storage_word(url, address, map_slot, request_id)
        request_id += 1
        map_expiry = word_int(map_obj)
        signers.append(
            {
                "index": index,
                "address": signer,
                "array_expiry": expiry_value,
                "mapping_expiry": map_expiry,
                "mapping_slot": map_slot,
                "mapping_matches_array": map_expiry == expiry_value,
                "active_at_latest_block": expiry_value > latest_timestamp,
            }
        )

    fee_obj = storage_word(url, address, VERIFICATION_FEE_SLOT, request_id)
    request_id += 1
    fee_storage = word_int(fee_obj)

    normalized = sorted(
        (s["address"].lower(), int(s["array_expiry"])) for s in signers
    )
    active = sorted(
        (s["address"].lower(), int(s["array_expiry"]))
        for s in signers
        if s["active_at_latest_block"]
    )
    address_counts = Counter(s["address"].lower() for s in signers)

    checks = {
        "all_storage_reads_succeeded": not read_errors,
        "no_duplicate_signer_addresses": all(count == 1 for count in address_counts.values()),
        "mapping_matches_array_for_all_signers": all(s["mapping_matches_array"] for s in signers),
        "no_nonzero_expiry_in_empty_slots": not stale_expiry_slots,
        "at_least_one_active_signer": bool(active),
        "fee_storage_matches_view": fee_storage == item.get("verification_fee"),
    }

    return {
        "name": name,
        "chain_id": item.get("observed_chain_id"),
        "contract": address,
        "rpc": url,
        "latest_block": item.get("latest_block"),
        "version": item.get("version"),
        "implementation_address": item.get("implementation_address"),
        "owner": item.get("owner"),
        "verification_fee_view": item.get("verification_fee"),
        "verification_fee_storage": fee_storage,
        "signers": signers,
        "normalized_signer_set": normalized,
        "active_signer_set": active,
        "read_errors": read_errors,
        "stale_expiry_slots": stale_expiry_slots,
        "checks": checks,
    }


def main() -> None:
    source = json.loads((OUT / "RESULTS.json").read_text())
    scanned = [item for item in source["results"] if item.get("status") == "SCANNED"]
    results = [scan_chain(item, 50000 + i * 1000) for i, item in enumerate(scanned)]

    groups: dict[str, list[str]] = defaultdict(list)
    active_groups: dict[str, list[str]] = defaultdict(list)
    for result in results:
        groups[json.dumps(result["normalized_signer_set"], separators=(",", ":"))].append(result["name"])
        active_groups[json.dumps(result["active_signer_set"], separators=(",", ":"))].append(result["name"])

    failing = {
        key: [r["name"] for r in results if not r["checks"][key]]
        for key in sorted(results[0]["checks"] if results else {})
    }
    summary = {
        "mode": "PUBLIC_CHAIN_READ_ONLY_ETH_GETSTORAGEAT",
        "signed_or_broadcast_transactions": 0,
        "scanned_count": len(results),
        "signer_set_groups": groups,
        "active_signer_set_groups": active_groups,
        "failing_checks": failing,
        "results": results,
    }
    (OUT / "SIGNER_RESULTS.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    markers = [
        "PUBLIC_CHAIN_SIGNER_MODE=READ_ONLY_ETH_GETSTORAGEAT",
        "SIGNED_OR_BROADCAST_TRANSACTIONS=0",
        f"SIGNER_SCANNED_COUNT={len(results)}",
        f"SIGNER_SET_GROUP_COUNT={len(groups)}",
        f"ACTIVE_SIGNER_SET_GROUP_COUNT={len(active_groups)}",
        f"CHAINS_WITH_NO_ACTIVE_SIGNER={len(failing.get('at_least_one_active_signer', []))}",
        f"CHAINS_WITH_MAPPING_MISMATCH={len(failing.get('mapping_matches_array_for_all_signers', []))}",
        f"CHAINS_WITH_DUPLICATE_SIGNER={len(failing.get('no_duplicate_signer_addresses', []))}",
        f"CHAINS_WITH_STALE_EMPTY_SLOT_EXPIRY={len(failing.get('no_nonzero_expiry_in_empty_slots', []))}",
        f"CHAINS_WITH_STORAGE_READ_ERROR={len(failing.get('all_storage_reads_succeeded', []))}",
        f"CHAINS_WITH_FEE_VIEW_STORAGE_MISMATCH={len(failing.get('fee_storage_matches_view', []))}",
    ]
    (OUT / "SIGNER_MARKERS.txt").write_text("\n".join(markers) + "\n")
    for marker in markers:
        print(marker)


if __name__ == "__main__":
    main()
