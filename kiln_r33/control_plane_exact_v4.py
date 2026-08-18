#!/usr/bin/env python3
"""ABI-corpus and Vault-config extension for the R33 control-plane gate."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from web3 import Web3

import control_plane_exact_v2 as gate


def slot(label: str) -> int:
    return int.from_bytes(bytes(Web3.keccak(text=label)), "big") - 1


gate.IMPLEMENTATION_SLOT = slot("eip1967.proxy.implementation")
gate.ADMIN_SLOT = slot("eip1967.proxy.admin")
gate.ADMIN_SLOT_CANON = gate.ADMIN_SLOT
gate.BEACON_SLOT = slot("eip1967.proxy.beacon")
gate.SENSITIVE_SLOTS = {
    "eip1967_implementation": gate.IMPLEMENTATION_SLOT,
    "eip1967_admin": gate.ADMIN_SLOT,
    "eip1967_beacon": gate.BEACON_SLOT,
}

ORIGINAL_DISCOVER = gate.discover_components
ORIGINAL_BUILD_PAYLOADS = gate.build_payloads
ORIGINAL_STATE_FINGERPRINT = gate.state_fingerprint
ORIGINAL_SENSITIVE_DIFF = gate.sensitive_diff

CONFIG_VIEW_SIGNATURES = [
    "asset()",
    "vaultFactory()",
    "connectorRegistry()",
    "connectorName()",
    "blockList()",
    "depositFee()",
    "rewardFee()",
    "additionalRewardsStrategy()",
    "transferable()",
    "feeDispatcher()",
    "feeReceiver()",
    "paused()",
    "frozen()",
]


def discover_components_extended(w3: Web3, rows: list[Any], block: int) -> dict[str, Any]:
    result = ORIGINAL_DISCOVER(w3, rows, block)
    by_address = {entry["address"].lower():entry for entry in result["components"]}
    # One representative Vault proxy per runtime/beacon/connector cluster. Access
    # control is implementation-level; testing all 101 identical proxies would
    # add cost without adding a new authorization boundary.
    seen_clusters: set[tuple[Any, ...]] = set()
    for row in result["vaults"]:
        cluster = (
            row.get("vault_code_sha256"),
            (row.get("beacon") or "").lower(),
            row.get("scope_connector"),
        )
        if cluster in seen_clusters:
            continue
        seen_clusters.add(cluster)
        address = Web3.to_checksum_address(row["vault"])
        entry = by_address.setdefault(address.lower(), {
            "address":address,
            "categories":[],
            "discovered_from":[],
            "code_sha256":row.get("vault_code_sha256"),
        })
        entry["categories"] = sorted(set(entry["categories"] + ["vault_proxy_representative"]))
        entry["discovered_from"] = sorted(set(entry["discovered_from"] + [address]))
    result["components"] = sorted(by_address.values(), key=lambda item:item["address"].lower())
    return result


def build_payloads_extended(w3: Web3, attacker: str) -> list[dict[str, Any]]:
    payloads = ORIGINAL_BUILD_PAYLOADS(w3, attacker)
    corpus_path = Path(os.environ.get("R33_PAYLOAD_CORPUS", "r33_payload_corpus.json"))
    if corpus_path.exists():
        corpus = json.loads(corpus_path.read_text())
        for entry in corpus.get("entries", []):
            try:
                payloads.append({
                    "label":entry["label"],
                    "data":bytes.fromhex(str(entry["data_hex"]).removeprefix("0x")),
                    "abi_contract":entry.get("contract"),
                    "abi_signature":entry.get("signature"),
                })
            except Exception as exc:
                payloads.append({
                    "label":f"corpus_decode_error:{entry.get('label')}",
                    "encoding_error":f"{type(exc).__name__}: {exc}",
                })
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for payload in payloads:
        data = payload.get("data")
        if isinstance(data, (bytes, bytearray)):
            key = bytes(data).hex()
            if key in seen:
                continue
            seen.add(key)
        deduped.append(payload)
    return deduped


def state_fingerprint_extended(w3: Web3, target: str, attacker: str) -> dict[str, Any]:
    result = ORIGINAL_STATE_FINGERPRINT(w3, target, attacker)
    result["control_views"] = {
        signature: gate.view_raw(w3, target, signature)
        for signature in CONFIG_VIEW_SIGNATURES
    }
    return result


def sensitive_diff_extended(before: dict[str, Any], after: dict[str, Any], attacker: str) -> dict[str, Any]:
    changes = ORIGINAL_SENSITIVE_DIFF(before, after, attacker)
    before_views = before.get("control_views", {})
    after_views = after.get("control_views", {})
    for signature in sorted(set(before_views) | set(after_views)):
        if gate.normalize(before_views.get(signature)) != gate.normalize(after_views.get(signature)):
            changes[f"control_view:{signature}"] = {
                "before":before_views.get(signature),
                "after":after_views.get(signature),
            }
    # Payloads are restricted to admin/control verbs. A deterministic storage
    # write in the first 16 conventional slots is therefore a real mutation
    # signal, though it still requires source/impact review before severity.
    for slot_index in gate.generic_storage_diff(before, after):
        changes[f"control_storage_slot:{slot_index}"] = {
            "before":before["storage_0_15"][str(slot_index)],
            "after":after["storage_0_15"][str(slot_index)],
        }
    return changes


gate.discover_components = discover_components_extended
gate.build_payloads = build_payloads_extended
gate.state_fingerprint = state_fingerprint_extended
gate.sensitive_diff = sensitive_diff_extended

if __name__ == "__main__":
    raise SystemExit(gate.main())
