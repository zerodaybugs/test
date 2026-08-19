#!/usr/bin/env python3
"""R45 per-network hardening wrapper around the pinned R42 live census.

It isolates each network, replaces fragile batch behavior, extends live checks for
BlockList/FeeDispatcher/target-asset bindings, and remains read-only.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

SAFE_NETWORKS: dict[str, tuple[int, list[str]]] = {
    "ethereum": (1, ["https://rpc.flashbots.net", "https://eth.llamarpc.com", "https://1rpc.io/eth", "https://ethereum-rpc.publicnode.com"]),
    "optimism": (10, ["https://mainnet.optimism.io", "https://optimism.llamarpc.com", "https://1rpc.io/op", "https://optimism-rpc.publicnode.com"]),
    "bnb": (56, ["https://bsc-dataseed.binance.org", "https://binance.llamarpc.com", "https://1rpc.io/bnb", "https://bsc-rpc.publicnode.com"]),
    "polygon": (137, ["https://polygon-rpc.com", "https://polygon.llamarpc.com", "https://1rpc.io/matic", "https://polygon-bor-rpc.publicnode.com"]),
    "base": (8453, ["https://mainnet.base.org", "https://base.llamarpc.com", "https://1rpc.io/base", "https://base-rpc.publicnode.com"]),
    "arbitrum": (42161, ["https://arb1.arbitrum.io/rpc", "https://arbitrum.llamarpc.com", "https://1rpc.io/arb", "https://arbitrum-one-rpc.publicnode.com"]),
}
ZERO = "0x" + "00" * 20
PROBE = "0x1000000000000000000000000000000000000045"
VAULT_STORAGE_BASE = int("6bb5a2a0ae924c2ea94f037035a09f65614421e2a7d96c9bcbd59acdd32e6000", 16)


def load_module(network: str):
    source_path = Path("kiln_r42/live_config_delta.py")
    source = source_path.read_text()
    source = source.replace('OUT = Path("r42_results")', f'OUT = Path("r45_results/{network}")')
    source = source.replace("len(scope_rows) >= 49", "len(scope_rows) >= 1")
    patched = Path("kiln_r45") / f"_patched_r42_{network}.py"
    patched.write_text(source)
    spec = importlib.util.spec_from_file_location(f"kiln_r45_{network}", patched)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to create module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.NETWORKS = {network: SAFE_NETWORKS[network]}

    original_scope = module.fetch_scope
    def filtered_scope():
        rows, summary, sha = original_scope()
        selected = [row for row in rows if row.get("network") == network]
        summary = dict(summary)
        summary["full_scope_count"] = len(rows)
        summary["selected_network"] = network
        summary["selected_network_count"] = len(selected)
        summary["checks"] = dict(summary.get("checks", {}), selected_network_nonempty=bool(selected))
        return selected, summary, sha
    module.fetch_scope = filtered_scope

    def robust_batch(self, calls, chunk=18):
        results = []
        for start in range(0, len(calls), chunk):
            current = calls[start:start + chunk]
            payload = []
            id_to_index = {}
            for index, (method, params) in enumerate(current):
                request_id = self.next_id
                self.next_id += 1
                id_to_index[request_id] = index
                payload.append({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            ordered = [None] * len(current)
            try:
                response = module.json_request(self.url, payload)
                if not isinstance(response, list):
                    raise RuntimeError("batch response not list")
                for item in response:
                    if item.get("id") in id_to_index:
                        ordered[id_to_index[item["id"]]] = item
            except Exception:
                pass
            for index, item in enumerate(ordered):
                method, params = current[index]
                if item is not None and item.get("error") is None:
                    results.append({"ok": True, "value": item.get("result"), "method": method})
                    continue
                try:
                    value = self.call(method, params)
                    results.append({"ok": True, "value": value, "method": method})
                except Exception as exc:
                    results.append({"ok": False, "error": f"{type(exc).__name__}: {exc}", "method": method})
        return results
    module.RpcEndpoint.batch = robust_batch
    return module


def safe_decode(module, rpc, to: str, signature: str, block: int, kind: str, args: list[str] | None = None) -> dict[str, Any]:
    try:
        call = module.eth_call(to, module.calldata(signature, args or []), block)
        result = rpc.batch([call])[0]
        return module.decode_result(result, kind)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def code_state(module, rpc, address: str | None, block: int) -> dict[str, Any]:
    if not address or address == ZERO:
        return {"ok": False, "bytes": 0, "error": "zero/unresolved address"}
    result = rpc.batch([module.code_call(address, block)])[0]
    raw = result.get("value") if result.get("ok") else None
    return {
        "ok": bool(result.get("ok")),
        "bytes": len(raw.removeprefix("0x")) // 2 if isinstance(raw, str) else 0,
        "sha256": module.code_sha256(raw) if isinstance(raw, str) else None,
        "error": result.get("error") if not result.get("ok") else None,
    }


def first_address(module, rpc, target: str | None, signatures: list[str], block: int) -> dict[str, Any]:
    attempts = []
    if not target:
        return {"address": None, "getter": None, "attempts": attempts}
    for signature in signatures:
        result = safe_decode(module, rpc, target, signature, block, "address")
        attempts.append({"signature": signature, "result": result})
        value = module.addr_or_none(result)
        if value and value != ZERO:
            return {"address": value, "getter": signature, "attempts": attempts}
    return {"address": None, "getter": None, "attempts": attempts}


def extend_evidence(module, network: str) -> int:
    out = Path("r45_results") / network
    evidence_path = out / "EVIDENCE.json"
    evidence = json.loads(evidence_path.read_text())
    if not evidence.get("chains"):
        return 2
    chain = evidence["chains"][0]
    block = int(chain["block"])
    primary = module.RpcEndpoint(chain["rpc_urls"][0], SAFE_NETWORKS[network][0])
    secondary = module.RpcEndpoint(chain["rpc_urls"][1], SAFE_NETWORKS[network][0])
    candidates = list(evidence.get("research_candidates", []))
    inventory = list(evidence.get("inventory_triggers", []))
    known = list(evidence.get("duplicate_or_known_signals", []))
    extension_mismatches: list[dict[str, Any]] = []
    now = int(time.time())

    for item in evidence.get("vaults", []):
        vault = item["address"]
        supply = module.int_or_none(item.get("total_supply", {}))
        share_decimals = module.int_or_none(item.get("share_decimals", {}))
        min_supply = module.int_or_none(item.get("min_total_supply_storage", {})) or 0
        material = bool(supply is not None and supply > max(min_supply * 100, 10 ** max(0, (share_decimals or 0) - 3)))
        item["material_supply_r45"] = material
        base = {
            "network": network, "vault": vault, "label": item.get("label"),
            "connector_name": item.get("connector_name_decoded") or item.get("scope_connector"),
            "block": block, "block_hash": chain.get("block_hash"),
        }

        blocklist_a = safe_decode(module, primary, vault, "blockList()", block, "address")
        blocklist_b = safe_decode(module, secondary, vault, "blockList()", block, "address")
        item["r45_blocklist"] = blocklist_a
        if blocklist_a.get("ok") != blocklist_b.get("ok") or blocklist_a.get("value") != blocklist_b.get("value"):
            extension_mismatches.append({**base, "field": "blockList", "primary": blocklist_a, "secondary": blocklist_b})
        blocklist = module.addr_or_none(blocklist_a)
        item["r45_blocklist_code"] = code_state(module, primary, blocklist, block)
        if blocklist and blocklist != ZERO:
            sanctions_a = safe_decode(module, primary, blocklist, "underlyingSanctionsList()", block, "address")
            sanctions_b = safe_decode(module, secondary, blocklist, "underlyingSanctionsList()", block, "address")
            item["r45_sanctions_list"] = sanctions_a
            if sanctions_a.get("ok") != sanctions_b.get("ok") or sanctions_a.get("value") != sanctions_b.get("value"):
                extension_mismatches.append({**base, "field": "underlyingSanctionsList", "primary": sanctions_a, "secondary": sanctions_b})
            sanctions = module.addr_or_none(sanctions_a)
            item["r45_sanctions_code"] = code_state(module, primary, sanctions, block)
            blocked = safe_decode(module, primary, blocklist, "isBlocked(address)", block, "bool", [module.encode_address(PROBE)])
            item["r45_blocklist_probe"] = blocked
            if material and (item["r45_blocklist_code"].get("bytes", 0) == 0 or not blocked.get("ok")):
                candidates.append({**base, "kind": "material_blocklist_liveness_failure", "severity_ceiling": "High"})
            if material and (not sanctions or item["r45_sanctions_code"].get("bytes", 0) == 0):
                candidates.append({**base, "kind": "material_sanctions_binding_missing_or_no_code", "severity_ceiling": "High"})

        storage = primary.batch([module.storage_call(vault, VAULT_STORAGE_BASE + 9, block)])[0]
        raw = storage.get("value") if storage.get("ok") else None
        try:
            packed = int(str(raw), 16)
            dispatcher = "0x" + format((packed >> 16) & ((1 << 160) - 1), "040x")
            item["r45_slot9"] = {"ok": True, "deposit_paused": bool(packed & 0xff), "strategy": (packed >> 8) & 0xff, "fee_dispatcher": dispatcher, "raw": raw}
        except Exception as exc:
            dispatcher = None
            item["r45_slot9"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "raw": raw}
        item["r45_fee_dispatcher_code"] = code_state(module, primary, dispatcher, block)
        if material and (not dispatcher or dispatcher == ZERO or item["r45_fee_dispatcher_code"].get("bytes", 0) == 0):
            candidates.append({**base, "kind": "material_fee_dispatcher_missing_or_no_code", "severity_ceiling": "High"})

        connector = module.addr_or_none(item.get("connector", {}))
        name = item.get("connector_name_decoded") or item.get("scope_connector")
        target = None
        target_source = None
        if name == "COMPOUND_V3":
            target = module.addr_or_none(item.get("comet", {})); target_source = "market_registry"
        elif str(name).startswith("METAMORPHO"):
            target = module.addr_or_none(item.get("nested_vault", {})); target_source = "metamorpho()"
        elif name == "FLUID":
            target = module.addr_or_none(item.get("f_token", {})); target_source = "fToken()"
        elif name == "VENUS":
            target = module.addr_or_none(item.get("v_token", {})); target_source = "vToken()"
        elif name == "AAVE_V3":
            target = module.addr_or_none(item.get("aave_pool", {})); target_source = "aave()"
        elif name == "SDAI":
            resolved = first_address(module, primary, connector, ["sDAI()"], block); target = resolved["address"]; target_source = resolved["getter"]
        elif name == "SUSDS":
            resolved = first_address(module, primary, connector, ["sUSDS()"], block); target = resolved["address"]; target_source = resolved["getter"]
        elif str(name).startswith("ANGLE_"):
            resolved = first_address(module, primary, connector, ["stakingVault()"], block); target = resolved["address"]; target_source = resolved["getter"]
        item["r45_target"] = {"address": target, "source": target_source, "code": code_state(module, primary, target, block)}

        target_asset = None
        getter = None
        attempts = []
        if target and name != "AAVE_V3":
            for signature in ["asset()", "underlying()", "baseToken()", "token()"]:
                result = safe_decode(module, primary, target, signature, block, "address")
                attempts.append({"signature": signature, "result": result})
                value = module.addr_or_none(result)
                if value and value != ZERO:
                    target_asset = value; getter = signature; break
        vault_asset = module.addr_or_none(item.get("asset", {}))
        item["r45_target_asset"] = {
            "target": target, "target_asset": target_asset, "getter": getter,
            "attempts": attempts, "vault_asset": vault_asset,
            "matches": bool(target_asset and vault_asset and target_asset == vault_asset),
        }
        if material and target_asset and vault_asset and target_asset != vault_asset:
            candidates.append({**base, "kind": "connector_target_asset_mismatch", "target": target, "target_asset": target_asset, "vault_asset": vault_asset, "severity_ceiling": "Critical"})
        if material and target and item["r45_target"]["code"].get("bytes", 0) == 0:
            candidates.append({**base, "kind": "material_connector_target_no_code", "severity_ceiling": "High"})

        direct = module.int_or_none(item.get("direct_asset_balance", {}))
        pending = (module.int_or_none(item.get("pending_deposit_fee", {})) or 0) + (module.int_or_none(item.get("pending_reward_fee", {})) or 0)
        if direct is not None and direct < pending:
            candidates.append({**base, "kind": "fee_reserve_shortfall", "shortfall_raw": pending - direct, "severity_ceiling": "Medium"})
        pause_timestamp = module.int_or_none(item.get("pause_timestamp", {})) or 0
        if material and bool(item.get("connector_paused", {}).get("value")):
            candidates.append({**base, "kind": "material_connector_paused", "pause_timestamp": pause_timestamp, "seconds_remaining": max(0, pause_timestamp - now), "severity_ceiling": "High" if pause_timestamp > now + 172800 else "Medium"})

    deduped = []
    seen = set()
    for candidate in candidates:
        key = (candidate.get("network"), candidate.get("vault"), candidate.get("kind"))
        if key not in seen:
            seen.add(key); deduped.append(candidate)
    candidates = deduped

    coverage = bool(evidence.get("coverage_complete")) and not extension_mismatches
    if not coverage:
        decision = "INCONCLUSIVE_R45_EXTENSION_QUORUM_OR_BASE_COVERAGE"
    elif candidates:
        decision = "HOLD_R45_NEW_RUNTIME_CANDIDATES_REQUIRE_FIXED_BLOCK_POC"
    elif inventory:
        decision = "HOLD_R45_INVENTORY_DELTA_REQUIRES_SOURCE_DIFF"
    else:
        decision = "KILL_R45_NO_NEW_RUNTIME_INVARIANT_SIGNAL"

    evidence["schema"] = "kiln-r45-network-evidence-v2"
    evidence["r45_extension_quorum_mismatches"] = extension_mismatches
    evidence["research_candidates"] = candidates
    evidence["inventory_triggers"] = inventory
    evidence["duplicate_or_known_signals"] = known
    evidence["coverage_complete"] = coverage
    evidence["decision"] = decision
    evidence["submit_ready"] = False
    evidence["validated_critical"] = 0
    evidence["validated_high"] = 0
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True))

    gate = {
        "schema": "kiln-r45-network-public-gate-v2",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "network": network, "decision": decision, "coverage_complete": coverage,
        "selected_count": len(evidence.get("vaults", [])), "inspected_count": len(evidence.get("vaults", [])),
        "base_error_count": len(evidence.get("errors", [])),
        "base_quorum_mismatch_count": len(evidence.get("quorum_mismatches", [])),
        "extension_quorum_mismatch_count": len(extension_mismatches),
        "candidate_count": len(candidates), "inventory_trigger_count": len(inventory),
        "known_or_duplicate_signal_count": len(known),
        "candidate_kinds": dict(sorted({kind: sum(1 for c in candidates if c.get("kind") == kind) for kind in {c.get("kind") for c in candidates}}.items())),
        "block": block, "block_hash": chain.get("block_hash"), "rpc_urls": chain.get("rpc_urls"),
        "submit_ready": False, "validated_critical": 0, "validated_high": 0,
        "public_chain_state_changes": 0, "transactions_signed": 0, "transactions_sent": 0,
    }
    (out / "PUBLIC_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    (out / "CANDIDATE_SUMMARY.json").write_text(json.dumps({
        "network": network, "decision": decision, "candidates": candidates,
        "inventory_triggers": inventory, "known_or_duplicate_signals": known,
        "submit_ready": False, "validated_critical": 0, "validated_high": 0,
    }, indent=2, sort_keys=True))
    files = sorted(p for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt")
    (out / "SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files
    ))
    print(json.dumps(gate, sort_keys=True))
    return 0 if coverage else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", required=True, choices=sorted(SAFE_NETWORKS))
    args = parser.parse_args()
    module = load_module(args.network)
    base_code = module.main()
    extension_code = extend_evidence(module, args.network)
    return 0 if base_code == 0 and extension_code == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
