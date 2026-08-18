#!/usr/bin/env python3
"""Fail-closed post-processor for Kiln R42 coverage.

The primary census intentionally preserves contract-level reverts as evidence. This
hardener distinguishes a potentially meaningful totalAssets() revert from missing
instrumentation: every other binding/accounting field must decode successfully.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

OUT = Path("r42_results")
EVIDENCE = OUT / "EVIDENCE.json"
GATE = OUT / "PUBLIC_GATE.json"
SUMMARY = OUT / "CANDIDATE_SUMMARY.json"

ESSENTIAL_OK_FIELDS = (
    "asset",
    "connector_registry",
    "connector_name_raw",
    "total_supply",
    "share_decimals",
    "reward_fee",
    "deposit_fee",
    "additional_rewards_strategy",
    "pending_deposit_fee",
    "pending_reward_fee",
    "transferable",
    "last_total_assets_storage",
    "min_total_supply_storage",
    "packed_transferable_offset_storage",
    "beacon_storage",
    "vault_implementation",
    "connector",
    "asset_decimals",
    "direct_asset_balance",
)

QUORUM_OK_FIELDS = (
    "asset",
    "connector_registry",
    "connector_name_raw",
    "total_supply",
    "additional_rewards_strategy",
    "reward_fee",
    "beacon_storage",
)


def okay(value: Any) -> bool:
    return isinstance(value, dict) and value.get("ok") is True


def main() -> int:
    if not EVIDENCE.exists() or not GATE.exists():
        return 2

    evidence = json.loads(EVIDENCE.read_text())
    gate = json.loads(GATE.read_text())
    failures: list[dict[str, Any]] = []

    vaults = evidence.get("vaults")
    if not isinstance(vaults, list):
        failures.append({"stage": "schema", "error": "vaults is not a list"})
        vaults = []

    for item in vaults:
        identity = {
            "network": item.get("network"),
            "vault": item.get("address"),
            "label": item.get("label"),
        }
        for field in ESSENTIAL_OK_FIELDS:
            if not okay(item.get(field)):
                failures.append({**identity, "field": field, "error": item.get(field)})
        connector_code = item.get("connector_code")
        if not isinstance(connector_code, dict) or not connector_code.get("ok") or not connector_code.get("sha256") or int(connector_code.get("bytes", 0) or 0) == 0:
            failures.append({**identity, "field": "connector_code", "error": connector_code})
        implementation_code = item.get("vault_implementation_code")
        if not isinstance(implementation_code, dict) or not implementation_code.get("ok") or not implementation_code.get("sha256") or int(implementation_code.get("bytes", 0) or 0) == 0:
            failures.append({**identity, "field": "vault_implementation_code", "error": implementation_code})

        secondary = item.get("quorum_secondary")
        if not isinstance(secondary, dict):
            failures.append({**identity, "field": "quorum_secondary", "error": secondary})
        else:
            for field in QUORUM_OK_FIELDS:
                if not okay(secondary.get(field)):
                    failures.append({**identity, "field": f"quorum_secondary.{field}", "error": secondary.get(field)})

    scope_count = int((evidence.get("scope_summary") or {}).get("row_count", 0) or 0)
    chain_count = len(evidence.get("chains") or [])
    expected_chain_count = len({item.get("network") for item in vaults if item.get("network")})
    if scope_count != len(vaults):
        failures.append({"stage": "coverage", "error": f"scope_count={scope_count}, vault_count={len(vaults)}"})
    if chain_count != expected_chain_count:
        failures.append({"stage": "coverage", "error": f"chain_count={chain_count}, expected={expected_chain_count}"})
    if evidence.get("errors"):
        failures.append({"stage": "primary_errors", "error": evidence.get("errors")})
    if evidence.get("quorum_mismatches"):
        failures.append({"stage": "quorum_mismatches", "error": evidence.get("quorum_mismatches")})

    hardened_complete = not failures and bool(evidence.get("coverage_complete"))
    evidence["essential_coverage_failures"] = failures
    evidence["essential_coverage_failure_count"] = len(failures)
    evidence["coverage_complete_before_hardener"] = bool(evidence.get("coverage_complete"))
    evidence["coverage_complete"] = hardened_complete
    if not hardened_complete:
        evidence["decision"] = "INCONCLUSIVE_FAIL_CLOSED_ESSENTIAL_FIELD_COVERAGE"

    gate["essential_coverage_failure_count"] = len(failures)
    gate["coverage_complete_before_hardener"] = bool(gate.get("coverage_complete"))
    gate["coverage_complete"] = hardened_complete
    if not hardened_complete:
        gate["decision"] = "INCONCLUSIVE_FAIL_CLOSED_ESSENTIAL_FIELD_COVERAGE"
    gate["submit_ready"] = False
    gate["validated_critical"] = 0
    gate["validated_high"] = 0

    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True))
    GATE.write_text(json.dumps(gate, indent=2, sort_keys=True))
    if SUMMARY.exists():
        summary = json.loads(SUMMARY.read_text())
        summary["essential_coverage_failure_count"] = len(failures)
        summary["coverage_complete"] = hardened_complete
        SUMMARY.write_text(json.dumps(summary, indent=2, sort_keys=True))

    files = sorted(path for path in OUT.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files
    ))
    print(json.dumps({
        "coverage_complete": hardened_complete,
        "essential_coverage_failure_count": len(failures),
        "decision": gate.get("decision"),
    }, sort_keys=True))
    return 0 if hardened_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
