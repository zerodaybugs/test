#!/usr/bin/env python3
"""Fail-closed classifier for Kiln R31 runtime evidence.

The output intentionally omits exact vault addresses and raw exploit-sensitive data.
It classifies public-chain accounting/configuration signals only; it never assigns
bounty severity or submit-ready status.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def value(result: Any) -> Any:
    return result.get("value") if isinstance(result, dict) and result.get("ok") else None


def integer(value_: Any, default: int = 0) -> int:
    try:
        return int(value_)
    except Exception:
        return default


def anonymize(network: str, vault: str) -> str:
    return hashlib.sha256(f"kiln-r32|{network}|{vault.lower()}".encode()).hexdigest()[:16]


def amount_bucket(amount: float | None) -> str:
    if amount is None:
        return "unknown"
    if amount < 1:
        return "lt_1_token"
    if amount < 100:
        return "1_to_100_tokens"
    if amount < 10_000:
        return "100_to_10k_tokens"
    return "gte_10k_tokens"


def ratio_bucket(ppm: int | None) -> str:
    if ppm is None:
        return "unknown"
    if ppm < 100:
        return "lt_1bp"
    if ppm < 1_000:
        return "1bp_to_10bp"
    if ppm < 10_000:
        return "10bp_to_1pct"
    return "gte_1pct"


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: classify_runtime.py EVIDENCE.json OUTPUT.json")
    source_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    evidence = json.loads(source_path.read_text())

    category_counts: Counter[str] = Counter()
    connector_signal_counts: dict[str, Counter[str]] = defaultdict(Counter)
    error_connector_counts: Counter[str] = Counter()
    amount_buckets: Counter[str] = Counter()
    ratio_buckets: Counter[str] = Counter()
    classified_rows: list[dict[str, Any]] = []
    escalation_rows: list[dict[str, Any]] = []

    for row in evidence.get("rows", []):
        network = str(row.get("network") or evidence.get("matrix", {}).get("network") or "unknown")
        vault = str(row.get("vault") or "")
        connector = str(row.get("connector_name_ascii") or row.get("scope_connector") or "UNKNOWN")
        raw_signals = [str(x) for x in row.get("signals", [])]
        signals = sorted(set(raw_signals))
        if not signals:
            continue

        quorum = row.get("secondary_quorum") or {}
        quorum_confirmed = bool(quorum.get("matches_primary") and quorum.get("direct_matches"))
        if "unconfirmed_single_rpc_only" in signals or "killed_rpc_quorum_mismatch" in signals:
            quorum_confirmed = False

        accounting = row.get("accounting") or {}
        excess_raw = integer(accounting.get("direct_minus_pending"))
        decimals = value((row.get("asset_token") or {}).get("decimals"))
        decimals_int = integer(decimals, -1)
        excess_tokens = (excess_raw / (10 ** decimals_int)) if decimals_int >= 0 else None
        total_assets = integer(value(row.get("totalAssets")))
        ratio_ppm = (excess_raw * 1_000_000 // total_assets) if excess_raw > 0 and total_assets > 0 else None

        row_categories: list[str] = []
        for signal in signals:
            if signal in {
                "direct_asset_exceeds_pending_fee_reserve",
                "direct_asset_below_pending_fee_reserve",
                "positive_supply_totalAssets_reverts",
                "positive_supply_zero_totalAssets",
                "connector_paused_with_positive_supply",
                "connector_frozen",
                "scope_connector_name_runtime_mismatch",
            }:
                row_categories.append(signal)
            elif signal not in {"unconfirmed_single_rpc_only", "killed_rpc_quorum_mismatch"}:
                row_categories.append("other_runtime_signal")

        for category in row_categories:
            category_counts[category] += 1
            connector_signal_counts[connector][category] += 1

        if "direct_asset_exceeds_pending_fee_reserve" in signals:
            amount_buckets[amount_bucket(excess_tokens)] += 1
            ratio_buckets[ratio_bucket(ratio_ppm)] += 1

        escalation_reasons: list[str] = []
        if quorum_confirmed:
            if "positive_supply_totalAssets_reverts" in signals:
                escalation_reasons.append("positive_supply_totalAssets_reverts")
            if "positive_supply_zero_totalAssets" in signals:
                escalation_reasons.append("positive_supply_zero_totalAssets")
            if "scope_connector_name_runtime_mismatch" in signals:
                escalation_reasons.append("scope_connector_name_runtime_mismatch")
            if "direct_asset_below_pending_fee_reserve" in signals and abs(excess_raw) >= 10 ** max(decimals_int, 0):
                escalation_reasons.append("material_pending_fee_reserve_shortfall")
            if (
                "direct_asset_exceeds_pending_fee_reserve" in signals
                and excess_tokens is not None
                and excess_tokens >= 100
                and ((ratio_ppm or 0) >= 10_000 or excess_tokens >= 10_000)
            ):
                escalation_reasons.append("material_unaccounted_direct_asset")

        item = {
            "id": anonymize(network, vault),
            "network": network,
            "connector": connector,
            "signal_categories": row_categories,
            "quorum_confirmed": quorum_confirmed,
            "direct_excess_amount_bucket": amount_bucket(excess_tokens) if excess_raw > 0 else None,
            "direct_excess_ratio_bucket": ratio_bucket(ratio_ppm) if excess_raw > 0 else None,
            "escalation_reasons": escalation_reasons,
        }
        classified_rows.append(item)
        if escalation_reasons:
            escalation_rows.append(item)

    scope_rows = {}
    scope_path = Path("r30_scope/SCOPE.json")
    if scope_path.exists():
        scope_rows = {
            str(row.get("address", "")).lower(): str(row.get("connector") or "UNKNOWN")
            for row in json.loads(scope_path.read_text()).get("rows", [])
        }
    for err in evidence.get("errors", []):
        connector = scope_rows.get(str(err.get("vault", "")).lower(), "UNKNOWN")
        error_connector_counts[connector] += 1

    result = {
        "schema": "kiln-r32-public-signal-classifier-v1",
        "source_evidence_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "matrix": evidence.get("matrix"),
        "chain": {
            "chain_id": (evidence.get("chain") or {}).get("chain_id"),
            "pinned_block": (evidence.get("chain") or {}).get("pinned_block"),
            "pinned_block_hash": (evidence.get("chain") or {}).get("pinned_block_hash"),
            "rpc_quorum_size": (evidence.get("chain") or {}).get("rpc_quorum_size"),
        },
        "summary": {
            "inspected_count": integer((evidence.get("summary") or {}).get("inspected_count")),
            "error_count": integer((evidence.get("summary") or {}).get("error_count")),
            "signal_row_count": len(classified_rows),
            "quorum_confirmed_signal_count": sum(bool(x["quorum_confirmed"]) for x in classified_rows),
            "escalation_count": len(escalation_rows),
            "category_counts": dict(sorted(category_counts.items())),
            "connector_signal_counts": {
                connector: dict(sorted(counts.items()))
                for connector, counts in sorted(connector_signal_counts.items())
            },
            "error_connector_counts": dict(sorted(error_connector_counts.items())),
            "direct_excess_amount_buckets": dict(sorted(amount_buckets.items())),
            "direct_excess_ratio_buckets": dict(sorted(ratio_buckets.items())),
        },
        "classified_rows": classified_rows,
        "escalation_rows": escalation_rows,
        "decision": "HOLD_PRIVATE_CAUSAL_REVIEW" if escalation_rows else "KILL_NO_MATERIAL_RUNTIME_SIGNAL",
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "safety": evidence.get("safety"),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True))
    print(json.dumps({
        "decision": result["decision"],
        "signal_rows": len(classified_rows),
        "escalations": len(escalation_rows),
        "errors": result["summary"]["error_count"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
