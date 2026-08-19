#!/usr/bin/env python3
"""Aggregate six R45v3 network artifacts without exposing private evidence."""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

EXPECTED_NETWORKS = {"ethereum", "optimism", "bnb", "polygon", "base", "arbitrum"}
ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "r45_downloads")
OUT = Path("r45_aggregate_v3")
OUT.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def main() -> int:
    gate_paths = sorted(ROOT.rglob("PUBLIC_GATE.json"))
    candidate_paths = sorted(ROOT.rglob("CANDIDATE_PUBLIC.json"))
    gates: dict[str, dict[str, Any]] = {}
    duplicate_networks: list[str] = []
    parse_errors: list[str] = []

    for path in gate_paths:
        try:
            gate = load_json(path)
            network = str(gate.get("network") or "").lower()
            if network not in EXPECTED_NETWORKS:
                continue
            if network in gates:
                duplicate_networks.append(network)
                continue
            gate["_source_path"] = path.as_posix()
            gate["_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            gates[network] = gate
        except Exception as exc:
            parse_errors.append(f"{path}: {type(exc).__name__}: {exc}")

    public_candidates: list[dict[str, Any]] = []
    for path in candidate_paths:
        try:
            data = load_json(path)
            rows = data.get("candidates") or []
            if isinstance(rows, list):
                public_candidates.extend(row for row in rows if isinstance(row, dict))
        except Exception as exc:
            parse_errors.append(f"{path}: {type(exc).__name__}: {exc}")

    missing = sorted(EXPECTED_NETWORKS - set(gates))
    rows: list[dict[str, Any]] = []
    for network in sorted(gates):
        gate = gates[network]
        rows.append(
            {
                "network": network,
                "decision": gate.get("decision"),
                "coverage_complete": bool(gate.get("coverage_complete", False)),
                "runner_exit_code": int(gate.get("runner_exit_code", 255) or 0),
                "selected_count": int(gate.get("selected_count", 0) or 0),
                "inspected_count": int(gate.get("inspected_count", 0) or 0),
                "base_error_count": int(gate.get("base_error_count", 0) or 0),
                "base_quorum_mismatch_count": int(gate.get("base_quorum_mismatch_count", 0) or 0),
                "extension_quorum_mismatch_count": int(gate.get("extension_quorum_mismatch_count", 0) or 0),
                "candidate_count": int(gate.get("candidate_count", 0) or 0),
                "inventory_trigger_count": int(gate.get("inventory_trigger_count", 0) or 0),
                "known_or_duplicate_signal_count": int(gate.get("known_or_duplicate_signal_count", 0) or 0),
                "candidate_kinds": gate.get("candidate_kinds") or {},
                "submit_ready": bool(gate.get("submit_ready", False)),
                "validated_critical": int(gate.get("validated_critical", 0) or 0),
                "validated_high": int(gate.get("validated_high", 0) or 0),
                "public_chain_state_changes": int(gate.get("public_chain_state_changes", 0) or 0),
                "transactions_signed": int(gate.get("transactions_signed", 0) or 0),
                "transactions_sent": int(gate.get("transactions_sent", 0) or 0),
                "source_path": gate.get("_source_path"),
                "sha256": gate.get("_sha256"),
            }
        )

    selected_total = sum(row["selected_count"] for row in rows)
    inspected_total = sum(row["inspected_count"] for row in rows)
    error_total = sum(row["base_error_count"] for row in rows)
    quorum_total = sum(row["base_quorum_mismatch_count"] + row["extension_quorum_mismatch_count"] for row in rows)
    candidate_total = sum(row["candidate_count"] for row in rows)
    inventory_total = sum(row["inventory_trigger_count"] for row in rows)
    known_total = sum(row["known_or_duplicate_signal_count"] for row in rows)
    candidate_kinds = Counter()
    for row in rows:
        for key, value in row["candidate_kinds"].items():
            try:
                candidate_kinds[str(key)] += int(value)
            except Exception:
                candidate_kinds[str(key)] += 0

    safety_pass = all(
        not row["submit_ready"]
        and row["validated_critical"] == 0
        and row["validated_high"] == 0
        and row["public_chain_state_changes"] == 0
        and row["transactions_signed"] == 0
        and row["transactions_sent"] == 0
        for row in rows
    )
    coverage_complete = (
        not missing
        and not duplicate_networks
        and not parse_errors
        and len(rows) == len(EXPECTED_NETWORKS)
        and all(row["coverage_complete"] and row["runner_exit_code"] == 0 for row in rows)
        and selected_total == inspected_total
        and selected_total >= 49
        and error_total == 0
        and quorum_total == 0
        and safety_pass
    )

    if not coverage_complete:
        decision = "INCONCLUSIVE_R45V3_FAIL_CLOSED_COVERAGE_INTEGRITY_OR_QUORUM"
    elif candidate_total:
        decision = "HOLD_R45V3_LIVE_CANDIDATES_REQUIRE_FIXED_BLOCK_POC"
    elif inventory_total:
        decision = "HOLD_R45V3_DEPLOYMENT_DELTA_REQUIRES_SOURCE_DIFF"
    else:
        decision = "KILL_R45V3_NO_NEW_LIVE_INVARIANT_TRIGGER"

    aggregate = {
        "schema": "kiln-r45v3-aggregate-public-gate-v1",
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "coverage_complete": coverage_complete,
        "network_count": len(rows),
        "missing_networks": missing,
        "duplicate_networks": sorted(set(duplicate_networks)),
        "parse_errors": parse_errors,
        "selected_total": selected_total,
        "inspected_total": inspected_total,
        "error_total": error_total,
        "quorum_mismatch_total": quorum_total,
        "candidate_total": candidate_total,
        "inventory_trigger_total": inventory_total,
        "known_or_duplicate_signal_total": known_total,
        "candidate_kinds": dict(sorted(candidate_kinds.items())),
        "public_candidate_detail_count": len(public_candidates),
        "rows": rows,
        "safety": {
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
        },
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(aggregate, indent=2, sort_keys=True))
    (OUT / "CANDIDATE_PUBLIC_AGGREGATE.json").write_text(
        json.dumps({"candidates": public_candidates}, indent=2, sort_keys=True)
    )
    files = sorted(path for path in OUT.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
    )
    print(json.dumps(aggregate, sort_keys=True))
    return 0 if coverage_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
