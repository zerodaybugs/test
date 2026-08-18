#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ORIGINAL = Path("kiln_r37/fee_invariant_census.py")
OUT = Path("r37_results")


def main() -> int:
    proc = subprocess.run(
        ["python3", str(ORIGINAL)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    evidence_path = OUT / "EVIDENCE.json"
    gate_path = OUT / "PUBLIC_GATE.json"
    if not evidence_path.exists() or not gate_path.exists():
        print(proc.stdout, end="")
        return proc.returncode or 2

    evidence = json.loads(evidence_path.read_text())
    for row in evidence.get("rows", []):
        signals = list(row.get("signals", []))
        total_assets = row.get("totalAssets", {})
        if "positive_supply_zero_total_assets" in signals and not total_assets.get("ok"):
            signals.remove("positive_supply_zero_total_assets")
        substantive = [
            signal for signal in signals
            if signal not in {"unconfirmed_single_rpc_only", "killed_rpc_quorum_mismatch"}
        ]
        if not substantive and "unconfirmed_single_rpc_only" in signals:
            signals.remove("unconfirmed_single_rpc_only")
        row["signals"] = sorted(set(signals))
        if int((row.get("fee_state") or {}).get("total_supply", 0) or 0) > 0 and not total_assets.get("ok"):
            row["non_fee_observation"] = "totalAssets_reverts; handled by prior Venus registry-removal analysis"

    candidates = [
        row for row in evidence.get("rows", [])
        if row.get("signals") and "killed_rpc_quorum_mismatch" not in row.get("signals", [])
    ]
    counts = {}
    for row in candidates:
        for signal in row.get("signals", []):
            counts[signal] = counts.get(signal, 0) + 1

    summary = evidence.setdefault("summary", {})
    summary["candidate_count"] = len(candidates)
    summary["signal_counts"] = counts
    summary["classifier_correction"] = (
        "A reverting totalAssets() call is not a zero totalAssets value and is not a fee-invariant signal."
    )
    evidence["schema"] = "kiln-r37-fee-invariant-census-v2"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True))

    gate = json.loads(gate_path.read_text())
    gate.update(
        schema="kiln-r37-public-gate-v2",
        decision=(
            "HOLD_PRIVATE_FEE_SIGNAL_REVIEW" if candidates
            else "INCONCLUSIVE_RUNTIME_ERRORS" if gate.get("error_count")
            else "KILL_NO_LIVE_FEE_INVARIANT_SIGNAL"
        ),
        candidate_count=len(candidates),
        submit_ready=False,
        validated_critical=0,
        validated_high=0,
        classifier_correction_applied=True,
    )
    gate_path.write_text(json.dumps(gate, indent=2, sort_keys=True))

    files = sorted(path for path in OUT.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
    )
    print(json.dumps(gate, sort_keys=True))
    return 0 if evidence.get("rows") else 2


if __name__ == "__main__":
    raise SystemExit(main())
