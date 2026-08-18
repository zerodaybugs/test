#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

SOURCE = Path("kiln_r37/fee_invariant_census.py")
RESULTS = Path("r37_results")
OUT = Path("r37c_candidate_summary")
CASES = (("ethereum", 2, 4), ("ethereum", 3, 4))


def safe_value(value):
    if isinstance(value, dict) and value.get("ok"):
        return value.get("value")
    return None


def main() -> int:
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    candidates = []
    runs = []
    errors = []

    for network, shard, count in CASES:
        shutil.rmtree(RESULTS, ignore_errors=True)
        env = os.environ.copy()
        env.update(TARGET_NETWORK=network, SHARD_INDEX=str(shard), SHARD_COUNT=str(count))
        proc = subprocess.run(
            ["python3", str(SOURCE)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1800,
            check=False,
        )
        evidence_path = RESULTS / "EVIDENCE.json"
        gate_path = RESULTS / "PUBLIC_GATE.json"
        run = {
            "network": network,
            "shard_index": shard,
            "shard_count": count,
            "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-4000:],
            "evidence_present": evidence_path.exists(),
            "gate_present": gate_path.exists(),
        }
        if gate_path.exists():
            run["gate"] = json.loads(gate_path.read_text())
        runs.append(run)
        if proc.returncode != 0 or not evidence_path.exists():
            errors.append({"case": [network, shard, count], "returncode": proc.returncode})
            continue
        evidence = json.loads(evidence_path.read_text())
        for row in evidence.get("rows", []):
            signals = list(row.get("signals", []))
            if not signals or "killed_rpc_quorum_mismatch" in signals:
                continue
            state = row.get("fee_state", {})
            dispatcher = row.get("fee_dispatcher", {})
            token = row.get("asset_token", {})
            candidates.append({
                "network": row.get("network"),
                "label": row.get("label"),
                "vault": row.get("vault"),
                "scope_connector": row.get("scope_connector"),
                "block": row.get("block"),
                "block_hash": row.get("block_hash"),
                "signals": signals,
                "total_assets_raw": safe_value(row.get("totalAssets")),
                "total_supply_raw": safe_value(row.get("totalSupply")),
                "deposit_fee_raw": safe_value(row.get("depositFee")),
                "reward_fee_raw": safe_value(row.get("rewardFee")),
                "pending_deposit_fee_raw": state.get("pending_deposit"),
                "pending_reward_fee_raw": state.get("pending_reward"),
                "pending_total_raw": state.get("pending_total"),
                "direct_balance_raw": state.get("direct_balance"),
                "direct_minus_pending_raw": state.get("direct_minus_pending"),
                "allowance_raw": state.get("allowance"),
                "collectable_reward_fees_raw": state.get("collectable_reward_fees"),
                "asset_decimals": state.get("asset_decimals"),
                "share_decimals": state.get("share_decimals"),
                "recipient_count": state.get("recipient_count"),
                "deposit_split_sum": state.get("deposit_split_sum"),
                "reward_split_sum": state.get("reward_split_sum"),
                "expected_split_sum": state.get("expected_split_sum"),
                "asset": token.get("address"),
                "asset_symbol": safe_value(token.get("symbol")),
                "fee_dispatcher": dispatcher.get("address"),
                "fee_dispatcher_code_sha256": dispatcher.get("code_sha256"),
                "vault_dispatch_eth_call_ok": row.get("vault_dispatch_eth_call", {}).get("ok"),
                "secondary_quorum": row.get("secondary_quorum"),
            })

    candidate_signal_counts = {}
    for candidate in candidates:
        for signal in candidate["signals"]:
            candidate_signal_counts[signal] = candidate_signal_counts.get(signal, 0) + 1

    result = {
        "schema": "kiln-r37c-candidate-summary-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "decision": "HOLD_EXACT_FORK_IMPACT_GATE_REQUIRED" if candidates else "KILL_NO_REPRODUCED_R37_CANDIDATE",
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "candidate_count": len(candidates),
        "signal_counts": candidate_signal_counts,
        "candidates": candidates,
        "runs": runs,
        "errors": errors,
        "safety": {
            "read_only": True,
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
        },
    }
    summary = OUT / "CANDIDATE_SUMMARY.json"
    summary.write_text(json.dumps(result, indent=2, sort_keys=True))
    gate = {
        "schema": "kiln-r37c-public-gate-v1",
        "decision": result["decision"],
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "candidate_count": len(candidates),
        "error_count": len(errors),
        "public_chain_state_changes": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    files = sorted(p for p in OUT.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text(
        "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files)
    )
    assert gate["submit_ready"] is False
    assert gate["validated_critical"] == gate["validated_high"] == 0
    print(json.dumps(gate, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
