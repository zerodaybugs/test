#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

SOURCE = Path("public-data/stacks-contract-history.json")
OUT = Path("public-data/stacks-contract-key-findings.json")


def compact(event: dict[str, Any] | None) -> dict[str, Any] | None:
    if event is None:
        return None
    return {
        "tx_id": event.get("tx_id"),
        "block_height": event.get("block_height"),
        "block_time_iso": event.get("block_time_iso"),
        "tx_index": event.get("tx_index"),
        "sender": event.get("sender"),
        "contract_id": event.get("contract_id"),
        "function": event.get("function"),
        "args": event.get("args"),
        "result": event.get("result"),
        "status": event.get("status"),
    }


def sort_key(event: dict[str, Any]) -> tuple[int, int]:
    return int(event.get("block_height") or 0), int(event.get("tx_index") or 0)


def main() -> None:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    derived = data.get("derived") or {}
    sweeps = [compact(x) for x in derived.get("sweeps") or []]
    rewards = [compact(x) for x in derived.get("rewards") or []]
    deposits = [compact(x) for x in derived.get("deposits") or []]
    claim_calls = [compact(x) for x in derived.get("claim_calls") or []]
    controls = [compact(x) for x in derived.get("state_controls") or []]

    focused_pairs = []
    for pair in derived.get("sweep_reward_pairs") or []:
        sweep = compact(pair.get("sweep"))
        before = compact(pair.get("nearest_reward_before"))
        after = compact(pair.get("nearest_reward_after"))
        nearest = compact(pair.get("nearest_reward"))
        between = [compact(x) for x in pair.get("deposits_between_sweep_and_nearest_reward") or []]
        focused_pairs.append(
            {
                "sweep": sweep,
                "nearest_reward_before": before,
                "nearest_reward_after": after,
                "nearest_reward": nearest,
                "block_gap_to_nearest_reward": (
                    abs(int((nearest or {}).get("block_height") or 0) - int((sweep or {}).get("block_height") or 0))
                    if sweep and nearest
                    else None
                ),
                "deposits_between_count": len(between),
                "deposits_between": between[:50],
            }
        )

    control_windows = []
    all_claims = [x for x in claim_calls if x is not None]
    for control in [x for x in controls if x is not None]:
        height = int(control.get("block_height") or 0)
        nearby = [x for x in all_claims if abs(int(x.get("block_height") or 0) - height) <= 5000]
        control_windows.append({"control": control, "nearby_claim_calls": nearby[:100]})

    actor_focus: dict[str, list[dict[str, Any]]] = {}
    relevant_functions = {
        "sweep",
        "log-reward",
        "zest-sweep-and-reward",
        "deposit",
        "fund-claim",
        "fund-claim-many",
        "request-redeem",
        "cancel-redeem",
        "redeem",
        "redeem-peg-out",
        "redeem-peg-out-many",
        "disable-redeem",
        "set-redeem-enabled",
    }
    for actor, rows in (data.get("actor_calls") or {}).items():
        actor_focus[actor] = [
            compact(row)
            for row in rows
            if row.get("function") in relevant_functions
        ][:200]

    all_direct = data.get("direct_calls") or {}
    function_counts = {
        label: dict(Counter(str(row.get("function")) for row in rows))
        for label, rows in all_direct.items()
    }

    key = {
        "source": data.get("source"),
        "contracts": data.get("contracts"),
        "raw_related_transaction_counts": data.get("counts"),
        "direct_function_counts": function_counts,
        "sweep_count": len(sweeps),
        "reward_count": len(rewards),
        "deposit_count": len(deposits),
        "claim_call_count": len(claim_calls),
        "state_control_count": len(controls),
        "sweeps": sweeps[:100],
        "rewards_first_10": sorted([x for x in rewards if x], key=sort_key)[:10],
        "rewards_last_20": sorted([x for x in rewards if x], key=sort_key)[-20:],
        "sweep_reward_pairs": focused_pairs[:100],
        "state_controls": controls[:100],
        "state_control_windows": control_windows[:100],
        "actor_focus": actor_focus,
    }
    OUT.write_text(json.dumps(key, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
