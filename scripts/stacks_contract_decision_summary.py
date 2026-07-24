#!/usr/bin/env python3
from __future__ import annotations

import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

SOURCE = Path("public-data/stacks-contract-history.json")
OUT = Path("public-data/stacks-contract-decision-summary.json")


def amount(event: dict[str, Any] | None) -> int | None:
    if not event:
        return None
    args = event.get("args") or []
    if not args:
        return None
    for value in reversed(args):
        if isinstance(value, str) and value.startswith("u") and value[1:].isdigit():
            return int(value[1:])
    return None


def small(event: dict[str, Any] | None) -> dict[str, Any] | None:
    if not event:
        return None
    return {
        "tx_id": event.get("tx_id"),
        "block_height": event.get("block_height"),
        "block_time": event.get("block_time"),
        "block_time_iso": event.get("block_time_iso"),
        "tx_index": event.get("tx_index"),
        "sender": event.get("sender"),
        "function": event.get("function"),
        "args": event.get("args"),
        "result": event.get("result"),
    }


def main() -> None:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    derived = data.get("derived") or {}
    pairs = derived.get("sweep_reward_pairs") or []
    rows = []
    for pair in pairs:
        sweep = pair.get("sweep")
        before = pair.get("nearest_reward_before")
        after = pair.get("nearest_reward_after")
        nearest = pair.get("nearest_reward")
        deposits = pair.get("deposits_between_sweep_and_nearest_reward") or []
        sweep_time = int((sweep or {}).get("block_time") or 0)
        after_time = int((after or {}).get("block_time") or 0)
        sweep_height = int((sweep or {}).get("block_height") or 0)
        after_height = int((after or {}).get("block_height") or 0)
        rows.append(
            {
                "sweep": small(sweep),
                "reward_before": small(before),
                "reward_after": small(after),
                "nearest_reward": small(nearest),
                "sweep_amount": amount(sweep),
                "reward_after_amount": amount(after),
                "amount_exact_match_after": amount(sweep) == amount(after) if sweep and after else False,
                "gap_to_reward_after_seconds": after_time - sweep_time if after_time and sweep_time else None,
                "gap_to_reward_after_blocks": after_height - sweep_height if after_height and sweep_height else None,
                "deposits_between_count": len(deposits),
                "deposits_between": [small(x) for x in deposits],
            }
        )

    positive_gaps = [r["gap_to_reward_after_seconds"] for r in rows if isinstance(r["gap_to_reward_after_seconds"], int) and r["gap_to_reward_after_seconds"] >= 0]
    with_deposits = [r for r in rows if r["deposits_between_count"] > 0]
    amount_mismatches = [r for r in rows if r["reward_after"] and not r["amount_exact_match_after"]]

    controls = derived.get("state_controls") or []
    claims = derived.get("claim_calls") or []
    control_windows = []
    for control in controls:
        h = int(control.get("block_height") or 0)
        nearby = [x for x in claims if abs(int(x.get("block_height") or 0) - h) <= 5000]
        control_windows.append({"control": small(control), "claim_calls_within_5000_blocks": [small(x) for x in nearby]})

    direct = data.get("direct_calls") or {}
    trading_calls = direct.get("trading") or []
    decision = {
        "source": data.get("source"),
        "counts": data.get("counts"),
        "direct_function_counts": {
            label: dict(Counter(str(x.get("function")) for x in values))
            for label, values in direct.items()
        },
        "sweep_reward": {
            "sweep_count": len(rows),
            "reward_after_available_count": sum(1 for r in rows if r["reward_after"]),
            "exact_amount_match_after_count": sum(1 for r in rows if r["amount_exact_match_after"]),
            "pairs_with_deposits_between_count": len(with_deposits),
            "gap_seconds_min": min(positive_gaps) if positive_gaps else None,
            "gap_seconds_median": statistics.median(positive_gaps) if positive_gaps else None,
            "gap_seconds_max": max(positive_gaps) if positive_gaps else None,
            "pairs_with_deposits_between": with_deposits,
            "amount_mismatch_pairs_first_20": amount_mismatches[:20],
            "latest_10_pairs": rows[-10:],
        },
        "emergency_controls": {
            "count": len(controls),
            "events": [small(x) for x in controls],
            "control_windows": control_windows,
        },
        "claim_call_counts": dict(Counter(str(x.get("function")) for x in claims)),
        "atomic_wrapper_calls": [small(x) for x in trading_calls if x.get("function") == "zest-sweep-and-reward"],
    }
    OUT.write_text(json.dumps(decision, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
