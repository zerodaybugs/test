#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

SOURCE = Path("public-data/stacks-contract-history.json")
OUT = Path("public-data/stacks-accounting-timeline.json")

CLAIM_FUNCTIONS = {
    "request-redeem",
    "fund-claim",
    "fund-claim-many",
    "cancel-redeem",
    "redeem",
    "redeem-many",
    "redeem-peg-out",
    "redeem-peg-out-many",
}


def small(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "tx_id": row.get("tx_id"),
        "block_height": row.get("block_height"),
        "block_time": row.get("block_time"),
        "block_time_iso": row.get("block_time_iso"),
        "tx_index": row.get("tx_index"),
        "sender": row.get("sender"),
        "contract_id": row.get("contract_id"),
        "function": row.get("function"),
        "args": row.get("args"),
        "result": row.get("result"),
        "status": row.get("status"),
    }


def parse_uint(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"u(\d+)", value)
    return int(match.group(1)) if match else None


def reward_row(row: dict[str, Any]) -> dict[str, Any]:
    args = row.get("args") or []
    amount = parse_uint(args[0]) if len(args) >= 1 else None
    is_positive = args[1] == "true" if len(args) >= 2 else None
    return {**small(row), "amount": amount, "is_positive": is_positive}


def key(row: dict[str, Any]) -> tuple[int, int]:
    return (int(row.get("block_height") or 0), int(row.get("tx_index") or 0))


def main() -> None:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    direct = data.get("direct_calls") or {}

    rewards = [
        reward_row(row)
        for row in (direct.get("controller") or [])
        if row.get("function") == "log-reward"
    ]
    claims = [
        small(row)
        for row in (direct.get("vault") or [])
        if row.get("function") in CLAIM_FUNCTIONS
    ]
    rewards.sort(key=key)
    claims.sort(key=key)

    negative_rewards = [row for row in rewards if row.get("is_positive") is False]
    failed_rewards = [row for row in rewards if row.get("status") != "success"]

    windows: list[dict[str, Any]] = []
    for reward in negative_rewards:
        reward_time = int(reward.get("block_time") or 0)
        nearby = [
            row
            for row in claims
            if abs(int(row.get("block_time") or 0) - reward_time) <= 86_400
        ]
        before = [row for row in nearby if key(row) < key(reward)]
        after = [row for row in nearby if key(row) > key(reward)]
        windows.append(
            {
                "reward": reward,
                "claim_calls_24h_before": before,
                "claim_calls_24h_after": after,
            }
        )

    payload = {
        "source": data.get("source"),
        "counts": {
            "rewards": len(rewards),
            "positive_rewards": sum(row.get("is_positive") is True for row in rewards),
            "negative_rewards": len(negative_rewards),
            "failed_rewards": len(failed_rewards),
            "claim_calls": len(claims),
        },
        "claim_function_counts": dict(Counter(str(row.get("function")) for row in claims)),
        "negative_rewards": negative_rewards,
        "failed_rewards": failed_rewards,
        "negative_reward_windows": windows,
        "rewards": rewards,
        "claim_calls": claims,
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
