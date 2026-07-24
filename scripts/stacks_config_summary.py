#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SOURCE = Path("public-data/stacks-contract-history.json")
OUT = Path("public-data/stacks-state-config-summary.json")

DEFAULTS = {
    "deposit-cap": 100_000_000,
    "min-deposit": 100,
    "mgmt-fee": 0,
    "perf-fee": 1000,
    "exit-fee": 0,
    "express-fee": 50,
    "max-reward": 5,
    "reserve-rate": 500,
}

RELEVANT = {
    "set-deposit-cap",
    "set-min-deposit",
    "set-reserve-rate",
    "request-max-reward-update",
    "confirm-max-reward-request",
    "request-mgmt-fee-update",
    "confirm-mgmt-fee-request",
    "request-perf-fee-update",
    "confirm-perf-fee-request",
    "request-exit-fee-update",
    "confirm-exit-fee-request",
    "request-express-fee-update",
    "confirm-express-fee-request",
}

REQUEST_TO_KEY = {
    "request-max-reward-update": "max-reward",
    "request-mgmt-fee-update": "mgmt-fee",
    "request-perf-fee-update": "perf-fee",
    "request-exit-fee-update": "exit-fee",
    "request-express-fee-update": "express-fee",
}

CONFIRM_TO_KEY = {
    "confirm-max-reward-request": "max-reward",
    "confirm-mgmt-fee-request": "mgmt-fee",
    "confirm-perf-fee-request": "perf-fee",
    "confirm-exit-fee-request": "exit-fee",
    "confirm-express-fee-request": "express-fee",
}

SET_TO_KEY = {
    "set-deposit-cap": "deposit-cap",
    "set-min-deposit": "min-deposit",
    "set-reserve-rate": "reserve-rate",
}


def uint_arg(row: dict[str, Any]) -> int | None:
    for arg in row.get("args") or []:
        if isinstance(arg, str):
            match = re.fullmatch(r"u(\d+)", arg)
            if match:
                return int(match.group(1))
    return None


def small(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "tx_id": row.get("tx_id"),
        "block_height": row.get("block_height"),
        "block_time": row.get("block_time"),
        "block_time_iso": row.get("block_time_iso"),
        "tx_index": row.get("tx_index"),
        "sender": row.get("sender"),
        "function": row.get("function"),
        "args": row.get("args"),
        "result": row.get("result"),
        "status": row.get("status"),
    }


def main() -> None:
    data = json.loads(SOURCE.read_text(encoding="utf-8"))
    state_calls = (data.get("direct_calls") or {}).get("state") or []
    calls = [row for row in state_calls if row.get("function") in RELEVANT]
    calls.sort(key=lambda row: (int(row.get("block_height") or 0), int(row.get("tx_index") or 0)))

    values = dict(DEFAULTS)
    pending: dict[str, int] = {}
    timeline: list[dict[str, Any]] = []
    for row in calls:
        if row.get("status") != "success" or row.get("result") not in {"(ok true)", None}:
            timeline.append({"call": small(row), "applied": False, "values_after": dict(values)})
            continue
        fn = str(row.get("function"))
        applied = False
        value = uint_arg(row)
        if fn in SET_TO_KEY and value is not None:
            values[SET_TO_KEY[fn]] = value
            applied = True
        elif fn in REQUEST_TO_KEY and value is not None:
            pending[REQUEST_TO_KEY[fn]] = value
        elif fn in CONFIRM_TO_KEY:
            key = CONFIRM_TO_KEY[fn]
            if key in pending:
                values[key] = pending.pop(key)
                applied = True
        timeline.append(
            {
                "call": small(row),
                "applied": applied,
                "pending_after": dict(pending),
                "values_after": dict(values),
            }
        )

    checkpoints = {}
    for label, timestamp in {
        "2026-04-28-before-window": 1777411800,
        "2026-05-26-before-window": 1779831000,
        "latest-collected": 2**63 - 1,
    }.items():
        checkpoint_values = dict(DEFAULTS)
        for entry in timeline:
            call_time = int((entry.get("call") or {}).get("block_time") or 0)
            if call_time <= timestamp:
                checkpoint_values = dict(entry.get("values_after") or checkpoint_values)
        checkpoints[label] = checkpoint_values

    OUT.write_text(
        json.dumps(
            {
                "defaults_from_pinned_source": DEFAULTS,
                "current_reconstructed_values": values,
                "unconfirmed_pending_requests": pending,
                "checkpoints": checkpoints,
                "timeline": timeline,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
