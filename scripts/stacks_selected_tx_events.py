#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE = "https://api.hiro.so"
HISTORY = Path("public-data/stacks-contract-history.json")
OUT = Path("public-data/stacks-selected-tx-events.json")

TXS = {
    "2026-04-28-sweep": "0xcd7f96d9e3eb2ab04c402de41ee62eac5a312bc441a59261a93cc7d7ce73fbe5",
    "2026-04-28-deposit": "0xf00d2911f0cebf2f367cd8623d82a14f2e81ac4f55c587d70e3e4a3f350861c0",
    "2026-04-28-reward": "0xfbad904a4ee4dc02f3c56bbdf779bfdf60e746a8012256bcd7da3f049935e562",
    "2026-05-26-sweep": "0x9afc199caf6487b6fdc5eea164082ece38c8e7830b3259ed18492f012cfb00be",
    "2026-05-26-deposit": "0xeb7c5dae953c13ca1eed8616f49d7ad1e8c15802afcb6071011744dff5ed847b",
    "2026-05-26-reward": "0xe59f48fee2567d09210d1c2f3ec137bd71460f4e82b1a1816708534baf415fde",
}


def get_json(url: str, attempts: int = 6) -> dict[str, Any]:
    last: Exception | None = None
    for i in range(attempts):
        try:
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": "public-stacks-history-collector/1.2"},
            )
            with urllib.request.urlopen(request, timeout=45) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code not in {408, 429, 500, 502, 503, 504}:
                raise
            time.sleep(min(30, 2**i))
    raise RuntimeError(f"request failed: {url}: {last!r}")


def trim_event(event: dict[str, Any]) -> dict[str, Any]:
    keep = {
        "event_index": event.get("event_index"),
        "event_type": event.get("event_type"),
        "tx_id": event.get("tx_id"),
    }
    for key in (
        "contract_log",
        "ft_transfer",
        "ft_mint",
        "ft_burn",
        "stx_transfer",
        "stx_mint",
        "stx_burn",
    ):
        if key in event:
            keep[key] = event[key]
    # Some API revisions use *_event keys.
    for key, value in event.items():
        if key.endswith("_event") or key == "contract_log":
            keep[key] = value
    return keep


def trim_tx(tx: dict[str, Any]) -> dict[str, Any]:
    return {
        "tx_id": tx.get("tx_id"),
        "block_height": tx.get("block_height"),
        "block_time": tx.get("block_time"),
        "block_time_iso": tx.get("block_time_iso"),
        "tx_index": tx.get("tx_index"),
        "sender_address": tx.get("sender_address"),
        "tx_status": tx.get("tx_status"),
        "tx_result": tx.get("tx_result"),
        "contract_call": tx.get("contract_call"),
        "events": [trim_event(x) for x in tx.get("events") or []],
    }


def main() -> None:
    selected: dict[str, Any] = {}
    for label, txid in TXS.items():
        url = f"{BASE}/extended/v1/tx/{txid}?event_offset=0&event_limit=100"
        selected[label] = trim_tx(get_json(url))
        time.sleep(0.15)

    history = json.loads(HISTORY.read_text(encoding="utf-8"))
    state_calls = (history.get("direct_calls") or {}).get("state") or []
    config_functions = {
        "set-deposit-cap",
        "set-min-deposit",
        "set-reserve-rate",
        "set-custom-cooldown",
        "remove-custom-cooldown",
        "request-mgmt-fee-update",
        "confirm-mgmt-fee-request",
        "request-perf-fee-update",
        "confirm-perf-fee-request",
        "request-exit-fee-update",
        "confirm-exit-fee-request",
        "request-express-fee-update",
        "confirm-express-fee-request",
        "set-request-redeem-enabled",
        "set-redeem-enabled",
        "disable-redeem",
    }
    selected["state-configuration-calls"] = [
        row for row in state_calls if row.get("function") in config_functions
    ]
    OUT.write_text(json.dumps(selected, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
