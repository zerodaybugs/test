#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE = "https://api.hiro.so"
DEPLOYER = "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D"
CONTRACTS = {
    "controller": f"{DEPLOYER}.controller-hbtc-v1",
    "zest_interface": f"{DEPLOYER}.zest-interface-hbtc-v1",
    "vault": f"{DEPLOYER}.vault-hbtc-v1-2",
    "state": f"{DEPLOYER}.state-hbtc-v1",
    "trading": f"{DEPLOYER}.trading-hbtc-v1",
}
ACTORS = {
    "actor_sp20": "SP20V8SG811G6CT2QMZQNX6XCN20YAX36DYD1BAE0",
    "actor_sp2as": "SP2AS467J369H67HK3TS2TDH1YB0XNN7YZ8M7FM1B",
    "actor_sp1c72": "SP1C72K3FP2VCMW6814TGPG2Q07A54597WW6HB1YR",
}
OUT = Path("public-data/stacks-contract-history.json")


def get_json(url: str, attempts: int = 6) -> dict[str, Any]:
    last: Exception | None = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "public-stacks-history-collector/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=45) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code not in {
                408,
                429,
                500,
                502,
                503,
                504,
            }:
                raise
            time.sleep(min(30, 2**i))
    raise RuntimeError(f"request failed after retries: {url}: {last!r}")


def get_address_transactions(principal: str, max_rows: int = 5000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    limit = 50
    offset = 0
    while offset < max_rows:
        encoded = urllib.parse.quote(principal, safe="")
        url = f"{BASE}/extended/v1/address/{encoded}/transactions?limit={limit}&offset={offset}"
        page = get_json(url)
        results = page.get("results") or []
        rows.extend(results)
        total = int(page.get("total") or len(rows))
        if not results or len(rows) >= total:
            break
        offset += len(results)
        time.sleep(0.15)
    return rows[:max_rows]


def unwrap_tx(row: dict[str, Any]) -> dict[str, Any]:
    tx = row.get("tx")
    return tx if isinstance(tx, dict) else row


def normalize(tx: dict[str, Any]) -> dict[str, Any]:
    contract_call = tx.get("contract_call") or {}
    args = contract_call.get("function_args") or []
    result = tx.get("tx_result") or {}
    return {
        "tx_id": tx.get("tx_id"),
        "block_height": tx.get("block_height"),
        "block_time": tx.get("block_time"),
        "block_time_iso": tx.get("block_time_iso"),
        "tx_index": tx.get("tx_index"),
        "nonce": tx.get("nonce"),
        "sender": tx.get("sender_address"),
        "status": tx.get("tx_status"),
        "tx_type": tx.get("tx_type"),
        "contract_id": contract_call.get("contract_id"),
        "function": contract_call.get("function_name"),
        "args": [arg.get("repr") for arg in args],
        "result": result.get("repr"),
        "event_count": tx.get("event_count"),
    }


def direct_contract_calls(rows: list[dict[str, Any]], contract_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        tx = unwrap_tx(row)
        call = tx.get("contract_call") or {}
        if tx.get("tx_type") == "contract_call" and call.get("contract_id") == contract_id:
            out.append(normalize(tx))
    return sorted(out, key=lambda x: (x.get("block_height") or 0, x.get("tx_index") or 0))


def actor_calls(rows: list[dict[str, Any]], actor: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    targets = set(CONTRACTS.values())
    for row in rows:
        tx = unwrap_tx(row)
        call = tx.get("contract_call") or {}
        if (
            tx.get("sender_address") == actor
            and tx.get("tx_type") == "contract_call"
            and call.get("contract_id") in targets
        ):
            out.append(normalize(tx))
    return sorted(out, key=lambda x: (x.get("block_height") or 0, x.get("tx_index") or 0))


def between(events: list[dict[str, Any]], a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    lo = (a.get("block_height") or 0, a.get("tx_index") or 0)
    hi = (b.get("block_height") or 0, b.get("tx_index") or 0)
    if lo > hi:
        lo, hi = hi, lo
    return [
        event
        for event in events
        if lo < (event.get("block_height") or 0, event.get("tx_index") or 0) < hi
    ]


def pair_sweeps(
    sweeps: list[dict[str, Any]],
    rewards: list[dict[str, Any]],
    deposits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    for sweep in sweeps:
        before = [r for r in rewards if (r.get("block_height") or 0) <= (sweep.get("block_height") or 0)]
        after = [r for r in rewards if (r.get("block_height") or 0) >= (sweep.get("block_height") or 0)]
        nearest_before = max(before, key=lambda r: (r.get("block_height") or 0, r.get("tx_index") or 0), default=None)
        nearest_after = min(after, key=lambda r: (r.get("block_height") or 0, r.get("tx_index") or 0), default=None)
        candidates = [x for x in (nearest_before, nearest_after) if x is not None]
        nearest = min(
            candidates,
            key=lambda r: abs((r.get("block_height") or 0) - (sweep.get("block_height") or 0)),
            default=None,
        )
        pairs.append(
            {
                "sweep": sweep,
                "nearest_reward_before": nearest_before,
                "nearest_reward_after": nearest_after,
                "nearest_reward": nearest,
                "deposits_between_sweep_and_nearest_reward": between(deposits, sweep, nearest) if nearest else [],
            }
        )
    return pairs


def main() -> None:
    contract_rows: dict[str, list[dict[str, Any]]] = {}
    direct: dict[str, list[dict[str, Any]]] = {}
    for label, principal in CONTRACTS.items():
        rows = get_address_transactions(principal)
        contract_rows[label] = rows
        direct[label] = direct_contract_calls(rows, principal)

    actor_direct: dict[str, list[dict[str, Any]]] = {}
    for label, actor in ACTORS.items():
        actor_direct[label] = actor_calls(get_address_transactions(actor), actor)

    sweeps = [x for x in direct["zest_interface"] if x.get("function") == "sweep"]
    rewards = [x for x in direct["controller"] if x.get("function") == "log-reward"]
    deposits = [x for x in direct["vault"] if x.get("function") == "deposit"]
    claim_calls = [
        x
        for x in direct["vault"]
        if x.get("function") in {"request-redeem", "fund-claim", "fund-claim-many", "cancel-redeem", "redeem", "redeem-many", "redeem-peg-out", "redeem-peg-out-many"}
    ]
    controls = [
        x
        for x in direct["state"]
        if x.get("function")
        in {
            "set-redeem-enabled",
            "disable-redeem",
            "set-request-redeem-enabled",
            "set-deposit-enabled",
            "disable-deposits",
            "set-reward-enabled",
            "disable-reward",
            "set-trading-enabled",
            "disable-trading",
        }
    ]

    payload = {
        "source": "Hiro public Stacks API",
        "contracts": CONTRACTS,
        "actors": ACTORS,
        "counts": {label: len(rows) for label, rows in contract_rows.items()},
        "direct_calls": direct,
        "actor_calls": actor_direct,
        "derived": {
            "sweeps": sweeps,
            "rewards": rewards,
            "deposits": deposits,
            "claim_calls": claim_calls,
            "state_controls": controls,
            "sweep_reward_pairs": pair_sweeps(sweeps, rewards, deposits),
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
