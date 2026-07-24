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
HQ = f"{DEPLOYER}.hq-hbtc-v1"
OUT = Path("public-data/hermetica-role-ledger.json")

ROLES = ("guardian", "trader", "rewarder", "manager", "fee-setter", "protocol")


def get_json(url: str, attempts: int = 6) -> dict[str, Any]:
    last: Exception | None = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "hermetica-public-role-replay/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=45) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code not in {
                408, 429, 500, 502, 503, 504
            }:
                raise
            time.sleep(min(30, 2**i))
    raise RuntimeError(f"request failed after retries: {url}: {last!r}")


def address_transactions(principal: str, max_rows: int = 5000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    limit = 50
    offset = 0
    while offset < max_rows:
        encoded = urllib.parse.quote(principal, safe="")
        page = get_json(
            f"{BASE}/extended/v1/address/{encoded}/transactions?limit={limit}&offset={offset}"
        )
        results = page.get("results") or []
        rows.extend(results)
        total = int(page.get("total") or len(rows))
        if not results or len(rows) >= total:
            break
        offset += len(results)
        time.sleep(0.15)
    return rows[:max_rows]


def unwrap(row: dict[str, Any]) -> dict[str, Any]:
    tx = row.get("tx")
    return tx if isinstance(tx, dict) else row


def normalize(tx: dict[str, Any]) -> dict[str, Any]:
    call = tx.get("contract_call") or {}
    args = call.get("function_args") or []
    result = tx.get("tx_result") or {}
    return {
        "tx_id": tx.get("tx_id"),
        "block_height": tx.get("block_height"),
        "block_time": tx.get("block_time"),
        "block_time_iso": tx.get("block_time_iso"),
        "tx_index": tx.get("tx_index"),
        "sender": tx.get("sender_address"),
        "status": tx.get("tx_status"),
        "function": call.get("function_name"),
        "args": [arg.get("repr") for arg in args],
        "result": result.get("repr"),
    }


def principal_arg(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value[1:] if value.startswith("'") else value


def role_from_function(function: str, prefix: str, suffix: str) -> str | None:
    for role in ROLES:
        if function == f"{prefix}-{role}-{suffix}":
            return role
    return None


def key(row: dict[str, Any]) -> tuple[int, int]:
    return (int(row.get("block_height") or 0), int(row.get("tx_index") or 0))


def main() -> None:
    calls: list[dict[str, Any]] = []
    for row in address_transactions(HQ):
        tx = unwrap(row)
        call = tx.get("contract_call") or {}
        if tx.get("tx_type") == "contract_call" and call.get("contract_id") == HQ:
            calls.append(normalize(tx))
    calls.sort(key=key)

    pending: dict[tuple[str, str], bool] = {}
    active: dict[str, set[str]] = {role: set() for role in ROLES}
    timeline: list[dict[str, Any]] = []

    for call in calls:
        fn = str(call.get("function") or "")
        args = call.get("args") or []
        applied: dict[str, Any] | None = None
        # Only committed successful calls mutate state.
        if call.get("status") == "success" and str(call.get("result") or "").startswith("(ok"):
            role = role_from_function(fn, "request", "update")
            if role and len(args) >= 2:
                address = principal_arg(args[0])
                is_add = args[1] == "true"
                if address:
                    pending[(role, address)] = is_add
                    applied = {"operation": "request", "role": role, "address": address, "is_add": is_add}
            role = role_from_function(fn, "cancel", "request")
            if role and args:
                address = principal_arg(args[0])
                if address:
                    pending.pop((role, address), None)
                    applied = {"operation": "cancel", "role": role, "address": address}
            role = role_from_function(fn, "confirm", "request")
            if role and args:
                address = principal_arg(args[0])
                if address and (role, address) in pending:
                    is_add = pending.pop((role, address))
                    if is_add:
                        active[role].add(address)
                    else:
                        active[role].discard(address)
                    applied = {"operation": "confirm", "role": role, "address": address, "is_add": is_add}
        timeline.append({"call": call, "applied": applied})

    reverse: dict[str, list[str]] = {}
    for role, addresses in active.items():
        for address in addresses:
            reverse.setdefault(address, []).append(role)

    payload = {
        "source": "Hiro public Stacks API",
        "hq_contract": HQ,
        "direct_call_count": len(calls),
        "active_roles": {role: sorted(addresses) for role, addresses in active.items()},
        "roles_by_address": {address: sorted(roles) for address, roles in sorted(reverse.items())},
        "pending_requests": [
            {"role": role, "address": address, "is_add": is_add}
            for (role, address), is_add in sorted(pending.items())
        ],
        "timeline": timeline,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
