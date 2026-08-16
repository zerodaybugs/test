#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

REST = os.environ.get("REST", "https://api.mainnet.aptoslabs.com/v1").rstrip("/")
POOL = os.environ.get(
    "AAVE_POOL",
    "0x39ddcd9e1a39fa14f25e3f9ec8a86074d05cc0881cbf667df8a6ee70942016fb",
)
ROOT = pathlib.Path(os.environ.get("EVIDENCE_DIR", "evidence/aave-r19-live-accounting"))
RAY = 10**27


def request_json(url: str, body: dict[str, Any] | None = None) -> Any:
    encoded = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json", "User-Agent": "aave-r19-live-accounting/1.2"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for attempt in range(12):
        try:
            request = urllib.request.Request(url, data=encoded, headers=headers)
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code != 429 and exc.code < 500:
                raw = exc.read().decode(errors="replace")
                raise RuntimeError(f"HTTP {exc.code}: {raw[:1000]}") from exc
            time.sleep(min(30.0, 2.0 + attempt * 2.0))
        except Exception as exc:
            last = exc
            time.sleep(min(20.0, 1.0 + attempt * 1.5))
    raise RuntimeError(repr(last))


def with_ledger_version(path: str, ledger_version: int) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}ledger_version={ledger_version}"


def view(
    function: str,
    arguments: list[Any],
    ledger_version: int,
    type_arguments: list[str] | None = None,
) -> Any:
    return request_json(with_ledger_version(REST + "/view", ledger_version), {
        "function": function,
        "type_arguments": type_arguments or [],
        "arguments": arguments,
    })


def as_scalar(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def as_int(value: Any) -> int:
    return int(str(as_scalar(value)), 0)


def ray_mul_down(a: int, b: int) -> int:
    return a * b // RAY


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    ledger = request_json(REST)
    ledger_version = int(ledger["ledger_version"])
    (ROOT / "ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
    (ROOT / "ledger_version.txt").write_text(str(ledger_version) + "\n")

    raw = view(
        f"{POOL}::ui_pool_data_provider_v3::get_reserves_data",
        [],
        ledger_version,
    )
    (ROOT / "reserves_raw.json").write_text(json.dumps(raw, indent=2) + "\n")
    reserves = raw[0]
    rows = []
    errors = []

    for reserve in reserves:
        symbol = reserve["symbol"]
        underlying = reserve["underlying_asset"]
        atoken = reserve["a_token_address"]
        vtoken = reserve["variable_debt_token_address"]
        try:
            token_account = str(as_scalar(view(
                f"{POOL}::a_token_factory::get_token_account_address",
                [atoken],
                ledger_version,
            )))
            actual_liquidity = as_int(view(
                "0x1::primary_fungible_store::balance",
                [token_account, underlying],
                ledger_version,
                ["0x1::fungible_asset::Metadata"],
            ))
            scaled_atoken_supply = as_int(view(
                f"{POOL}::a_token_factory::scaled_total_supply",
                [atoken],
                ledger_version,
            ))
            atoken_supply = as_int(view(
                f"{POOL}::a_token_factory::total_supply",
                [atoken],
                ledger_version,
            ))
            scaled_debt = as_int(view(
                f"{POOL}::variable_debt_token_factory::scaled_total_supply",
                [vtoken],
                ledger_version,
            ))
            variable_debt = as_int(view(
                f"{POOL}::variable_debt_token_factory::total_supply",
                [vtoken],
                ledger_version,
            ))
            normalized_income = as_int(view(
                f"{POOL}::pool::get_reserve_normalized_income",
                [underlying],
                ledger_version,
            ))
            normalized_debt = as_int(view(
                f"{POOL}::pool::get_reserve_normalized_variable_debt",
                [underlying],
                ledger_version,
            ))

            accrued_scaled = int(reserve["accrued_to_treasury"])
            deficit = int(reserve["deficit"])
            ui_available = int(reserve["available_liquidity"])
            ui_virtual = int(reserve["virtual_underlying_balance"])
            treasury_claim = ray_mul_down(accrued_scaled, normalized_income)

            # Deficit is a recorded missing asset after uncollectable debt is
            # burned. Therefore the accounting identity is:
            # cash + variable debt + deficit == aToken claims + unminted treasury.
            gross_assets_plus_deficit = actual_liquidity + variable_debt + deficit
            user_and_treasury_claims = atoken_supply + treasury_claim
            protocol_surplus = gross_assets_plus_deficit - user_and_treasury_claims

            rows.append({
                "ledger_version": ledger_version,
                "symbol": symbol,
                "underlying": underlying,
                "atoken": atoken,
                "atoken_resource_account": token_account,
                "vtoken": vtoken,
                "decimals": int(reserve["decimals"]),
                "actual_liquidity": actual_liquidity,
                "ui_available_liquidity": ui_available,
                "ui_virtual_underlying_balance": ui_virtual,
                "actual_minus_ui_available": actual_liquidity - ui_available,
                "actual_minus_ui_virtual": actual_liquidity - ui_virtual,
                "scaled_atoken_supply": scaled_atoken_supply,
                "atoken_supply": atoken_supply,
                "accrued_to_treasury_scaled": accrued_scaled,
                "treasury_claim": treasury_claim,
                "scaled_variable_debt": scaled_debt,
                "variable_debt": variable_debt,
                "ui_scaled_variable_debt": int(reserve["total_scaled_variable_debt"]),
                "normalized_income": normalized_income,
                "normalized_debt": normalized_debt,
                "deficit": deficit,
                "gross_assets_plus_deficit": gross_assets_plus_deficit,
                "user_and_treasury_claims": user_and_treasury_claims,
                "protocol_surplus": protocol_surplus,
                "user_shortfall": max(0, -protocol_surplus),
            })
        except Exception as exc:
            errors.append({"symbol": symbol, "error": repr(exc)})

    (ROOT / "rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    (ROOT / "errors.json").write_text(json.dumps(errors, indent=2) + "\n")

    shortfalls = []
    surpluses = []
    for row in rows:
        unit = 10 ** row["decimals"]
        threshold = max(10, unit // 10_000)
        liquidity_mismatch = max(
            abs(row["actual_minus_ui_available"]),
            abs(row["actual_minus_ui_virtual"]),
        )
        if row["user_shortfall"] >= threshold or liquidity_mismatch >= threshold:
            shortfalls.append({
                **row,
                "screening_threshold": threshold,
                "liquidity_mismatch": liquidity_mismatch,
            })
        if row["protocol_surplus"] > 0:
            surpluses.append(row)
    (ROOT / "material_shortfalls.json").write_text(json.dumps(shortfalls, indent=2) + "\n")
    (ROOT / "protocol_surpluses.json").write_text(json.dumps(surpluses, indent=2) + "\n")

    summary = {
        "ledger_version": ledger_version,
        "reserve_count": len(reserves),
        "successful_rows": len(rows),
        "errors": len(errors),
        "material_shortfalls": len(shortfalls),
        "max_user_shortfall": max((r["user_shortfall"] for r in rows), default=0),
        "min_protocol_surplus": min((r["protocol_surplus"] for r in rows), default=0),
        "max_protocol_surplus": max((r["protocol_surplus"] for r in rows), default=0),
        "max_actual_vs_ui_difference": max((abs(r["actual_minus_ui_available"]) for r in rows), default=0),
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    marker = "MATERIAL_USER_SHORTFALL" if shortfalls else "NO_MATERIAL_USER_SHORTFALL"
    (ROOT / marker).write_text(marker + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
