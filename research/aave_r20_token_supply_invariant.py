#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

REST = os.environ.get("REST", "https://api.mainnet.aptoslabs.com/v1").rstrip("/")
POOL = os.environ.get(
    "AAVE_POOL",
    "0x39ddcd9e1a39fa14f25e3f9ec8a86074d05cc0881cbf667df8a6ee70942016fb",
)
ROOT = pathlib.Path(os.environ.get("EVIDENCE_DIR", "evidence/aave-r20-token-supply"))


def request_json(url: str, body: dict[str, Any] | None = None) -> Any:
    encoded = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json", "User-Agent": "aave-r20-token-supply/1.0"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for attempt in range(12):
        try:
            req = urllib.request.Request(url, data=encoded, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code != 429 and exc.code < 500:
                raw = exc.read().decode(errors="replace")
                raise RuntimeError(f"HTTP {exc.code}: {raw[:1000]}") from exc
            time.sleep(min(30.0, 2.0 + attempt * 2.5))
        except Exception as exc:
            last = exc
            time.sleep(min(20.0, 1.0 + attempt * 1.5))
    raise RuntimeError(repr(last))


def versioned(path: str, ledger_version: int) -> str:
    return f"{path}{'&' if '?' in path else '?'}ledger_version={ledger_version}"


def view(
    function: str,
    arguments: list[Any],
    ledger_version: int,
    type_arguments: list[str] | None = None,
) -> Any:
    return request_json(versioned(REST + "/view", ledger_version), {
        "function": function,
        "type_arguments": type_arguments or [],
        "arguments": arguments,
    })


def scalar(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def integer(value: Any) -> int:
    return int(str(scalar(value)), 0)


def option_integer(value: Any) -> int | None:
    value = scalar(value)
    if value is None:
        return None
    if isinstance(value, dict):
        for key in ("vec", "values", "value"):
            if key not in value:
                continue
            nested = value[key]
            if nested is None or nested == []:
                return None
            if isinstance(nested, list):
                return int(str(nested[0]), 0)
            return int(str(nested), 0)
    if isinstance(value, list):
        if not value:
            return None
        return int(str(value[0]), 0)
    return int(str(value), 0)


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    ledger = request_json(REST)
    ledger_version = int(ledger["ledger_version"])
    raw = view(f"{POOL}::ui_pool_data_provider_v3::get_reserves_data", [], ledger_version)
    reserves = raw[0]

    rows = []
    errors = []
    mismatches = []
    for reserve in reserves:
        symbol = reserve["symbol"]
        for token_kind, token_address, module in (
            ("aToken", reserve["a_token_address"], "a_token_factory"),
            ("variableDebtToken", reserve["variable_debt_token_address"], "variable_debt_token_factory"),
        ):
            try:
                internal_scaled_supply = integer(view(
                    f"{POOL}::{module}::scaled_total_supply",
                    [token_address],
                    ledger_version,
                ))
                fa_supply = option_integer(view(
                    "0x1::fungible_asset::supply",
                    [token_address],
                    ledger_version,
                    ["0x1::fungible_asset::Metadata"],
                ))
                difference = None if fa_supply is None else internal_scaled_supply - fa_supply
                row = {
                    "ledger_version": ledger_version,
                    "symbol": symbol,
                    "token_kind": token_kind,
                    "token_address": token_address,
                    "internal_scaled_supply": internal_scaled_supply,
                    "fungible_asset_supply": fa_supply,
                    "internal_minus_fa_supply": difference,
                }
                rows.append(row)
                if difference not in (0, None):
                    mismatches.append(row)
            except Exception as exc:
                errors.append({
                    "symbol": symbol,
                    "token_kind": token_kind,
                    "token_address": token_address,
                    "error": repr(exc),
                })

    (ROOT / "ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
    (ROOT / "rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    (ROOT / "mismatches.json").write_text(json.dumps(mismatches, indent=2) + "\n")
    (ROOT / "errors.json").write_text(json.dumps(errors, indent=2) + "\n")
    summary = {
        "ledger_version": ledger_version,
        "token_rows": len(rows),
        "mismatches": len(mismatches),
        "errors": len(errors),
        "max_absolute_mismatch": max(
            (abs(row["internal_minus_fa_supply"]) for row in mismatches),
            default=0,
        ),
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    marker = "TOKEN_SUPPLY_MISMATCH" if mismatches else "TOKEN_SUPPLIES_MATCH"
    (ROOT / marker).write_text(marker + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
