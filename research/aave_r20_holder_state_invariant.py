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
GRAPHQL = os.environ.get("GRAPHQL", "https://indexer.mainnet.aptoslabs.com/v1/graphql")
POOL = os.environ.get(
    "AAVE_POOL",
    "0x39ddcd9e1a39fa14f25e3f9ec8a86074d05cc0881cbf667df8a6ee70942016fb",
)
ROOT = pathlib.Path(os.environ.get("EVIDENCE_DIR", "evidence/aave-r20-holder-state"))
PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "50"))
MAX_HOLDERS_PER_TOKEN = int(os.environ.get("MAX_HOLDERS_PER_TOKEN", "10000"))


def request_json(url: str, body: dict[str, Any] | None = None, attempts: int = 20) -> Any:
    encoded = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json", "User-Agent": "aave-r20-holder-state/1.0"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, data=encoded, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in (408, 409, 425, 429) and exc.code < 500:
                raw = exc.read().decode(errors="replace")
                raise RuntimeError(f"HTTP {exc.code}: {raw[:1000]}") from exc
            time.sleep(min(60.0, 3.0 + attempt * 3.0))
        except Exception as exc:
            last = exc
            time.sleep(min(30.0, 2.0 + attempt * 2.0))
    raise RuntimeError(repr(last))


def graphql(query: str, variables: dict[str, Any]) -> Any:
    result = request_json(GRAPHQL, {"query": query, "variables": variables})
    if result.get("errors"):
        raise RuntimeError(result["errors"])
    return result


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


def holders(asset: str) -> list[dict[str, Any]]:
    query = """query Holders($asset: String!, $limit: Int!, $offset: Int!) {
      current_fungible_asset_balances(
        where: {asset_type_v2: {_eq: $asset}},
        limit: $limit,
        offset: $offset
      ) {
        owner_address amount asset_type_v2 storage_id is_primary
      }
    }"""
    rows = []
    seen = set()
    for offset in range(0, MAX_HOLDERS_PER_TOKEN, PAGE_SIZE):
        page = graphql(query, {
            "asset": asset,
            "limit": PAGE_SIZE,
            "offset": offset,
        }).get("data", {}).get("current_fungible_asset_balances", [])
        for row in page:
            if int(str(row["amount"]), 0) <= 0:
                continue
            owner = str(row["owner_address"]).lower()
            if owner in seen:
                continue
            seen.add(owner)
            rows.append(row)
        if len(page) < PAGE_SIZE:
            break
        time.sleep(1.0)
    return rows


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    ledger = request_json(REST)
    ledger_version = int(ledger["ledger_version"])
    reserve_data = view(
        f"{POOL}::ui_pool_data_provider_v3::get_reserves_data", [], ledger_version
    )[0]

    token_rows = []
    holder_rows = []
    mismatches = []
    query_errors = []
    for reserve in reserve_data:
        for kind, token, module in (
            ("aToken", reserve["a_token_address"], "a_token_factory"),
            ("variableDebtToken", reserve["variable_debt_token_address"], "variable_debt_token_factory"),
        ):
            try:
                current = holders(token)
            except Exception as exc:
                query_errors.append({
                    "symbol": reserve["symbol"],
                    "kind": kind,
                    "token": token,
                    "stage": "indexer_holders",
                    "error": repr(exc),
                })
                continue
            token_rows.append({
                "symbol": reserve["symbol"],
                "kind": kind,
                "token": token,
                "holder_count": len(current),
            })
            for holder in current:
                owner = str(holder["owner_address"]).lower()
                try:
                    internal_balance = integer(view(
                        f"{POOL}::{module}::scaled_balance_of",
                        [owner, token],
                        ledger_version,
                    ))
                    fa_balance = integer(view(
                        "0x1::primary_fungible_store::balance",
                        [owner, token],
                        ledger_version,
                        ["0x1::fungible_asset::Metadata"],
                    ))
                    row = {
                        "ledger_version": ledger_version,
                        "symbol": reserve["symbol"],
                        "kind": kind,
                        "token": token,
                        "owner": owner,
                        "indexer_amount": str(holder["amount"]),
                        "internal_scaled_balance": internal_balance,
                        "fa_scaled_balance": fa_balance,
                        "internal_minus_fa": internal_balance - fa_balance,
                    }
                    holder_rows.append(row)
                    if internal_balance != fa_balance:
                        mismatches.append(row)
                except Exception as exc:
                    query_errors.append({
                        "symbol": reserve["symbol"],
                        "kind": kind,
                        "token": token,
                        "owner": owner,
                        "stage": "fullnode_compare",
                        "error": repr(exc),
                    })
            time.sleep(1.0)

    (ROOT / "ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
    (ROOT / "tokens.json").write_text(json.dumps(token_rows, indent=2) + "\n")
    (ROOT / "holders.json").write_text(json.dumps(holder_rows, indent=2) + "\n")
    (ROOT / "mismatches.json").write_text(json.dumps(mismatches, indent=2) + "\n")
    (ROOT / "errors.json").write_text(json.dumps(query_errors, indent=2) + "\n")

    complete = len(query_errors) == 0
    summary = {
        "ledger_version": ledger_version,
        "token_count": len(token_rows),
        "holder_rows_checked": len(holder_rows),
        "mismatches": len(mismatches),
        "errors": len(query_errors),
        "complete": complete,
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if mismatches:
        marker = "HOLDER_STATE_MISMATCH"
    elif complete:
        marker = "HOLDER_STATES_MATCH"
    else:
        marker = "INCOMPLETE_SCAN"
    (ROOT / marker).write_text(marker + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
