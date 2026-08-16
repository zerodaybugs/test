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
ROOT = pathlib.Path(os.environ.get("EVIDENCE_DIR", "evidence/aave-r20-user-config"))
PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "50"))
MAX_HOLDERS_PER_TOKEN = int(os.environ.get("MAX_HOLDERS_PER_TOKEN", "10000"))


def request_json(url: str, body: dict[str, Any] | None = None, attempts: int = 20) -> Any:
    encoded = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json", "User-Agent": "aave-r20-user-config/2.0"}
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
            retryable = exc.code in (408, 409, 425, 429) or exc.code >= 500
            if not retryable:
                raw = exc.read().decode(errors="replace")
                raise RuntimeError(f"HTTP {exc.code} {url}: {raw[:1000]}") from exc
            retry_after = exc.headers.get("Retry-After")
            delay = float(retry_after) if retry_after else min(60.0, 3.0 + attempt * 3.0)
            time.sleep(delay)
        except Exception as exc:
            last = exc
            time.sleep(min(30.0, 2.0 + attempt * 2.0))
    raise RuntimeError(f"request failed: {url}: {last!r}")


def graphql(query: str, variables: dict[str, Any] | None = None) -> Any:
    result = request_json(GRAPHQL, {"query": query, "variables": variables or {}})
    if result.get("errors"):
        raise RuntimeError(result["errors"])
    return result


def with_ledger_version(path: str, ledger_version: int) -> str:
    return f"{path}{'&' if '?' in path else '?'}ledger_version={ledger_version}"


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


def scalar(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def integer(value: Any) -> int:
    return int(str(scalar(value)), 0)


def user_config_data(result: Any) -> int:
    value = scalar(result)
    if isinstance(value, dict):
        for key in ("data", "inner", "value"):
            if key in value:
                return int(str(value[key]), 0)
    if isinstance(value, (str, int)):
        return int(str(value), 0)
    raise TypeError(f"unsupported UserConfiguration serialization: {value!r}")


def type_fields(type_name: str) -> list[str]:
    query = """query Introspect($name: String!) {
      __type(name: $name) { fields { name } inputFields { name } }
    }"""
    payload = graphql(query, {"name": type_name})
    obj = payload.get("data", {}).get("__type") or {}
    fields = obj.get("fields") or obj.get("inputFields") or []
    return [str(item["name"]) for item in fields]


def current_holders(
    asset: str,
    asset_field: str,
    owner_field: str,
    output_fields: list[str],
) -> list[dict[str, Any]]:
    selected = "\n        ".join(output_fields)
    # Deliberately omit amount filtering and ordering. Both can force expensive
    # indexer query plans. Exact asset equality is sufficient; zero rows are
    # filtered locally.
    query = f"""query Holders($asset: String!, $limit: Int!, $offset: Int!) {{
      current_fungible_asset_balances(
        where: {{{asset_field}: {{_eq: $asset}}}},
        limit: $limit,
        offset: $offset
      ) {{
        {selected}
      }}
    }}"""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for offset in range(0, MAX_HOLDERS_PER_TOKEN, PAGE_SIZE):
        response = graphql(query, {"asset": asset, "limit": PAGE_SIZE, "offset": offset})
        page = response.get("data", {}).get("current_fungible_asset_balances", [])
        for row in page:
            try:
                amount = int(str(row["amount"]), 0)
            except Exception:
                continue
            if amount <= 0:
                continue
            key = (str(row[owner_field]).lower(), str(row.get(asset_field, asset)).lower())
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
        if len(page) < PAGE_SIZE:
            break
        time.sleep(1.0)
    return rows


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    ledger = request_json(REST)
    ledger_version = int(ledger["ledger_version"])
    (ROOT / "ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")

    balance_fields = type_fields("current_fungible_asset_balances")
    bool_fields = type_fields("current_fungible_asset_balances_bool_exp")
    schema = {"balance_fields": balance_fields, "bool_fields": bool_fields}
    (ROOT / "schema.json").write_text(json.dumps(schema, indent=2) + "\n")

    asset_field = next(
        (field for field in ("asset_type_v2", "asset_type", "asset_type_v1")
         if field in balance_fields and field in bool_fields),
        None,
    )
    owner_field = next(
        (field for field in ("owner_address", "owner", "storage_id")
         if field in balance_fields),
        None,
    )
    if asset_field is None or owner_field is None or "amount" not in balance_fields:
        raise RuntimeError(f"unsupported current balance schema: {schema}")

    output_fields = [owner_field, "amount", asset_field]
    for optional in ("last_transaction_version", "is_primary", "storage_id"):
        if optional in balance_fields and optional not in output_fields:
            output_fields.append(optional)

    reserves_raw = view(
        f"{POOL}::ui_pool_data_provider_v3::get_reserves_data", [], ledger_version
    )
    reserves_ui = reserves_raw[0]
    reserves_list = scalar(view(f"{POOL}::pool::get_reserves_list", [], ledger_version))
    if not isinstance(reserves_list, list):
        raise TypeError(f"unexpected reserves list: {reserves_list!r}")
    ui_by_underlying = {
        str(item["underlying_asset"]).lower(): item for item in reserves_ui
    }
    reserves = []
    for index, underlying in enumerate(reserves_list):
        item = ui_by_underlying.get(str(underlying).lower())
        if item is None:
            raise RuntimeError(f"reserve missing from UI data: {underlying}")
        reserves.append({
            "id": index,
            "symbol": item["symbol"],
            "underlying": item["underlying_asset"],
            "atoken": item["a_token_address"],
            "vtoken": item["variable_debt_token_address"],
            "decimals": int(item["decimals"]),
        })
    (ROOT / "reserves.json").write_text(json.dumps(reserves, indent=2) + "\n")

    indexer_holders = []
    holders_by_owner: dict[str, list[dict[str, Any]]] = {}
    holder_query_errors = []
    for reserve in reserves:
        try:
            holders = current_holders(
                reserve["vtoken"], asset_field, owner_field, output_fields
            )
        except Exception as exc:
            holder_query_errors.append({
                "symbol": reserve["symbol"],
                "vtoken": reserve["vtoken"],
                "error": repr(exc),
            })
            continue
        for holder in holders:
            owner = str(holder[owner_field]).lower()
            record = {
                "reserve_id": reserve["id"],
                "symbol": reserve["symbol"],
                "vtoken": reserve["vtoken"],
                "owner": owner,
                "indexer_amount": str(holder["amount"]),
                "indexer_row": holder,
            }
            indexer_holders.append(record)
            holders_by_owner.setdefault(owner, []).append(record)
        time.sleep(1.0)
    (ROOT / "indexer_debt_holders.json").write_text(
        json.dumps(indexer_holders, indent=2) + "\n"
    )
    (ROOT / "holder_query_errors.json").write_text(
        json.dumps(holder_query_errors, indent=2) + "\n"
    )

    checked = []
    hidden_debt = []
    stale_borrow_bits = []
    errors = []
    for number, owner in enumerate(sorted(holders_by_owner)):
        try:
            config_raw = view(f"{POOL}::pool::get_user_configuration", [owner], ledger_version)
            config = user_config_data(config_raw)
            account_data = None
            for reserve in reserves:
                scaled_debt = integer(view(
                    f"{POOL}::variable_debt_token_factory::scaled_balance_of",
                    [owner, reserve["vtoken"]],
                    ledger_version,
                ))
                borrowing_bit = bool((config >> (2 * reserve["id"])) & 1)
                row = {
                    "owner": owner,
                    "reserve_id": reserve["id"],
                    "symbol": reserve["symbol"],
                    "vtoken": reserve["vtoken"],
                    "config_data": str(config),
                    "borrowing_bit": borrowing_bit,
                    "scaled_debt": scaled_debt,
                }
                checked.append(row)
                if scaled_debt > 0 and not borrowing_bit:
                    if account_data is None:
                        account_data = view(
                            f"{POOL}::user_logic::get_user_account_data",
                            [owner],
                            ledger_version,
                        )
                    hidden_debt.append({**row, "account_data": account_data})
                if scaled_debt == 0 and borrowing_bit:
                    stale_borrow_bits.append(row)
        except Exception as exc:
            errors.append({"owner": owner, "error": repr(exc)})
        if number % 20 == 0:
            time.sleep(0.5)

    (ROOT / "checked_positions.json").write_text(json.dumps(checked, indent=2) + "\n")
    (ROOT / "hidden_debt_candidates.json").write_text(json.dumps(hidden_debt, indent=2) + "\n")
    (ROOT / "stale_borrow_bit_candidates.json").write_text(
        json.dumps(stale_borrow_bits, indent=2) + "\n"
    )
    (ROOT / "errors.json").write_text(json.dumps(errors, indent=2) + "\n")

    complete = len(holder_query_errors) == 0 and len(errors) == 0
    summary = {
        "ledger_version": ledger_version,
        "asset_field": asset_field,
        "owner_field": owner_field,
        "reserve_count": len(reserves),
        "indexer_nonzero_debt_rows": len(indexer_holders),
        "unique_debt_owners": len(holders_by_owner),
        "checked_owner_reserve_pairs": len(checked),
        "hidden_debt_candidates": len(hidden_debt),
        "stale_borrow_bit_candidates": len(stale_borrow_bits),
        "holder_query_errors": len(holder_query_errors),
        "owner_check_errors": len(errors),
        "complete": complete,
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    if hidden_debt:
        marker = "HIDDEN_DEBT_CANDIDATE"
    elif complete:
        marker = "NO_HIDDEN_DEBT_CANDIDATE"
    else:
        marker = "INCOMPLETE_SCAN"
    (ROOT / marker).write_text(marker + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
