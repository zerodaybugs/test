#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(os.environ.get("EVIDENCE_DIR", "evidence/live-incentives"))
ENDPOINT = os.environ.get("FULLNODE", "https://api.mainnet.aptoslabs.com/v1").rstrip("/")
AAVE = os.environ.get(
    "AAVE",
    "0x39ddcd9e1a39fa14f25e3f9ec8a86074d05cc0881cbf667df8a6ee70942016fb",
)
METADATA_TYPE = "0x1::fungible_asset::Metadata"


def request_json(url: str, body: dict[str, Any] | None = None) -> Any:
    data = None if body is None else json.dumps(body).encode()
    headers = {
        "Accept": "application/json",
        "User-Agent": "aave-aptos-round7-validation",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for attempt in range(6):
        try:
            request = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read())
        except Exception as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"request failed for {url}: {last!r}")


def view(
    function: str,
    type_arguments: list[str] | None = None,
    arguments: list[Any] | None = None,
) -> Any:
    return request_json(
        ENDPOINT + "/view",
        {
            "function": function,
            "type_arguments": type_arguments or [],
            "arguments": arguments or [],
        },
    )


def return_value(raw: Any) -> Any:
    if isinstance(raw, list) and len(raw) == 1:
        return raw[0]
    return raw


def option_value(raw: Any) -> Any:
    value = return_value(raw)
    if value is None:
        return None
    if isinstance(value, list):
        return value[0] if value else None
    if isinstance(value, dict):
        vector = value.get("vec")
        if isinstance(vector, list):
            return vector[0] if vector else None
    return value


def integer_value(raw: Any) -> int | None:
    value = return_value(raw)
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, dict) and "vec" in value:
        vector = value["vec"]
        value = vector[0] if vector else None
    return None if value is None else int(value)


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    ledger = request_json(ENDPOINT)
    chain_time = int(ledger["ledger_timestamp"]) // 1_000_000
    incentives_raw = view(
        f"{AAVE}::ui_incentive_data_provider_v3::get_reserves_incentives_data"
    )
    reserves_raw = view(f"{AAVE}::ui_pool_data_provider_v3::get_reserves_data")

    (ROOT / "ledger.json").write_text(json.dumps(ledger, indent=2) + "\n")
    (ROOT / "incentives_raw.json").write_text(
        json.dumps(incentives_raw, indent=2) + "\n"
    )
    (ROOT / "reserves_raw.json").write_text(
        json.dumps(reserves_raw, indent=2) + "\n"
    )

    incentives = return_value(incentives_raw)
    if not isinstance(incentives, list):
        raise TypeError(f"unexpected incentives response: {type(incentives)!r}")

    reserve_values = (
        reserves_raw[0] if isinstance(reserves_raw, list) and reserves_raw else []
    )
    reserve_by_underlying = {
        str(row.get("underlying_asset", "")).lower(): row
        for row in reserve_values
        if isinstance(row, dict)
    }

    rows: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for reserve in incentives:
        underlying = str(reserve.get("underlying_asset", ""))
        reserve_data = reserve_by_underlying.get(underlying.lower(), {})
        for token_kind, key in (
            ("aToken", "a_incentive_data"),
            ("variableDebtToken", "v_incentive_data"),
        ):
            token_data = reserve.get(key) or {}
            token = str(token_data.get("token_address", "0x0"))
            controller = str(token_data.get("incentive_controller_address", "0x0"))
            supply_raw = view(
                "0x1::dispatchable_fungible_asset::derived_supply",
                [METADATA_TYPE],
                [token],
            )
            token_supply = integer_value(supply_raw)

            for reward in token_data.get("rewards_token_information") or []:
                reward_token = str(reward.get("reward_token_address"))
                emission = int(reward.get("emission_per_second", 0))
                end = int(reward.get("emission_end_timestamp", 0))
                strategy = None
                vault = None
                vault_balance = None

                if controller.lower() not in ("0x0", "0x"):
                    strategy = option_value(
                        view(
                            f"{AAVE}::rewards_controller::get_pull_rewards_transfer_strategy",
                            [],
                            [reward_token, controller],
                        )
                    )
                if strategy:
                    vault = return_value(
                        view(
                            f"{AAVE}::transfer_strategy::pull_rewards_transfer_strategy_get_rewards_vault",
                            [],
                            [strategy],
                        )
                    )
                    if isinstance(vault, list):
                        vault = vault[0] if vault else None
                if vault:
                    vault_balance = integer_value(
                        view(
                            "0x1::primary_fungible_store::balance",
                            [METADATA_TYPE],
                            [vault, reward_token],
                        )
                    )

                active = emission > 0 and end > chain_time
                zero_supply = token_supply == 0
                funded = vault_balance is not None and vault_balance > 0
                row = {
                    "underlying_asset": underlying,
                    "reserve_symbol": reserve_data.get("symbol"),
                    "reserve_name": reserve_data.get("name"),
                    "borrowing_enabled": reserve_data.get("borrowing_enabled"),
                    "token_kind": token_kind,
                    "token_address": token,
                    "token_supply": token_supply,
                    "controller": controller,
                    "reward_symbol": reward.get("reward_token_symbol"),
                    "reward_token": reward_token,
                    "emission_per_second": emission,
                    "last_update_timestamp": int(
                        reward.get("incentives_last_update_timestamp", 0)
                    ),
                    "emission_end_timestamp": end,
                    "chain_timestamp": chain_time,
                    "active_emission": active,
                    "zero_token_supply": zero_supply,
                    "transfer_strategy": strategy,
                    "rewards_vault": vault,
                    "rewards_vault_balance": vault_balance,
                    "vault_funded": funded,
                }
                rows.append(row)
                if active and zero_supply and funded:
                    candidates.append(row)

    (ROOT / "classified_incentives.json").write_text(
        json.dumps(rows, indent=2) + "\n"
    )
    (ROOT / "zero_supply_active_reward_candidates.json").write_text(
        json.dumps(candidates, indent=2) + "\n"
    )

    summary = [
        f"chain_timestamp={chain_time}",
        f"reserves={len(incentives)}",
        f"reward_rows={len(rows)}",
        f"zero_supply_active_funded_candidates={len(candidates)}",
    ]
    for row in rows:
        summary.append(
            f"{row['reserve_symbol']} {row['token_kind']} "
            f"reward={row['reward_symbol']} supply={row['token_supply']} "
            f"emission={row['emission_per_second']} "
            f"end={row['emission_end_timestamp']} "
            f"active={row['active_emission']} "
            f"vault_balance={row['rewards_vault_balance']}"
        )
    (ROOT / "summary.txt").write_text("\n".join(summary) + "\n")
    marker = (
        "LIVE_ZERO_SUPPLY_INCENTIVE_CANDIDATE"
        if candidates
        else "NO_LIVE_ZERO_SUPPLY_INCENTIVE_CANDIDATE"
    )
    (ROOT / marker).write_text(marker + "\n")
    print((ROOT / "summary.txt").read_text())


if __name__ == "__main__":
    main()
