#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("evidence-cardano-live")
OUT.mkdir(parents=True, exist_ok=True)

POLICIES = {
    "pyth": {
        "policy": "c935c937d0deda8975142c7b77aeef8f8cd48791e89a8ca7a0edc154",
        "asset_name": "50797468205374617465",  # Pyth State
    }
}
BASES = {
    "koios_api": "https://api.koios.rest/api/v1",
    "koios_guild": "https://guild.koios.rest/api/v1",
}


def request_json(
    url: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> Any:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": "pyth-cardano-readonly-census/1",
        },
    )
    with urllib.request.urlopen(req, timeout=45) as response:
        raw = response.read()
        return json.loads(raw)


def probe_asset(base: str, policy: str, asset_name: str) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    candidates = [
        (
            "POST_asset_utxos_pairs",
            f"{base}/asset_utxos",
            "POST",
            {"_asset_list": [[policy, asset_name]], "_extended": True},
        ),
        (
            "POST_asset_utxos_unit",
            f"{base}/asset_utxos",
            "POST",
            {"_asset_list": [f"{policy}.{asset_name}"], "_extended": True},
        ),
        (
            "GET_asset_utxos",
            f"{base}/asset_utxos?"
            + urllib.parse.urlencode(
                {
                    "_asset_policy": policy,
                    "_asset_name": asset_name,
                    "_extended": "true",
                }
            ),
            "GET",
            None,
        ),
        (
            "GET_asset_info",
            f"{base}/asset_info?"
            + urllib.parse.urlencode(
                {"_asset_policy": policy, "_asset_name": asset_name}
            ),
            "GET",
            None,
        ),
    ]
    for name, url, method, body in candidates:
        try:
            payload = request_json(url, method=method, body=body)
            attempts.append(
                {
                    "name": name,
                    "url": url,
                    "method": method,
                    "ok": True,
                    "payload": payload,
                }
            )
        except Exception as error:  # evidence records all provider failures
            attempts.append(
                {
                    "name": name,
                    "url": url,
                    "method": method,
                    "ok": False,
                    "error": repr(error),
                }
            )
    return {"attempts": attempts}


def stable_rows(provider: dict[str, Any]) -> list[dict[str, Any]]:
    for attempt in provider["attempts"]:
        if not attempt["ok"]:
            continue
        payload = attempt["payload"]
        if isinstance(payload, list) and payload:
            rows = []
            for item in payload:
                if not isinstance(item, dict):
                    continue
                if "tx_hash" not in item:
                    continue
                rows.append(
                    {
                        "tx_hash": item.get("tx_hash"),
                        "tx_index": item.get("tx_index"),
                        "address": item.get("address"),
                        "payment_cred": item.get("payment_cred"),
                        "datum_hash": item.get("datum_hash"),
                        "inline_datum": item.get("inline_datum"),
                        "reference_script": item.get("reference_script"),
                        "asset_list": item.get("asset_list"),
                        "is_spent": item.get("is_spent"),
                        "block_height": item.get("block_height"),
                        "block_time": item.get("block_time"),
                    }
                )
            if rows:
                return rows
    return []


def main() -> int:
    output: dict[str, Any] = {
        "schema": "pyth-cardano-live-state-census/v1",
        "generated_at_unix": int(time.time()),
        "policies": POLICIES,
        "providers": {},
    }
    for provider_name, base in BASES.items():
        output["providers"][provider_name] = {}
        for asset_name, config in POLICIES.items():
            result = probe_asset(base, config["policy"], config["asset_name"])
            result["stable_rows"] = stable_rows(result)
            output["providers"][provider_name][asset_name] = result

    comparable: list[list[dict[str, Any]]] = []
    for provider in output["providers"].values():
        rows = provider["pyth"]["stable_rows"]
        if rows:
            comparable.append(rows)
    exact_agreement = len(comparable) >= 2 and all(
        rows == comparable[0] for rows in comparable[1:]
    )
    output["successful_provider_count"] = len(comparable)
    output["multi_provider_exact_agreement"] = exact_agreement

    (OUT / "census.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    summary = [
        f"SUCCESSFUL_PROVIDER_COUNT={len(comparable)}",
        f"MULTI_PROVIDER_EXACT_AGREEMENT={str(exact_agreement).lower()}",
    ]
    if comparable:
        summary += [
            f"PYTH_STATE_UTXO_COUNT={len(comparable[0])}",
            f"PYTH_STATE_TX={comparable[0][0]['tx_hash']}#{comparable[0][0]['tx_index']}",
            f"PYTH_STATE_ADDRESS={comparable[0][0]['address']}",
            f"PYTH_STATE_PAYMENT_CRED={comparable[0][0]['payment_cred']}",
            f"PYTH_STATE_BLOCK_TIME={comparable[0][0]['block_time']}",
            f"INLINE_DATUM_PRESENT={comparable[0][0]['inline_datum'] is not None}",
            f"REFERENCE_SCRIPT_PRESENT={comparable[0][0]['reference_script'] is not None}",
        ]
    text = "\n".join(summary) + "\n"
    (OUT / "summary.txt").write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if comparable else 2


if __name__ == "__main__":
    raise SystemExit(main())
