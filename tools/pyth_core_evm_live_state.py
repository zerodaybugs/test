#!/usr/bin/env python3
"""Read-only state snapshot for the public Pyth Core EVM BSC proxy."""
from __future__ import annotations

import argparse
import json
import pathlib
import time
import urllib.request
from typing import Any

RPCS = [
    "https://bsc-dataseed.binance.org",
    "https://bsc-rpc.publicnode.com",
    "https://bsc-dataseed.bnbchain.org",
]
CALLS = {
    "chain_id": "0x9a8a0592",
    "last_executed_governance_sequence": "0x586d3cf8",
    "governance_data_source": "0x426234e4",
    "governance_data_source_index": "0x6c72f51b",
    "single_update_fee_in_wei": "0x48b6404d",
    "valid_time_period_seconds": "0xcb718a9b",
    "transaction_fee_in_wei": "0x978a800d",
    "wormhole": "0x84acd1bb",
}


def rpc(url: str, method: str, params: list[Any], request_id: int) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
    errors: list[str] = []
    for attempt in range(5):
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "content-type": "application/json",
                "accept": "application/json",
                "user-agent": "pyth-core-readonly-state/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                obj = json.load(response)
            if "error" in obj:
                raise RuntimeError(obj["error"])
            return obj["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))
            if attempt < 4:
                time.sleep(attempt + 1)
    raise RuntimeError({"rpc": url, "method": method, "errors": errors})


def uint256(value: str) -> int:
    return int(value, 16)


def address(value: str) -> str:
    return "0x" + value.removeprefix("0x")[-40:]


def governance_source(value: str) -> dict[str, Any]:
    raw = value.removeprefix("0x")
    if len(raw) < 128:
        raise ValueError({"short_governance_source": value})
    return {
        "chain_id": int(raw[:64], 16),
        "emitter_address": "0x" + raw[64:128],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    proxy = args.proxy.lower()

    rows: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for provider_index, url in enumerate(RPCS):
        try:
            raw: dict[str, str] = {}
            for call_index, (name, selector) in enumerate(CALLS.items()):
                raw[name] = rpc(
                    url,
                    "eth_call",
                    [{"to": proxy, "data": selector}, "latest"],
                    1000 + provider_index * 100 + call_index,
                )
            block = rpc(url, "eth_getBlockByNumber", ["latest", False], 1090 + provider_index)
            decoded = {
                "chain_id": uint256(raw["chain_id"]),
                "last_executed_governance_sequence": uint256(
                    raw["last_executed_governance_sequence"]
                ),
                "governance_data_source": governance_source(raw["governance_data_source"]),
                "governance_data_source_index": uint256(raw["governance_data_source_index"]),
                "single_update_fee_in_wei": uint256(raw["single_update_fee_in_wei"]),
                "valid_time_period_seconds": uint256(raw["valid_time_period_seconds"]),
                "transaction_fee_in_wei": uint256(raw["transaction_fee_in_wei"]),
                "wormhole": address(raw["wormhole"]).lower(),
            }
            rows.append(
                {
                    "rpc": url,
                    "latest_block_number": block.get("number"),
                    "latest_block_hash": block.get("hash"),
                    "raw": raw,
                    "decoded": decoded,
                }
            )
        except Exception as exc:  # noqa: BLE001
            failures.append({"rpc": url, "error": repr(exc)})

    if len(rows) < 2:
        raise RuntimeError({"successful_provider_count": len(rows), "failures": failures})
    normalized = [json.dumps(row["decoded"], sort_keys=True) for row in rows]
    state_identical = len(set(normalized)) == 1
    result = {
        "mode": "BSC_READ_ONLY_ETH_CALL",
        "signed_or_broadcast_transactions": 0,
        "proxy": proxy,
        "successful_provider_count": len(rows),
        "provider_failures": failures,
        "state_identical": state_identical,
        "state": rows[0]["decoded"],
        "rows": rows,
    }
    (out / "LIVE_STATE.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    state = rows[0]["decoded"]
    markers = [
        "PYTH_CORE_EVM_LIVE_STATE_CAPTURED",
        "PUBLIC_CHAIN_MODE=READ_ONLY",
        "SIGNED_OR_BROADCAST_TRANSACTIONS=0",
        f"SUCCESSFUL_STATE_PROVIDER_COUNT={len(rows)}",
        f"STATE_IDENTICAL={str(state_identical).lower()}",
        f"LIVE_PYTH_CHAIN_ID={state['chain_id']}",
        f"LIVE_LAST_EXECUTED_GOVERNANCE_SEQUENCE={state['last_executed_governance_sequence']}",
        f"LIVE_GOVERNANCE_EMITTER_CHAIN={state['governance_data_source']['chain_id']}",
        f"LIVE_GOVERNANCE_EMITTER={state['governance_data_source']['emitter_address']}",
        f"LIVE_GOVERNANCE_DATA_SOURCE_INDEX={state['governance_data_source_index']}",
        f"LIVE_WORMHOLE={state['wormhole']}",
    ]
    (out / "LIVE_STATE_MARKERS.txt").write_text("\n".join(markers) + "\n")
    print("\n".join(markers))
    if not state_identical:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
