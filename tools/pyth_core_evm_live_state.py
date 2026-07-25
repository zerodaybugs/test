#!/usr/bin/env python3
"""Read-only state snapshot for the public Pyth Core EVM BSC proxy.

The deployed BSC implementation predates the newer transactionFeeInWei getter,
so this script intentionally queries only selectors present in the verified live ABI.
All providers are pinned to the same block before state comparison.
"""
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
    "pyth_wormhole_chain_id": "0x9a8a0592",
    "last_executed_governance_sequence": "0x586d3cf8",
    "governance_data_source": "0x426234e4",
    "governance_data_source_index": "0x6c72f51b",
    "single_update_fee_in_wei": "0x48b6404d",
    "valid_time_period_seconds": "0xcb718a9b",
    "wormhole": "0x84acd1bb",
    "valid_data_sources": "0xa38d81c6",
    "owner": "0x8da5cb5b",
    "version": "0x54fd4d50",
}


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def rpc(url: str, method: str, params: list[Any], request_id: int) -> Any:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()
    errors: list[str] = []
    for attempt in range(5):
        request = urllib.request.Request(
            url,
            data=payload,
            headers={
                "content-type": "application/json",
                "accept": "application/json",
                "user-agent": "pyth-core-readonly-state/2.0",
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


def words(value: str) -> list[str]:
    raw = value.removeprefix("0x")
    if len(raw) % 64 != 0:
        raise ValueError({"non_word_aligned_abi": value})
    return [raw[index : index + 64] for index in range(0, len(raw), 64)]


def uint_word(value: str) -> int:
    raw = value.removeprefix("0x")
    if len(raw) < 64:
        raise ValueError({"short_uint_return": value})
    return int(raw[:64], 16)


def address_word(value: str) -> str:
    raw = value.removeprefix("0x")
    if len(raw) < 64:
        raise ValueError({"short_address_return": value})
    return ("0x" + raw[24:64]).lower()


def governance_source(value: str) -> dict[str, Any]:
    values = words(value)
    if len(values) < 2:
        raise ValueError({"short_governance_source": value})
    return {
        "chain_id": int(values[0], 16),
        "emitter_address": "0x" + values[1],
    }


def dynamic_string(value: str) -> str:
    raw = value.removeprefix("0x")
    if len(raw) < 128:
        raise ValueError({"short_dynamic_string": value})
    offset = int(raw[:64], 16) * 2
    if offset + 64 > len(raw):
        raise ValueError({"invalid_string_offset": offset})
    length = int(raw[offset : offset + 64], 16)
    start = offset + 64
    end = start + length * 2
    if end > len(raw):
        raise ValueError({"truncated_dynamic_string": length})
    return bytes.fromhex(raw[start:end]).decode("utf-8")


def data_sources(value: str) -> list[dict[str, Any]]:
    raw = value.removeprefix("0x")
    if len(raw) < 128:
        raise ValueError({"short_data_sources": value})
    offset = int(raw[:64], 16) * 2
    if offset + 64 > len(raw):
        raise ValueError({"invalid_data_sources_offset": offset})
    count = int(raw[offset : offset + 64], 16)
    cursor = offset + 64
    expected = cursor + count * 128
    if expected > len(raw):
        raise ValueError({"truncated_data_sources": count})
    decoded: list[dict[str, Any]] = []
    for _ in range(count):
        chain_word = raw[cursor : cursor + 64]
        emitter_word = raw[cursor + 64 : cursor + 128]
        decoded.append(
            {
                "chain_id": int(chain_word, 16),
                "emitter_address": "0x" + emitter_word,
            }
        )
        cursor += 128
    return decoded


def common_block() -> tuple[str, list[dict[str, Any]], list[dict[str, str]]]:
    heads: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, url in enumerate(RPCS):
        try:
            chain_id = rpc(url, "eth_chainId", [], 10 + index * 10)
            latest = rpc(url, "eth_getBlockByNumber", ["latest", False], 11 + index * 10)
            heads.append(
                {
                    "rpc": url,
                    "evm_chain_id": int(chain_id, 16),
                    "latest_block_number": latest.get("number"),
                    "latest_block_hash": latest.get("hash"),
                }
            )
        except Exception as exc:  # noqa: BLE001
            failures.append({"rpc": url, "stage": "head", "error": repr(exc)})
    if len(heads) < 2:
        raise RuntimeError({"successful_head_provider_count": len(heads), "failures": failures})
    if len({row["evm_chain_id"] for row in heads}) != 1:
        raise RuntimeError({"provider_chain_id_mismatch": heads})
    block_number = min(int(row["latest_block_number"], 16) for row in heads)
    return hex(block_number), heads, failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    proxy = args.proxy.lower()

    pinned_block, heads, failures = common_block()
    rows: list[dict[str, Any]] = []
    for provider_index, head in enumerate(heads):
        url = str(head["rpc"])
        raw: dict[str, str] = {}
        call_failures: list[dict[str, str]] = []
        try:
            block = rpc(
                url,
                "eth_getBlockByNumber",
                [pinned_block, False],
                1000 + provider_index * 100,
            )
            if not block or str(block.get("number", "")).lower() != pinned_block.lower():
                raise RuntimeError({"missing_pinned_block": pinned_block, "block": block})
            for call_index, (name, selector) in enumerate(CALLS.items()):
                try:
                    raw[name] = rpc(
                        url,
                        "eth_call",
                        [{"to": proxy, "data": selector}, pinned_block],
                        1010 + provider_index * 100 + call_index,
                    )
                except Exception as exc:  # noqa: BLE001
                    call_failures.append({"call": name, "selector": selector, "error": repr(exc)})
            if call_failures:
                raise RuntimeError({"call_failures": call_failures})
            decoded = {
                "evm_chain_id": head["evm_chain_id"],
                "pyth_wormhole_chain_id": uint_word(raw["pyth_wormhole_chain_id"]),
                "last_executed_governance_sequence": uint_word(
                    raw["last_executed_governance_sequence"]
                ),
                "governance_data_source": governance_source(raw["governance_data_source"]),
                "governance_data_source_index": uint_word(raw["governance_data_source_index"]),
                "single_update_fee_in_wei": uint_word(raw["single_update_fee_in_wei"]),
                "valid_time_period_seconds": uint_word(raw["valid_time_period_seconds"]),
                "wormhole": address_word(raw["wormhole"]),
                "valid_data_sources": data_sources(raw["valid_data_sources"]),
                "owner": address_word(raw["owner"]),
                "version": dynamic_string(raw["version"]),
            }
            rows.append(
                {
                    "rpc": url,
                    "pinned_block_number": block.get("number"),
                    "pinned_block_hash": block.get("hash"),
                    "raw": raw,
                    "decoded": decoded,
                }
            )
        except Exception as exc:  # noqa: BLE001
            failures.append({"rpc": url, "stage": "state", "error": repr(exc)})

    if len(rows) < 2:
        raise RuntimeError({"successful_provider_count": len(rows), "failures": failures})
    normalized = [json.dumps(row["decoded"], sort_keys=True) for row in rows]
    state_identical = (
        len(set(normalized)) == 1
        and len({row["pinned_block_hash"] for row in rows}) == 1
    )
    state = rows[0]["decoded"]
    result = {
        "mode": "BSC_PINNED_BLOCK_READ_ONLY_ETH_CALL",
        "signed_or_broadcast_transactions": 0,
        "proxy": proxy,
        "pinned_block_number": pinned_block,
        "pinned_block_hash": rows[0]["pinned_block_hash"],
        "successful_provider_count": len(rows),
        "provider_failures": failures,
        "state_identical": state_identical,
        "state": state,
        "provider_heads": heads,
        "rows": rows,
    }
    write_json(out / "LIVE_STATE.json", result)
    markers = [
        "PYTH_CORE_EVM_LIVE_STATE_CAPTURED",
        "PUBLIC_CHAIN_MODE=READ_ONLY",
        "SIGNED_OR_BROADCAST_TRANSACTIONS=0",
        f"PINNED_STATE_BLOCK_NUMBER={pinned_block}",
        f"PINNED_STATE_BLOCK_HASH={rows[0]['pinned_block_hash']}",
        f"SUCCESSFUL_STATE_PROVIDER_COUNT={len(rows)}",
        f"STATE_IDENTICAL={str(state_identical).lower()}",
        f"LIVE_EVM_CHAIN_ID={state['evm_chain_id']}",
        f"LIVE_PYTH_WORMHOLE_CHAIN_ID={state['pyth_wormhole_chain_id']}",
        f"LIVE_LAST_EXECUTED_GOVERNANCE_SEQUENCE={state['last_executed_governance_sequence']}",
        f"LIVE_GOVERNANCE_EMITTER_CHAIN={state['governance_data_source']['chain_id']}",
        f"LIVE_GOVERNANCE_EMITTER={state['governance_data_source']['emitter_address']}",
        f"LIVE_GOVERNANCE_DATA_SOURCE_INDEX={state['governance_data_source_index']}",
        f"LIVE_VALID_DATA_SOURCE_COUNT={len(state['valid_data_sources'])}",
        f"LIVE_OWNER={state['owner']}",
        f"LIVE_VERSION={state['version']}",
        f"LIVE_WORMHOLE={state['wormhole']}",
    ]
    (out / "LIVE_STATE_MARKERS.txt").write_text("\n".join(markers) + "\n")
    print("\n".join(markers))
    if not state_identical:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
