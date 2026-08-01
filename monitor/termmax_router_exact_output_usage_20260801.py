#!/usr/bin/env python3
"""Read-only calldata census for official Ethereum TermMax Router V2.

The scanner decodes public successful transactions and classifies TermMaxSwapAdapter
exact-output units by path position. It has no signer, private key, transaction
construction, broadcast, impersonation, or state mutation capability.
"""
from __future__ import annotations

import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from eth_abi import decode
from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

ROUTER = Web3.to_checksum_address("0x324596C1682a5675008f6e58F9C4E0A894b079c7")
TERMMAX_ADAPTER = Web3.to_checksum_address("0xd8a90e69aFa072B9ff33BbFdFf56767BE2028Dc9")
ENDPOINT = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
PATH_TYPE = "(uint256,address,bool,(address,address,address,bytes)[])"
PATHS_TYPE = PATH_TYPE + "[]"
TERMMAX_DATA_TYPE = "(bool,uint32,address[],uint128[],uint128,uint256,address)"


def selector(signature: str) -> bytes:
    return Web3.keccak(text=signature)[:4]


METHODS: dict[bytes, dict[str, Any]] = {
    selector(f"swapTokens({PATHS_TYPE})"): {
        "name": "swapTokens",
        "types": [PATHS_TYPE],
        "paths": lambda values: list(values[0]),
    },
    selector(f"leverage(address,address,uint128,bool,{PATHS_TYPE},{PATH_TYPE},{PATH_TYPE})"): {
        "name": "leverage",
        "types": ["address", "address", "uint128", "bool", PATHS_TYPE, PATH_TYPE, PATH_TYPE],
        "paths": lambda values: list(values[4]) + [values[5], values[6]],
    },
    selector(f"borrowTokenFromCollateral(address,address,uint256,uint128,{PATH_TYPE})"): {
        "name": "borrowTokenFromCollateral",
        "types": ["address", "address", "uint256", "uint128", PATH_TYPE],
        "paths": lambda values: [values[4]],
    },
    selector(f"swapAndRepay(address,uint256,uint128,bool,{PATHS_TYPE})"): {
        "name": "swapAndRepay",
        "types": ["address", "uint256", "uint128", "bool", PATHS_TYPE],
        "paths": lambda values: list(values[4]),
    },
}


def fetch_transactions() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows_all: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    page = 1
    while True:
        params = {
            "module": "account",
            "action": "txlist",
            "address": ROUTER,
            "startblock": 0,
            "endblock": 999999999,
            "page": page,
            "offset": 10000,
            "sort": "asc",
        }
        payload: Any = None
        error: Exception | None = None
        for attempt in range(8):
            try:
                response = requests.get(
                    ENDPOINT,
                    params=params,
                    timeout=75,
                    headers={"User-Agent": "ZeroDayBugs-TermMax-Readonly/5"},
                )
                if response.status_code == 429:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as exc:  # noqa: BLE001
                error = exc
                time.sleep(1.25 * (attempt + 1))
        if payload is None:
            raise RuntimeError(f"Routescan txlist failed: {error}")
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            if "no transactions" in rows.lower() or "not found" in rows.lower():
                rows = []
            else:
                raise RuntimeError(f"Unexpected Routescan response: {payload}")
        diagnostics.append({"page": page, "rowCount": len(rows)})
        rows_all.extend(rows)
        if len(rows) < 10000:
            break
        page += 1
        time.sleep(0.3)
    return rows_all, diagnostics


def parse_hex(data: str) -> bytes:
    text = str(data or "0x")
    if text.startswith("0x"):
        text = text[2:]
    return bytes.fromhex(text) if text else b""


def classify_paths(tx: dict[str, Any], method: dict[str, Any], values: tuple[Any, ...]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    paths = method["paths"](values)
    for path_index, path in enumerate(paths):
        input_amount, recipient, use_balance, units = path
        for unit_index, unit in enumerate(units):
            adapter, token_in, token_out, swap_data = unit
            if str(adapter).lower() != TERMMAX_ADAPTER.lower():
                continue
            decoded_data: dict[str, Any]
            try:
                data = decode([TERMMAX_DATA_TYPE], bytes(swap_data))[0]
                decoded_data = {
                    "swapExactTokenForToken": bool(data[0]),
                    "scalingFactor": int(data[1]),
                    "orders": [Web3.to_checksum_address(x) for x in data[2]],
                    "tradingAmts": [int(x) for x in data[3]],
                    "netTokenAmt": int(data[4]),
                    "deadline": int(data[5]),
                    "refundAddress": Web3.to_checksum_address(data[6]),
                }
            except Exception as exc:  # noqa: BLE001
                decoded_data = {"decodeError": f"{type(exc).__name__}: {exc}"}
            exact_output = decoded_data.get("swapExactTokenForToken") is False
            non_final = unit_index < len(units) - 1
            findings.append({
                "txHash": tx.get("hash"),
                "blockNumber": int(tx.get("blockNumber", "0")),
                "timestamp": int(tx.get("timeStamp", "0")),
                "timestampUtc": datetime.fromtimestamp(int(tx.get("timeStamp", "0")), tz=timezone.utc).isoformat()
                if int(tx.get("timeStamp", "0")) else None,
                "from": tx.get("from"),
                "method": method["name"],
                "pathIndex": path_index,
                "pathInputAmount": int(input_amount),
                "pathRecipient": Web3.to_checksum_address(recipient),
                "pathUseBalanceOnchain": bool(use_balance),
                "unitIndex": unit_index,
                "unitCount": len(units),
                "nonFinal": non_final,
                "tokenIn": Web3.to_checksum_address(token_in),
                "tokenOut": Web3.to_checksum_address(token_out),
                "exactOutput": exact_output,
                "termMaxSwapData": decoded_data,
            })
    return findings


def main() -> int:
    transactions, fetch_diagnostics = fetch_transactions()
    selector_counts: Counter[str] = Counter()
    method_counts: Counter[str] = Counter()
    decode_errors: list[dict[str, Any]] = []
    termmax_units: list[dict[str, Any]] = []
    successful_to_router = 0

    for tx in transactions:
        if str(tx.get("to", "")).lower() != ROUTER.lower():
            continue
        if str(tx.get("isError", "0")) not in {"0", ""}:
            continue
        if str(tx.get("txreceipt_status", "1")) not in {"1", ""}:
            continue
        successful_to_router += 1
        raw = parse_hex(tx.get("input", "0x"))
        if len(raw) < 4:
            continue
        sel = raw[:4]
        selector_counts["0x" + sel.hex()] += 1
        method = METHODS.get(sel)
        if method is None:
            continue
        method_counts[method["name"]] += 1
        try:
            values = decode(method["types"], raw[4:])
            termmax_units.extend(classify_paths(tx, method, values))
        except Exception as exc:  # noqa: BLE001
            decode_errors.append({
                "txHash": tx.get("hash"),
                "selector": "0x" + sel.hex(),
                "method": method["name"],
                "error": f"{type(exc).__name__}: {exc}",
            })

    exact_output = [row for row in termmax_units if row.get("exactOutput")]
    exact_output_non_final = [row for row in exact_output if row.get("nonFinal")]
    exact_input_non_final = [row for row in termmax_units if not row.get("exactOutput") and row.get("nonFinal")]
    result = {
        "schema": "termmax-router-exact-output-usage/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {
            "privateKeys": 0,
            "signers": 0,
            "signedTransactions": 0,
            "broadcastTransactions": 0,
            "stateChanges": 0,
        },
        "router": ROUTER,
        "termMaxAdapter": TERMMAX_ADAPTER,
        "fetchDiagnostics": fetch_diagnostics,
        "transactionCount": len(transactions),
        "successfulTransactionsToRouter": successful_to_router,
        "selectorCounts": dict(selector_counts),
        "decodedMethodCounts": dict(method_counts),
        "decodeErrorCount": len(decode_errors),
        "decodeErrors": decode_errors,
        "termMaxAdapterUnitCount": len(termmax_units),
        "termMaxExactOutputUnitCount": len(exact_output),
        "termMaxExactOutputNonFinalUnitCount": len(exact_output_non_final),
        "termMaxExactInputNonFinalUnitCount": len(exact_input_non_final),
        "nextStep": "PIN_EXACT_PRODUCTION_TX_AND_FORK" if exact_output_non_final else "NO_HISTORICAL_EXACT_OUTPUT_NONFINAL_USAGE_FOUND",
        "termMaxUnits": termmax_units,
        "exactOutputNonFinal": exact_output_non_final,
    }
    (OUT / "ROUTER_EXACT_OUTPUT_USAGE.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (OUT / "VERDICT.txt").write_text(json.dumps({
        "transactionCount": result["transactionCount"],
        "successfulTransactionsToRouter": successful_to_router,
        "termMaxAdapterUnitCount": len(termmax_units),
        "termMaxExactOutputUnitCount": len(exact_output),
        "termMaxExactOutputNonFinalUnitCount": len(exact_output_non_final),
        "decodeErrorCount": len(decode_errors),
        "nextStep": result["nextStep"],
    }, indent=2), encoding="utf-8")
    print((OUT / "VERDICT.txt").read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
