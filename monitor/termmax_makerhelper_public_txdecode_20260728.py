#!/usr/bin/env python3
"""Decode public Ethereum MakerHelper place-order transaction inputs.

This is a read-only public-chain inventory. It uses the keyless Routescan API,
contains no private key, and cannot sign or broadcast a transaction.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
MAKER_HELPER = Web3.to_checksum_address("0x513690136500dEc06553385f7a00b010455dce92")
ZERO = "0x0000000000000000000000000000000000000000"
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"

CURVE_CUT = [
    {"name":"xtReserve","type":"uint256"},
    {"name":"liqSquare","type":"uint256"},
    {"name":"offset","type":"int256"},
]
CURVE_CUTS = [
    {"name":"lendCurveCuts","type":"tuple[]","components":CURVE_CUT},
    {"name":"borrowCurveCuts","type":"tuple[]","components":CURVE_CUT},
]
FEE_CONFIG = [
    {"name":"lendTakerFeeRatio","type":"uint32"},
    {"name":"lendMakerFeeRatio","type":"uint32"},
    {"name":"borrowTakerFeeRatio","type":"uint32"},
    {"name":"borrowMakerFeeRatio","type":"uint32"},
    {"name":"mintGtFeeRatio","type":"uint32"},
    {"name":"mintGtFeeRef","type":"uint32"},
]
ORDER_CONFIG = [
    {"name":"curveCuts","type":"tuple","components":CURVE_CUTS},
    {"name":"gtId","type":"uint256"},
    {"name":"maxXtReserve","type":"uint256"},
    {"name":"swapTrigger","type":"address"},
    {"name":"feeConfig","type":"tuple","components":FEE_CONFIG},
]
ORDER_INITIAL_PARAMS = [
    {"name":"maker","type":"address"},
    {"name":"ft","type":"address"},
    {"name":"xt","type":"address"},
    {"name":"debtToken","type":"address"},
    {"name":"gt","type":"address"},
    {"name":"virtualXtReserve","type":"uint256"},
    {"name":"pool","type":"address"},
    {"name":"maturity","type":"uint64"},
    {"name":"orderConfig","type":"tuple","components":ORDER_CONFIG},
]
DELEGATE_PARAMS = [
    {"name":"delegator","type":"address"},
    {"name":"delegatee","type":"address"},
    {"name":"isDelegate","type":"bool"},
    {"name":"nonce","type":"uint256"},
    {"name":"deadline","type":"uint256"},
]
SIGNATURE = [
    {"name":"v","type":"uint8"},
    {"name":"r","type":"bytes32"},
    {"name":"s","type":"bytes32"},
]

ABI = [
    {
        "type":"function","name":"placeOrderForV1","stateMutability":"nonpayable",
        "inputs":[
            {"name":"market","type":"address"},{"name":"maker","type":"address"},
            {"name":"collateralToMintGt","type":"uint256"},{"name":"debtTokenToDeposit","type":"uint256"},
            {"name":"ftToDeposit","type":"uint128"},{"name":"xtToDeposit","type":"uint128"},
            {"name":"orderConfig","type":"tuple","components":ORDER_CONFIG},
        ],
        "outputs":[{"name":"order","type":"address"},{"name":"gtId","type":"uint256"}],
    },
    {
        "type":"function","name":"placeOrderForV2","stateMutability":"nonpayable",
        "inputs":[
            {"name":"market","type":"address"},{"name":"salt","type":"uint256"},
            {"name":"collateralToMintGt","type":"uint256"},{"name":"debtTokenToDeposit","type":"uint256"},
            {"name":"ftToDeposit","type":"uint128"},{"name":"xtToDeposit","type":"uint128"},
            {"name":"initialParams","type":"tuple","components":ORDER_INITIAL_PARAMS},
            {"name":"delegateParams","type":"tuple","components":DELEGATE_PARAMS},
            {"name":"delegateSignature","type":"tuple","components":SIGNATURE},
        ],
        "outputs":[{"name":"order","type":"address"},{"name":"gtId","type":"uint256"}],
    },
]


def serial(value: Any) -> Any:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "items"):
        return {str(k): serial(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [serial(v) for v in value]
    return value


def named_tuple(value: Any, names: list[str]) -> dict[str, Any]:
    if hasattr(value, "items"):
        return {str(k): serial(v) for k, v in value.items()}
    return {name: serial(value[index]) for index, name in enumerate(names)}


def get_transactions() -> list[dict[str, Any]]:
    params = {
        "module":"account","action":"txlist","address":MAKER_HELPER,
        "startblock":0,"endblock":999999999,"page":1,"offset":10000,"sort":"asc",
    }
    last: Exception | None = None
    for attempt in range(6):
        try:
            response = requests.get(ROUTESCAN, params=params, timeout=60, headers={"User-Agent":"termmax-public-txdecode/1"})
            if response.status_code == 429:
                time.sleep(2 * (attempt + 1)); continue
            response.raise_for_status()
            payload = response.json()
            rows = payload.get("result", []) if isinstance(payload, dict) else []
            if isinstance(rows, str):
                raise RuntimeError(str(payload))
            return rows
        except Exception as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"Routescan txlist failed: {last}")


def main() -> int:
    w3 = Web3()
    contract = w3.eth.contract(address=MAKER_HELPER, abi=ABI)
    rows = get_transactions()
    decoded: list[dict[str, Any]] = []
    relevant_raw: list[dict[str, Any]] = []
    for tx in rows:
        input_data = tx.get("input") or "0x"
        if len(input_data) < 10:
            continue
        try:
            function, args = contract.decode_function_input(input_data)
        except Exception:
            continue
        if function.fn_name not in {"placeOrderForV1", "placeOrderForV2"}:
            continue
        relevant_raw.append(tx)
        item: dict[str, Any] = {
            "hash":tx.get("hash"),"blockNumber":int(tx.get("blockNumber") or 0),
            "timeStamp":int(tx.get("timeStamp") or 0),"from":tx.get("from"),
            "to":tx.get("to"),"isError":tx.get("isError"),"function":function.fn_name,
            "selector":input_data[:10],
        }
        if function.fn_name == "placeOrderForV1":
            config = named_tuple(args["orderConfig"], ["curveCuts","gtId","maxXtReserve","swapTrigger","feeConfig"])
            item.update({
                "market":args["market"],"maker":args["maker"],
                "collateralToMintGt":int(args["collateralToMintGt"]),
                "debtTokenToDeposit":int(args["debtTokenToDeposit"]),
                "ftToDeposit":int(args["ftToDeposit"]),"xtToDeposit":int(args["xtToDeposit"]),
                "gtId":int(config["gtId"]),"maxXtReserve":int(config["maxXtReserve"]),
            })
        else:
            initial = named_tuple(args["initialParams"], ["maker","ft","xt","debtToken","gt","virtualXtReserve","pool","maturity","orderConfig"])
            config = named_tuple(initial["orderConfig"], ["curveCuts","gtId","maxXtReserve","swapTrigger","feeConfig"])
            delegate = named_tuple(args["delegateParams"], ["delegator","delegatee","isDelegate","nonce","deadline"])
            item.update({
                "market":args["market"],"salt":int(args["salt"]),
                "collateralToMintGt":int(args["collateralToMintGt"]),
                "debtTokenToDeposit":int(args["debtTokenToDeposit"]),
                "ftToDeposit":int(args["ftToDeposit"]),"xtToDeposit":int(args["xtToDeposit"]),
                "maker":initial["maker"],"gt":initial["gt"],
                "virtualXtReserve":int(initial["virtualXtReserve"]),"maturity":int(initial["maturity"]),
                "gtId":int(config["gtId"]),"maxXtReserve":int(config["maxXtReserve"]),
                "delegator":delegate["delegator"],"delegatee":delegate["delegatee"],
                "isDelegate":bool(delegate["isDelegate"]),"delegateNonce":int(delegate["nonce"]),
                "delegateDeadline":int(delegate["deadline"]),
            })
            item["usesDelegationSignature"] = str(item["delegator"]).lower() != ZERO
            item["usesExistingGt"] = item["collateralToMintGt"] == 0 and item["gtId"] != 0
            item["existingGtDelegationFlow"] = item["usesDelegationSignature"] and item["usesExistingGt"]
        decoded.append(item)

    existing = [x for x in decoded if x.get("existingGtDelegationFlow")]
    new_gt = [x for x in decoded if x.get("function") == "placeOrderForV2" and x.get("collateralToMintGt", 0) > 0]
    delegated = [x for x in decoded if x.get("usesDelegationSignature")]
    summary = {
        "schema":"termmax-makerhelper-public-txdecode/v1",
        "generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "makerHelper":MAKER_HELPER,
        "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "allAddressTransactions":len(rows),"placeOrderTransactions":len(decoded),
        "placeOrderV1Count":sum(x["function"] == "placeOrderForV1" for x in decoded),
        "placeOrderV2Count":sum(x["function"] == "placeOrderForV2" for x in decoded),
        "delegatedV2Count":len(delegated),"newGtV2Count":len(new_gt),
        "existingGtDelegatedV2Count":len(existing),
        "existingGtDelegatedV2":existing,
        "decoded":decoded,
    }
    (OUT / "MAKERHELPER_TXS_RAW.json").write_text(json.dumps(relevant_raw, indent=2), encoding="utf-8")
    (OUT / "MAKERHELPER_TXS_DECODED.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
