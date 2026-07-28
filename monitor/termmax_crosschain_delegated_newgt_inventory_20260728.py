#!/usr/bin/env python3
"""Cross-chain read-only inventory of TermMax delegated new-GT MakerHelper flows.

The scanner uses public JSON-RPC reads only. It has no signer, private key,
transaction construction, or broadcast capability.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hexbytes import HexBytes
from web3 import Web3
from web3._utils.events import get_event_data
from web3.middleware import ExtraDataToPOAMiddleware

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

CHAINS = [
    {
        "name": "ethereum", "chainId": 1,
        "makerHelper": "0x513690136500dEc06553385f7a00b010455dce92",
        "startBlock": 24_883_366,
        "rpcs": ["https://ethereum-rpc.publicnode.com", "https://rpc.mevblocker.io", "https://eth.drpc.org"],
    },
    {
        "name": "arbitrum", "chainId": 42161,
        "makerHelper": "0x1EE3fAc93F08F84107ce21FF5380314B5473Bf5c",
        "startBlock": 452_661_450,
        "rpcs": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.drpc.org"],
    },
    {
        "name": "bnb", "chainId": 56,
        "makerHelper": "0x066B5861d15261009a3bb48305770600E49745aB",
        "startBlock": 92_629_573,
        "rpcs": ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.binance.org", "https://bsc.drpc.org"],
        "poa": True,
    },
    {
        "name": "base", "chainId": 8453,
        "makerHelper": "0x2c5d576681d625ea9b6E9EE5d6A9159147328292",
        "startBlock": 44_722_441,
        "rpcs": ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"],
    },
    {
        "name": "b2", "chainId": 223,
        "makerHelper": "0x2c5d576681d625ea9b6E9EE5d6A9159147328292",
        "startBlock": 31_535_305,
        "rpcs": ["https://rpc.bsquared.network", "https://mainnet.b2-rpc.com", "https://b2-mainnet.alt.technology"],
    },
    {
        "name": "berachain", "chainId": 80094,
        "makerHelper": "0xbb35188CD8Ba0A85ED8C8406187cA6443203423d",
        "startBlock": 19_609_794,
        "rpcs": ["https://rpc.berachain.com"],
    },
    {
        "name": "xlayer", "chainId": 196,
        "makerHelper": "0x830fBad7Cd1c3Cc5B693Dc64b985f2901B253C5B",
        "startBlock": 57_465_452,
        "rpcs": ["https://rpc.xlayer.tech", "https://xlayerrpc.okx.com"],
    },
    {
        "name": "hyperevm", "chainId": 999,
        "makerHelper": "0x4dF00b86ceB111dD727c14942b5Fdab8A695cCD3",
        "startBlock": 15_997_130,
        "rpcs": ["https://rpc.hyperliquid.xyz/evm"],
    },
    {
        "name": "pharos", "chainId": 1672,
        "makerHelper": "0x09d0C75EEeDD8970857698144cAa19b15f1F501A",
        "startBlock": 5_278_169,
        "rpcs": ["https://rpc.pharos.xyz"],
    },
]

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address"},{"type":"uint64"},{"type":"tuple","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
]
GT_ABI = [
    {"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[
        {"type":"address"},{"type":"uint128"},{"type":"bytes"}
    ]},
    {"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"isDelegate","stateMutability":"view","inputs":[{"type":"address"},{"type":"address"}],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]
ORDER_ABI = [
    {"type":"function","name":"virtualXtReserve","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"tokenReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]

ORDER_PLACED = {
    "anonymous": False, "type":"event", "name":"OrderPlaced",
    "inputs":[
        {"indexed":True,"name":"maker","type":"address"},
        {"indexed":True,"name":"market","type":"address"},
        {"indexed":False,"name":"order","type":"address"},
        {"indexed":False,"name":"gtId","type":"uint256"},
        {"indexed":False,"name":"debtTokenToDeposit","type":"uint256"},
        {"indexed":False,"name":"ftToDeposit","type":"uint256"},
        {"indexed":False,"name":"xtToDeposit","type":"uint256"},
    ],
}
ISSUE_FT = {
    "anonymous": False, "type":"event", "name":"IssueFt",
    "inputs":[
        {"indexed":True,"name":"caller","type":"address"},
        {"indexed":True,"name":"recipient","type":"address"},
        {"indexed":True,"name":"gtId","type":"uint256"},
        {"indexed":False,"name":"debtAmt","type":"uint128"},
        {"indexed":False,"name":"ftAmt","type":"uint128"},
        {"indexed":False,"name":"fee","type":"uint128"},
        {"indexed":False,"name":"collateralData","type":"bytes"},
    ],
}
DELEGATE_CHANGED = {
    "anonymous": False, "type":"event", "name":"DelegateChanged",
    "inputs":[
        {"indexed":True,"name":"delegator","type":"address"},
        {"indexed":True,"name":"delegatee","type":"address"},
        {"indexed":False,"name":"isDelegate","type":"bool"},
    ],
}


def default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, HexBytes)):
        return "0x" + bytes(value).hex()
    if hasattr(value, "items"):
        return dict(value)
    return str(value)


def safe(function) -> dict[str, Any]:
    try:
        result = function.call()
        return {"ok": True, "value": list(result) if isinstance(result, tuple) else result}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def value(result: dict[str, Any], fallback: Any = None) -> Any:
    return result.get("value", fallback) if result.get("ok") else fallback


def topic0(abi: dict[str, Any]) -> HexBytes:
    return Web3.keccak(text=f"{abi['name']}({','.join(item['type'] for item in abi['inputs'])})")


def connect(config: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in config["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 45}))
            if config.get("poa"):
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            latest = w3.eth.block_number
            block = w3.eth.get_block(latest)
            if chain_id != config["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({
                "url": url, "ok": True, "chainId": chain_id, "block": latest,
                "blockHash": block.hash.hex(),
            })
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def scan_logs(
    w3: Web3,
    address: str,
    start_block: int,
    end_block: int,
    event_topic: HexBytes,
) -> tuple[list[Any], list[dict[str, Any]]]:
    address = Web3.to_checksum_address(address)
    cursor = start_block
    chunk = 500_000
    minimum_chunk = 500
    maximum_chunk = 2_000_000
    logs: list[Any] = []
    diagnostics: list[dict[str, Any]] = []
    while cursor <= end_block:
        stop = min(cursor + chunk - 1, end_block)
        try:
            batch = w3.eth.get_logs({
                "address": address,
                "fromBlock": cursor,
                "toBlock": stop,
                "topics": [event_topic],
            })
            logs.extend(batch)
            diagnostics.append({"from": cursor, "to": stop, "ok": True, "count": len(batch), "chunk": chunk})
            cursor = stop + 1
            if len(batch) < 100 and chunk < maximum_chunk:
                chunk = min(maximum_chunk, chunk * 2)
        except Exception as exc:  # noqa: BLE001
            diagnostics.append({
                "from": cursor, "to": stop, "ok": False, "chunk": chunk,
                "error": f"{type(exc).__name__}: {exc}",
            })
            if chunk <= minimum_chunk:
                raise
            chunk = max(minimum_chunk, chunk // 2)
    return logs, diagnostics


def decode_receipt_event(w3: Web3, receipt: Any, abi: dict[str, Any]) -> list[dict[str, Any]]:
    signature = topic0(abi)
    output: list[dict[str, Any]] = []
    for raw in receipt.logs:
        if raw["topics"] and bytes(raw["topics"][0]) == bytes(signature):
            decoded = get_event_data(w3.codec, abi, raw)
            output.append({
                "address": Web3.to_checksum_address(raw["address"]),
                "logIndex": int(raw["logIndex"]),
                "args": dict(decoded["args"]),
            })
    return output


def decode_single_log(w3: Web3, raw: Any, abi: dict[str, Any]) -> dict[str, Any]:
    decoded = get_event_data(w3.codec, abi, raw)
    return {
        "address": Web3.to_checksum_address(raw["address"]),
        "blockNumber": int(raw["blockNumber"]),
        "transactionHash": raw["transactionHash"].hex(),
        "logIndex": int(raw["logIndex"]),
        "args": dict(decoded["args"]),
    }


def token_metadata(w3: Web3, address: str) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    token = w3.eth.contract(address=address, abi=ERC20_ABI)
    return {
        "address": address,
        "symbol": safe(token.functions.symbol()),
        "name": safe(token.functions.name()),
        "decimals": safe(token.functions.decimals()),
        "totalSupply": safe(token.functions.totalSupply()),
    }


def inspect_flow(
    w3: Web3,
    chain: str,
    latest_timestamp: int,
    order_event: dict[str, Any],
) -> dict[str, Any]:
    tx_hash = order_event["transactionHash"]
    receipt = w3.eth.get_transaction_receipt(tx_hash)
    issue_events = decode_receipt_event(w3, receipt, ISSUE_FT)
    delegate_events = decode_receipt_event(w3, receipt, DELEGATE_CHANGED)
    args = order_event["args"]
    maker = Web3.to_checksum_address(args["maker"])
    market_address = Web3.to_checksum_address(args["market"])
    order_address = Web3.to_checksum_address(args["order"])
    gt_id = int(args["gtId"])

    matching_issue = next(
        (
            event for event in issue_events
            if int(event["args"]["gtId"]) == gt_id
            and Web3.to_checksum_address(event["args"]["recipient"]) == maker
        ),
        None,
    )
    matching_delegate = next(
        (
            event for event in delegate_events
            if Web3.to_checksum_address(event["args"]["delegator"]) == maker
            and Web3.to_checksum_address(event["args"]["delegatee"]) == order_address
            and bool(event["args"]["isDelegate"])
        ),
        None,
    )
    result: dict[str, Any] = {
        "chain": chain,
        "txHash": tx_hash,
        "blockNumber": order_event["blockNumber"],
        "maker": maker,
        "market": market_address,
        "order": order_address,
        "gtId": gt_id,
        "debtTokenToDeposit": int(args["debtTokenToDeposit"]),
        "ftToDeposit": int(args["ftToDeposit"]),
        "xtToDeposit": int(args["xtToDeposit"]),
        "matchingIssueFt": matching_issue,
        "matchingDelegation": matching_delegate,
        "isDelegatedNewGtFlow": matching_issue is not None and matching_delegate is not None,
    }
    if not result["isDelegatedNewGtFlow"]:
        return result

    market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
    tokens_result = safe(market.functions.tokens())
    config_result = safe(market.functions.config())
    result["marketTokens"] = tokens_result
    result["marketConfig"] = config_result
    tokens = value(tokens_result)
    config = value(config_result)
    if not tokens or len(tokens) != 5 or not config:
        return result

    ft, xt, gt, collateral, debt = [Web3.to_checksum_address(item) for item in tokens]
    maturity = int(config[1])
    gt_contract = w3.eth.contract(address=gt, abi=GT_ABI)
    order_contract = w3.eth.contract(address=order_address, abi=ORDER_ABI)
    collateral_meta = token_metadata(w3, collateral)
    debt_meta = token_metadata(w3, debt)
    collateral_decimals = int(value(collateral_meta["decimals"], 18))
    original_data = bytes(matching_issue["args"]["collateralData"])
    original_amount = int.from_bytes(original_data, "big") if len(original_data) == 32 else None
    original_value = safe(gt_contract.functions.getCollateralValue(original_data))
    loan = safe(gt_contract.functions.loanInfo(gt_id))
    current_collateral_data = None
    current_value: dict[str, Any] = {"ok": False, "error": "current loan unavailable"}
    current_collateral_amount = None
    if loan.get("ok") and len(loan["value"]) == 3:
        current_collateral_data = bytes(loan["value"][2])
        current_value = safe(gt_contract.functions.getCollateralValue(current_collateral_data))
        if len(current_collateral_data) == 32:
            current_collateral_amount = int.from_bytes(current_collateral_data, "big")

    result.update({
        "addresses": {"ft": ft, "xt": xt, "gt": gt, "collateral": collateral, "debtToken": debt},
        "tokenMetadata": {"collateral": collateral_meta, "debtToken": debt_meta},
        "maturity": maturity,
        "maturityUtc": datetime.fromtimestamp(maturity, tz=timezone.utc).isoformat(),
        "activeBeforeMaturity": latest_timestamp < maturity,
        "marketPaused": safe(market.functions.paused()),
        "delegationStillSet": safe(gt_contract.functions.isDelegate(maker, order_address)),
        "currentLoanInfo": loan,
        "currentLoanExists": bool(loan.get("ok")),
        "originalCollateralData": original_data,
        "originalCollateralRaw": original_amount,
        "originalCollateralHuman": original_amount / (10 ** collateral_decimals) if original_amount is not None else None,
        "originalCollateralValueUsdCurrentOracle": int(value(original_value, 0)) / 1e8 if original_value.get("ok") else None,
        "currentCollateralData": current_collateral_data,
        "currentCollateralRaw": current_collateral_amount,
        "currentCollateralHuman": current_collateral_amount / (10 ** collateral_decimals) if current_collateral_amount is not None else None,
        "currentCollateralValueUsd": int(value(current_value, 0)) / 1e8 if current_value.get("ok") else None,
        "gtTotalSupply": safe(gt_contract.functions.totalSupply()),
        "gtCollateralTokenBalance": safe(w3.eth.contract(address=collateral, abi=ERC20_ABI).functions.balanceOf(gt)),
        "ftTotalSupply": token_metadata(w3, ft)["totalSupply"],
        "orderVirtualXtReserve": safe(order_contract.functions.virtualXtReserve()),
        "orderReserves": safe(order_contract.functions.tokenReserves()),
    })
    result["currentlyActiveAndDelegated"] = (
        result["activeBeforeMaturity"]
        and bool(value(result["delegationStillSet"], False))
        and result["currentLoanExists"]
    )
    return result


def scan_chain(config: dict[str, Any]) -> dict[str, Any]:
    w3, rpc, attempts = connect(config)
    latest_number = w3.eth.block_number
    latest_block = w3.eth.get_block(latest_number)
    raw_logs, diagnostics = scan_logs(
        w3,
        config["makerHelper"],
        int(config["startBlock"]),
        latest_number,
        topic0(ORDER_PLACED),
    )
    decoded_logs = [decode_single_log(w3, raw, ORDER_PLACED) for raw in raw_logs]
    flows: list[dict[str, Any]] = []
    for index, event in enumerate(decoded_logs, start=1):
        try:
            flows.append(inspect_flow(w3, config["name"], int(latest_block.timestamp), event))
        except Exception as exc:  # noqa: BLE001
            flows.append({
                "chain": config["name"],
                "txHash": event["transactionHash"],
                "blockNumber": event["blockNumber"],
                "fatalError": f"{type(exc).__name__}: {exc}",
            })
        print(f"{config['name']} [{index}/{len(decoded_logs)}] {event['transactionHash']}", flush=True)
        time.sleep(0.05)
    delegated = [flow for flow in flows if flow.get("isDelegatedNewGtFlow")]
    active = [flow for flow in delegated if flow.get("currentlyActiveAndDelegated")]
    return {
        "chain": config["name"],
        "chainId": config["chainId"],
        "makerHelper": Web3.to_checksum_address(config["makerHelper"]),
        "startBlock": config["startBlock"],
        "rpc": rpc,
        "rpcAttempts": attempts,
        "latestBlock": {
            "number": latest_number,
            "hash": latest_block.hash.hex(),
            "timestamp": int(latest_block.timestamp),
            "timestampUtc": datetime.fromtimestamp(latest_block.timestamp, tz=timezone.utc).isoformat(),
        },
        "scanDiagnostics": diagnostics,
        "orderPlacedCount": len(decoded_logs),
        "delegatedNewGtCount": len(delegated),
        "currentlyActiveDelegatedCount": len(active),
        "flows": flows,
    }


def main() -> int:
    chain_results: list[dict[str, Any]] = []
    for config in CHAINS:
        try:
            chain_results.append(scan_chain(config))
        except Exception as exc:  # noqa: BLE001
            chain_results.append({
                "chain": config["name"],
                "chainId": config["chainId"],
                "makerHelper": config["makerHelper"],
                "fatalError": f"{type(exc).__name__}: {exc}",
            })

    active_ranking = sorted(
        [
            {
                "chain": flow.get("chain"),
                "txHash": flow.get("txHash"),
                "maker": flow.get("maker"),
                "market": flow.get("market"),
                "order": flow.get("order"),
                "gtId": flow.get("gtId"),
                "collateralSymbol": value(flow.get("tokenMetadata", {}).get("collateral", {}).get("symbol", {})),
                "debtSymbol": value(flow.get("tokenMetadata", {}).get("debtToken", {}).get("symbol", {})),
                "currentCollateralHuman": flow.get("currentCollateralHuman"),
                "currentCollateralValueUsd": flow.get("currentCollateralValueUsd"),
                "maturityUtc": flow.get("maturityUtc"),
                "delegationStillSet": value(flow.get("delegationStillSet", {})),
                "orderVirtualXtReserve": value(flow.get("orderVirtualXtReserve", {})),
                "orderReserves": value(flow.get("orderReserves", {})),
            }
            for chain in chain_results
            for flow in chain.get("flows", [])
            if flow.get("currentlyActiveAndDelegated")
        ],
        key=lambda item: float(item.get("currentCollateralValueUsd") or 0),
        reverse=True,
    )
    historical_ranking = sorted(
        [
            {
                "chain": flow.get("chain"),
                "txHash": flow.get("txHash"),
                "market": flow.get("market"),
                "order": flow.get("order"),
                "gtId": flow.get("gtId"),
                "originalCollateralValueUsdCurrentOracle": flow.get("originalCollateralValueUsdCurrentOracle"),
                "maturityUtc": flow.get("maturityUtc"),
                "currentlyActiveAndDelegated": flow.get("currentlyActiveAndDelegated"),
            }
            for chain in chain_results
            for flow in chain.get("flows", [])
            if flow.get("isDelegatedNewGtFlow")
        ],
        key=lambda item: float(item.get("originalCollateralValueUsdCurrentOracle") or 0),
        reverse=True,
    )
    result = {
        "schema": "termmax-crosschain-delegated-newgt-inventory/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "activeRanking": active_ranking,
        "historicalRanking": historical_ranking,
        "chains": chain_results,
    }
    compact = {
        "generatedAtUtc": result["generatedAtUtc"],
        "activeRanking": active_ranking,
        "historicalRankingTop20": historical_ranking[:20],
        "chainSummary": [
            {
                "chain": chain.get("chain"),
                "chainId": chain.get("chainId"),
                "orderPlacedCount": chain.get("orderPlacedCount"),
                "delegatedNewGtCount": chain.get("delegatedNewGtCount"),
                "currentlyActiveDelegatedCount": chain.get("currentlyActiveDelegatedCount"),
                "fatalError": chain.get("fatalError"),
            }
            for chain in chain_results
        ],
    }
    (OUT / "CROSSCHAIN_DELEGATED_NEWGT_FULL.json").write_text(json.dumps(result, indent=2, default=default), encoding="utf-8")
    (OUT / "CROSSCHAIN_DELEGATED_NEWGT_COMPACT.json").write_text(json.dumps(compact, indent=2, default=default), encoding="utf-8")
    print(json.dumps(compact, indent=2, default=default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
