#!/usr/bin/env python3
"""Read-only inventory of every observed TermMax MakerHelper delegated new-GT flow."""
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

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
RPC_URLS = [u for u in [os.environ.get("ETH_RPC_URL", "").strip(), "https://ethereum-rpc.publicnode.com", "https://rpc.mevblocker.io", "https://eth.drpc.org", "https://1rpc.io/eth"] if u]

FLOWS = [
    ("0xfabbb942f8ba5020ea381f4f6da8ebd949ae102ec7ec87590690c74dce642d53", "0x71ef8b44013C5e45B0043d794ab57FdB8e9ac06C", "0x8F4A1D6d6897Bb112C728568a522A70b7d83D40C", "0xfC3ea7c930DBbc0a4E594aA6d056B8fdFf026194"),
    ("0x0f50c0f165a72bc48412c6f08e6601c31d65686b5b1054f2f8c478692090ed08", "0x591F1C49DBcc5f48d90020475fF12BCD67512b06", "0xF9e4556aF43644AC2715259ef489Be06D305E7a6", "0x51e7dbDF1EA1bF711AAD67e428b2bB8E2a0dEb23"),
    ("0xfb26e0b121c1c51690728f39ea930468164b8664a076c97265f2a1cfaa19ac5c", "0xe7f1F9097142cd1710C8F2ac36aC0D4db63FD05E", "0xb81b7df4a5EdECC384e13203D37FbaeaAD1C01c3", "0xF82f8d46B175827Fb4f6bEbeFF846cE0c4d0A90e"),
    ("0x918a221abcd568674621ab3e09a428b00b977d298cdac52f8f5e3ed6d1a94695", "0x92Be6B4fF25485f62A06853CcCA0B908F136b53b", "0xAa72195C2e39853855192637C7E38a93914eaCDa", "0xFe6C23E4706A091eC3D2B66A7FB40e2a5e74e151"),
    ("0x8183bdf6f12f620e0bec6ed7f6f2161cebe0e1d13c886ef900549438ad4d16f2", "0x67d3dc578989e1ea202A6909d7299B41Acfb414a", "0x6e625a2218D1475A3B62304Bab8F0155ab56D2d0", "0x2A58A3D405c527491Daae4C62561B949e7F87EFE"),
    ("0xdd00ef6727fbf0be658916986094fbbbcb089aaddb83489dcab070d1a10624aa", "0x67d3dc578989e1ea202A6909d7299B41Acfb414a", "0x17B386aa08D4988d607D5a5503b8130662B0D982", "0x2A58A3D405c527491Daae4C62561B949e7F87EFE"),
    ("0x048be0adbe2b042308daf39f470814b29d887cebaaf16e09d17b45ade5200ff4", "0x0ECbB252647721115985451B793c986FcBa843e6", "0xC54A6AddDeCCD48A49757bfB357096c62cEb3c08", "0xb70D15a43937d4433dDF058C69D1402d35578556"),
    ("0x3ee2d77dc72af42c7bf71564b6093bf4ea5c8f8e4bdbd2598c924e0a57a7fe72", "0x1d6B083288Fb63B5F3A32FDb6157bE5FD32940E8", "0x8C2854aEe2fF77d1a6404c1E8E2eC503A2028b94", "0xF82f8d46B175827Fb4f6bEbeFF846cE0c4d0A90e"),
]

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}]}]}]},
]
GT_ABI = [
    {"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"address"},{"type":"uint128"},{"type":"bytes"}]},
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
ORDER_PLACED = {"anonymous":False,"type":"event","name":"OrderPlaced","inputs":[{"indexed":True,"name":"maker","type":"address"},{"indexed":True,"name":"market","type":"address"},{"indexed":False,"name":"order","type":"address"},{"indexed":False,"name":"gtId","type":"uint256"},{"indexed":False,"name":"debtTokenToDeposit","type":"uint256"},{"indexed":False,"name":"ftToDeposit","type":"uint256"},{"indexed":False,"name":"xtToDeposit","type":"uint256"}]}
ISSUE_FT = {"anonymous":False,"type":"event","name":"IssueFt","inputs":[{"indexed":True,"name":"caller","type":"address"},{"indexed":True,"name":"recipient","type":"address"},{"indexed":True,"name":"gtId","type":"uint256"},{"indexed":False,"name":"debtAmt","type":"uint128"},{"indexed":False,"name":"ftAmt","type":"uint128"},{"indexed":False,"name":"fee","type":"uint128"},{"indexed":False,"name":"collateralData","type":"bytes"}]}


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


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts = []
    for url in RPC_URLS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 40}))
            chain_id = w3.eth.chain_id
            block = w3.eth.block_number
            if chain_id != 1:
                raise RuntimeError(f"chainId={chain_id}")
            attempts.append({"url": url, "ok": True, "block": block})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def decode_events(w3: Web3, receipt: Any, abi: dict[str, Any]) -> list[dict[str, Any]]:
    signature = Web3.keccak(text=f"{abi['name']}({','.join(item['type'] for item in abi['inputs'])})")
    output = []
    for raw in receipt.logs:
        if raw["topics"] and bytes(raw["topics"][0]) == bytes(signature):
            decoded = get_event_data(w3.codec, abi, raw)
            output.append({"address": raw["address"], "args": dict(decoded["args"])})
    return output


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


def main() -> int:
    w3, rpc, attempts = connect()
    latest = w3.eth.get_block("latest")
    rows = []
    for tx_hash, expected_market, expected_order, delegator in FLOWS:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        placed = decode_events(w3, receipt, ORDER_PLACED)
        issued = decode_events(w3, receipt, ISSUE_FT)
        row: dict[str, Any] = {
            "txHash": tx_hash,
            "blockNumber": int(receipt.blockNumber),
            "status": int(receipt.status),
            "expectedMarket": expected_market,
            "expectedOrder": expected_order,
            "delegator": delegator,
            "OrderPlaced": placed,
            "IssueFt": issued,
        }
        if not placed or not issued:
            row["error"] = "required events missing"
            rows.append(row)
            continue
        order_address = Web3.to_checksum_address(placed[0]["args"]["order"])
        market_address = Web3.to_checksum_address(placed[0]["args"]["market"])
        gt_id = int(placed[0]["args"]["gtId"])
        collateral_data = bytes(issued[0]["args"]["collateralData"])
        market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
        ft, xt, gt, collateral, debt = [Web3.to_checksum_address(item) for item in market.functions.tokens().call()]
        gt_contract = w3.eth.contract(address=gt, abi=GT_ABI)
        order = w3.eth.contract(address=order_address, abi=ORDER_ABI)
        collateral_meta = token_metadata(w3, collateral)
        debt_meta = token_metadata(w3, debt)
        collateral_decimals = int(value(collateral_meta["decimals"], 18))
        original_amount = int.from_bytes(collateral_data, "big") if len(collateral_data) == 32 else None
        original_value = safe(gt_contract.functions.getCollateralValue(collateral_data))
        current_loan = safe(gt_contract.functions.loanInfo(gt_id))
        config = list(market.functions.config().call())
        maturity = int(config[1])
        row.update({
            "market": market_address,
            "order": order_address,
            "gt": gt,
            "gtId": gt_id,
            "ft": ft,
            "xt": xt,
            "collateral": collateral,
            "debtToken": debt,
            "collateralMetadata": collateral_meta,
            "debtMetadata": debt_meta,
            "originalCollateralData": collateral_data,
            "originalCollateralRaw": original_amount,
            "originalCollateralHuman": original_amount / (10 ** collateral_decimals) if original_amount is not None else None,
            "originalCollateralValueUsdCurrentOracle": int(value(original_value, 0)) / 1e8 if original_value.get("ok") else None,
            "marketMaturity": maturity,
            "marketMaturityUtc": datetime.fromtimestamp(maturity, tz=timezone.utc).isoformat(),
            "activeBeforeMaturity": int(latest.timestamp) < maturity,
            "delegationStillSet": safe(gt_contract.functions.isDelegate(Web3.to_checksum_address(delegator), order_address)),
            "gtTotalSupply": safe(gt_contract.functions.totalSupply()),
            "currentLoanInfo": current_loan,
            "ftTotalSupply": token_metadata(w3, ft)["totalSupply"],
            "currentGtCollateralBalance": safe(w3.eth.contract(address=collateral, abi=ERC20_ABI).functions.balanceOf(gt)),
            "orderVirtualXtReserve": safe(order.functions.virtualXtReserve()),
            "orderReserves": safe(order.functions.tokenReserves()),
            "assertions": {
                "marketMatches": market_address.lower() == expected_market.lower(),
                "orderMatches": order_address.lower() == expected_order.lower(),
                "makerMatchesDelegator": str(placed[0]["args"]["maker"]).lower() == delegator.lower(),
            },
        })
        rows.append(row)
        time.sleep(0.1)

    ranking = sorted(
        [
            {
                "txHash": row["txHash"],
                "market": row.get("market"),
                "order": row.get("order"),
                "gtId": row.get("gtId"),
                "collateralSymbol": value(row.get("collateralMetadata", {}).get("symbol", {})),
                "originalCollateralHuman": row.get("originalCollateralHuman"),
                "originalCollateralValueUsdCurrentOracle": row.get("originalCollateralValueUsdCurrentOracle"),
                "activeBeforeMaturity": row.get("activeBeforeMaturity"),
                "delegationStillSet": value(row.get("delegationStillSet", {})),
                "currentLoanExists": bool(row.get("currentLoanInfo", {}).get("ok")),
            }
            for row in rows
        ],
        key=lambda item: float(item.get("originalCollateralValueUsdCurrentOracle") or 0),
        reverse=True,
    )
    result = {
        "schema": "termmax-all-delegated-new-gt-flows/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "latestBlock": {
            "number": int(latest.number),
            "hash": latest.hash.hex(),
            "timestamp": int(latest.timestamp),
            "timestampUtc": datetime.fromtimestamp(latest.timestamp, tz=timezone.utc).isoformat(),
        },
        "flowCount": len(rows),
        "ranking": ranking,
        "flows": rows,
    }
    (OUT / "ALL_DELEGATED_FLOWS_FULL.json").write_text(json.dumps(result, indent=2, default=default), encoding="utf-8")
    (OUT / "ALL_DELEGATED_FLOWS_RANKING.json").write_text(json.dumps({"latestBlock": result["latestBlock"], "ranking": ranking}, indent=2), encoding="utf-8")
    print(json.dumps({"latestBlock": result["latestBlock"], "ranking": ranking}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
