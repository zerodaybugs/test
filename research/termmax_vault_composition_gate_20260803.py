#!/usr/bin/env python3
"""Read-only current-state census for a public TermMax multi-market vault.

The script performs only Ethereum JSON-RPC reads and eth_call simulations. It
uses no signer, private key, transaction construction, broadcast, impersonation,
or state mutation.
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

VAULT = Web3.to_checksum_address("0xF488ccdf04079cC03183cDB6A147d12Cf97F9317")
CURATOR = Web3.to_checksum_address("0x008c7DC790fA31E6CA19D8Cb6d11C53f6A88DF6c")
USDC = Web3.to_checksum_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
COLLATERAL = Web3.to_checksum_address("0x29fD7180E5cCEd14Ad148c7997e6B6857a8BE86e")
GT = Web3.to_checksum_address("0xbEabD241853B217660788694125e1809465d6393")
ORACLE = Web3.to_checksum_address("0xE3a31690392E8E18DC3d862651C079339E2c1ADE")

ORDERS = [
    Web3.to_checksum_address("0x667DDd85358E8765814f07efd1C4A9caD67521d7"),
    Web3.to_checksum_address("0x93257038eCc1337D296eC61B2629704fe89acfa5"),
    Web3.to_checksum_address("0xe7059DdD2Dc6f7D54088628655D8C3A096804448"),
    Web3.to_checksum_address("0x66197a8bb9621a6DA48E9c28FD6f23341901af8d"),
    Web3.to_checksum_address("0xD8409CAa2497dFeE072722A8155503F744514ca7"),
]

RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
]

TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)").hex()
ZERO = "0x0000000000000000000000000000000000000000"

VAULT_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"curator","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxDeposit","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"badDebtMapping","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"redeemOrder","stateMutability":"nonpayable","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
]
ORDER_ABI = [
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"tokenReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
    {"type":"function","name":"orderExpiryTimestamp","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]
MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"name":"treasurer","type":"address"},{"name":"maturity","type":"uint64"},{"name":"feeConfig","type":"tuple","components":[{"name":"lendTakerFeeRatio","type":"uint64"},{"name":"lendMakerFeeRatio","type":"uint64"},{"name":"borrowTakerFeeRatio","type":"uint64"},{"name":"borrowMakerFeeRatio","type":"uint64"},{"name":"mintGtFeeRatio","type":"uint64"},{"name":"mintGtFeeRef","type":"uint64"}]}]}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]
GT_ABI = [
    {"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},
]
ORACLE_ABI = [
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            chain_id = w3.eth.chain_id
            latest = w3.eth.get_block("latest")
            if chain_id != 1:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": latest.number})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        if isinstance(value, bytes):
            value = Web3.to_hex(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def find_deployment_block(w3: Web3, latest: int) -> int:
    lo, hi = 0, latest
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            has_code = len(w3.eth.get_code(VAULT, block_identifier=mid)) > 0
        except Exception:
            # Conservatively move forward when an endpoint cannot serve very old state.
            lo = mid + 1
            continue
        if has_code:
            hi = mid
        else:
            lo = mid + 1
    return lo


def get_transfer_logs(w3: Web3, start: int, end: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    logs: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    cursor = start
    chunk = 50_000
    while cursor <= end:
        upper = min(end, cursor + chunk - 1)
        try:
            batch = w3.eth.get_logs({"address": VAULT, "fromBlock": cursor, "toBlock": upper, "topics": [TRANSFER_TOPIC]})
            logs.extend(batch)
            diagnostics.append({"from": cursor, "to": upper, "ok": True, "count": len(batch)})
            cursor = upper + 1
            if chunk < 100_000:
                chunk = min(100_000, chunk * 2)
        except Exception as exc:  # noqa: BLE001
            diagnostics.append({"from": cursor, "to": upper, "ok": False, "chunk": chunk, "error": f"{type(exc).__name__}: {exc}"})
            if chunk <= 2_000:
                raise
            chunk = max(2_000, chunk // 4)
            time.sleep(0.2)
    return logs, diagnostics


def topic_address(topic: Any) -> str:
    raw = topic.hex() if hasattr(topic, "hex") else str(topic)
    raw = raw[2:] if raw.startswith("0x") else raw
    return Web3.to_checksum_address("0x" + raw[-40:])


def main() -> int:
    out = Path(os.environ.get("OUT_DIR", "evidence"))
    out.mkdir(parents=True, exist_ok=True)
    w3, rpc, attempts = connect()
    block = w3.eth.get_block("latest")
    block_no = block.number
    vault = w3.eth.contract(address=VAULT, abi=VAULT_ABI)
    usdc = w3.eth.contract(address=USDC, abi=ERC20_ABI)
    gt = w3.eth.contract(address=GT, abi=GT_ABI)
    oracle = w3.eth.contract(address=ORACLE, abi=ORACLE_ABI)

    total_assets = safe(vault.functions.totalAssets().call, block_identifier=block_no)
    total_supply = safe(vault.functions.totalSupply().call, block_identifier=block_no)
    max_deposit = safe(vault.functions.maxDeposit(ZERO).call, block_identifier=block_no)
    debt_price = safe(oracle.functions.getPrice(USDC).call, block_identifier=block_no)

    order_rows: list[dict[str, Any]] = []
    for address in ORDERS:
        order = w3.eth.contract(address=address, abi=ORDER_ABI)
        market_r = safe(order.functions.market().call, block_identifier=block_no)
        market_addr = Web3.to_checksum_address(market_r["value"]) if market_r.get("ok") else None
        market = w3.eth.contract(address=market_addr, abi=MARKET_ABI) if market_addr else None
        tokens_r = safe(market.functions.tokens().call, block_identifier=block_no) if market else {"ok": False, "error": "market unavailable"}
        ft_addr = Web3.to_checksum_address(tokens_r["value"][0]) if tokens_r.get("ok") else None
        collateral_addr = Web3.to_checksum_address(tokens_r["value"][3]) if tokens_r.get("ok") else None
        debt_addr = Web3.to_checksum_address(tokens_r["value"][4]) if tokens_r.get("ok") else None
        ft = w3.eth.contract(address=ft_addr, abi=ERC20_ABI) if ft_addr else None
        ft_balance = safe(ft.functions.balanceOf(address).call, block_identifier=block_no) if ft else {"ok": False, "error": "FT unavailable"}
        redeem = safe(vault.functions.redeemOrder(address).call, {"from": CURATOR}, block_identifier=block_no)

        bad_debt_value = None
        delivery_value = None
        economic_loss = None
        if redeem.get("ok") and debt_price.get("ok") and debt_addr and collateral_addr and collateral_addr.lower() == COLLATERAL.lower():
            bad_debt, delivery = redeem["value"]
            price, price_decimals = debt_price["value"]
            debt_decimals = safe(w3.eth.contract(address=debt_addr, abi=ERC20_ABI).functions.decimals().call, block_identifier=block_no)
            if debt_decimals.get("ok"):
                bad_debt_value = bad_debt * price * 10**8 // (10**debt_decimals["value"] * 10**price_decimals)
                delivery_value_r = safe(gt.functions.getCollateralValue(Web3.to_bytes(hexstr=Web3.to_hex(delivery.to_bytes(32, "big")))).call, block_identifier=block_no)
                if delivery_value_r.get("ok"):
                    delivery_value = delivery_value_r["value"]
                    economic_loss = max(0, bad_debt_value - delivery_value)

        order_rows.append({
            "order": address,
            "codeBytes": len(w3.eth.get_code(address, block_identifier=block_no)),
            "vaultOrderMaturity": safe(vault.functions.orderMaturity(address).call, block_identifier=block_no),
            "orderExpiry": safe(order.functions.orderExpiryTimestamp().call, block_identifier=block_no),
            "market": market_r,
            "marketConfig": safe(market.functions.config().call, block_identifier=block_no) if market else {"ok": False},
            "tokens": tokens_r,
            "ft": ft_addr,
            "ftSymbol": safe(ft.functions.symbol().call, block_identifier=block_no) if ft else {"ok": False},
            "ftBalanceAtOrder": ft_balance,
            "tokenReserves": safe(order.functions.tokenReserves().call, block_identifier=block_no),
            "redeemOrderEthCall": redeem,
            "simulatedBadDebtValue1e8": bad_debt_value,
            "simulatedDeliveryValue1e8": delivery_value,
            "simulatedEconomicLoss1e8": economic_loss,
        })

    deployment_block = find_deployment_block(w3, block_no)
    logs, log_diag = get_transfer_logs(w3, deployment_block, block_no)
    addresses: set[str] = set()
    for log in logs:
        if len(log["topics"]) >= 3:
            from_addr = topic_address(log["topics"][1])
            to_addr = topic_address(log["topics"][2])
            if from_addr != ZERO:
                addresses.add(from_addr)
            if to_addr != ZERO:
                addresses.add(to_addr)

    holder_rows: list[dict[str, Any]] = []
    for addr in sorted(addresses):
        bal_r = safe(vault.functions.balanceOf(addr).call, block_identifier=block_no)
        if not bal_r.get("ok") or bal_r["value"] == 0:
            continue
        holder_rows.append({"address": addr, "shares": bal_r["value"]})
    holder_rows.sort(key=lambda row: row["shares"], reverse=True)

    for row in holder_rows[:75]:
        addr = row["address"]
        row["codeBytes"] = len(w3.eth.get_code(addr, block_identifier=block_no))
        row["maxWithdraw"] = safe(vault.functions.maxWithdraw(addr).call, block_identifier=block_no)
        if total_supply.get("ok") and total_supply["value"]:
            row["shareBps1e8"] = row["shares"] * 10**8 // total_supply["value"]

    result = {
        "schema": "termmax-vault-composition-gate/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {"number": block_no, "hash": block.hash.hex(), "timestamp": block.timestamp, "timestampUtc": datetime.fromtimestamp(block.timestamp, tz=timezone.utc).isoformat()},
        "vault": {
            "address": VAULT,
            "name": safe(vault.functions.name().call, block_identifier=block_no),
            "symbol": safe(vault.functions.symbol().call, block_identifier=block_no),
            "asset": safe(vault.functions.asset().call, block_identifier=block_no),
            "paused": safe(vault.functions.paused().call, block_identifier=block_no),
            "curator": safe(vault.functions.curator().call, block_identifier=block_no),
            "totalAssets": total_assets,
            "totalSupply": total_supply,
            "maxDeposit": max_deposit,
            "assetBalance": safe(usdc.functions.balanceOf(VAULT).call, block_identifier=block_no),
            "collateralBadDebt": safe(vault.functions.badDebtMapping(COLLATERAL).call, block_identifier=block_no),
            "deploymentBlock": deployment_block,
        },
        "orders": order_rows,
        "holderDiscovery": {"transferLogCount": len(logs), "candidateAddressCount": len(addresses), "currentHolderCount": len(holder_rows), "diagnostics": log_diag},
        "topHolders": holder_rows[:75],
        "verdict": {
            "activeTrackedOrderCount": sum(1 for row in order_rows if row["vaultOrderMaturity"].get("ok") and row["vaultOrderMaturity"]["value"] != 0),
            "positiveFtOrderCount": sum(1 for row in order_rows if row["ftBalanceAtOrder"].get("ok") and row["ftBalanceAtOrder"]["value"] > 0),
            "positiveEconomicLossSimulationCount": sum(1 for row in order_rows if (row["simulatedEconomicLoss1e8"] or 0) > 0),
            "maxSimulatedEconomicLoss1e8": max([row["simulatedEconomicLoss1e8"] or 0 for row in order_rows] or [0]),
            "largestEoaHolderShares": max([row["shares"] for row in holder_rows[:75] if row.get("codeBytes") == 0] or [0]),
        },
    }
    (out / "TERMMAX_VAULT_COMPOSITION.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "VERDICT.json").write_text(json.dumps(result["verdict"], indent=2), encoding="utf-8")
    print(json.dumps(result["verdict"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
