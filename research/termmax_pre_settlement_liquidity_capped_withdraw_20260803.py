#!/usr/bin/env python3
"""Read-only current-state TermMax pre-settlement withdrawal gate.

Simulates a real EOA withdrawing the maximum currently liquid amount from a
matured loss-making vault before curator settlement. Ethereum reads and eth_call
only; no signer, broadcast, impersonation, or state mutation.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3

VAULT = Web3.to_checksum_address("0xF488ccdf04079cC03183cDB6A147d12Cf97F9317")
ORDER = Web3.to_checksum_address("0x93257038eCc1337D296eC61B2629704fe89acfa5")
HOLDER = Web3.to_checksum_address("0xB355F88FB60E3fca64dD94E0932144069f2671a9")
COLLATERAL = Web3.to_checksum_address("0x29fD7180E5cCEd14Ad148c7997e6B6857a8BE86e")
ZERO = Web3.to_checksum_address("0x0000000000000000000000000000000000000000")
RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://rpc.mevblocker.io",
]

VAULT_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"curator","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewWithdraw","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"withdraw","stateMutability":"nonpayable","inputs":[{"type":"uint256"},{"type":"address"},{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"badDebtMapping","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"redeemOrder","stateMutability":"nonpayable","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
]
ORDER_ABI = [{"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]
MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address","name":"treasurer"},{"type":"uint64","name":"maturity"},
        {"type":"tuple","name":"feeConfig","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
]
GT_ABI = [
    {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address","name":"collateral"},{"type":"address","name":"debtToken"},
        {"type":"address","name":"ft"},{"type":"address","name":"treasurer"},
        {"type":"uint64","name":"maturity"},{"type":"tuple","name":"loanConfig","components":[
            {"type":"address","name":"oracle"},{"type":"uint32","name":"liquidationLtv"},
            {"type":"uint32","name":"maxLtv"},{"type":"bool","name":"liquidatable"}
        ]}
    ]}]},
    {"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},
]
ORACLE_ABI = [{"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]}]
ERC20_ABI = [
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
POOL_ABI = [
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple): value = list(value)
        if isinstance(value, bytes): value = Web3.to_hex(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            if w3.eth.chain_id != 1: raise RuntimeError(f"unexpected chain id {w3.eth.chain_id}")
            block = w3.eth.get_block("latest")
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def main() -> int:
    out = Path(os.environ.get("OUT_DIR", "evidence")); out.mkdir(parents=True, exist_ok=True)
    w3, rpc, attempts = connect(); block = w3.eth.get_block("latest"); bn = block.number; ts = int(block.timestamp)
    vault = w3.eth.contract(address=VAULT, abi=VAULT_ABI)
    order = w3.eth.contract(address=ORDER, abi=ORDER_ABI)
    market_addr = Web3.to_checksum_address(order.functions.market().call(block_identifier=bn))
    market = w3.eth.contract(address=market_addr, abi=MARKET_ABI)
    ft_addr, xt_addr, gt_addr, collateral_addr, debt_addr = [Web3.to_checksum_address(x) for x in market.functions.tokens().call(block_identifier=bn)]
    maturity = int(market.functions.config().call(block_identifier=bn)[1])
    curator = Web3.to_checksum_address(vault.functions.curator().call(block_identifier=bn))
    pool_addr = Web3.to_checksum_address(vault.functions.pool().call(block_identifier=bn))
    total_assets = int(vault.functions.totalAssets().call(block_identifier=bn)); total_supply = int(vault.functions.totalSupply().call(block_identifier=bn))
    holder_shares = int(vault.functions.balanceOf(HOLDER).call(block_identifier=bn)); holder_max = int(vault.functions.maxWithdraw(HOLDER).call(block_identifier=bn))
    debt_token = w3.eth.contract(address=debt_addr, abi=ERC20_ABI); debt_decimals = int(debt_token.functions.decimals().call(block_identifier=bn))
    vault_cash = int(debt_token.functions.balanceOf(VAULT).call(block_identifier=bn))
    pool_max = 0; pool_shares = 0; pool_assets = 0
    if pool_addr != ZERO:
        pool = w3.eth.contract(address=pool_addr, abi=POOL_ABI)
        pool_max = int(pool.functions.maxWithdraw(VAULT).call(block_identifier=bn))
        pool_shares = int(pool.functions.balanceOf(VAULT).call(block_identifier=bn))
        pool_assets = int(pool.functions.convertToAssets(pool_shares).call(block_identifier=bn))
    liquid_cap = vault_cash + pool_max
    withdraw_assets = min(holder_max, liquid_cap)
    if withdraw_assets > 0: withdraw_assets -= 1  # avoid edge rounding at the exact pool maximum
    burn_shares = int(vault.functions.previewWithdraw(withdraw_assets).call(block_identifier=bn)) if withdraw_assets else 0
    withdraw_call = safe(vault.functions.withdraw(withdraw_assets, HOLDER, HOLDER).call, {"from": HOLDER}, block_identifier=bn) if withdraw_assets else {"ok": False, "error": "zero liquid capacity"}
    settlement_call = safe(vault.functions.redeemOrder(ORDER).call, {"from": curator}, block_identifier=bn)
    gt = w3.eth.contract(address=gt_addr, abi=GT_ABI); gt_cfg = gt.functions.getGtConfig().call(block_identifier=bn)
    oracle_addr = Web3.to_checksum_address(gt_cfg[5][0]); oracle = w3.eth.contract(address=oracle_addr, abi=ORACLE_ABI)
    price, price_decimals = [int(x) for x in oracle.functions.getPrice(debt_addr).call(block_identifier=bn)]
    bad_debt = delivery = bad_value = delivery_value = loss_1e8 = loss_raw = fair_value = shift_raw = shift_1e8 = 0
    if settlement_call.get("ok"):
        bad_debt, delivery = [int(x) for x in settlement_call["value"]]
        bad_value = bad_debt * price * 10**8 // (10**debt_decimals * 10**price_decimals)
        delivery_value = int(gt.functions.getCollateralValue(w3.codec.encode(["uint256"], [delivery])).call(block_identifier=bn))
        loss_1e8 = max(0, bad_value - delivery_value)
        loss_raw = loss_1e8 * 10**debt_decimals * 10**price_decimals // (price * 10**8) if price else 0
        if total_supply and total_assets > loss_raw:
            fair_value = burn_shares * (total_assets - loss_raw) // total_supply
            shift_raw = max(0, withdraw_assets - fair_value)
            shift_1e8 = shift_raw * price * 10**8 // (10**debt_decimals * 10**price_decimals)
    result = {
        "schema": "termmax-pre-settlement-liquidity-capped-withdraw/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc, "rpcAttempts": attempts,
        "block": {"number": bn, "hash": block.hash.hex(), "timestamp": ts, "timestampUtc": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()},
        "vault": VAULT, "order": ORDER, "market": market_addr, "maturity": maturity,
        "orderStillTracked": int(vault.functions.orderMaturity(ORDER).call(block_identifier=bn)) != 0,
        "recognizedBadDebtBeforeSettlement": int(vault.functions.badDebtMapping(COLLATERAL).call(block_identifier=bn)),
        "holder": HOLDER, "holderCodeBytes": len(w3.eth.get_code(HOLDER, block_identifier=bn)),
        "totalAssets": total_assets, "totalSupply": total_supply, "holderShares": holder_shares, "holderMaxWithdraw": holder_max,
        "vaultCash": vault_cash, "pool": pool_addr, "poolShares": pool_shares, "poolAssets": pool_assets, "poolMaxWithdraw": pool_max,
        "liquidCapacity": liquid_cap, "withdrawAssets": withdraw_assets, "burnShares": burn_shares,
        "normalWithdrawEthCall": withdraw_call, "settlementEthCall": settlement_call,
        "badDebt": bad_debt, "deliveryCollateral": delivery, "badDebtValue1e8": bad_value, "deliveryValue1e8": delivery_value,
        "economicLoss1e8": loss_1e8, "economicLossAssetRaw": loss_raw,
        "fairLossAdjustedValueRaw": fair_value, "estimatedPrincipalShiftRaw": shift_raw, "estimatedPrincipalShift1e8": shift_1e8,
        "verdict": {
            "orderMatured": maturity <= ts,
            "badDebtNotYetRecognized": int(vault.functions.badDebtMapping(COLLATERAL).call(block_identifier=bn)) == 0,
            "settlementDeterministicallyLossMaking": loss_1e8 > 0,
            "holderCanWithdrawCurrentLiquidCapacity": bool(withdraw_call.get("ok")),
            "estimatedPrincipalShiftPositive": shift_1e8 > 0,
        },
    }
    (out / "TERMMAX_PRE_SETTLEMENT_LIQUIDITY_CAPPED_WITHDRAW.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "LIQUIDITY_CAPPED_WITHDRAW_VERDICT.json").write_text(json.dumps(result["verdict"], indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2)); return 0


if __name__ == "__main__": raise SystemExit(main())
