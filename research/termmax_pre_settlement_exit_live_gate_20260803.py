#!/usr/bin/env python3
"""Read-only current-state gate for a matured TermMax vault order before settlement.

The script performs only Ethereum JSON-RPC reads and eth_call simulations. It
checks whether a real vault-share holder can redeem at the current reported NAV
while a matured order has a deterministic economic loss that has not yet been
written to the vault's bad-debt state. No transaction is signed or broadcast.
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
ATTACK_RECEIVER = HOLDER
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
    {"type":"function","name":"maxRedeem","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"redeem","stateMutability":"nonpayable","inputs":[{"type":"uint256"},{"type":"address"},{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"badDebtMapping","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"redeemOrder","stateMutability":"nonpayable","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
]
ORDER_ABI = [
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
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
ORACLE_ABI = [
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ERC4626_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]


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


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 40}))
            if w3.eth.chain_id != 1:
                raise RuntimeError(f"unexpected chain id {w3.eth.chain_id}")
            block = w3.eth.get_block("latest")
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def main() -> int:
    out = Path(os.environ.get("OUT_DIR", "evidence"))
    out.mkdir(parents=True, exist_ok=True)
    w3, rpc, attempts = connect()
    block = w3.eth.get_block("latest")
    block_no = block.number
    timestamp = int(block.timestamp)

    vault = w3.eth.contract(address=VAULT, abi=VAULT_ABI)
    order = w3.eth.contract(address=ORDER, abi=ORDER_ABI)
    market_address = Web3.to_checksum_address(order.functions.market().call(block_identifier=block_no))
    market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
    tokens = market.functions.tokens().call(block_identifier=block_no)
    _ft, _xt, gt_address, collateral_address, debt_address = [Web3.to_checksum_address(x) for x in tokens]
    config = market.functions.config().call(block_identifier=block_no)
    market_maturity = int(config[1])

    asset = Web3.to_checksum_address(vault.functions.asset().call(block_identifier=block_no))
    curator = Web3.to_checksum_address(vault.functions.curator().call(block_identifier=block_no))
    pool_address = Web3.to_checksum_address(vault.functions.pool().call(block_identifier=block_no))
    total_assets = int(vault.functions.totalAssets().call(block_identifier=block_no))
    total_supply = int(vault.functions.totalSupply().call(block_identifier=block_no))
    holder_shares = int(vault.functions.balanceOf(HOLDER).call(block_identifier=block_no))
    max_redeem = int(vault.functions.maxRedeem(HOLDER).call(block_identifier=block_no))
    max_withdraw = int(vault.functions.maxWithdraw(HOLDER).call(block_identifier=block_no))
    redeem_shares = min(holder_shares, max_redeem)
    preview_assets = int(vault.functions.previewRedeem(redeem_shares).call(block_identifier=block_no))
    active_order_maturity = int(vault.functions.orderMaturity(ORDER).call(block_identifier=block_no))
    recognized_bad_debt = int(vault.functions.badDebtMapping(COLLATERAL).call(block_identifier=block_no))

    redeem_call = safe(
        vault.functions.redeem(redeem_shares, ATTACK_RECEIVER, HOLDER).call,
        {"from": HOLDER},
        block_identifier=block_no,
    )
    settlement_call = safe(
        vault.functions.redeemOrder(ORDER).call,
        {"from": curator},
        block_identifier=block_no,
    )

    gt = w3.eth.contract(address=gt_address, abi=GT_ABI)
    gt_config = gt.functions.getGtConfig().call(block_identifier=block_no)
    oracle_address = Web3.to_checksum_address(gt_config[5][0])
    oracle = w3.eth.contract(address=oracle_address, abi=ORACLE_ABI)
    price, price_decimals = [int(x) for x in oracle.functions.getPrice(debt_address).call(block_identifier=block_no)]
    debt_token = w3.eth.contract(address=debt_address, abi=ERC20_ABI)
    debt_decimals = int(debt_token.functions.decimals().call(block_identifier=block_no))

    bad_debt = 0
    delivery = 0
    bad_debt_value_1e8 = 0
    delivery_value_1e8 = 0
    economic_loss_1e8 = 0
    economic_loss_asset_raw = 0
    fair_assets = None
    estimated_shift_raw = None
    estimated_shift_1e8 = None
    if settlement_call.get("ok"):
        bad_debt, delivery = [int(x) for x in settlement_call["value"]]
        bad_debt_value_1e8 = bad_debt * price * 10**8 // (10**debt_decimals * 10**price_decimals)
        delivery_value_1e8 = int(
            gt.functions.getCollateralValue(w3.codec.encode(["uint256"], [delivery])).call(block_identifier=block_no)
        )
        economic_loss_1e8 = max(0, bad_debt_value_1e8 - delivery_value_1e8)
        if price > 0:
            economic_loss_asset_raw = (
                economic_loss_1e8 * 10**debt_decimals * 10**price_decimals // (price * 10**8)
            )
        if total_supply and total_assets > economic_loss_asset_raw:
            fair_assets = redeem_shares * (total_assets - economic_loss_asset_raw) // total_supply
            stale_assets = int(redeem_call.get("value", preview_assets)) if redeem_call.get("ok") else preview_assets
            estimated_shift_raw = max(0, stale_assets - fair_assets)
            estimated_shift_1e8 = estimated_shift_raw * price * 10**8 // (10**debt_decimals * 10**price_decimals)

    pool_row: dict[str, Any] = {"address": pool_address, "codeBytes": len(w3.eth.get_code(pool_address, block_identifier=block_no))}
    if pool_address != Web3.to_checksum_address("0x0000000000000000000000000000000000000000"):
        pool = w3.eth.contract(address=pool_address, abi=ERC4626_ABI)
        pool_shares = safe(pool.functions.balanceOf(VAULT).call, block_identifier=block_no)
        pool_row.update({
            "asset": safe(pool.functions.asset().call, block_identifier=block_no),
            "vaultPoolShares": pool_shares,
            "vaultPoolAssets": (
                safe(pool.functions.convertToAssets(int(pool_shares["value"])).call, block_identifier=block_no)
                if pool_shares.get("ok") else {"ok": False, "error": "pool shares unavailable"}
            ),
            "vaultPoolMaxWithdraw": safe(pool.functions.maxWithdraw(VAULT).call, block_identifier=block_no),
        })

    result = {
        "schema": "termmax-pre-settlement-first-exit-live-gate/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {"number": block_no, "hash": block.hash.hex(), "timestamp": timestamp, "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()},
        "vault": VAULT,
        "order": ORDER,
        "market": market_address,
        "marketMaturity": market_maturity,
        "vaultOrderMaturity": active_order_maturity,
        "vaultPaused": safe(vault.functions.paused().call, block_identifier=block_no),
        "asset": asset,
        "debtToken": debt_address,
        "collateral": collateral_address,
        "gt": gt_address,
        "oracle": oracle_address,
        "curator": curator,
        "holder": HOLDER,
        "holderCodeBytes": len(w3.eth.get_code(HOLDER, block_identifier=block_no)),
        "totalAssets": total_assets,
        "totalSupply": total_supply,
        "holderShares": holder_shares,
        "maxRedeem": max_redeem,
        "maxWithdraw": max_withdraw,
        "redeemShares": redeem_shares,
        "previewRedeemAssets": preview_assets,
        "normalRedeemEthCall": redeem_call,
        "recognizedBadDebtBeforeSettlement": recognized_bad_debt,
        "settlementEthCall": settlement_call,
        "badDebt": bad_debt,
        "deliveryCollateral": delivery,
        "badDebtValue1e8": bad_debt_value_1e8,
        "deliveryValue1e8": delivery_value_1e8,
        "economicLoss1e8": economic_loss_1e8,
        "economicLossAssetRaw": economic_loss_asset_raw,
        "fairLossAdjustedRedeemAssets": fair_assets,
        "estimatedFirstExitShiftRaw": estimated_shift_raw,
        "estimatedFirstExitShift1e8": estimated_shift_1e8,
        "pool": pool_row,
        "verdict": {
            "orderMatured": market_maturity <= timestamp,
            "orderStillTrackedByVault": active_order_maturity != 0,
            "badDebtNotYetRecognized": recognized_bad_debt == 0,
            "settlementDeterministicallyLossMaking": economic_loss_1e8 > 0,
            "holderIsEoa": len(w3.eth.get_code(HOLDER, block_identifier=block_no)) == 0,
            "holderCanRedeemAtCurrentNav": bool(redeem_call.get("ok")),
            "estimatedPrincipalShiftPositive": bool(estimated_shift_1e8 and estimated_shift_1e8 > 0),
        },
    }
    (out / "TERMMAX_PRE_SETTLEMENT_FIRST_EXIT_LIVE_GATE.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "PRE_SETTLEMENT_FIRST_EXIT_VERDICT.json").write_text(json.dumps(result["verdict"], indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
