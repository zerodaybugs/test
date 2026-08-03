#!/usr/bin/env python3
"""Read-only global TermMax multi-Order vault cherry-pick census.

Uses a pinned public vault/order inventory only for address discovery, then binds
all conclusions to fresh Ethereum RPC state. For each still-active Order it
simulates curator settlement with eth_call, values bad debt and delivered
collateral through the Order's live GT/oracle configuration, and identifies
vaults that simultaneously hold near-lossless FT claims and loss-making FT
claims. It constructs, signs, and broadcasts no transaction.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
INVENTORY_URL = (
    "https://raw.githubusercontent.com/zerodaybugs/test/"
    "dff02533050ac6c929e42ebad95196d1fa991c43/"
    "public-results/termmax-vault-asset-debt/ethereum/VAULT_ASSET_DEBT_FULL.json"
)
RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://rpc.mevblocker.io",
]
ZERO = "0x0000000000000000000000000000000000000000"
DUST_LOSS_1E8 = 100  # one millionth of a dollar

VAULT_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"curator","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxDeposit","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewWithdraw","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
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
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
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


def fetch_inventory() -> dict[str, Any]:
    response = requests.get(INVENTORY_URL, timeout=60, headers={"User-Agent":"ZeroDayBugs-TermMax-Readonly/6"})
    response.raise_for_status()
    return response.json()


def main() -> int:
    inventory = fetch_inventory()
    w3, rpc, rpc_attempts = connect()
    block = w3.eth.get_block("latest")
    block_no = block.number
    timestamp = int(block.timestamp)
    vault_rows: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    for source_vault in inventory.get("vaults", []):
        vault_address = Web3.to_checksum_address(source_vault["vault"])
        if len(w3.eth.get_code(vault_address, block_identifier=block_no)) == 0:
            continue
        vault = w3.eth.contract(address=vault_address, abi=VAULT_ABI)
        total_assets_r = safe(vault.functions.totalAssets().call, block_identifier=block_no)
        total_supply_r = safe(vault.functions.totalSupply().call, block_identifier=block_no)
        total_assets = int(total_assets_r.get("value", 0) or 0)
        total_supply = int(total_supply_r.get("value", 0) or 0)
        if total_supply == 0 or total_assets == 0:
            continue
        asset_r = safe(vault.functions.asset().call, block_identifier=block_no)
        curator_r = safe(vault.functions.curator().call, block_identifier=block_no)
        if not asset_r.get("ok") or not curator_r.get("ok"):
            continue
        asset = Web3.to_checksum_address(asset_r["value"])
        curator = Web3.to_checksum_address(curator_r["value"])
        asset_token = w3.eth.contract(address=asset, abi=ERC20_ABI)
        asset_decimals = int(asset_token.functions.decimals().call(block_identifier=block_no))
        order_rows: list[dict[str, Any]] = []
        safe_ft_raw = 0
        total_loss_1e8 = 0
        asset_price: int | None = None
        asset_price_decimals: int | None = None

        for source_order in source_vault.get("orders", []):
            order_address = Web3.to_checksum_address(source_order["order"])
            if len(w3.eth.get_code(order_address, block_identifier=block_no)) == 0:
                continue
            active_maturity_r = safe(vault.functions.orderMaturity(order_address).call, block_identifier=block_no)
            active_maturity = int(active_maturity_r.get("value", 0) or 0)
            if active_maturity == 0:
                continue
            order = w3.eth.contract(address=order_address, abi=ORDER_ABI)
            market_r = safe(order.functions.market().call, block_identifier=block_no)
            if not market_r.get("ok"):
                continue
            market_address = Web3.to_checksum_address(market_r["value"])
            market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
            tokens_r = safe(market.functions.tokens().call, block_identifier=block_no)
            config_r = safe(market.functions.config().call, block_identifier=block_no)
            if not tokens_r.get("ok") or not config_r.get("ok"):
                continue
            ft_addr, _xt_addr, gt_addr, collateral_addr, debt_addr = [Web3.to_checksum_address(x) for x in tokens_r["value"]]
            if debt_addr.lower() != asset.lower():
                continue
            maturity = int(config_r["value"][1])
            ft = w3.eth.contract(address=ft_addr, abi=ERC20_ABI)
            ft_balance = int(ft.functions.balanceOf(order_address).call(block_identifier=block_no))
            if ft_balance == 0:
                continue
            row: dict[str, Any] = {
                "order": order_address,
                "market": market_address,
                "maturity": maturity,
                "matured": maturity <= timestamp,
                "ft": ft_addr,
                "ftSymbol": safe(ft.functions.symbol().call, block_identifier=block_no),
                "ftBalance": ft_balance,
                "gt": gt_addr,
                "collateral": collateral_addr,
                "debtToken": debt_addr,
                "activeOrderMaturity": active_maturity,
            }
            if maturity > timestamp:
                row["settlement"] = {"ok": False, "reason": "not matured"}
                order_rows.append(row)
                continue

            redeem_r = safe(vault.functions.redeemOrder(order_address).call, {"from": curator}, block_identifier=block_no)
            row["settlement"] = redeem_r
            if not redeem_r.get("ok"):
                order_rows.append(row)
                continue
            bad_debt, delivery = [int(x) for x in redeem_r["value"]]
            gt = w3.eth.contract(address=gt_addr, abi=GT_ABI)
            gt_cfg_r = safe(gt.functions.getGtConfig().call, block_identifier=block_no)
            if not gt_cfg_r.get("ok"):
                row["valuationError"] = gt_cfg_r
                order_rows.append(row)
                continue
            loan_config = gt_cfg_r["value"][5]
            oracle_address = Web3.to_checksum_address(loan_config[0])
            oracle = w3.eth.contract(address=oracle_address, abi=ORACLE_ABI)
            debt_price_r = safe(oracle.functions.getPrice(debt_addr).call, block_identifier=block_no)
            debt_decimals_r = safe(w3.eth.contract(address=debt_addr, abi=ERC20_ABI).functions.decimals().call, block_identifier=block_no)
            collateral_value_r = safe(
                gt.functions.getCollateralValue(w3.codec.encode(["uint256"], [delivery])).call,
                block_identifier=block_no,
            )
            if not debt_price_r.get("ok") or not debt_decimals_r.get("ok") or not collateral_value_r.get("ok"):
                row["valuationError"] = {
                    "debtPrice": debt_price_r,
                    "debtDecimals": debt_decimals_r,
                    "collateralValue": collateral_value_r,
                }
                order_rows.append(row)
                continue
            price, price_decimals = [int(x) for x in debt_price_r["value"]]
            debt_decimals = int(debt_decimals_r["value"])
            bad_debt_value_1e8 = bad_debt * price * 10**8 // (10**debt_decimals * 10**price_decimals)
            collateral_value_1e8 = int(collateral_value_r["value"])
            loss_1e8 = max(0, bad_debt_value_1e8 - collateral_value_1e8)
            ft_value_1e8 = ft_balance * price * 10**8 // (10**debt_decimals * 10**price_decimals)
            row.update({
                "badDebt": bad_debt,
                "deliveryCollateral": delivery,
                "debtPrice": price,
                "debtPriceDecimals": price_decimals,
                "debtDecimals": debt_decimals,
                "badDebtValue1e8": bad_debt_value_1e8,
                "deliveryValue1e8": collateral_value_1e8,
                "economicLoss1e8": loss_1e8,
                "ftValue1e8": ft_value_1e8,
                "nearLossless": loss_1e8 <= DUST_LOSS_1E8,
            })
            if debt_addr.lower() == asset.lower():
                asset_price, asset_price_decimals = price, price_decimals
            if loss_1e8 <= DUST_LOSS_1E8:
                safe_ft_raw += ft_balance
            else:
                total_loss_1e8 += loss_1e8
            order_rows.append(row)

        vault_row: dict[str, Any] = {
            "vault": vault_address,
            "name": safe(vault.functions.name().call, block_identifier=block_no),
            "symbol": safe(vault.functions.symbol().call, block_identifier=block_no),
            "asset": asset,
            "assetDecimals": asset_decimals,
            "curator": curator,
            "paused": safe(vault.functions.paused().call, block_identifier=block_no),
            "totalAssets": total_assets,
            "totalSupply": total_supply,
            "maxDeposit": safe(vault.functions.maxDeposit(ZERO).call, block_identifier=block_no),
            "orders": order_rows,
            "safeSettlementEligibleFtRaw": safe_ft_raw,
            "totalSettlementEligibleEconomicLoss1e8": total_loss_1e8,
        }
        if safe_ft_raw > 0 and total_loss_1e8 > 0 and asset_price and asset_price_decimals is not None:
            max_select_raw = min(safe_ft_raw, total_assets)
            preview_r = safe(vault.functions.previewWithdraw(max_select_raw).call, block_identifier=block_no)
            loss_asset_raw = total_loss_1e8 * 10**asset_decimals * 10**asset_price_decimals // (asset_price * 10**8)
            excess_raw = None
            excess_1e8 = None
            if preview_r.get("ok") and total_assets > loss_asset_raw:
                burn_shares = int(preview_r["value"])
                fair_raw = burn_shares * (total_assets - loss_asset_raw) // total_supply
                excess_raw = max_select_raw - fair_raw if max_select_raw > fair_raw else 0
                excess_1e8 = excess_raw * asset_price * 10**8 // (10**asset_decimals * 10**asset_price_decimals)
            candidate = {
                "vault": vault_address,
                "name": vault_row["name"],
                "symbol": vault_row["symbol"],
                "asset": asset,
                "totalAssets": total_assets,
                "totalSupply": total_supply,
                "safeSettlementEligibleFtRaw": safe_ft_raw,
                "totalEconomicLoss1e8": total_loss_1e8,
                "maxSelectableSafeFtRaw": max_select_raw,
                "previewSharesToBurn": preview_r,
                "lossAssetRaw": loss_asset_raw,
                "estimatedCurrentCherryPickExcessRaw": excess_raw,
                "estimatedCurrentCherryPickExcess1e8": excess_1e8,
                "orders": order_rows,
            }
            candidates.append(candidate)
            vault_row["candidate"] = candidate
        vault_rows.append(vault_row)

    candidates.sort(key=lambda row: int(row.get("estimatedCurrentCherryPickExcess1e8") or 0), reverse=True)
    result = {
        "schema": "termmax-wfc1-global-census/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "inventory": {"url": INVENTORY_URL, "sourceBlock": inventory.get("block")},
        "rpc": rpc,
        "rpcAttempts": rpc_attempts,
        "block": {"number": block_no, "hash": block.hash.hex(), "timestamp": timestamp, "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()},
        "verdict": {
            "fundedVaultCount": len(vault_rows),
            "heterogeneousSettlementCandidateCount": len(candidates),
            "maxEstimatedCurrentCherryPickExcess1e8": max((int(row.get("estimatedCurrentCherryPickExcess1e8") or 0) for row in candidates), default=0),
        },
        "candidates": candidates,
        "vaults": vault_rows,
    }
    (OUT / "TERMMAX_WFC1_GLOBAL_CENSUS.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (OUT / "WFC1_GLOBAL_VERDICT.json").write_text(json.dumps(result["verdict"], indent=2), encoding="utf-8")
    print(json.dumps({"block": result["block"], "verdict": result["verdict"], "candidates": candidates[:10]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
