#!/usr/bin/env python3
"""Read-only current-state gate for one official TermMax settlement target.

Safety boundary: public eth_call/storage/balance reads only. No private key,
signer, transaction construction, broadcast, impersonation, or state change.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eth_abi import encode
from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

CHAIN_ID = 1
VAULT = Web3.to_checksum_address("0xD7977c2A74005CA3af5b201546369F0c7c177842")
ORDER = Web3.to_checksum_address("0xCf819fa7fbB96845AD3Ed8C6dd45BCcBC121d82C")
CURATOR = Web3.to_checksum_address("0x008c7DC790fA31E6CA19D8Cb6d11C53f6A88DF6c")
USDC = Web3.to_checksum_address("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
COLLATERAL = Web3.to_checksum_address("0xe6A934089BBEe34F832060CE98848359883749B3")
FT = Web3.to_checksum_address("0x61996fb4a9ea4E5D240b69fd6272C35432C7574a")
GT = Web3.to_checksum_address("0xa4657AE69E75Ce5ac4b99fa1b2de40b5Fc50BC14")
ORACLE = Web3.to_checksum_address("0xEDB5DFB6393551fAF499CF55494b1F6e44C2c612")
PROBE_RECEIVER = Web3.to_checksum_address("0x1000000000000000000000000000000000000001")

RPCS = [
    os.environ.get("ETH_RPC_URL", "").strip(),
    "https://rpc.mevblocker.io",
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://eth.llamarpc.com",
]
RPCS = [url for url in RPCS if url]

VAULT_ABI = [
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxDeposit","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"badDebtMapping","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewWithdraw","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"redeemOrder","stateMutability":"nonpayable","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
GT_ABI = [
    {"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},
]
ORACLE_ABI = [
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
ORDER_ABI = [
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            chain_id = w3.eth.chain_id
            block = w3.eth.get_block("latest")
            if chain_id != CHAIN_ID:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def main() -> int:
    w3, rpc, rpc_attempts = connect()
    block = w3.eth.get_block("latest")
    block_number = int(block.number)
    timestamp = int(block.timestamp)

    vault = w3.eth.contract(address=VAULT, abi=VAULT_ABI)
    usdc = w3.eth.contract(address=USDC, abi=ERC20_ABI)
    collateral = w3.eth.contract(address=COLLATERAL, abi=ERC20_ABI)
    ft = w3.eth.contract(address=FT, abi=ERC20_ABI)
    gt = w3.eth.contract(address=GT, abi=GT_ABI)
    oracle = w3.eth.contract(address=ORACLE, abi=ORACLE_ABI)
    order = w3.eth.contract(address=ORDER, abi=ORDER_ABI)

    total_assets = int(vault.functions.totalAssets().call(block_identifier=block_number))
    total_supply = int(vault.functions.totalSupply().call(block_identifier=block_number))
    max_deposit = int(vault.functions.maxDeposit(PROBE_RECEIVER).call(block_identifier=block_number))
    paused = bool(vault.functions.paused().call(block_identifier=block_number))
    maturity = int(vault.functions.orderMaturity(ORDER).call(block_identifier=block_number))
    current_bad_debt = int(vault.functions.badDebtMapping(COLLATERAL).call(block_identifier=block_number))
    current_collateral = int(collateral.functions.balanceOf(VAULT).call(block_identifier=block_number))
    ft_at_order = int(ft.functions.balanceOf(ORDER).call(block_identifier=block_number))
    market = order.functions.market().call(block_identifier=block_number)
    debt_price, debt_price_decimals = oracle.functions.getPrice(USDC).call(block_identifier=block_number)
    debt_price = int(debt_price)
    debt_price_decimals = int(debt_price_decimals)

    current_collateral_value = int(
        gt.functions.getCollateralValue(encode(["uint256"], [current_collateral])).call(block_identifier=block_number)
    ) if current_collateral else 0
    current_bad_debt_value = current_bad_debt * debt_price * 10**8 // (10**6 * 10**debt_price_decimals)
    current_surplus = current_collateral_value - current_bad_debt_value

    redeem_sim = safe(
        vault.functions.redeemOrder(ORDER).call,
        {"from": CURATOR},
        block_identifier=block_number,
    )
    simulated_bad_debt = 0
    simulated_collateral = 0
    simulated_collateral_value = 0
    simulated_bad_debt_value = 0
    simulated_surplus = 0
    if redeem_sim.get("ok"):
        simulated_bad_debt = int(redeem_sim["value"][0])
        simulated_collateral = int(redeem_sim["value"][1])
        simulated_collateral_value = int(
            gt.functions.getCollateralValue(encode(["uint256"], [simulated_collateral])).call(
                block_identifier=block_number
            )
        ) if simulated_collateral else 0
        simulated_bad_debt_value = simulated_bad_debt * debt_price * 10**8 // (
            10**6 * 10**debt_price_decimals
        )
        simulated_surplus = simulated_collateral_value - simulated_bad_debt_value

    immediate_open = current_bad_debt > 1 and current_collateral > 0 and current_surplus > 0
    future_trigger_open = (
        not immediate_open
        and bool(redeem_sim.get("ok"))
        and simulated_bad_debt > 0
        and simulated_collateral > 0
        and simulated_surplus > 0
    )
    required_deposit = (current_bad_debt if immediate_open else current_bad_debt + simulated_bad_debt) + 10**6
    capacity_sufficient = max_deposit >= required_deposit
    shares_required = int(vault.functions.previewWithdraw(
        current_bad_debt if immediate_open else current_bad_debt + simulated_bad_debt
    ).call(block_identifier=block_number)) if (current_bad_debt or simulated_bad_debt) else 0

    if immediate_open and capacity_sufficient:
        next_step = "IMMEDIATE_PUBLIC_SETTLEMENT_SURPLUS_CAPTURE_OPEN"
    elif future_trigger_open and capacity_sufficient:
        next_step = "SETTLEMENT_TRIGGER_READY_PUBLIC_SURPLUS_CAPTURE_OPEN_AFTER_REDEEM"
    elif immediate_open or future_trigger_open:
        next_step = "SURPLUS_EXISTS_BUT_CURRENT_DEPOSIT_CAPACITY_INSUFFICIENT"
    else:
        next_step = "KILL_OR_HOLD_NO_CURRENT_POSITIVE_SURPLUS"

    result = {
        "schema": "termmax-settlement-surplus-live-gate/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys":0,"signers":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "rpc": rpc,
        "rpcAttempts": rpc_attempts,
        "block": {
            "number": block_number,
            "hash": block.hash.hex(),
            "timestamp": timestamp,
            "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        },
        "target": {
            "vault": VAULT,
            "order": ORDER,
            "market": market,
            "curatorUsedForEthCallOnly": CURATOR,
            "asset": USDC,
            "collateral": COLLATERAL,
            "ft": FT,
            "gt": GT,
            "oracle": ORACLE,
        },
        "state": {
            "vaultCodeBytes": len(w3.eth.get_code(VAULT, block_identifier=block_number)),
            "orderCodeBytes": len(w3.eth.get_code(ORDER, block_identifier=block_number)),
            "totalAssetsRaw": total_assets,
            "totalSupplyRaw": total_supply,
            "maxDepositRaw": max_deposit,
            "paused": paused,
            "orderMaturity": maturity,
            "matured": timestamp >= maturity,
            "ftBalanceAtOrderRaw": ft_at_order,
            "currentBadDebtRaw": current_bad_debt,
            "currentCollateralRaw": current_collateral,
            "currentBadDebtValue1e8": current_bad_debt_value,
            "currentCollateralValue1e8": current_collateral_value,
            "currentSurplus1e8": current_surplus,
        },
        "settlementEthCall": {
            "result": redeem_sim,
            "simulatedBadDebtRaw": simulated_bad_debt,
            "simulatedCollateralRaw": simulated_collateral,
            "simulatedBadDebtValue1e8": simulated_bad_debt_value,
            "simulatedCollateralValue1e8": simulated_collateral_value,
            "simulatedSurplus1e8": simulated_surplus,
        },
        "captureGate": {
            "immediateOpen": immediate_open,
            "futureTriggerOpen": future_trigger_open,
            "requiredDepositRaw": required_deposit,
            "maxDepositRaw": max_deposit,
            "capacitySufficient": capacity_sufficient,
            "sharesRequiredRaw": shares_required,
            "nextStep": next_step,
        },
    }

    (OUT / "SETTLEMENT_SURPLUS_LIVE_GATE.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (OUT / "VERDICT.txt").write_text(json.dumps(result["captureGate"], indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
