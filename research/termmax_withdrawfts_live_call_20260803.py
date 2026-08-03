#!/usr/bin/env python3
"""Read-only live eth_call gate for caller-selected TermMax vault FT withdrawal.

Consumes the composition census generated in the same workflow, selects the
largest current EOA share holder and the largest near-lossless FT Order, then
simulates withdrawFts() at the exact pinned census block. No transaction is
constructed, signed, broadcast, or persisted.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
COMPOSITION = OUT / "TERMMAX_VAULT_COMPOSITION.json"
RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://rpc.mevblocker.io",
]

VAULT_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxRedeem","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewWithdraw","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"withdrawFts","stateMutability":"nonpayable","inputs":[
        {"type":"address","name":"order"},{"type":"uint256","name":"amount"},
        {"type":"address","name":"recipient"},{"type":"address","name":"owner"}
    ],"outputs":[{"type":"uint256","name":"shares"}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect(block: int) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            if w3.eth.chain_id != 1:
                raise RuntimeError(f"unexpected chain id {w3.eth.chain_id}")
            pinned = w3.eth.get_block(block)
            attempts.append({"url": url, "ok": True, "blockHash": pinned.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def main() -> int:
    data = json.loads(COMPOSITION.read_text(encoding="utf-8"))
    block = int(data["block"]["number"])
    expected_hash = str(data["block"]["hash"]).lower().removeprefix("0x")
    vault_address = Web3.to_checksum_address(data["vault"]["address"])

    eoa_holders = [row for row in data.get("topHolders", []) if int(row.get("codeBytes", 1)) == 0 and int(row.get("shares", 0)) > 0]
    if not eoa_holders:
        raise RuntimeError("no current EOA holder in composition census")
    holder = Web3.to_checksum_address(eoa_holders[0]["address"])

    safe_orders = [
        row for row in data.get("orders", [])
        if row.get("ft")
        and int((row.get("ftBalanceAtOrder") or {}).get("value", 0)) > 0
        and int((row.get("redeemOrderEthCall") or {}).get("value", [2**256 - 1])[0]) <= 1
    ]
    if not safe_orders:
        raise RuntimeError("no near-lossless positive-FT Order in composition census")
    safe_order_row = max(safe_orders, key=lambda row: int(row["ftBalanceAtOrder"]["value"]))
    safe_order = Web3.to_checksum_address(safe_order_row["order"])
    ft_address = Web3.to_checksum_address(safe_order_row["ft"])

    w3, rpc, attempts = connect(block)
    pinned = w3.eth.get_block(block)
    if pinned.hash.hex().lower().removeprefix("0x") != expected_hash:
        raise RuntimeError("pinned block hash mismatch")

    vault = w3.eth.contract(address=vault_address, abi=VAULT_ABI)
    ft = w3.eth.contract(address=ft_address, abi=ERC20_ABI)
    holder_shares = int(vault.functions.balanceOf(holder).call(block_identifier=block))
    max_redeem = int(vault.functions.maxRedeem(holder).call(block_identifier=block))
    max_withdraw = int(vault.functions.maxWithdraw(holder).call(block_identifier=block))
    safe_ft_balance = int(ft.functions.balanceOf(safe_order).call(block_identifier=block))
    amount = min(safe_ft_balance, max_withdraw)
    if amount <= 0:
        raise RuntimeError("no positive live withdrawal amount")
    preview_shares = int(vault.functions.previewWithdraw(amount).call(block_identifier=block))
    call_result = safe(
        vault.functions.withdrawFts(safe_order, amount, holder, holder).call,
        {"from": holder},
        block_identifier=block,
    )

    result = {
        "schema": "termmax-withdrawfts-live-call/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {"number": block, "hash": pinned.hash.hex(), "timestamp": pinned.timestamp},
        "vault": vault_address,
        "holder": holder,
        "holderCodeBytes": len(w3.eth.get_code(holder, block_identifier=block)),
        "holderShares": holder_shares,
        "holderMaxRedeem": max_redeem,
        "holderMaxWithdraw": max_withdraw,
        "safeOrder": safe_order,
        "safeFt": ft_address,
        "safeFtBalance": safe_ft_balance,
        "simulatedWithdrawalAmount": amount,
        "previewSharesToBurn": preview_shares,
        "withdrawFtsEthCall": call_result,
        "verdict": {
            "holderIsEoa": len(w3.eth.get_code(holder, block_identifier=block)) == 0,
            "holderCanCoverPreviewShares": preview_shares <= holder_shares and preview_shares <= max_redeem,
            "fullSafeFtReserveSelected": amount == safe_ft_balance,
            "withdrawFtsSucceedsAtPinnedState": bool(call_result.get("ok")),
        },
    }
    (OUT / "TERMMAX_WITHDRAWFTS_LIVE_CALL.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (OUT / "WITHDRAWFTS_VERDICT.json").write_text(json.dumps(result["verdict"], indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if all(result["verdict"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
