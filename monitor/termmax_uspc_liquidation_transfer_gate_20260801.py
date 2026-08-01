#!/usr/bin/env python3
"""Read-only liquidation-transfer and redeemability gate for live USPC TermMax markets.

The exact collateral-transfer operation used by liquidation is simulated through
eth_call from each production GT contract to an arbitrary EOA. No signer,
transaction construction, broadcast, impersonation, or state change is used.
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
USPC = Web3.to_checksum_address("0xbF4e3fbE8B60062A00C7a6B1D97d0d49c2971A19")
GTS = [
    Web3.to_checksum_address("0x715bBef39f245aF599FcEc4ABf7417F736A8A75F"),
    Web3.to_checksum_address("0xd4A3ac77FFe2220f2727C26234B00E5223Bad943"),
]
RECIPIENTS = [
    Web3.to_checksum_address("0x1000000000000000000000000000000000000001"),
    Web3.to_checksum_address("0x2000000000000000000000000000000000000002"),
]
IMPLEMENTATION_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
RPCS = [
    os.environ.get("ETH_RPC_URL", "").strip(),
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
]
RPCS = [x for x in RPCS if x]

ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"transfer","stateMutability":"nonpayable","inputs":[{"type":"address"},{"type":"uint256"}],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
]
ERC4626_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxRedeem","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        if isinstance(value, (bytes, bytearray)):
            value = "0x" + bytes(value).hex()
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            block = w3.eth.get_block("latest")
            if int(w3.eth.chain_id) != 1:
                raise RuntimeError(f"unexpected chain id {w3.eth.chain_id}")
            attempts.append({"url":url,"ok":True,"block":block.number,"hash":block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def get_source(address: str) -> dict[str, Any]:
    endpoint = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
    try:
        response = requests.get(
            endpoint,
            params={"module":"contract","action":"getsourcecode","address":address},
            timeout=45,
            headers={"User-Agent":"ZeroDayBugs-TermMax-Readonly-USPC/1"},
        )
        response.raise_for_status()
        payload = response.json()
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if not isinstance(rows, list) or not rows:
            return {"ok":False,"error":f"unexpected response: {payload}"}
        row = rows[0]
        return {
            "ok": True,
            "contractName": row.get("ContractName"),
            "compilerVersion": row.get("CompilerVersion"),
            "optimizationUsed": row.get("OptimizationUsed"),
            "runs": row.get("Runs"),
            "proxy": row.get("Proxy"),
            "implementation": row.get("Implementation"),
            "sourceCode": row.get("SourceCode"),
            "abi": row.get("ABI"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok":False,"error":f"{type(exc).__name__}: {exc}"}


def main() -> int:
    w3, rpc, attempts = connect()
    block_obj = w3.eth.get_block("latest")
    block = int(block_obj.number)
    token = w3.eth.contract(address=USPC, abi=ERC20_ABI + ERC4626_ABI)
    impl_raw = w3.eth.get_storage_at(USPC, IMPLEMENTATION_SLOT, block_identifier=block)
    implementation = Web3.to_checksum_address("0x" + impl_raw[-20:].hex())
    unit = 10 ** int(token.functions.decimals().call(block_identifier=block))

    gt_rows: list[dict[str, Any]] = []
    for gt in GTS:
        balance = int(token.functions.balanceOf(gt).call(block_identifier=block))
        transfer_rows = []
        for recipient in RECIPIENTS:
            amount = 1 if balance else 0
            transfer_rows.append({
                "recipient": recipient,
                "amountRaw": amount,
                "ethCall": safe(
                    token.functions.transfer(recipient, amount).call,
                    {"from": gt},
                    block_identifier=block,
                ),
            })
        gt_rows.append({
            "gt": gt,
            "codeBytes": len(w3.eth.get_code(gt, block_identifier=block)),
            "uspcBalanceRaw": balance,
            "maxRedeemRaw": safe(token.functions.maxRedeem(gt).call, block_identifier=block),
            "maxWithdrawRaw": safe(token.functions.maxWithdraw(gt).call, block_identifier=block),
            "arbitraryRecipientTransferSimulations": transfer_rows,
            "allTransfersSucceeded": bool(balance) and all(row["ethCall"].get("ok") and row["ethCall"].get("value") is True for row in transfer_rows),
        })

    source_proxy = get_source(USPC)
    source_impl = get_source(implementation)
    if source_proxy.get("ok"):
        (OUT / "USPC_PROXY_SOURCE.json").write_text(json.dumps(source_proxy, indent=2), encoding="utf-8")
    if source_impl.get("ok"):
        (OUT / "USPC_IMPLEMENTATION_SOURCE.json").write_text(json.dumps(source_impl, indent=2), encoding="utf-8")

    transfer_blocked = any(row["uspcBalanceRaw"] > 0 and not row["allTransfersSucceeded"] for row in gt_rows)
    redeem_restricted = any(
        row["uspcBalanceRaw"] > 0
        and (
            not row["maxRedeemRaw"].get("ok")
            or int(row["maxRedeemRaw"].get("value", 0) or 0) < row["uspcBalanceRaw"]
        )
        for row in gt_rows
    )
    verdict = {
        "gtCount": len(gt_rows),
        "gtWithBalanceCount": sum(1 for row in gt_rows if row["uspcBalanceRaw"] > 0),
        "arbitraryLiquidatorTransferBlocked": transfer_blocked,
        "fullRedeemCurrentlyRestricted": redeem_restricted,
        "nextStep": "PINNED_FORK_LIQUIDATION_DOS_OR_INSOLVENCY_POC" if transfer_blocked else "KILL_USPC_TRANSFER_RECIPIENT_RESTRICTION",
    }
    result = {
        "schema":"termmax-uspc-liquidation-transfer-gate/v1",
        "generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signers":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "rpc":rpc,
        "rpcAttempts":attempts,
        "block":{"number":block,"hash":block_obj.hash.hex(),"timestamp":int(block_obj.timestamp),"timestampUtc":datetime.fromtimestamp(block_obj.timestamp,tz=timezone.utc).isoformat()},
        "uspc":{
            "proxy":USPC,
            "implementation":implementation,
            "symbol":safe(token.functions.symbol().call, block_identifier=block),
            "decimals":safe(token.functions.decimals().call, block_identifier=block),
            "paused":safe(token.functions.paused().call, block_identifier=block),
            "asset":safe(token.functions.asset().call, block_identifier=block),
            "totalAssets":safe(token.functions.totalAssets().call, block_identifier=block),
            "totalSupply":safe(token.functions.totalSupply().call, block_identifier=block),
            "convertToAssetsOneShare":safe(token.functions.convertToAssets(unit).call, block_identifier=block),
            "previewRedeemOneShare":safe(token.functions.previewRedeem(unit).call, block_identifier=block),
            "proxySource":{k:v for k,v in source_proxy.items() if k not in ("sourceCode","abi")},
            "implementationSource":{k:v for k,v in source_impl.items() if k not in ("sourceCode","abi")},
        },
        "gtRows":gt_rows,
        "verdict":verdict,
    }
    (OUT / "USPC_LIQUIDATION_TRANSFER_GATE.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    (OUT / "VERDICT.json").write_text(json.dumps(verdict,indent=2),encoding="utf-8")
    print(json.dumps(verdict,indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
