#!/usr/bin/env python3
"""Read-only PT-srUSDat / TermMax maturity-boundary probe.

Reads public Ethereum state only. No signer, private key, transaction construction,
broadcast, impersonation, or state mutation.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3

MARKET = Web3.to_checksum_address("0xf61d02aE5D19fA11fC825dc565cFaf264720F6C4")
GT = Web3.to_checksum_address("0xD58Dd7Cd72AeA98FdAafBc4a965F4fCC49C68859")
GT_ID = 2
RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://rpc.mevblocker.io",
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
    {"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[
        {"type":"address"},{"type":"uint128"},{"type":"bytes"}
    ]},
    {"type":"function","name":"getLiquidationInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[
        {"type":"bool"},{"type":"uint128"},{"type":"uint128"}
    ]},
]
ORACLE_ABI = [
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"int256"},{"type":"int256"},{"type":"uint32"},{"type":"uint32"}
    ]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
COMMON_EXPIRY_ABI = [
    {"type":"function","name":"expiry","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"YT","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"SY","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
FEED_ABI = [
    {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[
        {"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}
    ]},
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"DURATION","stateMutability":"view","inputs":[],"outputs":[{"type":"uint32"}]},
    {"type":"function","name":"duration","stateMutability":"view","inputs":[],"outputs":[{"type":"uint32"}]},
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
            if w3.eth.chain_id != 1:
                raise RuntimeError(f"unexpected chain id {w3.eth.chain_id}")
            block = w3.eth.get_block("latest")
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def main() -> int:
    out = Path(os.environ.get("OUT_DIR", "evidence")); out.mkdir(parents=True, exist_ok=True)
    w3, rpc, attempts = connect(); block = w3.eth.get_block("latest"); bn = block.number
    market = w3.eth.contract(address=MARKET, abi=MARKET_ABI)
    gt = w3.eth.contract(address=GT, abi=GT_ABI)
    tokens = [Web3.to_checksum_address(x) for x in market.functions.tokens().call(block_identifier=bn)]
    ft, xt, gt_addr, collateral, debt = tokens
    market_cfg = market.functions.config().call(block_identifier=bn)
    gt_cfg = gt.functions.getGtConfig().call(block_identifier=bn)
    oracle_addr = Web3.to_checksum_address(gt_cfg[5][0])
    oracle = w3.eth.contract(address=oracle_addr, abi=ORACLE_ABI)
    coll_cfg = safe(oracle.functions.oracles(collateral).call, block_identifier=bn)
    debt_cfg = safe(oracle.functions.oracles(debt).call, block_identifier=bn)
    coll_price = safe(oracle.functions.getPrice(collateral).call, block_identifier=bn)
    debt_price = safe(oracle.functions.getPrice(debt).call, block_identifier=bn)
    feed_addr = None
    if coll_cfg.get("ok") and coll_cfg["value"]:
        feed_addr = Web3.to_checksum_address(coll_cfg["value"][0])
    feed = w3.eth.contract(address=feed_addr, abi=FEED_ABI) if feed_addr else None
    feed_row = {
        "address": feed_addr,
        "codeBytes": len(w3.eth.get_code(feed_addr, block_identifier=bn)) if feed_addr else 0,
        "latestRoundData": safe(feed.functions.latestRoundData().call, block_identifier=bn) if feed else {"ok": False},
        "market": safe(feed.functions.market().call, block_identifier=bn) if feed else {"ok": False},
        "DURATION": safe(feed.functions.DURATION().call, block_identifier=bn) if feed else {"ok": False},
        "duration": safe(feed.functions.duration().call, block_identifier=bn) if feed else {"ok": False},
    }
    expiry_candidates: list[dict[str, Any]] = []
    for label, address in (("collateral", collateral), ("feedMarket", feed_row.get("market", {}).get("value"))):
        if not address: continue
        address = Web3.to_checksum_address(address)
        contract = w3.eth.contract(address=address, abi=COMMON_EXPIRY_ABI)
        expiry_candidates.append({
            "label": label, "address": address, "codeBytes": len(w3.eth.get_code(address, block_identifier=bn)),
            "expiry": safe(contract.functions.expiry().call, block_identifier=bn),
            "YT": safe(contract.functions.YT().call, block_identifier=bn),
            "SY": safe(contract.functions.SY().call, block_identifier=bn),
        })
    # Follow YT pointers once, because PT contracts often expose YT while expiry lives on YT.
    for row in list(expiry_candidates):
        yt_r = row.get("YT", {})
        if yt_r.get("ok") and yt_r.get("value"):
            address = Web3.to_checksum_address(yt_r["value"])
            contract = w3.eth.contract(address=address, abi=COMMON_EXPIRY_ABI)
            expiry_candidates.append({
                "label": row["label"] + ".YT", "address": address,
                "codeBytes": len(w3.eth.get_code(address, block_identifier=bn)),
                "expiry": safe(contract.functions.expiry().call, block_identifier=bn),
                "YT": safe(contract.functions.YT().call, block_identifier=bn),
                "SY": safe(contract.functions.SY().call, block_identifier=bn),
            })
    result = {
        "schema": "termmax-pt-srusdat-post-expiry-probe/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "rpc": rpc, "rpcAttempts": attempts,
        "block": {"number":bn,"hash":block.hash.hex(),"timestamp":block.timestamp,"timestampUtc":datetime.fromtimestamp(block.timestamp,tz=timezone.utc).isoformat()},
        "market": MARKET, "gt": GT, "gtId": GT_ID,
        "marketMaturity": int(market_cfg[1]), "gtMaturity": int(gt_cfg[4]),
        "tokens": {"ft":ft,"xt":xt,"gt":gt_addr,"collateral":collateral,"debt":debt},
        "symbols": {
            "collateral": safe(w3.eth.contract(address=collateral, abi=ERC20_ABI).functions.symbol().call, block_identifier=bn),
            "debt": safe(w3.eth.contract(address=debt, abi=ERC20_ABI).functions.symbol().call, block_identifier=bn),
        },
        "loanInfo": safe(gt.functions.loanInfo(GT_ID).call, block_identifier=bn),
        "liquidationInfo": safe(gt.functions.getLiquidationInfo(GT_ID).call, block_identifier=bn),
        "oracle": oracle_addr, "collateralOracleConfig": coll_cfg, "debtOracleConfig": debt_cfg,
        "collateralPrice": coll_price, "debtPrice": debt_price,
        "feed": feed_row, "expiryCandidates": expiry_candidates,
    }
    expiries = [int(r["expiry"]["value"]) for r in expiry_candidates if r.get("expiry", {}).get("ok")]
    result["verdict"] = {
        "marketAndGtBindingMatch": gt_addr.lower() == GT.lower(),
        "marketMaturityInFuture": int(market_cfg[1]) > int(block.timestamp),
        "expiryDiscovered": bool(expiries),
        "earliestExpiry": min(expiries) if expiries else 0,
        "postExpiryPreMarketWindowSeconds": max(0, int(market_cfg[1]) - min(expiries)) if expiries else 0,
        "currentCollateralPriceWorks": bool(coll_price.get("ok")),
        "currentLiquidationInfoWorks": bool(result["liquidationInfo"].get("ok")),
    }
    (out / "TERMMAX_PT_SRUSDAT_LIVE_BINDING.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2)); return 0

if __name__ == "__main__": raise SystemExit(main())
