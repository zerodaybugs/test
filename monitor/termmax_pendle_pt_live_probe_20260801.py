#!/usr/bin/env python3
"""Read-only live-state probe for TermMax Pendle PT collateral feeds.

No signer, transaction construction, broadcast, impersonation, or state change.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

CHAIN_ID = 1
FEEDS = [
    Web3.to_checksum_address("0x762CAacE43CD1a5a57761fFc2744be6235544f1e"),
    Web3.to_checksum_address("0x892f5d46c4291cC854820ebA04b72362794693d0"),
    Web3.to_checksum_address("0x90ee94f8fC1362849ae861Ce68Efc1D705E529E7"),
]
RPCS = [
    os.environ.get("ETH_RPC_URL", "").strip(),
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
]
RPCS = [x for x in RPCS if x]

FEED_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"PY_LP_ORACLE","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"MARKET","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"DURATION","stateMutability":"view","inputs":[],"outputs":[{"type":"uint32"}]},
    {"type":"function","name":"PRICE_FEED","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"assetPriceFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[
        {"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}
    ]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"description","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]
MARKET_ABI = [
    {"type":"function","name":"readTokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"}]},
    {"type":"function","name":"_storage","stateMutability":"view","inputs":[],"outputs":[
        {"type":"int128"},{"type":"int128"},{"type":"uint96"},{"type":"uint16"},{"type":"uint16"},{"type":"uint16"}
    ]},
    {"type":"function","name":"readState","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"tuple","components":[
            {"type":"int256","name":"totalPt"},{"type":"int256","name":"totalSy"},{"type":"int256","name":"totalLp"},
            {"type":"address","name":"treasury"},{"type":"int256","name":"scalarRoot"},{"type":"uint256","name":"expiry"},
            {"type":"uint256","name":"lnFeeRateRoot"},{"type":"uint256","name":"reserveFeePercent"},{"type":"uint256","name":"lastLnImpliedRate"}
        ]}
    ]},
    {"type":"function","name":"observe","stateMutability":"view","inputs":[{"type":"uint32[]"}],"outputs":[{"type":"uint216[]"}]},
    {"type":"function","name":"expiry","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]
ORACLE_ABI = [
    {"type":"function","name":"getOracleState","stateMutability":"view","inputs":[{"type":"address"},{"type":"uint32"}],"outputs":[{"type":"bool"},{"type":"uint16"},{"type":"bool"}]},
]
TOKEN_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"exchangeRate","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"assetInfo","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"},{"type":"address"},{"type":"uint8"}]},
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple): value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts=[]
    for url in RPCS:
        try:
            w3=Web3(Web3.HTTPProvider(url, request_kwargs={"timeout":40}))
            cid=w3.eth.chain_id; b=w3.eth.get_block("latest")
            if cid != CHAIN_ID: raise RuntimeError(f"unexpected chain id {cid}")
            attempts.append({"url":url,"ok":True,"block":b.number,"hash":b.hash.hex()})
            return w3,url,attempts
        except Exception as exc:
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def token_row(w3:Web3,address:str,holder:str,block:int)->dict[str,Any]:
    address=Web3.to_checksum_address(address); c=w3.eth.contract(address=address,abi=TOKEN_ABI)
    return {
        "address":address,"codeBytes":len(w3.eth.get_code(address,block_identifier=block)),
        "symbol":safe(c.functions.symbol().call,block_identifier=block),
        "name":safe(c.functions.name().call,block_identifier=block),
        "decimals":safe(c.functions.decimals().call,block_identifier=block),
        "totalSupply":safe(c.functions.totalSupply().call,block_identifier=block),
        "balanceAtMarket":safe(c.functions.balanceOf(holder).call,block_identifier=block),
        "exchangeRate":safe(c.functions.exchangeRate().call,block_identifier=block),
        "assetInfo":safe(c.functions.assetInfo().call,block_identifier=block),
    }


def main()->int:
    w3,rpc,attempts=connect(); block=w3.eth.get_block("latest"); bn=int(block.number); ts=int(block.timestamp)
    rows=[]
    for address in FEEDS:
        feed=w3.eth.contract(address=address,abi=FEED_ABI)
        row={
            "feed":address,"codeBytes":len(w3.eth.get_code(address,block_identifier=bn)),
            "asset":safe(feed.functions.asset().call,block_identifier=bn),
            "description":safe(feed.functions.description().call,block_identifier=bn),
            "decimals":safe(feed.functions.decimals().call,block_identifier=bn),
            "latestRoundData":safe(feed.functions.latestRoundData().call,block_identifier=bn),
            "PY_LP_ORACLE":safe(feed.functions.PY_LP_ORACLE().call,block_identifier=bn),
            "MARKET":safe(feed.functions.MARKET().call,block_identifier=bn),
            "DURATION":safe(feed.functions.DURATION().call,block_identifier=bn),
            "PRICE_FEED":safe(feed.functions.PRICE_FEED().call,block_identifier=bn),
            "assetPriceFeed":safe(feed.functions.assetPriceFeed().call,block_identifier=bn),
        }
        market_addr=row["MARKET"].get("value") if row["MARKET"].get("ok") else None
        duration=int(row["DURATION"].get("value") or 0) if row["DURATION"].get("ok") else 0
        oracle_addr=row["PY_LP_ORACLE"].get("value") if row["PY_LP_ORACLE"].get("ok") else None
        if market_addr:
            market_addr=Web3.to_checksum_address(market_addr); market=w3.eth.contract(address=market_addr,abi=MARKET_ABI)
            tokens=safe(market.functions.readTokens().call,block_identifier=bn)
            market_data={
                "address":market_addr,"codeBytes":len(w3.eth.get_code(market_addr,block_identifier=bn)),
                "readTokens":tokens,"storage":safe(market.functions._storage().call,block_identifier=bn),
                "readState":safe(market.functions.readState("0x0000000000000000000000000000000000000000").call,block_identifier=bn),
                "expiry":safe(market.functions.expiry().call,block_identifier=bn),
                "totalSupply":safe(market.functions.totalSupply().call,block_identifier=bn),
                "observe":safe(market.functions.observe([duration,0]).call,block_identifier=bn) if duration else {"ok":False,"error":"duration unavailable"},
            }
            if tokens.get("ok"):
                sy,pt,yt=tokens["value"]
                market_data["sy"]=token_row(w3,sy,market_addr,bn)
                market_data["pt"]=token_row(w3,pt,market_addr,bn)
                market_data["yt"]=token_row(w3,yt,market_addr,bn)
            row["marketData"]=market_data
        if oracle_addr and market_addr and duration:
            oracle=w3.eth.contract(address=Web3.to_checksum_address(oracle_addr),abi=ORACLE_ABI)
            row["oracleState"]=safe(oracle.functions.getOracleState(market_addr,duration).call,block_identifier=bn)
        price_feed=row["PRICE_FEED"].get("value") if row["PRICE_FEED"].get("ok") else None
        if price_feed:
            pc=w3.eth.contract(address=Web3.to_checksum_address(price_feed),abi=FEED_ABI)
            row["underlyingPriceFeed"]={
                "address":Web3.to_checksum_address(price_feed),
                "description":safe(pc.functions.description().call,block_identifier=bn),
                "decimals":safe(pc.functions.decimals().call,block_identifier=bn),
                "latestRoundData":safe(pc.functions.latestRoundData().call,block_identifier=bn),
            }
        rows.append(row)
    result={
        "schema":"termmax-pendle-pt-live-probe/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signers":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "rpc":rpc,"rpcAttempts":attempts,
        "block":{"number":bn,"hash":block.hash.hex(),"timestamp":ts,"timestampUtc":datetime.fromtimestamp(ts,tz=timezone.utc).isoformat()},
        "rows":rows,
    }
    (OUT/"PENDLE_PT_LIVE_PROBE.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2))
    return 0

if __name__=="__main__": raise SystemExit(main())
