#!/usr/bin/env python3
"""Fast read-only Base TermMax zero-price live-binding gate.

Enumerates factory CreateMarket logs through Base Blockscout and reads only the
current market/GT/oracle/feed state needed to decide whether a zero-price feed
can affect an active market. No position enumeration and no state change.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path("evidence")
OUT.mkdir(parents=True, exist_ok=True)
RPCS = ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://base.drpc.org"]
FACTORY = Web3.to_checksum_address("0x08c50Bd46992d35694208eC3Cf1f1EDcE38f5fd1")
FROM_BLOCK = 44722441
CREATE_MARKET_TOPIC = Web3.to_hex(Web3.keccak(text="CreateMarket(address,address,address)"))
ZERO = "0x0000000000000000000000000000000000000000"

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address"},{"type":"uint64"},{"type":"tuple","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
]
GT_ABI = [
    {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"uint64"},
        {"type":"tuple","components":[{"type":"address"},{"type":"uint32"},{"type":"uint32"},{"type":"bool"}]}
    ]}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]
ORACLE_ABI = [
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"int256"},{"type":"int256"},{"type":"uint32"},{"type":"uint32"}
    ]},
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
ROUND_ABI = [
    {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[
        {"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}
    ]},
    {"type":"function","name":"description","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
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
            w3=Web3(Web3.HTTPProvider(url, request_kwargs={"timeout":30}))
            if w3.eth.chain_id != 8453: raise RuntimeError(f"wrong chain {w3.eth.chain_id}")
            latest=w3.eth.block_number
            attempts.append({"url":url,"ok":True,"latest":latest})
            return w3,url,attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def topic_address(value: str) -> str:
    raw=value[2:] if value.startswith("0x") else value
    return Web3.to_checksum_address("0x"+raw[-40:])


def feed(w3:Web3,address:str,block:int,timestamp:int)->dict[str,Any]|None:
    if address.lower()==ZERO.lower(): return None
    c=w3.eth.contract(address=Web3.to_checksum_address(address),abi=ROUND_ABI)
    r=safe(c.functions.latestRoundData().call,block_identifier=block)
    row={"address":address,"round":r,"description":safe(c.functions.description().call,block_identifier=block)}
    if r.get("ok"):
        row["answer"]=int(r["value"][1]); row["updatedAt"]=int(r["value"][3])
        row["ageSeconds"]=max(timestamp-int(r["value"][3]),0) if int(r["value"][3]) else None
    return row


def side(w3:Web3,oracle:Any,asset:str,block:int,timestamp:int)->dict[str,Any]:
    cfg=safe(oracle.functions.oracles(asset).call,block_identifier=block)
    price=safe(oracle.functions.getPrice(asset).call,block_identifier=block)
    row={"asset":asset,"config":cfg,"getPrice":price}
    if cfg.get("ok"):
        agg,backup,maxp,minp,hb,bhb=cfg["value"]
        row.update({"aggregator":agg,"backupAggregator":backup,"maxPrice":int(maxp),"minPrice":int(minp),
                    "heartbeat":int(hb),"backupHeartbeat":int(bhb),"zeroFloor":int(minp)==0 and agg.lower()!=ZERO.lower(),
                    "primary":feed(w3,agg,block,timestamp),"backup":feed(w3,backup,block,timestamp)})
    return row


def main()->int:
    w3,rpc,attempts=connect(); latest=w3.eth.block_number; block=w3.eth.get_block(latest)
    response=requests.get("https://base.blockscout.com/api",params={
        "module":"logs","action":"getLogs","fromBlock":str(FROM_BLOCK),"toBlock":str(latest),
        "address":FACTORY,"topic0":CREATE_MARKET_TOPIC,
    },timeout=45,headers={"User-Agent":"ZeroDayBugs-TermMax-ReadOnly/1.0"})
    response.raise_for_status(); payload=response.json(); logs=payload.get("result",[])
    markets=sorted({topic_address(x["topics"][1]) for x in logs if len(x.get("topics",[]))>=2})
    rows=[]
    for address in markets:
        market=w3.eth.contract(address=address,abi=MARKET_ABI)
        tokens=safe(market.functions.tokens().call,block_identifier=latest)
        config=safe(market.functions.config().call,block_identifier=latest)
        row={"market":address,"tokens":tokens,"config":config}
        if not tokens.get("ok"): rows.append(row); continue
        ft,xt,gt,coll,debt=tokens["value"]
        maturity=int(config["value"][1]) if config.get("ok") else 0
        gt_c=w3.eth.contract(address=gt,abi=GT_ABI); gt_cfg=safe(gt_c.functions.getGtConfig().call,block_identifier=latest)
        oracle_addr=gt_cfg["value"][5][0] if gt_cfg.get("ok") else ZERO
        oracle=w3.eth.contract(address=oracle_addr,abi=ORACLE_ABI)
        row.update({"maturity":maturity,"active":maturity>int(block.timestamp),"gt":gt,
                    "gtSupply":safe(gt_c.functions.totalSupply().call,block_identifier=latest),
                    "collateral":coll,"debtToken":debt,"collateralSymbol":safe(w3.eth.contract(address=coll,abi=ERC20_ABI).functions.symbol().call,block_identifier=latest),
                    "debtSymbol":safe(w3.eth.contract(address=debt,abi=ERC20_ABI).functions.symbol().call,block_identifier=latest),
                    "oracle":oracle_addr,"collateralOracle":side(w3,oracle,coll,latest,int(block.timestamp)),
                    "debtOracle":side(w3,oracle,debt,latest,int(block.timestamp))})
        rows.append(row)
    active=[r for r in rows if r.get("active")]
    zero=[]
    for r in active:
        for s in ("collateralOracle","debtOracle"):
            if (r.get(s)or{}).get("zeroFloor"):
                zero.append({"market":r["market"],"side":s,"symbol":((r.get("collateralSymbol") if s=="collateralOracle" else r.get("debtSymbol"))or{}).get("value"),
                             "asset":r[s]["asset"],"aggregator":r[s].get("aggregator"),"price":r[s].get("getPrice"),"gtSupply":(r.get("gtSupply")or{}).get("value")})
    result={"schema":"termmax-zero-price-base-fast/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),
            "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
            "rpc":rpc,"rpcAttempts":attempts,"block":{"number":latest,"hash":block.hash.hex(),"timestamp":int(block.timestamp)},
            "factory":FACTORY,"rawLogCount":len(logs),"marketCount":len(rows),"activeMarketCount":len(active),
            "zeroFloorActiveSideCount":len(zero),"zeroFloorActiveSides":zero,"markets":rows}
    summary={k:result[k] for k in ("rawLogCount","marketCount","activeMarketCount","zeroFloorActiveSideCount")}
    (OUT/"BASE_ZERO_PRICE_FAST_FULL.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    (OUT/"SUMMARY.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary,indent=2)); return 0

if __name__=="__main__": raise SystemExit(main())
