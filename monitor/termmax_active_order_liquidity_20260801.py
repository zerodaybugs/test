#!/usr/bin/env python3
"""Read-only census of current TermMax Ethereum active-order liquidity.

Discovers V2 order clones from Market.CreateOrder events for a fixed active-market
set, then reads current reserves, pool assets, expiry, maker, GT linkage, and
underlying ERC-20 balances at one pinned latest block. No transaction signing,
construction, broadcast, impersonation, or state mutation.
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

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

CHAIN_ID = 1
START_BLOCK = 24_000_000
MARKETS = [
    "0x02d59E7C407CA565BACb0CDB1929d678786Eb2Af",
    "0xB42E5A5CddC97b1e459723f012ce99269fC3EfB7",
    "0x5fbA8eA801ea1Cf389A50e1379BaD614908C5360",
    "0x68d6fdec9e8AF84B0b8241519F488177BafD43FC",
    "0xf61d02aE5D19fA11fC825dc565cFaf264720F6C4",
    "0x546C6395be470FAeA356706d66c89429ee0D1Ef4",
    "0x4A640c87d048DBcDB1F27e1a5882fb7947446E7d",
    "0x8896204f4c3948C939Bcc556AD2361904d9A72AA",
    "0x17FbF5883eF9a8e0a756de8FDc95A4B5E20A3DA8",
    "0x57e92D2c565BaF64958a4fC820563621Dfb8f88D",
    "0xb7cf2714E3be17ea4082A4528076a97A8F3F4Fc4",
    "0x7A708678A40FEeD9eE43A83E594B29FAf9Ca0d12",
    "0x163c7607D9838793Af8dB2C6940cf275D503b379",
    "0x6c510aAe362d45A35CE60321a3f2e44ea4ea0ABe",
]
RPCS = [
    os.environ.get("ETH_RPC_URL", "").strip(),
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://rpc.mevblocker.io",
    "https://1rpc.io/eth",
    "https://eth.llamarpc.com",
]
RPCS = [x for x in RPCS if x]
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
CREATE_ORDER_TOPIC = "0x" + Web3.keccak(text="CreateOrder(address,address)").hex().removeprefix("0x")
ZERO = "0x0000000000000000000000000000000000000000"

MARKET_ABI = [
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"name":"treasurer","type":"address"},{"name":"maturity","type":"uint64"},{"name":"feeConfig","type":"tuple","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
]
ORDER_ABI = [
    {"type":"function","name":"maker","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"orderExpiryTimestamp","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]},
    {"type":"function","name":"virtualXtReserve","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"tokenReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
    {"type":"function","name":"getRealReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
    {"type":"function","name":"orderConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"name":"curveCuts","type":"tuple","components":[
            {"name":"lendCurveCuts","type":"tuple[]","components":[{"type":"uint256"},{"type":"uint256"},{"type":"int256"}]},
            {"name":"borrowCurveCuts","type":"tuple[]","components":[{"type":"uint256"},{"type":"uint256"},{"type":"int256"}]}
        ]},
        {"name":"gtId","type":"uint256"},
        {"name":"maxXtReserve","type":"uint256"},
        {"name":"swapTrigger","type":"address"},
        {"name":"feeConfig","type":"tuple","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]
POOL_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
GT_ABI = [
    {"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"address"},{"type":"uint128"},{"type":"bytes"}]},
    {"type":"function","name":"getLiquidationInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"bool"},{"type":"uint128"},{"type":"uint128"}]},
]


def jdefault(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray)):
        return "0x" + bytes(v).hex()
    return str(v)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        v = fn(*args, **kwargs)
        if isinstance(v, tuple):
            v = list(v)
        return {"ok": True, "value": v}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts=[]
    for url in RPCS:
        try:
            w3=Web3(Web3.HTTPProvider(url, request_kwargs={"timeout":45}))
            chain=w3.eth.chain_id
            block=w3.eth.get_block("latest")
            if chain != CHAIN_ID:
                raise RuntimeError(f"unexpected chain id {chain}")
            attempts.append({"url":url,"ok":True,"block":block.number,"hash":block.hash.hex()})
            return w3,url,attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def topic_address(topic: str) -> str:
    return Web3.to_checksum_address("0x" + topic[-40:])


def routescan_market_orders(market: str, latest: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    attempts=[]
    for attempt in range(6):
        try:
            response=requests.get(ROUTESCAN, params={
                "module":"logs","action":"getLogs","fromBlock":START_BLOCK,"toBlock":latest,
                "address":market,"topic0":CREATE_ORDER_TOPIC,"page":1,"offset":1000,
            }, timeout=60, headers={"User-Agent":"ZeroDayBugs-TermMax-Readonly/active-order-v1"})
            if response.status_code == 429:
                time.sleep(1.5*(attempt+1)); continue
            response.raise_for_status()
            payload=response.json()
            rows=payload.get("result",[]) if isinstance(payload,dict) else []
            if isinstance(rows,str):
                if "No records" in rows or "not found" in rows.lower(): rows=[]
                else: raise RuntimeError(str(payload))
            attempts.append({"transport":"routescan","ok":True,"rows":len(rows)})
            return rows,attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"transport":"routescan","ok":False,"error":f"{type(exc).__name__}: {exc}"})
            time.sleep(1.0*(attempt+1))
    return [],attempts


def token_row(w3: Web3, address: str, holder: str, block: int) -> dict[str, Any]:
    address=Web3.to_checksum_address(address)
    c=w3.eth.contract(address=address,abi=ERC20_ABI)
    return {
        "address":address,
        "symbol":safe(c.functions.symbol().call,block_identifier=block),
        "decimals":safe(c.functions.decimals().call,block_identifier=block),
        "totalSupply":safe(c.functions.totalSupply().call,block_identifier=block),
        "balance":safe(c.functions.balanceOf(Web3.to_checksum_address(holder)).call,block_identifier=block),
    }


def main() -> int:
    w3,rpc,rpc_attempts=connect()
    block=w3.eth.get_block("latest")
    rows=[]
    diagnostics=[]
    seen=set()
    for raw_market in MARKETS:
        market=Web3.to_checksum_address(raw_market)
        mc=w3.eth.contract(address=market,abi=MARKET_ABI)
        config=safe(mc.functions.config().call,block_identifier=block.number)
        tokens=safe(mc.functions.tokens().call,block_identifier=block.number)
        logs,log_attempts=routescan_market_orders(market,block.number)
        diagnostics.append({"market":market,"logAttempts":log_attempts,"logCount":len(logs)})
        if not tokens.get("ok"):
            rows.append({"market":market,"fatal":"tokens unavailable","tokens":tokens,"config":config})
            continue
        ft,xt,gt,collateral,debt=tokens["value"]
        for log in logs:
            topics=log.get("topics") or []
            if len(topics)<3: continue
            order=topic_address(topics[2])
            if order.lower() in seen: continue
            seen.add(order.lower())
            oc=w3.eth.contract(address=order,abi=ORDER_ABI)
            maker=safe(oc.functions.maker().call,block_identifier=block.number)
            omarket=safe(oc.functions.market().call,block_identifier=block.number)
            pool=safe(oc.functions.pool().call,block_identifier=block.number)
            paused=safe(oc.functions.paused().call,block_identifier=block.number)
            expiry=safe(oc.functions.orderExpiryTimestamp().call,block_identifier=block.number)
            virtual=safe(oc.functions.virtualXtReserve().call,block_identifier=block.number)
            reserves=safe(oc.functions.tokenReserves().call,block_identifier=block.number)
            real=safe(oc.functions.getRealReserves().call,block_identifier=block.number)
            order_config=safe(oc.functions.orderConfig().call,block_identifier=block.number)
            pool_row=None
            pool_address=(pool.get("value") if pool.get("ok") else ZERO)
            if pool_address and str(pool_address).lower()!=ZERO.lower():
                pc=w3.eth.contract(address=Web3.to_checksum_address(pool_address),abi=POOL_ABI)
                shares=safe(pc.functions.balanceOf(order).call,block_identifier=block.number)
                pool_row={
                    "address":pool_address,
                    "asset":safe(pc.functions.asset().call,block_identifier=block.number),
                    "shares":shares,
                    "assets":safe(pc.functions.convertToAssets(shares.get("value",0)).call,block_identifier=block.number) if shares.get("ok") else {"ok":False,"error":"share read failed"},
                }
            gt_link=None
            if order_config.get("ok"):
                try:
                    cfg=order_config["value"]
                    gt_id=int(cfg[1])
                    max_xt=int(cfg[2])
                    swap_trigger=cfg[3]
                    lend_count=len(cfg[0][0])
                    borrow_count=len(cfg[0][1])
                    order_config_compact={
                        "gtId":gt_id,"maxXtReserve":max_xt,"swapTrigger":swap_trigger,
                        "lendCurveCutCount":lend_count,"borrowCurveCutCount":borrow_count,
                    }
                    if gt_id:
                        gc=w3.eth.contract(address=Web3.to_checksum_address(gt),abi=GT_ABI)
                        gt_link={
                            "loanInfo":safe(gc.functions.loanInfo(gt_id).call,block_identifier=block.number),
                            "liquidationInfo":safe(gc.functions.getLiquidationInfo(gt_id).call,block_identifier=block.number),
                        }
                except Exception as exc:  # noqa: BLE001
                    order_config_compact={"decodeError":f"{type(exc).__name__}: {exc}","raw":order_config}
            else:
                order_config_compact=order_config
            row={
                "market":market,
                "marketConfig":config,
                "marketTokens":{"ft":ft,"xt":xt,"gt":gt,"collateral":collateral,"debt":debt},
                "createOrderLog":{"blockNumber":log.get("blockNumber"),"transactionHash":log.get("transactionHash"),"makerTopic":topics[1]},
                "order":order,
                "maker":maker,"marketBinding":omarket,"pool":pool_row,"paused":paused,"expiry":expiry,
                "expiryUtc":datetime.fromtimestamp(expiry.get("value",0),tz=timezone.utc).isoformat() if expiry.get("ok") and expiry.get("value") else None,
                "openAtPinnedBlock":bool(expiry.get("ok") and expiry.get("value",0)>block.timestamp and paused.get("ok") and paused.get("value") is False),
                "virtualXtReserve":virtual,"tokenReserves":reserves,"realReserves":real,
                "orderConfig":order_config_compact,"gtLink":gt_link,
                "balances":{
                    "ft":token_row(w3,ft,order,block.number),
                    "xt":token_row(w3,xt,order,block.number),
                    "debt":token_row(w3,debt,order,block.number),
                },
            }
            rows.append(row)
    open_rows=[r for r in rows if r.get("openAtPinnedBlock")]
    result={
        "schema":"termmax-active-order-liquidity/v1",
        "generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"impersonations":0,"stateChanges":0},
        "rpc":rpc,"rpcAttempts":rpc_attempts,
        "block":{"number":block.number,"hash":block.hash.hex(),"timestamp":block.timestamp,"timestampUtc":datetime.fromtimestamp(block.timestamp,tz=timezone.utc).isoformat()},
        "marketCount":len(MARKETS),"orderCount":len(rows),"openOrderCount":len(open_rows),
        "diagnostics":diagnostics,"orders":rows,
    }
    (OUT/"ACTIVE_ORDER_LIQUIDITY_FULL.json").write_text(json.dumps(result,indent=2,default=jdefault),encoding="utf-8")
    compact=[]
    for r in rows:
        def val(x,default=None): return x.get("value",default) if isinstance(x,dict) and x.get("ok") else default
        cfg=r.get("orderConfig") if isinstance(r.get("orderConfig"),dict) else {}
        compact.append({
            "market":r.get("market"),"order":r.get("order"),"maker":val(r.get("maker",{})),
            "open":r.get("openAtPinnedBlock"),"expiryUtc":r.get("expiryUtc"),"paused":val(r.get("paused",{})),
            "pool":(r.get("pool") or {}).get("address"),"poolAssets":val((r.get("pool") or {}).get("assets",{}),0),
            "ftReserve":(val(r.get("realReserves",{}),[0,0]) or [0,0])[0],
            "xtReserve":(val(r.get("realReserves",{}),[0,0]) or [0,0])[1],
            "debtBalance":val(r.get("balances",{}).get("debt",{}).get("balance",{}),0),
            "gtId":cfg.get("gtId"),"gtDebt":((val((r.get("gtLink") or {}).get("loanInfo",{}),[None,0,None]) or [None,0,None])[1] if r.get("gtLink") else 0),
            "lendCurveCutCount":cfg.get("lendCurveCutCount"),"borrowCurveCutCount":cfg.get("borrowCurveCutCount"),
        })
    (OUT/"ACTIVE_ORDER_LIQUIDITY_COMPACT.json").write_text(json.dumps(compact,indent=2,default=jdefault),encoding="utf-8")
    print(json.dumps({"block":result["block"],"orderCount":len(rows),"openOrderCount":len(open_rows),"compact":compact},indent=2,default=jdefault))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
