#!/usr/bin/env python3
"""Read-only liquidity census for the active Berachain TermMax market.

Enumerates CreateOrder events and measures direct token reserves, ERC-4626 pool
assets, and real FT/XT reserves. No signer, transaction, impersonation, or state
change is used.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

OUT = Path("evidence")
OUT.mkdir(parents=True, exist_ok=True)
MARKET = Web3.to_checksum_address("0x6544AAAb071c8a37553f849bBBCFD615cfacB55E")
FROM_BLOCK = 19609794
RPCS = ["https://rpc.berachain.com", "https://berachain-rpc.publicnode.com", "https://berachain.drpc.org"]
CREATE_ORDER_TOPIC = Web3.to_hex(Web3.keccak(text="CreateOrder(address,address)"))
ZERO = "0x0000000000000000000000000000000000000000"

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
]
ORDER_ABI = [
    {"type":"function","name":"maker","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"tokenReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
    {"type":"function","name":"getRealReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
    {"type":"function","name":"virtualXtReserve","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"orderExpiryTimestamp","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]
POOL_ABI = ERC20_ABI + [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
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
            w3=Web3(Web3.HTTPProvider(url,request_kwargs={"timeout":30}))
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware,layer=0)
            if w3.eth.chain_id != 80094: raise RuntimeError(f"wrong chain {w3.eth.chain_id}")
            latest=w3.eth.block_number
            attempts.append({"url":url,"ok":True,"latest":latest})
            return w3,url,attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def topic_address(value: str) -> str:
    raw=value[2:] if value.startswith("0x") else value
    return Web3.to_checksum_address("0x"+raw[-40:])


def token(w3:Web3,address:str,holder:str,block:int)->dict[str,Any]:
    c=w3.eth.contract(address=Web3.to_checksum_address(address),abi=ERC20_ABI)
    return {"address":address,"symbol":safe(c.functions.symbol().call,block_identifier=block),
            "decimals":safe(c.functions.decimals().call,block_identifier=block),
            "balance":safe(c.functions.balanceOf(holder).call,block_identifier=block)}


def main()->int:
    w3,rpc,attempts=connect(); latest=w3.eth.block_number; block=w3.eth.get_block(latest)
    market=w3.eth.contract(address=MARKET,abi=MARKET_ABI); tokens=market.functions.tokens().call(block_identifier=latest)
    ft,xt,gt,collateral,debt=tokens
    response=requests.get("https://api.routescan.io/v2/network/mainnet/evm/80094/etherscan/api",params={
        "module":"logs","action":"getLogs","fromBlock":str(FROM_BLOCK),"toBlock":str(latest),
        "address":MARKET,"topic0":CREATE_ORDER_TOPIC,
    },timeout=45,headers={"User-Agent":"ZeroDayBugs-TermMax-ReadOnly/1.0"})
    response.raise_for_status(); payload=response.json(); logs=payload.get("result",[])
    orders=sorted({topic_address(x["topics"][2]) for x in logs if len(x.get("topics",[]))>=3})
    rows=[]
    total_direct_debt=0; total_pool_assets=0; total_real_xt=0
    for address in orders:
        c=w3.eth.contract(address=address,abi=ORDER_ABI)
        pool_r=safe(c.functions.pool().call,block_identifier=latest)
        direct_debt=token(w3,debt,address,latest); ft_row=token(w3,ft,address,latest); xt_row=token(w3,xt,address,latest)
        direct_raw=int(direct_debt["balance"]["value"]) if direct_debt["balance"].get("ok") else 0
        pool_row=None; pool_assets=0
        if pool_r.get("ok") and pool_r["value"].lower()!=ZERO.lower():
            pool_addr=Web3.to_checksum_address(pool_r["value"]); pool=w3.eth.contract(address=pool_addr,abi=POOL_ABI)
            shares_r=safe(pool.functions.balanceOf(address).call,block_identifier=latest)
            shares=int(shares_r["value"]) if shares_r.get("ok") else 0
            preview=safe(pool.functions.previewRedeem(shares).call,block_identifier=latest)
            convert=safe(pool.functions.convertToAssets(shares).call,block_identifier=latest)
            maxw=safe(pool.functions.maxWithdraw(address).call,block_identifier=latest)
            pool_assets=int(preview["value"]) if preview.get("ok") else 0
            pool_row={"address":pool_addr,"asset":safe(pool.functions.asset().call,block_identifier=latest),
                      "shares":shares_r,"previewRedeem":preview,"convertToAssets":convert,"maxWithdraw":maxw}
        real=safe(c.functions.getRealReserves().call,block_identifier=latest)
        real_xt=int(real["value"][1]) if real.get("ok") else 0
        total_direct_debt+=direct_raw; total_pool_assets+=pool_assets; total_real_xt+=real_xt
        rows.append({"order":address,"maker":safe(c.functions.maker().call,block_identifier=latest),
                     "expiry":safe(c.functions.orderExpiryTimestamp().call,block_identifier=latest),
                     "virtualXtReserve":safe(c.functions.virtualXtReserve().call,block_identifier=latest),
                     "tokenReserves":safe(c.functions.tokenReserves().call,block_identifier=latest),
                     "realReserves":real,"ft":ft_row,"xt":xt_row,"debtToken":direct_debt,
                     "pool":pool_row,"directDebtRaw":direct_raw,"poolAssetsRaw":pool_assets,"realXtRaw":real_xt})
    summary={"orderEventCount":len(logs),"orderCount":len(rows),"totalDirectDebtRaw":total_direct_debt,
             "totalPoolAssetsRaw":total_pool_assets,"totalRealXtRaw":total_real_xt,
             "materialDebtExitLiquidityRaw":total_direct_debt+total_pool_assets+total_real_xt}
    result={"schema":"termmax-bera-order-liquidity/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),
            "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
            "rpc":rpc,"rpcAttempts":attempts,"block":{"number":latest,"hash":block.hash.hex(),"timestamp":int(block.timestamp)},
            "market":MARKET,"tokens":{"ft":ft,"xt":xt,"gt":gt,"collateral":collateral,"debtToken":debt},
            "explorerPayloadStatus":payload.get("status"),"explorerPayloadMessage":payload.get("message"),
            "summary":summary,"orders":rows}
    (OUT/"BERA_ORDER_LIQUIDITY_FULL.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    (OUT/"SUMMARY.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary,indent=2)); return 0

if __name__=="__main__": raise SystemExit(main())
