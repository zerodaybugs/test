#!/usr/bin/env python3
"""Read-only TermMax V2 vault asset/market debt-token binding census.

The scanner discovers public V2 vaults from known official factories and the
public DefiLlama TermMax pool index. For every observed NewOrderCreated event it
compares vault.asset() against market.tokens().debtToken and records whether the
order is still active and holds FT inventory.

No private key, signer, transaction construction, or state-changing call exists.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from hexbytes import HexBytes
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
CHAIN_FILTER = os.environ.get("CHAIN", "all").strip().lower()

CHAINS: list[dict[str, Any]] = [
    {
        "name":"ethereum","chainId":1,"routescanId":1,"defillama":"Ethereum","poa":False,
        "rpcs":["https://ethereum-rpc.publicnode.com","https://rpc.mevblocker.io","https://eth.drpc.org"],
        "factories":[
            ("0x5b8B26a6734B5eABDBe6C5A19580Ab2D0424f027",23_400_000),
            ("0xF2BDa87CA467eB90A1b68f824cB136baA68a8177",23_400_000),
        ],
    },
    {
        "name":"arbitrum","chainId":42161,"routescanId":42161,"defillama":"Arbitrum","poa":False,
        "rpcs":["https://arb1.arbitrum.io/rpc","https://arbitrum-one-rpc.publicnode.com","https://arbitrum.drpc.org"],
        "factories":[
            ("0xa7c93162962D050098f4BB44E88661517484C5EB",385_228_046),
            ("0x18b8A9433dBefcd15370F10a75e28149bcc2e301",385_228_046),
        ],
    },
    {
        "name":"bnb","chainId":56,"routescanId":56,"defillama":"BSC","poa":True,
        "rpcs":["https://bsc-dataseed.binance.org","https://bsc-rpc.publicnode.com","https://bsc.drpc.org"],
        "factories":[
            ("0x1401049368eD6AD8194f8bb7E41732c4620F170b",63_100_000),
            ("0xdffE6De6de1dB8e1B5Ce77D3222eba401C2573b5",63_100_000),
        ],
    },
    {
        "name":"base","chainId":8453,"routescanId":8453,"defillama":"Base","poa":False,
        "rpcs":["https://mainnet.base.org","https://base-rpc.publicnode.com","https://base.drpc.org"],
        "factories":[("0xDA4aAF85Bb924B53DCc2DFFa9e1A9C2Ef97aCFDF",43_289_755)],
    },
]

VAULT_CREATED_TOPIC = Web3.keccak(
    text="VaultCreated(address,address,(address,address,address,uint256,address,address,uint256,string,string,uint64,uint64))"
).hex()
NEW_ORDER_TOPIC = Web3.keccak(text="NewOrderCreated(address,address,address)").hex()

VAULT_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ORDER_ABI = [
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address"},{"type":"uint64"},{"type":"tuple","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]


def default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, HexBytes)):
        return "0x" + bytes(value).hex()
    return str(value)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok":True,"value":value}
    except Exception as exc:  # noqa: BLE001
        return {"ok":False,"error":f"{type(exc).__name__}: {exc}"}


def val(result: dict[str, Any], fallback: Any = None) -> Any:
    return result.get("value", fallback) if result.get("ok") else fallback


def parse_int(value: Any) -> int:
    if isinstance(value, int): return value
    text = str(value or "0")
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def topic_address(value: str) -> str:
    raw = value[2:] if value.startswith("0x") else value
    return Web3.to_checksum_address("0x" + raw[-40:])


def connect(config: dict[str, Any]) -> tuple[Web3,str,list[dict[str,Any]]]:
    attempts=[]
    urls=[os.environ.get(f"{config['name'].upper()}_RPC_URL","").strip(),*config["rpcs"]]
    for url in [x for x in urls if x]:
        try:
            w3=Web3(Web3.HTTPProvider(url,request_kwargs={"timeout":35}))
            if config.get("poa"):
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware,layer=0)
            cid=w3.eth.chain_id; latest=w3.eth.block_number; block=w3.eth.get_block(latest)
            if cid!=config["chainId"]: raise RuntimeError(f"unexpected chain id {cid}")
            attempts.append({"url":url,"ok":True,"block":latest,"hash":block.hash.hex()})
            return w3,url,attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def routescan_logs(config: dict[str,Any], address: str, from_block: int, to_block: int, topic0: str) -> list[dict[str,Any]]:
    url=f"https://api.routescan.io/v2/network/mainnet/evm/{config['routescanId']}/etherscan/api"
    output=[]; page=1
    while True:
        params={"module":"logs","action":"getLogs","address":address,"fromBlock":from_block,"toBlock":to_block,"topic0":topic0,"page":page,"offset":1000}
        payload=None; last=None
        for attempt in range(6):
            try:
                r=requests.get(url,params=params,timeout=60,headers={"User-Agent":"ZeroDayBugs-TermMax-VaultBinding/1"})
                if r.status_code==429: time.sleep(1.5*(attempt+1)); continue
                r.raise_for_status(); payload=r.json(); break
            except Exception as exc:  # noqa: BLE001
                last=exc; time.sleep(1.25*(attempt+1))
        if payload is None: raise RuntimeError(f"Routescan failure: {last}")
        rows=payload.get("result",[]) if isinstance(payload,dict) else []
        if isinstance(rows,str):
            if "No" in rows or "not found" in rows.lower(): break
            raise RuntimeError(str(payload))
        if not rows: break
        output.extend(rows)
        if len(rows)<1000: break
        page+=1
    return output


def rpc_logs(w3: Web3,address: str,from_block: int,to_block: int,topic0: str) -> list[Any]:
    output=[]; cursor=from_block; sizes=[100_000,20_000,5_000,1_000]; idx=0
    while cursor<=to_block:
        end=min(to_block,cursor+sizes[idx]-1)
        try:
            output.extend(w3.eth.get_logs({"address":address,"fromBlock":cursor,"toBlock":end,"topics":[topic0]}))
            cursor=end+1; idx=0
        except Exception:
            if idx+1<len(sizes): idx+=1
            else: raise
    return output


def get_logs(w3:Web3,config:dict[str,Any],address:str,start:int,end:int,topic0:str)->list[Any]:
    try:
        return routescan_logs(config,address,start,end,topic0)
    except Exception:
        return rpc_logs(w3,address,start,end,topic0)


def llama_vaults(config:dict[str,Any])->list[str]:
    try:
        payload=requests.get("https://yields.llama.fi/pools",timeout=60,headers={"User-Agent":"ZeroDayBugs-TermMax-VaultBinding/1"}).json()
        rows=payload.get("data",[]) if isinstance(payload,dict) else []
        out=[]
        for row in rows:
            if str(row.get("project","")).lower()!="termmax": continue
            if str(row.get("chain","")).lower()!=str(config["defillama"]).lower(): continue
            address=str(row.get("pool","")).split("-",1)[0]
            if address.startswith("0x") and len(address)==42:
                try: out.append(Web3.to_checksum_address(address))
                except ValueError: pass
        return out
    except Exception:
        return []


def token_meta(w3:Web3,address:str,block:int)->dict[str,Any]:
    c=w3.eth.contract(address=Web3.to_checksum_address(address),abi=ERC20_ABI)
    return {"address":Web3.to_checksum_address(address),"symbol":safe(c.functions.symbol().call,block_identifier=block),"decimals":safe(c.functions.decimals().call,block_identifier=block)}


def inspect_order(w3:Web3,vault_c,order_address:str,block:int,timestamp:int)->dict[str,Any]:
    order_address=Web3.to_checksum_address(order_address)
    order=w3.eth.contract(address=order_address,abi=ORDER_ABI)
    market_r=safe(order.functions.market().call,block_identifier=block)
    maturity_r=safe(vault_c.functions.orderMaturity(order_address).call,block_identifier=block)
    row={"order":order_address,"market":market_r,"vaultOrderMaturity":maturity_r,"active":int(val(maturity_r,0) or 0)>0}
    market_address=val(market_r)
    if not market_address: return row
    market_address=Web3.to_checksum_address(market_address)
    market=w3.eth.contract(address=market_address,abi=MARKET_ABI)
    tokens_r=safe(market.functions.tokens().call,block_identifier=block)
    cfg_r=safe(market.functions.config().call,block_identifier=block)
    row.update({"marketAddress":market_address,"tokens":tokens_r,"config":cfg_r,"paused":safe(market.functions.paused().call,block_identifier=block)})
    tokens=val(tokens_r)
    if not tokens or len(tokens)!=5: return row
    ft,xt,gt,collateral,debt=[Web3.to_checksum_address(x) for x in tokens]
    cfg=val(cfg_r); maturity=int(cfg[1]) if cfg else 0
    ft_c=w3.eth.contract(address=ft,abi=ERC20_ABI)
    row.update({
        "ft":token_meta(w3,ft,block),"xt":xt,"gt":gt,"collateral":token_meta(w3,collateral,block),"debtToken":token_meta(w3,debt,block),
        "marketMaturity":maturity,"marketMatured":bool(maturity and timestamp>=maturity),
        "ftBalanceAtOrder":safe(ft_c.functions.balanceOf(order_address).call,block_identifier=block),
    })
    return row


def inspect_vault(w3:Web3,config:dict[str,Any],vault_address:str,start_block:int,block:int,timestamp:int)->dict[str,Any]:
    vault_address=Web3.to_checksum_address(vault_address)
    vault=w3.eth.contract(address=vault_address,abi=VAULT_ABI)
    asset_r=safe(vault.functions.asset().call,block_identifier=block)
    row={
        "vault":vault_address,"name":safe(vault.functions.name().call,block_identifier=block),"symbol":safe(vault.functions.symbol().call,block_identifier=block),
        "asset":asset_r,"totalAssets":safe(vault.functions.totalAssets().call,block_identifier=block),"totalSupply":safe(vault.functions.totalSupply().call,block_identifier=block),
        "paused":safe(vault.functions.paused().call,block_identifier=block),"orders":[],
    }
    asset=val(asset_r)
    row["assetMeta"]=token_meta(w3,asset,block) if asset else None
    logs=get_logs(w3,config,vault_address,start_block,block,NEW_ORDER_TOPIC)
    seen=[]
    for log in logs:
        topics=log.get("topics",[]) if isinstance(log,dict) else log["topics"]
        if len(topics)<4: continue
        raw=topics[3].hex() if hasattr(topics[3],"hex") else str(topics[3])
        try: seen.append(topic_address(raw))
        except Exception: pass
    for order in dict.fromkeys(seen):
        item=inspect_order(w3,vault,order,block,timestamp)
        debt=(item.get("debtToken") or {}).get("address")
        item["assetDebtMatch"]=bool(asset and debt and asset.lower()==debt.lower())
        item["dangerousCurrentMismatch"]=bool(
            item.get("active") and not item.get("marketMatured") and not item["assetDebtMatch"] and int(val(item.get("ftBalanceAtOrder",{}),0) or 0)>0
        )
        row["orders"].append(item)
    row["mismatches"]=[o for o in row["orders"] if o.get("assetDebtMatch") is False]
    row["dangerousCurrentMismatches"]=[o for o in row["orders"] if o.get("dangerousCurrentMismatch")]
    return row


def inspect_chain(config:dict[str,Any])->dict[str,Any]:
    w3,rpc,attempts=connect(config); latest=w3.eth.block_number; block=w3.eth.get_block(latest); timestamp=int(block.timestamp)
    vaults:dict[str,tuple[str,int,str]]={}
    for factory,start in config["factories"]:
        factory=Web3.to_checksum_address(factory)
        try:
            logs=get_logs(w3,config,factory,start,latest,VAULT_CREATED_TOPIC)
            for log in logs:
                topics=log.get("topics",[]) if isinstance(log,dict) else log["topics"]
                if len(topics)>=2:
                    raw=topics[1].hex() if hasattr(topics[1],"hex") else str(topics[1])
                    address=topic_address(raw); bn=parse_int(log.get("blockNumber") if isinstance(log,dict) else log["blockNumber"])
                    vaults[address.lower()]=(address,bn,"factory")
        except Exception as exc:  # noqa: BLE001
            (OUT/f"{config['name']}_factory_errors.log").open("a",encoding="utf-8").write(f"{factory}: {type(exc).__name__}: {exc}\n")
    minimum=min(x[1] for x in config["factories"])
    for address in llama_vaults(config): vaults.setdefault(address.lower(),(address,minimum,"defillama"))
    rows=[]
    for address,start,source in vaults.values():
        try:
            item=inspect_vault(w3,config,address,start,latest,timestamp); item["discoverySource"]=source; rows.append(item)
        except Exception as exc:  # noqa: BLE001
            rows.append({"vault":address,"discoverySource":source,"fatalError":f"{type(exc).__name__}: {exc}"})
    mismatches=[]; dangerous=[]
    for vault in rows:
        for order in vault.get("mismatches",[]): mismatches.append({"vault":vault["vault"],"vaultName":val(vault.get("name",{})),**order})
        for order in vault.get("dangerousCurrentMismatches",[]): dangerous.append({"vault":vault["vault"],"vaultName":val(vault.get("name",{})),**order})
    return {
        "chain":config["name"],"chainId":config["chainId"],"rpc":rpc,"rpcAttempts":attempts,
        "block":{"number":latest,"hash":block.hash.hex(),"timestamp":timestamp,"timestampUtc":datetime.fromtimestamp(timestamp,tz=timezone.utc).isoformat()},
        "vaultCount":len(rows),"orderCount":sum(len(v.get("orders",[])) for v in rows),"mismatchCount":len(mismatches),
        "dangerousCurrentMismatchCount":len(dangerous),"mismatches":mismatches,"dangerousCurrentMismatches":dangerous,"vaults":rows,
    }


def main()->int:
    selected=[c for c in CHAINS if CHAIN_FILTER in {"all",c["name"]}]
    results=[]
    for config in selected:
        try: results.append(inspect_chain(config))
        except Exception as exc: results.append({"chain":config["name"],"chainId":config["chainId"],"fatalError":f"{type(exc).__name__}: {exc}"})
    dangerous=[x for chain in results for x in chain.get("dangerousCurrentMismatches",[])]
    all_mismatches=[x for chain in results for x in chain.get("mismatches",[])]
    summary={
        "schema":"termmax-vault-asset-binding-census/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "chainFilter":CHAIN_FILTER,"chainCount":len(results),"vaultCount":sum(x.get("vaultCount",0) for x in results),
        "orderCount":sum(x.get("orderCount",0) for x in results),"mismatchCount":len(all_mismatches),
        "dangerousCurrentMismatchCount":len(dangerous),"mismatches":all_mismatches,"dangerousCurrentMismatches":dangerous,
        "nextStep":"LOCAL_FORK_EXPLOIT" if dangerous else "KILL_NO_CURRENT_ASSET_DEBT_MISMATCH",
        "chains":results,
    }
    (OUT/"VAULT_ASSET_BINDING_FULL.json").write_text(json.dumps(summary,indent=2,default=default),encoding="utf-8")
    compact={k:summary[k] for k in ["generatedAtUtc","chainFilter","chainCount","vaultCount","orderCount","mismatchCount","dangerousCurrentMismatchCount","mismatches","dangerousCurrentMismatches","nextStep"]}
    (OUT/"VAULT_ASSET_BINDING_COMPACT.json").write_text(json.dumps(compact,indent=2,default=default),encoding="utf-8")
    print(json.dumps(compact,indent=2,default=default))
    return 0

if __name__=="__main__": raise SystemExit(main())
