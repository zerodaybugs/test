#!/usr/bin/env python3
"""Read-only inventory of every official TermMax Router deployment.

The workflow clones the public TermMax repository, recursively extracts Router
addresses from deployment manifests, then reads code, proxy implementation,
ownership, pause/version state, and current ERC-20 holdings. No signer, private
key, transaction construction, simulation, or state mutation is included.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

OUT=Path(os.environ.get("OUT_DIR","evidence")); OUT.mkdir(parents=True,exist_ok=True)
REPO=Path(os.environ.get("TERMMAX_REPO","/tmp/termmax-contract-v2"))
IMPLEMENTATION_SLOT=int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",16)
CHAIN_FILTER=os.environ.get("CHAIN","all").strip().lower()

CHAINS={
 "eth-mainnet":{"name":"ethereum","chainId":1,"routescanId":1,"poa":False,"rpcs":["https://ethereum-rpc.publicnode.com","https://rpc.mevblocker.io","https://eth.drpc.org"]},
 "ethereum":{"name":"ethereum","chainId":1,"routescanId":1,"poa":False,"rpcs":["https://ethereum-rpc.publicnode.com","https://rpc.mevblocker.io","https://eth.drpc.org"]},
 "arbitrum-mainnet":{"name":"arbitrum","chainId":42161,"routescanId":42161,"poa":False,"rpcs":["https://arb1.arbitrum.io/rpc","https://arbitrum-one-rpc.publicnode.com","https://arbitrum.drpc.org"]},
 "bsc-mainnet":{"name":"bnb","chainId":56,"routescanId":56,"poa":True,"rpcs":["https://bsc-dataseed.binance.org","https://bsc-rpc.publicnode.com","https://bsc.drpc.org"]},
 "bnb-mainnet":{"name":"bnb","chainId":56,"routescanId":56,"poa":True,"rpcs":["https://bsc-dataseed.binance.org","https://bsc-rpc.publicnode.com","https://bsc.drpc.org"]},
 "base-mainnet":{"name":"base","chainId":8453,"routescanId":8453,"poa":False,"rpcs":["https://mainnet.base.org","https://base-rpc.publicnode.com","https://base.drpc.org"]},
 "b2-mainnet":{"name":"b2","chainId":223,"routescanId":223,"poa":False,"rpcs":["https://rpc.bsquared.network","https://b2-mainnet.alt.technology"]},
 "berachain-mainnet":{"name":"berachain","chainId":80094,"routescanId":80094,"poa":False,"rpcs":["https://rpc.berachain.com","https://berachain-rpc.publicnode.com"]},
 "xlayer-mainnet":{"name":"xlayer","chainId":196,"routescanId":196,"poa":False,"rpcs":["https://rpc.xlayer.tech","https://xlayerrpc.okx.com"]},
 "pharos-mainnet":{"name":"pharos","chainId":688688,"routescanId":688688,"poa":False,"rpcs":["https://rpc.pharosnetwork.xyz","https://api.pharosnetwork.xyz"]},
 "hyperliquid-mainnet":{"name":"hyperevm","chainId":999,"routescanId":999,"poa":False,"rpcs":["https://rpc.hyperliquid.xyz/evm"]},
}

ROUTER_ABI=[
 {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
 {"type":"function","name":"owner","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 {"type":"function","name":"getVersion","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]
ERC20_ABI=[
 {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
 {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
 {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
ADDRESS_RE=re.compile(r"^0x[a-fA-F0-9]{40}$")
ROUTER_KEY_RE=re.compile(r"router",re.I)


def safe(fn,*args,**kwargs)->dict[str,Any]:
 try:
  value=fn(*args,**kwargs)
  if isinstance(value,tuple): value=list(value)
  return {"ok":True,"value":value}
 except Exception as exc: return {"ok":False,"error":f"{type(exc).__name__}: {exc}"}

def val(result:dict[str,Any],fallback:Any=None)->Any: return result.get("value",fallback) if result.get("ok") else fallback

def clone_repo()->None:
 if REPO.exists(): return
 subprocess.run(["git","clone","--quiet","--depth","1","https://github.com/term-structure/termmax-contract-v2.git",str(REPO)],check=True)

def chain_from_path(path:Path)->dict[str,Any]|None:
 lower="/".join(x.lower() for x in path.parts)
 for key,cfg in CHAINS.items():
  if key in lower: return cfg
 return None

def walk_router_values(node:Any,path:list[str],out:list[dict[str,Any]])->None:
 if isinstance(node,dict):
  contract_name=str(node.get("contractName") or node.get("contract") or node.get("name") or "")
  address=node.get("address") or node.get("proxy") or node.get("proxyAddress")
  label="/".join(path+[contract_name])
  if isinstance(address,str) and ADDRESS_RE.match(address) and (ROUTER_KEY_RE.search(label) or ROUTER_KEY_RE.search(contract_name)):
   out.append({"address":Web3.to_checksum_address(address),"label":label,"contractName":contract_name})
  for key,value in node.items():
   if isinstance(value,str) and ADDRESS_RE.match(value) and ROUTER_KEY_RE.search(str(key)):
    out.append({"address":Web3.to_checksum_address(value),"label":"/".join(path+[str(key)]),"contractName":str(key)})
   walk_router_values(value,path+[str(key)],out)
 elif isinstance(node,list):
  for i,value in enumerate(node): walk_router_values(value,path+[str(i)],out)

def extract_deployments()->list[dict[str,Any]]:
 rows=[]
 for path in REPO.rglob("*.json"):
  if "deployment" not in str(path).lower() and "broadcast" not in str(path).lower(): continue
  cfg=chain_from_path(path)
  if not cfg: continue
  try: data=json.loads(path.read_text(encoding="utf-8"))
  except Exception: continue
  found=[]; walk_router_values(data,[],found)
  for row in found:
   rows.append({**row,"chain":cfg["name"],"chainId":cfg["chainId"],"manifest":str(path.relative_to(REPO))})
 unique={}
 for row in rows:
  key=(row["chain"],row["address"].lower())
  unique.setdefault(key,row)
 return sorted(unique.values(),key=lambda x:(x["chain"],x["address"]))

def connect(cfg:dict[str,Any])->tuple[Web3,str,list[dict[str,Any]]]:
 attempts=[]
 for url in [os.environ.get(f"{cfg['name'].upper()}_RPC_URL","").strip(),*cfg["rpcs"]]:
  if not url: continue
  try:
   w3=Web3(Web3.HTTPProvider(url,request_kwargs={"timeout":35}))
   if cfg.get("poa"): w3.middleware_onion.inject(ExtraDataToPOAMiddleware,layer=0)
   cid=w3.eth.chain_id; latest=w3.eth.block_number; block=w3.eth.get_block(latest)
   if cid!=cfg["chainId"]: raise RuntimeError(f"unexpected chain id {cid}")
   attempts.append({"url":url,"ok":True,"block":latest,"hash":block.hash.hex()}); return w3,url,attempts
  except Exception as exc: attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
 raise RuntimeError(json.dumps(attempts))

def holdings_api(cfg:dict[str,Any],address:str)->tuple[list[dict[str,Any]],dict[str,Any]]:
 urls=[
  f"https://api.routescan.io/v2/network/mainnet/evm/{cfg['routescanId']}/erc20/{address}/holdings?limit=100",
  f"https://api.routescan.io/v2/network/mainnet/evm/{cfg['routescanId']}/address/{address}/erc20-holdings?limit=100",
 ]
 diagnostics=[]
 for url in urls:
  try:
   r=requests.get(url,timeout=60,headers={"User-Agent":"ZeroDayBugs-TermMax-AllRouter/1"}); diagnostics.append({"url":url,"status":r.status_code})
   if r.status_code!=200: continue
   payload=r.json(); items=payload.get("items") or payload.get("result") or payload.get("data") or []
   if isinstance(items,list): return items,{"ok":True,"attempts":diagnostics}
  except Exception as exc: diagnostics.append({"url":url,"error":f"{type(exc).__name__}: {exc}"})
 return [],{"ok":False,"attempts":diagnostics}

def parse_holding_item(item:dict[str,Any])->tuple[str|None,int]:
 token=item.get("tokenAddress") or item.get("address") or (item.get("token") or {}).get("address") or item.get("contractAddress")
 balance=item.get("balance") or item.get("value") or item.get("amount") or 0
 try:
  raw=int(str(balance),16) if str(balance).lower().startswith("0x") else int(str(balance))
 except Exception: raw=0
 try: token=Web3.to_checksum_address(token) if token else None
 except Exception: token=None
 return token,raw

def token_row(w3:Web3,token_address:str,router_address:str,block:int,api_raw:int|None=None)->dict[str,Any]:
 c=w3.eth.contract(address=token_address,abi=ERC20_ABI)
 balance_r=safe(c.functions.balanceOf(router_address).call,block_identifier=block)
 raw=int(val(balance_r,api_raw or 0) or 0); dec_r=safe(c.functions.decimals().call,block_identifier=block); dec=val(dec_r)
 human=None
 if dec is not None:
  try: human=raw/(10**int(dec))
  except Exception: pass
 return {"token":token_address,"balanceRaw":raw,"balanceHuman":human,"symbol":safe(c.functions.symbol().call,block_identifier=block),"name":safe(c.functions.name().call,block_identifier=block),"decimals":dec_r,"nonzero":raw>0}

def inspect_router(deployment:dict[str,Any],connections:dict[str,tuple[Web3,str,list[dict[str,Any]]]])->dict[str,Any]:
 cfg=next(x for x in CHAINS.values() if x["name"]==deployment["chain"])
 if deployment["chain"] not in connections: connections[deployment["chain"]]=connect(cfg)
 w3,rpc,attempts=connections[deployment["chain"]]; latest=w3.eth.block_number; block=w3.eth.get_block(latest); address=deployment["address"]
 code=w3.eth.get_code(address,block_identifier=latest); c=w3.eth.contract(address=address,abi=ROUTER_ABI)
 impl_raw=w3.eth.get_storage_at(address,IMPLEMENTATION_SLOT,block_identifier=latest); impl=Web3.to_checksum_address("0x"+impl_raw.hex()[-40:]) if int.from_bytes(impl_raw,"big") else None
 items,diag=holdings_api(cfg,address); tokens={}
 for item in items:
  token,raw=parse_holding_item(item)
  if token: tokens[token.lower()]=(token,raw)
 token_rows=[token_row(w3,t,a,latest,raw) for t,raw in tokens.values() for a in [address]]
 nonzero=[x for x in token_rows if x["nonzero"]]
 return {**deployment,"rpc":rpc,"rpcAttempts":attempts,"block":{"number":latest,"hash":block.hash.hex(),"timestamp":int(block.timestamp),"timestampUtc":datetime.fromtimestamp(block.timestamp,tz=timezone.utc).isoformat()},"codeBytes":len(code),"runtimeKeccak":Web3.keccak(code).hex(),"implementation":impl,"implementationCodeBytes":len(w3.eth.get_code(impl,block_identifier=latest)) if impl else 0,"paused":safe(c.functions.paused().call,block_identifier=latest),"owner":safe(c.functions.owner().call,block_identifier=latest),"version":safe(c.functions.getVersion().call,block_identifier=latest),"holdingsDiagnostics":diag,"tokenCount":len(token_rows),"nonzeroTokenCount":len(nonzero),"tokens":token_rows,"nonzeroTokens":nonzero}

def main()->int:
 clone_repo(); deployments=extract_deployments()
 if CHAIN_FILTER!="all": deployments=[x for x in deployments if x["chain"]==CHAIN_FILTER]
 connections={}; rows=[]
 for item in deployments:
  try: rows.append(inspect_router(item,connections))
  except Exception as exc: rows.append({**item,"fatalError":f"{type(exc).__name__}: {exc}"})
 nonzero=[{"chain":r.get("chain"),"router":r.get("address"),"label":r.get("label"),"version":val(r.get("version",{})),"paused":val(r.get("paused",{})),"tokens":r.get("nonzeroTokens",[])} for r in rows if r.get("nonzeroTokenCount",0)>0]
 summary={"schema":"termmax-all-router-inventory/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),"safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},"chainFilter":CHAIN_FILTER,"deploymentCount":len(deployments),"routerCount":len(rows),"nonzeroRouterCount":len(nonzero),"nonzeroRouters":nonzero,"routers":rows}
 (OUT/"ALL_ROUTER_INVENTORY_FULL.json").write_text(json.dumps(summary,indent=2,default=str),encoding="utf-8")
 compact={k:summary[k] for k in ["generatedAtUtc","chainFilter","deploymentCount","routerCount","nonzeroRouterCount","nonzeroRouters"]}
 (OUT/"ALL_ROUTER_INVENTORY_COMPACT.json").write_text(json.dumps(compact,indent=2,default=str),encoding="utf-8")
 print(json.dumps(compact,indent=2,default=str)); return 0
if __name__=="__main__": raise SystemExit(main())
