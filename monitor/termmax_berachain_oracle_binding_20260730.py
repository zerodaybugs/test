#!/usr/bin/env python3
"""Read-only Berachain TermMax market/oracle/feed binding scanner.

The scanner clones the public TermMax repository, extracts Berachain deployment
addresses and labels, identifies live markets by interface probing, resolves each
market GT oracle and collateral feed, and flags active exposure to Beefy/Kodiak
price adapters. It performs no signing, transaction construction, simulation, or
state mutation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3

OUT=Path(os.environ.get("OUT_DIR","evidence")); OUT.mkdir(parents=True,exist_ok=True)
REPO=Path(os.environ.get("TERMMAX_REPO","/tmp/termmax-contract-v2"))
RPCS=[os.environ.get("BERACHAIN_RPC_URL","").strip(),"https://rpc.berachain.com","https://berachain-rpc.publicnode.com"]
ADDRESS_RE=re.compile(r"^0x[a-fA-F0-9]{40}$")

MARKET_ABI=[
 {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},
 {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}]}]}]},
 {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
]
GT_ABI=[
 {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"address"},{"type":"uint32"},{"type":"uint32"},{"type":"bool"}]}]}]},
]
ORACLE_ABI=[
 {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address"},{"type":"address"},{"type":"int256"},{"type":"int256"},{"type":"uint32"},{"type":"uint32"}]},
 {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
ERC20_ABI=[
 {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
 {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
 {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
FEED_ABI=[
 {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[{"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}]},
 {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
COMMON_ABIS={
 "vault":{"type":"function","name":"vault","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "beefyVault":{"type":"function","name":"beefyVault","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "underlying":{"type":"function","name":"underlying","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "want":{"type":"function","name":"want","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "island":{"type":"function","name":"island","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "token0":{"type":"function","name":"token0","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "token1":{"type":"function","name":"token1","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "pool":{"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "priceFeed":{"type":"function","name":"priceFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "token0PriceFeed":{"type":"function","name":"token0PriceFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
 "token1PriceFeed":{"type":"function","name":"token1PriceFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
}


def safe(fn,*args,**kwargs)->dict[str,Any]:
 try:
  value=fn(*args,**kwargs)
  if isinstance(value,tuple): value=list(value)
  return {"ok":True,"value":value}
 except Exception as exc: return {"ok":False,"error":f"{type(exc).__name__}: {exc}"}

def val(r:dict[str,Any],default:Any=None)->Any: return r.get("value",default) if r.get("ok") else default

def clone()->None:
 if not REPO.exists(): subprocess.run(["git","clone","--quiet","--depth","1","https://github.com/term-structure/termmax-contract-v2.git",str(REPO)],check=True)

def connect()->tuple[Web3,str,list[dict[str,Any]]]:
 attempts=[]
 for url in [x for x in RPCS if x]:
  try:
   w3=Web3(Web3.HTTPProvider(url,request_kwargs={"timeout":35})); cid=w3.eth.chain_id; latest=w3.eth.block_number; block=w3.eth.get_block(latest)
   if cid!=80094: raise RuntimeError(f"unexpected chain id {cid}")
   attempts.append({"url":url,"ok":True,"block":latest,"hash":block.hash.hex()}); return w3,url,attempts
  except Exception as exc: attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
 raise RuntimeError(json.dumps(attempts))

def collect_addresses(node:Any,path:list[str],rows:list[dict[str,str]])->None:
 if isinstance(node,dict):
  label="/".join(path+[str(node.get("contractName") or node.get("contract") or node.get("name") or "")])
  for key,value in node.items():
   if isinstance(value,str) and ADDRESS_RE.match(value):
    rows.append({"address":Web3.to_checksum_address(value),"label":"/".join(path+[str(key),label])})
   collect_addresses(value,path+[str(key)],rows)
 elif isinstance(node,list):
  for i,value in enumerate(node): collect_addresses(value,path+[str(i)],rows)

def deployment_addresses()->tuple[list[dict[str,str]],dict[str,list[str]]]:
 rows=[]
 for path in REPO.rglob("*.json"):
  lower=str(path).lower()
  if "berachain" not in lower or ("deployment" not in lower and "broadcast" not in lower): continue
  try: data=json.loads(path.read_text(encoding="utf-8"))
  except Exception: continue
  found=[]; collect_addresses(data,[str(path.relative_to(REPO))],found); rows.extend(found)
 labels:dict[str,list[str]]={}
 for row in rows: labels.setdefault(row["address"].lower(),[]).append(row["label"])
 unique=[{"address":Web3.to_checksum_address(key),"labels":sorted(set(value))} for key,value in labels.items()]
 return unique,labels

def source_inventory()->list[dict[str,Any]]:
 out=[]
 for path in REPO.rglob("*.sol"):
  text=path.read_text(encoding="utf-8",errors="replace")
  if "beefy" not in text.lower() and "kodiak" not in text.lower(): continue
  out.append({"path":str(path.relative_to(REPO)),"sha256":hashlib.sha256(text.encode()).hexdigest(),"matchedLines":[line.strip() for line in text.splitlines() if "beefy" in line.lower() or "kodiak" in line.lower()][:80]})
 return out

def token_meta(w3:Web3,address:str,block:int)->dict[str,Any]:
 address=Web3.to_checksum_address(address); c=w3.eth.contract(address=address,abi=ERC20_ABI)
 return {"address":address,"symbol":safe(c.functions.symbol().call,block_identifier=block),"name":safe(c.functions.name().call,block_identifier=block),"decimals":safe(c.functions.decimals().call,block_identifier=block),"totalSupply":safe(c.functions.totalSupply().call,block_identifier=block)}

def common_calls(w3:Web3,address:str,block:int)->dict[str,Any]:
 out={}
 for name,abi in COMMON_ABIS.items():
  c=w3.eth.contract(address=address,abi=[abi]); out[name]=safe(getattr(c.functions,name)().call,block_identifier=block)
 return out

def inspect_feed(w3:Web3,address:str,labels:dict[str,list[str]],block:int)->dict[str,Any]:
 address=Web3.to_checksum_address(address); c=w3.eth.contract(address=address,abi=FEED_ABI); code=w3.eth.get_code(address,block_identifier=block)
 return {"address":address,"labels":labels.get(address.lower(),[]),"codeBytes":len(code),"runtimeKeccak":Web3.keccak(code).hex(),"latestRoundData":safe(c.functions.latestRoundData().call,block_identifier=block),"decimals":safe(c.functions.decimals().call,block_identifier=block),"common":common_calls(w3,address,block)}

def try_market(w3:Web3,address:str,labels:dict[str,list[str]],block:int,timestamp:int)->dict[str,Any]|None:
 address=Web3.to_checksum_address(address); c=w3.eth.contract(address=address,abi=MARKET_ABI); tokens_r=safe(c.functions.tokens().call,block_identifier=block); tokens=val(tokens_r)
 if not tokens or len(tokens)!=5: return None
 ft,xt,gt,collateral,debt=[Web3.to_checksum_address(x) for x in tokens]; cfg_r=safe(c.functions.config().call,block_identifier=block); cfg=val(cfg_r); maturity=int(cfg[1]) if cfg else 0
 gt_c=w3.eth.contract(address=gt,abi=GT_ABI); gt_cfg_r=safe(gt_c.functions.getGtConfig().call,block_identifier=block); gt_cfg=val(gt_cfg_r); oracle=None
 if gt_cfg and len(gt_cfg)>=6:
  try: oracle=Web3.to_checksum_address(gt_cfg[5][0])
  except Exception: pass
 collateral_c=w3.eth.contract(address=collateral,abi=ERC20_ABI); collateral_balance=safe(collateral_c.functions.balanceOf(gt).call,block_identifier=block)
 row={"market":address,"labels":labels.get(address.lower(),[]),"tokens":tokens_r,"config":cfg_r,"paused":safe(c.functions.paused().call,block_identifier=block),"maturity":maturity,"matured":bool(maturity and timestamp>=maturity),"ft":token_meta(w3,ft,block),"xt":xt,"gt":gt,"collateral":token_meta(w3,collateral,block),"debtToken":token_meta(w3,debt,block),"collateralBalanceAtGt":collateral_balance,"oracle":oracle,"gtConfig":gt_cfg_r}
 if oracle:
  oracle_c=w3.eth.contract(address=oracle,abi=ORACLE_ABI); ocfg_r=safe(oracle_c.functions.oracles(collateral).call,block_identifier=block); ocfg=val(ocfg_r); price_r=safe(oracle_c.functions.getPrice(collateral).call,block_identifier=block); feeds=[]
  if ocfg:
   for candidate in ocfg[:2]:
    try:
     candidate=Web3.to_checksum_address(candidate)
     if int(candidate,16): feeds.append(inspect_feed(w3,candidate,labels,block))
    except Exception: pass
  row["oracleConfiguration"]=ocfg_r; row["oraclePrice"]=price_r; row["feeds"]=feeds
  text=" ".join(x.lower() for feed in feeds for x in feed.get("labels",[]))
  text+=" "+" ".join(x.lower() for x in labels.get(collateral.lower(),[]))
  row["beefyKodiakBinding"]=bool("beefy" in text or "kodiak" in text)
  row["activeMaterialBinding"]=bool(row["beefyKodiakBinding"] and not row["matured"] and val(row["paused"],False) is not True and int(val(collateral_balance,0) or 0)>0)
 return row

def main()->int:
 clone(); w3,rpc,attempts=connect(); latest=w3.eth.block_number; block=w3.eth.get_block(latest); timestamp=int(block.timestamp); addresses,labels=deployment_addresses(); markets=[]
 for item in addresses:
  try:
   row=try_market(w3,item["address"],labels,latest,timestamp)
   if row: markets.append(row)
  except Exception: pass
 flagged=[x for x in markets if x.get("beefyKodiakBinding")]; active=[x for x in markets if x.get("activeMaterialBinding")]
 result={"schema":"termmax-berachain-oracle-binding/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),"safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},"rpc":rpc,"rpcAttempts":attempts,"block":{"number":latest,"hash":block.hash.hex(),"timestamp":timestamp,"timestampUtc":datetime.fromtimestamp(timestamp,tz=timezone.utc).isoformat()},"repoHead":subprocess.check_output(["git","-C",str(REPO),"rev-parse","HEAD"],text=True).strip(),"deploymentAddressCount":len(addresses),"marketCount":len(markets),"beefyKodiakMarketCount":len(flagged),"activeMaterialBindingCount":len(active),"activeMaterialBindings":active,"beefyKodiakMarkets":flagged,"markets":markets,"sourceInventory":source_inventory(),"nextStep":"LOCAL_FORK_SPOT_MANIPULATION_PNL" if active else "KILL_NO_ACTIVE_MATERIAL_BEEF_KODIAK_BINDING"}
 (OUT/"BERACHAIN_ORACLE_BINDING_FULL.json").write_text(json.dumps(result,indent=2,default=str),encoding="utf-8")
 compact={k:result[k] for k in ["generatedAtUtc","block","repoHead","deploymentAddressCount","marketCount","beefyKodiakMarketCount","activeMaterialBindingCount","activeMaterialBindings","beefyKodiakMarkets","sourceInventory","nextStep"]}
 (OUT/"BERACHAIN_ORACLE_BINDING_COMPACT.json").write_text(json.dumps(compact,indent=2,default=str),encoding="utf-8")
 print(json.dumps(compact,indent=2,default=str)); return 0
if __name__=="__main__": raise SystemExit(main())
