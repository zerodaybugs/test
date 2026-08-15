#!/usr/bin/env python3
"""Kiln OmniVault R11 read-only runtime/source collector."""
from __future__ import annotations
import hashlib, json, os, time
from pathlib import Path
from typing import Any
import requests

OUT=Path("r11_results"); OUT.mkdir(exist_ok=True); (OUT/"sources").mkdir(exist_ok=True)
UA={"User-Agent":"Kiln-R11-ReadOnly/1.0"}; T=25
CHAINS={
  1:{"name":"ethereum","rpcs":["https://ethereum-rpc.publicnode.com","https://eth.llamarpc.com","https://1rpc.io/eth"],"api":"https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api","beacon":"0x15f7f910e5a8c86e609fd11c58f7342d86d3a25c"},
  56:{"name":"bnb","rpcs":["https://bsc-rpc.publicnode.com","https://binance.llamarpc.com","https://bsc-dataseed.binance.org"],"api":"https://api.routescan.io/v2/network/mainnet/evm/56/etherscan/api","beacon":"0x50006F2C5C914cEF560ceeD7686f038480199202"},
}
VAULTS=[
 (1,"Ethereum Venus USDT","0xCcDed4b9D47F7F248bfe3F49a9C70A5F1E6EA4c4","0xdAC17F958D2ee523a2206206994597C13D831ec7"),
 (1,"Ethereum Venus USDC","0xDa273908A3f837091774164E2821ba8Ee8238501","0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
 (56,"BNB Venus DAI","0x290F5566a5269A52ad70D01aC860456b3B964f01","0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3"),
 (56,"BNB Venus USDT","0xB962E0B467E4EdA5b8df916c5756F9753d46914F","0x55d398326f99059fF775485246999027B3197955"),
 (56,"BNB Venus USDC","0xBF45a2e9bBa728037A714380899fd7C4ee587312","0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"),
]
S={"asset":"38d52e0f","connectorName":"607985fc","connectorRegistry":"b53c86d2","strategy":"aa9ff5d8","depositFee":"67a52793","rewardFee":"8b424267","totalAssets":"01e1d114","totalSupply":"18160ddd","decimals":"313ce567","transferable":"92ff0d31","blockList":"7d7e8d98","pendingDepositFee":"2c15e0f7","pendingRewardFee":"7c10c835","vaultFactory":"d8a06f73","implementation":"5c60da1b","connectorAddress":"2672c5bc","get":"8eaa6ac0","paused":"9e9e4666","frozen":"b91532b5","venusMarketRegistry":"90a7fde3","compoundMarketRegistry":"29eacedb","marketRegistry":"ecb96fe6","vToken":"9bb1a99c","vtoken":"74d24065","venus":"1df294fb","pool":"16f0115b","fToken":"a8694e57","underlyingVault":"c26af9d8","vault":"fbfa77cf","getMarket":"d4dfadbf","underlying":"6f307dc3","balanceOf":"70a08231","balanceOfUnderlying":"3af9e669","exchangeRateStored":"182df0f5","exchangeRateCurrent":"bd6d894d","getCash":"3b1d21a2","totalBorrows":"47bd3718","totalReserves":"8f840ddd","accrualBlockNumber":"6c540baf","supplyRatePerBlock":"ae9d70b0","borrowRatePerBlock":"f8f9da28"}
BEACON_SLOT="0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

def addr(x):
 if not x:return None
 x=x.lower().removeprefix("0x"); return "0x"+x[-40:].rjust(40,"0")
def aw(x):return addr(x)[2:].rjust(64,"0")
def ui(x):
 try:return int(x,16) if x and x!="0x" else None
 except:return None
def ad(x):return addr(x[-40:]) if x and len(x)>=42 else None
def asc(x):
 try:return bytes.fromhex(x[2:66]).rstrip(b"\0").decode(errors="replace")
 except:return None
def hcode(x):
 try:return hashlib.sha256(bytes.fromhex(x[2:])).hexdigest() if x and x!="0x" else None
 except:return None

class RPC:
 def __init__(self,cid):
  self.cid=cid; self.i=0; self.s=requests.Session(); self.s.headers.update(UA); self.url=None
  for u in CHAINS[cid]["rpcs"]:
   try:
    if int(self.q(u,"eth_chainId",[]),16)==cid:self.url=u;break
   except:pass
  if not self.url:raise RuntimeError(f"no RPC for {cid}")
 def q(self,u,m,p):
  assert m not in {"eth_sendTransaction","eth_sendRawTransaction","eth_sign","personal_sendTransaction"}
  self.i+=1; e=None
  for n in range(4):
   try:
    r=self.s.post(u,json={"jsonrpc":"2.0","id":self.i,"method":m,"params":p},timeout=T);r.raise_for_status();j=r.json()
    if j.get("error"):raise RuntimeError(j["error"])
    return j["result"]
   except Exception as z:e=z;time.sleep(n+1)
  raise e
 def call(self,to,data):return self.q(self.url,"eth_call",[{"to":addr(to),"data":"0x"+data.removeprefix("0x")},"latest"])
 def tr(self,to,data):
  try:return {"ok":True,"raw":self.call(to,data)}
  except Exception as e:return {"ok":False,"error":f"{type(e).__name__}: {e}"}
 def code(self,a):return self.q(self.url,"eth_getCode",[addr(a),"latest"])
 def storage(self,a,s):return self.q(self.url,"eth_getStorageAt",[addr(a),s,"latest"])
 def block(self):return int(self.q(self.url,"eth_blockNumber",[]),16)

def c0(r,a,k):return r.tr(a,S[k])
def ca(r,a,k,x):return r.tr(a,S[k]+aw(x))
def cb(r,a,k,x):return r.tr(a,S[k]+x.removeprefix("0x")[:64].ljust(64,"0"))
def val(c,k):
 if not c.get("ok"):return None
 return {"u":ui,"a":ad,"b":lambda x:bool(ui(x)),"s":asc,"r":lambda x:x}[k](c["raw"])

def source(api,address,label):
 try:j=requests.get(api,params={"module":"contract","action":"getsourcecode","address":addr(address)},headers=UA,timeout=T).json()
 except Exception as e:j={"status":"0","result":str(e)}
 p=OUT/"sources"/f"{label}_{addr(address)}.json";p.write_text(json.dumps(j,indent=2))
 src=""; meta={}
 if isinstance(j.get("result"),list) and j["result"]:meta=j["result"][0];src=meta.get("SourceCode") or ""
 if src.startswith("{{") and src.endswith("}}"):src=src[1:-1]
 if src.lstrip().startswith("{"):
  try:
   o=json.loads(src);src="\n\n".join("// FILE: "+n+"\n"+(v.get("content") or "") for n,v in o.get("sources",{}).items())
  except:pass
 if src:(OUT/"sources"/f"{label}_{addr(address)}.sol").write_text(src)
 return {"address":addr(address),"contractName":meta.get("ContractName"),"compiler":meta.get("CompilerVersion"),"proxy":meta.get("Proxy"),"implementation":addr(meta.get("Implementation")) if meta.get("Implementation") else None,"source_sha256":hashlib.sha256(src.encode()).hexdigest() if src else None,"source_bytes":len(src.encode()),"source":src}

def probe(r,cid,label,vault,expected):
 d={"chain_id":cid,"chain":CHAINS[cid]["name"],"label":label,"vault":addr(vault),"expected_asset":addr(expected),"rpc":r.url,"block":r.block()}
 gs={"asset":("asset","a"),"connector_name":("connectorName","s"),"connector_name_raw":("connectorName","r"),"connector_registry":("connectorRegistry","a"),"strategy":("strategy","u"),"deposit_fee":("depositFee","u"),"reward_fee":("rewardFee","u"),"total_assets":("totalAssets","u"),"total_supply":("totalSupply","u"),"share_decimals":("decimals","u"),"transferable":("transferable","b"),"block_list":("blockList","a"),"pending_deposit_fee":("pendingDepositFee","u"),"pending_reward_fee":("pendingRewardFee","u"),"vault_factory":("vaultFactory","a")}
 raw={}
 for n,(k,t) in gs.items():raw[n]=c0(r,vault,k);d[n]=val(raw[n],t)
 d["asset_decimals"]=val(c0(r,d["asset"],"decimals"),"u") if d.get("asset") else None
 d["vault_code_sha256"]=hcode(r.code(vault)); d["beacon"]=ad(r.storage(vault,BEACON_SLOT)); d["beacon_implementation"]=val(c0(r,d["beacon"],"implementation"),"a") if d.get("beacon") else None
 reg=d.get("connector_registry"); name=raw["connector_name_raw"].get("raw") if raw["connector_name_raw"].get("ok") else None; con=None
 if reg and name:
  con=val(cb(r,reg,"connectorAddress",name),"a") or val(cb(r,reg,"get",name),"a");d["connector_paused"]=val(cb(r,reg,"paused",name),"b");d["connector_frozen"]=val(cb(r,reg,"frozen",name),"b")
 d["connector"]=con; d["connector_code_sha256"]=hcode(r.code(con)) if con else None
 if con:d["connector_source"]=source(CHAINS[cid]["api"],con,f"{cid}_connector")
 dyn={}
 if con:
  for k in ["venusMarketRegistry","compoundMarketRegistry","marketRegistry","vToken","vtoken","venus","pool","fToken","underlyingVault","vault"]:
   x=val(c0(r,con,k),"a")
   if x and x!="0x0000000000000000000000000000000000000000":dyn[k]=x
 d["connector_getters"]=dyn; market=next((dyn[k] for k in ["vToken","vtoken","venus","pool","underlyingVault","vault"] if k in dyn),None)
 if not market and d.get("asset"):
  for k in ["venusMarketRegistry","compoundMarketRegistry","marketRegistry"]:
   if k in dyn:
    market=val(ca(r,dyn[k],"getMarket",d["asset"]),"a")
    if market:break
 d["market"]=market
 if market:
  d["market_source"]=source(CHAINS[cid]["api"],market,f"{cid}_market")
  m={"underlying":val(c0(r,market,"underlying"),"a"),"decimals":val(c0(r,market,"decimals"),"u"),"vault_vtoken_balance":val(ca(r,market,"balanceOf",vault),"u"),"balance_of_underlying_current":val(ca(r,market,"balanceOfUnderlying",vault),"u")}
  for k in ["exchangeRateStored","exchangeRateCurrent","getCash","totalBorrows","totalReserves","accrualBlockNumber","supplyRatePerBlock","borrowRatePerBlock"]:m[k]=val(c0(r,market,k),"u")
  d["market_state"]=m
  if None not in (d.get("asset_decimals"),m.get("decimals"),m.get("vault_vtoken_balance")):
   e=18+d["asset_decimals"]-m["decimals"]; sc=10**e if 0<=e<=77 else None;d["exchange_rate_scale_exp"]=e
   if sc:
    d["stored_claim_raw"]=m["vault_vtoken_balance"]*(m.get("exchangeRateStored") or 0)//sc
    d["current_claim_raw"]=m["vault_vtoken_balance"]*(m.get("exchangeRateCurrent") or 0)//sc
 d["gates"]={"asset_match":addr(d.get("asset"))==addr(expected),"connector_name_venus":(d.get("connector_name") or "").upper()=="VENUS","connector_resolved":bool(con),"market_resolved":bool(market),"underlying_match":addr((d.get("market_state") or {}).get("underlying"))==addr(d.get("asset")) if (d.get("market_state") or {}).get("underlying") else None,"beacon_match":addr(d.get("beacon"))==addr(CHAINS[cid]["beacon"])}
 # Strip embedded source from main JSON; source remains in evidence files.
 for k in ["connector_source","market_source"]:
  if d.get(k):d[k].pop("source",None)
 return d

def main():
 out=[];fatal=[];meta={}
 for cid in sorted({x[0] for x in VAULTS}):
  try:r=RPC(cid);meta[str(cid)]={"rpc":r.url,"block":r.block()}
  except Exception as e:fatal.append(f"chain {cid}: {e}");continue
  for x in [v for v in VAULTS if v[0]==cid]:
   try:out.append(probe(r,*x))
   except Exception as e:fatal.append(f"{x[1]}: {type(e).__name__}: {e}");out.append({"chain_id":cid,"label":x[1],"vault":addr(x[2]),"error":str(e)})
 result={"schema":"kiln-r11-readonly-v1","generated_at_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"safety":{"read_only":True,"rpc_methods":["eth_chainId","eth_blockNumber","eth_call","eth_getCode","eth_getStorageAt"],"transactions_signed":0,"transactions_sent":0,"private_keys":0},"chains":meta,"vaults":out,"fatal_errors":fatal}
 (OUT/"R11_RUNTIME.json").write_text(json.dumps(result,indent=2,sort_keys=True))
 master={"decision":"RESEARCH_CHECKPOINT_NOT_FOR_SUBMISSION","submit_ready":False,"validated_critical":0,"validated_high":0,"runtime_complete":len(out)==len(VAULTS) and not fatal,"fatal_errors":fatal}
 (OUT/"R11_MASTER_GATE.json").write_text(json.dumps(master,indent=2,sort_keys=True));print(json.dumps(master,indent=2))
 manifest=[]
 for p in sorted(OUT.rglob("*")):
  if p.is_file() and p.name!="SHA256SUMS.txt":manifest.append((hashlib.sha256(p.read_bytes()).hexdigest(),p.relative_to(OUT).as_posix()))
 (OUT/"SHA256SUMS.txt").write_text("".join(f"{h}  {p}\n" for h,p in manifest))
 return 0
if __name__=="__main__":raise SystemExit(main())
