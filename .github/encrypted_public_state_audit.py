#!/usr/bin/env python3
"""Generic read-only audit of public Veda deployment-registry drift.

The script discovers active Teller registries and recorded deployment files from
Veda's public repository, then performs pinned eth_call/getCode authorization
checks. It has no wallet, signing, transaction-construction, or broadcast path.
"""
from __future__ import annotations
import json, random, sys, time, urllib.parse, urllib.request
from pathlib import Path

COMMIT="77d6292bdfda606c9ffb7033db1332759b5568a3"
REPO="Veda-Labs/boring-vault"
EOA="0x000000000000000000000000000000000000dead"
ALLOWED={"eth_chainId","eth_blockNumber","eth_getBlockByNumber","eth_getCode","eth_call"}
FORBIDDEN={"eth_sendTransaction","eth_sendRawTransaction","personal_sendTransaction","eth_signTransaction"}
S={"hook":"7f5a7c7b","authority":"bf7e214f","vault":"fbfa77cf","accountant":"4fb3ccc5","shareLockPeriod":"9fdb11b6","isPaused":"b187bd26","canCall":"b7009613","getUserRoles":"06a36aee","isCapabilityPublic":"2f47571f","enter":"39d6ba32","exit":"18457e61","deposit3":"0efe6a8b","deposit4":"8b6099db","deposit5":"2a22f31f","withdraw":"16762eed","bulkDeposit":"9d574420","bulkWithdraw":"3e64ce99"}
CHAINS={
 "Mainnet":(1,["https://ethereum-rpc.publicnode.com","https://eth.llamarpc.com","https://rpc.flashbots.net"]),
 "Arbitrum":(42161,["https://arbitrum-one-rpc.publicnode.com","https://arb1.arbitrum.io/rpc","https://arbitrum.drpc.org"]),
 "BeraChain":(80094,["https://rpc.berachain.com","https://berachain-rpc.publicnode.com","https://berachain.drpc.org"]),
 "Corn":(21000000,["https://mainnet.corn-rpc.com","https://maizenet-rpc.usecorn.com","https://rpc.ankr.com/corn_maizenet"]),
 "Optimism":(10,["https://optimism-rpc.publicnode.com","https://mainnet.optimism.io","https://optimism.drpc.org"]),
 "Scroll":(534352,["https://rpc.scroll.io","https://scroll-rpc.publicnode.com","https://scroll.drpc.org"]),
 "TAC":(239,["https://rpc.tac.build","https://tac-mainnet.rpc.thirdweb.com"]),
 "UniChain":(130,["https://mainnet.unichain.org","https://unichain-rpc.publicnode.com"]),
}

def norm(a):
 a=str(a).lower().removeprefix("0x")
 if len(a)!=40 or any(c not in "0123456789abcdef" for c in a): raise ValueError(a)
 return "0x"+a
def a32(a): return norm(a)[2:].rjust(64,"0")
def b4(x): return x.removeprefix("0x").ljust(64,"0")
def call0(s): return "0x"+s
def call_addr(s,a): return "0x"+s+a32(a)
def call_can(u,t,s): return "0x"+S["canCall"]+a32(u)+a32(t)+b4(s)
def call_public(t,s): return "0x"+S["isCapabilityPublic"]+a32(t)+b4(s)
def uint(x): return int(x,16)
def boolean(x): return bool(uint(x))
def address(x): return "0x"+x[-40:].lower()
def bytes32(x): return "0x"+x[-64:].lower()
def short(e): return str(e).replace("\n"," ")[:800]

def get_json(url):
 q=urllib.request.Request(url,headers={"Accept":"application/vnd.github+json","User-Agent":"PublicStateAudit/1.0"})
 with urllib.request.urlopen(q,timeout=30) as r: return json.loads(r.read().decode())

def discover():
 tree=get_json(f"https://api.github.com/repos/{REPO}/git/trees/{COMMIT}?recursive=1")["tree"]
 paths=[x["path"] for x in tree if x.get("type")=="blob"]
 registries={}; deployments={}
 for chain in CHAINS:
  prefix=f"deployments/addresses/{chain}/"
  rpath=prefix+"Tellers.json"
  if rpath in paths:
   try: registries[chain]=get_json(f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{rpath}")
   except Exception as e: registries[chain]={"error":short(e)}
  deployments[chain]=[]
  for p in paths:
   if not p.startswith(prefix) or not p.endswith(".json") or p in (rpath,prefix+"Accountants.json"): continue
   if "/" in p[len(prefix):]: continue
   try:
    z=get_json(f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{p}")
    if isinstance(z,dict) and isinstance(z.get("contractAddresses"),dict): deployments[chain].append({"path":p,"data":z})
   except Exception: pass
 return registries,deployments

class RPC:
 def __init__(self,cid,urls): self.cid=cid; self.urls=urls; self.good=None; self.ok=set(); self.i=random.randint(1,99999); self.block=None; self.hash=None
 def raw(self,u,m,p):
  if m not in ALLOWED or m in FORBIDDEN: raise RuntimeError("blocked method "+m)
  self.i+=1; body=json.dumps({"jsonrpc":"2.0","id":self.i,"method":m,"params":p}).encode(); q=urllib.request.Request(u,data=body,headers={"Content-Type":"application/json","User-Agent":"PublicStateAudit/1.0"},method="POST")
  with urllib.request.urlopen(q,timeout=25) as r: z=json.loads(r.read().decode())
  if "error" in z: raise RuntimeError(z["error"])
  return z.get("result")
 def req(self,m,p):
  errors=[]; order=([self.good] if self.good else [])+[u for u in self.urls if u!=self.good]
  for _ in range(2):
   for u in order:
    try:
     if u not in self.ok:
      if int(self.raw(u,"eth_chainId",[]),16)!=self.cid: raise RuntimeError("wrong chain")
      self.ok.add(u)
     v=self.raw(u,m,p); self.good=u; return v
    except Exception as e: errors.append(urllib.parse.urlparse(u).netloc+":"+short(e))
   time.sleep(1)
  raise RuntimeError(" | ".join(errors[-6:]))
 def pin(self): self.block=self.req("eth_blockNumber",[]); self.hash=self.req("eth_getBlockByNumber",[self.block,False])["hash"]
 def code(self,a): return self.req("eth_getCode",[norm(a),self.block])
 def call(self,to,data,who=EOA): return self.req("eth_call",[{"from":norm(who),"to":norm(to),"data":data},self.block])

def safe(fn,decode=lambda x:x):
 try:
  x=fn()
  if x in (None,"0x","0x0"): return {"ok":False,"error":"empty return","raw":x}
  return {"ok":True,"value":decode(x),"raw":x}
 except Exception as e: return {"ok":False,"error":short(e)}
def val(x,d=None): return x.get("value",d) if isinstance(x,dict) and x.get("ok") else d
def code(r,a):
 x=safe(lambda:r.code(a)); raw=x.get("raw","") if x.get("ok") else ""
 return {**x,"hasCode":bool(x.get("ok") and raw not in ("0x","0x0")),"bytes":max(0,(len(raw)-2)//2) if raw else 0}
def view(r,a,s,d=uint): return safe(lambda:r.call(a,call0(s)),d)
def viewa(r,a,s,arg,d=uint): return safe(lambda:r.call(a,call_addr(s,arg)),d)
def can(r,auth,u,t,s): return safe(lambda:r.call(auth,call_can(u,t,s)),boolean)
def public(r,auth,t,s): return safe(lambda:r.call(auth,call_public(t,s)),boolean)

def contract(r,a):
 z={"address":norm(a),"code":code(r,a)}
 if not z["code"].get("hasCode"): return z
 for k,d in [("vault",address),("accountant",address),("authority",address),("shareLockPeriod",uint),("isPaused",boolean)]: z[k]=view(r,a,S[k],d)
 return z

def recorded_tellers(dep):
 out=[]
 for k,v in dep.get("contractAddresses",{}).items():
  kl=k.lower()
  if "teller" in kl and isinstance(v,str):
   try: out.append((k,norm(v)))
   except Exception: pass
 return out

def find_deployments(chain_deps,vault):
 out=[]
 for d in chain_deps:
  ca=d["data"].get("contractAddresses",{}); v=ca.get("BoringVault")
  try:
   if v and norm(v)==norm(vault): out.append(d)
  except Exception: pass
 return out

def probe_pair(r,chain,current,old,vault,dep_path,old_key):
 auth=val(view(r,vault,S["authority"],address)); cur=contract(r,current); prev=contract(r,old); row={"chain":chain,"deploymentPath":dep_path,"recordedTellerKey":old_key,"vault":norm(vault),"currentTeller":cur,"recordedTeller":prev,"authority":{"address":auth,"code":code(r,auth) if auth else None}}
 if auth:
  row["authority"].update({"oldRoles":viewa(r,auth,S["getUserRoles"],old,bytes32),"currentRoles":viewa(r,auth,S["getUserRoles"],current,bytes32),"randomCanCall":{"old":{},"current":{}},"tellerCanCallVault":{"old":{},"current":{}},"public":{}})
  for lab,t in [("old",old),("current",current)]:
   for n in ["deposit3","deposit4","deposit5","withdraw","bulkDeposit","bulkWithdraw"]:
    row["authority"]["randomCanCall"][lab][n]=can(r,auth,EOA,t,S[n]); row["authority"]["public"][lab+"."+n]=public(r,auth,t,S[n])
   for n in ["enter","exit"]: row["authority"]["tellerCanCallVault"][lab][n]=can(r,auth,t,vault,S[n])
 A=row["authority"]; dep=any(val(A.get("randomCanCall",{}).get("old",{}).get(n),False) for n in ["deposit3","deposit4","deposit5"]); mint=val(A.get("tellerCanCallVault",{}).get("old",{}).get("enter"),False); burn=val(A.get("tellerCanCallVault",{}).get("old",{}).get("exit"),False)
 ov=val(prev.get("vault")); cv=val(cur.get("vault")); oa=val(prev.get("accountant")); ca=val(cur.get("accountant")); ol=val(prev.get("shareLockPeriod")); cl=val(cur.get("shareLockPeriod")); samev=bool(ov and cv and norm(ov)==norm(cv)==norm(vault)); samea=bool(oa and ca and norm(oa)==norm(ca)); alive=bool(dep and mint and samev); lockb=bool(alive and cl and cl>0); drift=bool((oa and ca and not samea) or lockb)
 if alive and drift: verdict="LIVE_STALE_ENTRY_REQUIRES_ECONOMIC_CLOSURE"
 elif alive: verdict="STALE_ENTRY_ALIVE_NO_ACCOUNTANT_OR_LOCK_DRIFT"
 elif dep and not mint: verdict="OLD_PUBLIC_SELECTOR_BUT_MINTER_REVOKED"
 elif mint and not dep: verdict="OLD_MINTER_RETAINED_NO_PERMISSIONLESS_ENTRY"
 else: verdict="STALE_ENTRY_CRITICAL_PRECONDITION_ABSENT"
 row["analysis"]={"verdict":verdict,"oldPublicDeposit":dep,"oldMinter":mint,"oldBurner":burn,"sameVault":samev,"sameAccountant":samea,"oldAccountant":oa,"currentAccountant":ca,"oldShareLockPeriod":ol,"currentShareLockPeriod":cl,"hookLockBypass":lockb,"staleEntryAlive":alive,"materialDrift":drift}; return row

def main():
 outdir=Path("probe-output"); outdir.mkdir(exist_ok=True); registries,deps=discover(); chains=[]; pairs=[]; unmatched=[]
 for chain,(cid,urls) in CHAINS.items():
  reg=registries.get(chain,{}); addrs=reg.get("contractAddresses",{}) if isinstance(reg,dict) else {}
  if not addrs: continue
  r=RPC(cid,urls)
  try: r.pin()
  except Exception as e: chains.append({"chain":chain,"status":"RPC_PIN_FAILED","error":short(e)}); continue
  chains.append({"chain":chain,"chainId":cid,"block":int(r.block,16),"blockHex":r.block,"blockHash":r.hash,"endpointHost":urllib.parse.urlparse(r.good).netloc,"status":"PINNED"})
  for reg_key,current in addrs.items():
   try:
    current=norm(current); vault=val(view(r,current,S["vault"],address))
    if not vault: unmatched.append({"chain":chain,"registryKey":reg_key,"currentTeller":current,"reason":"current vault() unreadable"}); continue
    matches=find_deployments(deps.get(chain,[]),vault)
    if not matches: unmatched.append({"chain":chain,"registryKey":reg_key,"currentTeller":current,"vault":vault,"reason":"no deployment JSON with same vault"}); continue
    seen=set()
    for d in matches:
     for old_key,old in recorded_tellers(d["data"]):
      if old==current or old in seen: continue
      seen.add(old); pairs.append(probe_pair(r,chain,current,old,vault,d["path"],old_key))
    if not seen: unmatched.append({"chain":chain,"registryKey":reg_key,"currentTeller":current,"vault":vault,"reason":"no distinct recorded Teller"})
   except Exception as e: unmatched.append({"chain":chain,"registryKey":reg_key,"currentTeller":str(current),"reason":short(e)})
 result={"schemaVersion":1,"source":{"repository":REPO,"commit":COMMIT},"safety":{"readOnly":True,"allowedMethods":sorted(ALLOWED),"forbiddenMethods":sorted(FORBIDDEN),"transactionsSigned":0,"transactionsBroadcast":0},"chains":chains,"pairs":pairs,"unmatched":unmatched}
 (outdir/"results.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 live=[x for x in pairs if x["analysis"]["staleEntryAlive"]]; drift=[x for x in live if x["analysis"]["materialDrift"]]
 L=["# Encrypted public-state deployment drift audit","",f"Source commit: `{COMMIT}`","","```text",f"Pinned chains:       {sum(x['status']=='PINNED' for x in chains)}",f"Candidate pairs:     {len(pairs)}",f"Unmatched rows:      {len(unmatched)}",f"Live stale entries:  {len(live)}",f"Material drift:      {len(drift)}","Broadcast methods:   0","```","","| Chain | Deployment | Old public deposit | Old MINTER | Same accountant | Current lock | Verdict |","|---|---|---:|---:|---:|---:|---|"]
 for x in pairs:
  a=x["analysis"]; L.append(f"| {x['chain']} | `{x['deploymentPath'].split('/')[-1]}` | {a['oldPublicDeposit']} | {a['oldMinter']} | {a['sameAccountant']} | {a['currentShareLockPeriod']} | {a['verdict']} |")
 L += ["","## Hard gate","",("At least one permissionless stale entry survived with accountant/lock drift. Asset-state and fork economics remain mandatory." if drift else "No pair proved permissionless stale entry + retained mint authority + accountant/lock drift. No submission is authorized from this run.")]
 (outdir/"SUMMARY.md").write_text("\n".join(L)+"\n"); print(f"[read-only] pinned={sum(x['status']=='PINNED' for x in chains)} pairs={len(pairs)}",flush=True); return 0 if chains else 2
if __name__=="__main__": sys.exit(main())
