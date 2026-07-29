#!/usr/bin/env python3
"""Public read-only Hermetica hBTC claim/liability inventory; no chain writes."""
import concurrent.futures, hashlib, json, os, struct, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from pathlib import Path

H="https://api.hiro.so"; D="SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D"
S="state-hbtc-v1"; V="vault-hbtc-v1-2"; T="token-hbtc"; O=Path(os.getenv("SCAN_OUT","hermetica-claim-inventory-output"))
R=f"{D}.reserve-hbtc-v1"; F=f"{D}.reserve-fund-hbtc-v1"; W=f"{D}.{V}"
SB="SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4"; A="0123456789ABCDEFGHJKMNPQRSTVWXYZ"; UA="authorized-read-only-hermetica-inventory/1.0"
SER={
 R:"0x06167218e5f1066f78726b325de7d7c058691c521dc00f726573657276652d686274632d7631",
 F:"0x06167218e5f1066f78726b325de7d7c058691c521dc014726573657276652d66756e642d686274632d7631",
 W:"0x06167218e5f1066f78726b325de7d7c058691c521dc00f7661756c742d686274632d76312d32"}

def iso(t): return datetime.fromtimestamp(t,timezone.utc).isoformat().replace("+00:00","Z")
def get(url,body=None,n=6):
 data=None if body is None else json.dumps(body,separators=(",",":")).encode(); hd={"User-Agent":UA,"Accept":"application/json"}
 if data: hd["Content-Type"]="application/json"
 for i in range(n):
  try:
   q=urllib.request.Request(url,data=data,headers=hd,method="POST" if data else "GET")
   with urllib.request.urlopen(q,timeout=35) as r:return json.loads(r.read())
  except (urllib.error.URLError,urllib.error.HTTPError,TimeoutError,json.JSONDecodeError) as e:
   if isinstance(e,urllib.error.HTTPError) and e.code in (400,404): raise
   time.sleep(min(10,.7*2**i))
 raise RuntimeError(url)
def c32(h):
 if len(h)%2:h="0"+h
 h=h.lower(); x="0123456789abcdef"; out=[]; carry=0
 for i in range(len(h)-1,-1,-1):
  if carry<4:
   cur=x.index(h[i])>>carry; nxt=x.index(h[i-1]) if i else 0; nb=carry+1
   out.insert(0,A[cur+(nxt%(1<<nb)<<(5-nb))]); carry=nb
  else: carry=0
 while out and out[0]=="0":out.pop(0)
 z=0
 for b in bytes.fromhex(h):
  if b:break
  z+=1
 return "0"*z+"".join(out)
def addr(v,h):
 z=f"{v:02x}"+h.hex(); q=hashlib.sha256(hashlib.sha256(bytes.fromhex(z)).digest()).digest()[:4]
 return "S"+A[v]+c32(h.hex()+q.hex())
class P:
 def __init__(self,b):self.b=b;self.p=0
 def take(self,n):
  z=self.b[self.p:self.p+n]
  if len(z)!=n:raise ValueError("truncated")
  self.p+=n;return z
 def val(self):
  t=self.take(1)[0]
  if t==0:return int.from_bytes(self.take(16),"big",signed=True)
  if t==1:return int.from_bytes(self.take(16),"big")
  if t==2:return {"buffer_hex":self.take(int.from_bytes(self.take(4),"big")).hex()}
  if t==3:return True
  if t==4:return False
  if t in (5,6):
   v=self.take(1)[0];s=addr(v,self.take(20))
   if t==6:s+="."+self.take(self.take(1)[0]).decode()
   return s
  if t==7:return {"response":"ok","value":self.val()}
  if t==8:return {"response":"err","value":self.val()}
  if t==9:return None
  if t==10:return self.val()
  if t==11:return [self.val() for _ in range(int.from_bytes(self.take(4),"big"))]
  if t==12:
   d={}
   for _ in range(int.from_bytes(self.take(4),"big")):d[self.take(self.take(1)[0]).decode()]=self.val()
   return d
  if t in (13,14):return self.take(int.from_bytes(self.take(4),"big")).decode("ascii" if t==13 else "utf8")
  raise ValueError(f"cv {t}")
def dec(h):
 p=P(bytes.fromhex(h.removeprefix("0x")));v=p.val()
 if p.p!=len(p.b):raise ValueError("trailing")
 return v
def uint(n):return "0x01"+n.to_bytes(16,"big").hex()
def buff(b):return "0x02"+len(b).to_bytes(4,"big").hex()+b.hex()
def call(a,c,f,tip,args=[]):
 u=f"{H}/v2/contracts/call-read/{a}/{c}/{f}?tip={urllib.parse.quote(tip,safe='')}";r=get(u,{"sender":D,"arguments":args})
 return {"url":u,"raw":r,"decoded":dec(r["result"]) if r.get("okay") else None}
def ok(x):
 if not isinstance(x,dict) or x.get("response")!="ok":raise ValueError(x)
 return x["value"]
def ft(j,p):
 for k,v in j.get("fungible_tokens",{}).items():
  if k.startswith(p):return int(v["balance"]),k
 return 0,None

def main():
 O.mkdir(parents=True,exist_ok=True);info=get(H+"/v2/info");height=int(info["stacks_tip_height"]);tip=info["stacks_tip"]
 block=get(f"{H}/extended/v2/blocks/{height}");bt=int(block.get("block_time",0))
 fns=["get-claim-id","get-total-assets","get-net-assets","get-pending-fees","get-pending-rf","get-share-price","get-fees","get-cooldown","get-express-cooldown","get-deposit-cap","get-max-reward","get-update-window","get-reserve-rate","get-last-log-ts","get-vault-enabled","get-deposit-enabled","get-redeem-enabled","get-request-redeem-enabled","get-express-enabled","get-reward-enabled"]
 sc={f:call(D,S,f,tip) for f in fns}; supply=call(D,T,"get-total-supply",tip); timelock=call(D,"hq-v1","get-timelock",tip); req=call(D,S,"get-update-request-var",tip,[buff(b"\x01")])
 n=int(sc["get-claim-id"]["decoded"])
 if n>10000:raise RuntimeError(f"claim-id {n}")
 def one(i):
  z=call(D,V,"get-claim",tip,[uint(i)]);d=z["decoded"];return {"claim_id":i,"raw":z["raw"],"decoded":d,"exists":isinstance(d,dict) and d.get("response")=="ok",**(d["value"] if isinstance(d,dict) and d.get("response")=="ok" else {})}
 with concurrent.futures.ThreadPoolExecutor(max_workers=6) as e:claims=list(e.map(one,range(1,n+1)))
 active=[x for x in claims if x["exists"]]
 pc={"reserve_sbtc":call(SB,"sbtc-token","get-balance",tip,[SER[R]]),"rf_sbtc":call(SB,"sbtc-token","get-balance",tip,[SER[F]]),"vault_sbtc":call(SB,"sbtc-token","get-balance",tip,[SER[W]]),"vault_hbtc":call(D,T,"get-balance",tip,[SER[W]])}
 bal={}
 for p in (R,F,W):bal[p]=get(f"{H}/extended/v1/address/{p}/balances?until_block={height}")
 rs=int(ok(pc["reserve_sbtc"]["decoded"]));fs=int(ok(pc["rf_sbtc"]["decoded"]));ws=int(ok(pc["vault_sbtc"]["decoded"]));wh=int(ok(pc["vault_hbtc"]["decoded"]));sup=int(ok(supply["decoded"]));sp=int(sc["get-share-price"]["decoded"])
 ri,_=ft(bal[R],SB+".sbtc-token::");fi,_=ft(bal[F],SB+".sbtc-token::");wi,_=ft(bal[W],SB+".sbtc-token::");hi,_=ft(bal[W],D+".token-hbtc::")
 slim=[]
 for x in active:
  sh=int(x["shares"]);a=x.get("assets");fee=x.get("fee");ts=int(x["ts"]);fb=int(x["fee-bps"]);gross=(sh*sp)//100000000 if a is None else int(a)
  slim.append({"claim_id":x["claim_id"],"user":x["user"],"shares":sh,"share_fraction_pct":str(sh*100/sup if sup else 0),"share_price":x.get("share-price"),"assets":a,"fee":fee,"fee_bps":fb,"is_express":bool(x["is-express"]),"maturity_unix":ts,"maturity_utc":iso(ts),"mature_at_anchor":bt>=ts,"funded":a is not None,"current_gross_assets_if_funded":gross,"current_fee_if_funded":gross*fb//10000 if a is None else int(fee or 0)})
 funded=[x for x in slim if x["funded"]];unfunded=[x for x in slim if not x["funded"]];mature=[x for x in unfunded if x["mature_at_anchor"]]
 fg=sum(int(x["assets"]) for x in funded);ff=sum(int(x["fee"] or 0) for x in funded);ash=sum(x["shares"] for x in slim);ta=int(sc["get-total-assets"]["decoded"]);pf=int(sc["get-pending-fees"]["decoded"]);pr=int(sc["get-pending-rf"]["decoded"]);na=int(sc["get-net-assets"]["decoded"])
 inv={"active_claim_shares":ash,"vault_hbtc_balance":wh,"escrow_share_delta":wh-ash,"escrow_share_exact":wh==ash,"funded_claim_gross_liability":fg,"funded_claim_net_user_liability":fg-ff,"funded_claim_fee_liability":ff,"vault_sbtc_balance":ws,"vault_sbtc_minus_funded_gross":ws-fg,"funded_gross_fully_covered":ws>=fg,"state_total_assets":ta,"reserve_sbtc_balance":rs,"reserve_minus_total_assets":rs-ta,"reserve_matches_total_assets":rs==ta,"state_pending_fees":pf,"state_pending_rf":pr,"state_net_assets":na,"net_assets_identity":ta-pf-pr==na,"reserve_fund_sbtc_balance":fs,"unfunded_current_gross_if_funded":sum(x["current_gross_assets_if_funded"] for x in unfunded),"mature_unfunded_current_gross_if_funded":sum(x["current_gross_assets_if_funded"] for x in mature)}
 bad=not inv["escrow_share_exact"] or not inv["funded_gross_fully_covered"] or inv["reserve_minus_total_assets"]<0 or not inv["net_assets_identity"]
 summary={"generated_at_utc":datetime.now(timezone.utc).isoformat(),"mode":"public read-only","chain_writes":0,"anchor":{"stacks_height":height,"stacks_tip":tip,"block_time":bt,"block_time_utc":iso(bt),"index_block_hash":block.get("index_block_hash"),"until_block":height},"claim_id":n,"active_claim_count":len(slim),"funded_claim_count":len(funded),"unfunded_claim_count":len(unfunded),"mature_unfunded_claim_count":len(mature),"active_claims":slim,"balances":{"reserve_sbtc":rs,"reserve_fund_sbtc":fs,"vault_sbtc":ws,"vault_hbtc":wh,"indexed":{"reserve_sbtc":ri,"reserve_fund_sbtc":fi,"vault_sbtc":wi,"vault_hbtc":hi,"all_equal_to_tip_pinned":(rs,fs,ws,wh)==(ri,fi,wi,hi)}},"hq_timelock":timelock["decoded"],"max_reward_update_request":req["decoded"],"invariants":inv,"decision":"CRITICAL_CANDIDATE_REVIEW_REQUIRED" if bad else "NO_CURRENT_SOLVENCY_DIVERGENCE"}
 files={"SUMMARY.json":summary,"all_claim_calls.json":claims,"state_calls.json":sc,"pinned_balance_calls.json":pc,"indexed_balances.json":bal,"governance_calls.json":{"hq_timelock":timelock,"max_reward_update_request":req},"anchor_info.json":{"info":info,"block":block},"token_supply_call.json":supply}
 for name,val in files.items():(O/name).write_text(json.dumps(val,indent=2,sort_keys=True),encoding="utf8")
 (O/"SHA256SUMS.txt").write_text("\n".join(f"{hashlib.sha256((O/n).read_bytes()).hexdigest()}  {n}" for n in sorted(files))+"\n",encoding="utf8")
 print(json.dumps(summary,indent=2,sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
