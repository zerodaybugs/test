#!/usr/bin/env python3
"""Current-state binding for the latest public TermMax delegated new-GT transaction.

Uses the historical receipt only for immutable event data; every contract call is
made at latest state so a non-archive public RPC is sufficient. Read-only only.
"""
from __future__ import annotations
import hashlib, json, os, re, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import requests
from hexbytes import HexBytes
from web3 import Web3
from web3._utils.events import get_event_data

OUT=Path(os.environ.get("OUT_DIR","evidence")); OUT.mkdir(parents=True,exist_ok=True)
TX="0x3ee2d77dc72af42c7bf71564b6093bf4ea5c8f8e4bdbd2598c924e0a57a7fe72"
MARKET=Web3.to_checksum_address("0x1d6B083288Fb63B5F3A32FDb6157bE5FD32940E8")
EXPECTED_ORDER=Web3.to_checksum_address("0x8C2854aEe2fF77d1a6404c1E8E2eC503A2028b94")
EXPECTED_GT=Web3.to_checksum_address("0x63009034Ffac57EF0e5f1caF3F43BA077281Ec9B")
DELEGATOR=Web3.to_checksum_address("0xF82f8d46B175827Fb4f6bEbeFF846cE0c4d0A90e")
PINNED="e314f3f849577dfecd4614f148c4df81fdf8c72d"
ROUTESCAN="https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
EIP1967=int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",16)
RPC=[u for u in [os.environ.get("ETH_RPC_URL","").strip(),"https://ethereum-rpc.publicnode.com","https://rpc.mevblocker.io","https://eth.drpc.org","https://1rpc.io/eth"] if u]
MARKET_ABI=[{"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},{"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}]}]}]},{"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]}]
GT_ABI=[{"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"address"},{"type":"uint128"},{"type":"bytes"}]},{"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},{"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},{"type":"function","name":"isDelegate","stateMutability":"view","inputs":[{"type":"address"},{"type":"address"}],"outputs":[{"type":"bool"}]},{"type":"function","name":"nonces","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]}]
ORDER_ABI=[{"type":"function","name":"maker","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},{"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},{"type":"function","name":"virtualXtReserve","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},{"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},{"type":"function","name":"tokenReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]}]
ERC20=[{"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},{"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},{"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},{"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},{"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]}]
ORDER_PLACED={"anonymous":False,"type":"event","name":"OrderPlaced","inputs":[{"indexed":True,"name":"maker","type":"address"},{"indexed":True,"name":"market","type":"address"},{"indexed":False,"name":"order","type":"address"},{"indexed":False,"name":"gtId","type":"uint256"},{"indexed":False,"name":"debtTokenToDeposit","type":"uint256"},{"indexed":False,"name":"ftToDeposit","type":"uint256"},{"indexed":False,"name":"xtToDeposit","type":"uint256"}]}
ISSUE_FT={"anonymous":False,"type":"event","name":"IssueFt","inputs":[{"indexed":True,"name":"caller","type":"address"},{"indexed":True,"name":"recipient","type":"address"},{"indexed":True,"name":"gtId","type":"uint256"},{"indexed":False,"name":"debtAmt","type":"uint128"},{"indexed":False,"name":"ftAmt","type":"uint128"},{"indexed":False,"name":"fee","type":"uint128"},{"indexed":False,"name":"collateralData","type":"bytes"}]}
PATHS={"TermMaxMarketV2":"contracts/v2/TermMaxMarketV2.sol","TermMaxOrderV2":"contracts/v2/TermMaxOrderV2.sol","GearingTokenWithERC20V2":"contracts/v2/tokens/GearingTokenWithERC20V2.sol"}

def default(x:Any)->Any:
    if isinstance(x,(bytes,bytearray,HexBytes)): return "0x"+bytes(x).hex()
    if hasattr(x,"items"): return dict(x)
    return str(x)
def safe(fn)->dict[str,Any]:
    try:
        v=fn.call(); return {"ok":True,"value":list(v) if isinstance(v,tuple) else v}
    except Exception as e: return {"ok":False,"error":f"{type(e).__name__}: {e}"}
def value(r:dict[str,Any],d:Any=None)->Any: return r.get("value",d) if r.get("ok") else d
def connect():
    a=[]
    for u in RPC:
        try:
            w=Web3(Web3.HTTPProvider(u,request_kwargs={"timeout":40})); c=w.eth.chain_id; b=w.eth.block_number
            if c!=1: raise RuntimeError(c)
            a.append({"url":u,"ok":True,"block":b}); return w,u,a
        except Exception as e: a.append({"url":u,"ok":False,"error":f"{type(e).__name__}: {e}"})
    raise RuntimeError(json.dumps(a))
def events(w,receipt,abi):
    sig=Web3.keccak(text=f"{abi['name']}({','.join(i['type'] for i in abi['inputs'])})"); out=[]
    for raw in receipt.logs:
        if raw["topics"] and bytes(raw["topics"][0])==bytes(sig):
            d=get_event_data(w.codec,abi,raw); out.append({"address":raw["address"],"args":dict(d["args"])})
    return out
def meta(w,a):
    a=Web3.to_checksum_address(a); c=w.eth.contract(address=a,abi=ERC20)
    return {"address":a,"symbol":safe(c.functions.symbol()),"name":safe(c.functions.name()),"decimals":safe(c.functions.decimals()),"totalSupply":safe(c.functions.totalSupply())}
def bind(w,a):
    a=Web3.to_checksum_address(a); code=bytes(w.eth.get_code(a)); impl=a; kind="direct"
    m=re.fullmatch(r"363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3",code.hex())
    if m: impl=Web3.to_checksum_address("0x"+m.group(1)); kind="eip1167"
    else:
        raw=bytes(w.eth.get_storage_at(a,EIP1967))
        if any(raw):
            x=Web3.to_checksum_address("0x"+raw[-20:].hex())
            if bytes(w.eth.get_code(x)): impl=x; kind="eip1967"
    ic=bytes(w.eth.get_code(impl)); return {"address":a,"kind":kind,"implementation":impl,"runtimeKeccak256":Web3.keccak(code).hex(),"implementationRuntimeKeccak256":Web3.keccak(ic).hex()}
def explorer(p):
    last=None
    for i in range(7):
        try:
            r=requests.get(ROUTESCAN,params=p,timeout=60,headers={"User-Agent":"termmax-binding-v2/1"})
            if r.status_code==429: time.sleep(2*(i+1)); continue
            r.raise_for_status(); return r.json()
        except Exception as e: last=e; time.sleep(1.5*(i+1))
    raise RuntimeError(str(last))
def parse_source(t):
    t=t.strip()
    for x in ([t[1:-1],t] if t.startswith("{{") and t.endswith("}}") else [t]):
        try:
            o=json.loads(x)
            if isinstance(o,dict): return o
        except Exception: pass
    return None
def source(impl):
    p=explorer({"module":"contract","action":"getsourcecode","address":impl}); rows=p.get("result",[]) if isinstance(p,dict) else []; row=rows[0] if isinstance(rows,list) and rows else {}; n=str(row.get("ContractName") or ""); s=str(row.get("SourceCode") or ""); r={"contractName":n,"compilerVersion":row.get("CompilerVersion")}; o=parse_source(s); path=PATHS.get(n)
    if o and path:
        d=str(o.get("sources",{}).get(path,{}).get("content") or ""); q=requests.get(f"https://raw.githubusercontent.com/term-structure/termmax-contract-v2/{PINNED}/{path}",timeout=60).text; r.update({"path":path,"deployedSha256":hashlib.sha256(d.encode()).hexdigest(),"pinnedSha256":hashlib.sha256(q.encode()).hexdigest(),"equalsPinned":d==q})
    return r

def main():
    w,rpc,attempts=connect(); latest=w.eth.get_block("latest"); receipt=w.eth.get_transaction_receipt(TX); placed=events(w,receipt,ORDER_PLACED); issued=events(w,receipt,ISSUE_FT)
    if not placed or not issued: raise RuntimeError("required events missing")
    pa=placed[0]["args"]; ia=issued[0]["args"]; order=Web3.to_checksum_address(pa["order"]); gid=int(pa["gtId"])
    m=w.eth.contract(address=MARKET,abi=MARKET_ABI); ft,xt,gt,coll,debt=[Web3.to_checksum_address(x) for x in m.functions.tokens().call()]; g=w.eth.contract(address=gt,abi=GT_ABI); o=w.eth.contract(address=order,abi=ORDER_ABI)
    loan=safe(g.functions.loanInfo(gid)); cv=safe(g.functions.getCollateralValue(ia["collateralData"])); cfg=list(m.functions.config().call()); maturity=int(cfg[1]); cm=meta(w,coll); dm=meta(w,debt); dec=int(value(cm["decimals"],18)); amount=int.from_bytes(bytes(ia["collateralData"]),"big") if len(bytes(ia["collateralData"]))==32 else None
    bindings={"market":bind(w,MARKET),"order":bind(w,order),"gt":bind(w,gt)}
    for b in bindings.values(): b["source"]=source(b["implementation"])
    out={"schema":"termmax-latest-delegated-binding/v2","generatedAtUtc":datetime.now(timezone.utc).isoformat(),"safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},"rpc":rpc,"rpcAttempts":attempts,"latestBlock":{"number":int(latest.number),"hash":latest.hash.hex(),"timestamp":int(latest.timestamp),"timestampUtc":datetime.fromtimestamp(latest.timestamp,timezone.utc).isoformat()},"transaction":{"hash":TX,"blockNumber":int(receipt.blockNumber),"status":int(receipt.status),"OrderPlaced":placed,"IssueFt":issued},"assertions":{"marketMatches":Web3.to_checksum_address(pa["market"])==MARKET,"orderMatches":order==EXPECTED_ORDER,"gtMatches":gt==EXPECTED_GT,"delegateeMatchesOrder":order==EXPECTED_ORDER,"delegationStillSet":safe(g.functions.isDelegate(DELEGATOR,order)),"makerMatches":Web3.to_checksum_address(pa["maker"])==DELEGATOR},"addresses":{"market":MARKET,"order":order,"gt":gt,"ft":ft,"xt":xt,"collateral":coll,"debtToken":debt},"tokenMetadata":{"collateral":cm,"debtToken":dm},"current":{"marketConfig":cfg,"maturityUtc":datetime.fromtimestamp(maturity,timezone.utc).isoformat(),"activeBeforeMaturity":int(latest.timestamp)<maturity,"marketPaused":safe(m.functions.paused()),"loanInfo":loan,"collateralDataFromIssueFt":ia["collateralData"],"collateralAmountRaw":amount,"collateralAmountHuman":amount/(10**dec) if amount is not None else None,"collateralValueUsdCurrent":int(value(cv,0))/1e8 if cv.get("ok") else None,"gtTotalSupply":safe(g.functions.totalSupply()),"delegatorNonce":safe(g.functions.nonces(DELEGATOR)),"ftTotalSupply":meta(w,ft)["totalSupply"],"orderMaker":safe(o.functions.maker()),"orderMarket":safe(o.functions.market()),"orderVirtualXtReserve":safe(o.functions.virtualXtReserve()),"orderPool":safe(o.functions.pool()),"orderReserves":safe(o.functions.tokenReserves())},"bindings":bindings}
    (OUT/"LATEST_DELEGATED_FLOW_BINDING_V2.json").write_text(json.dumps(out,indent=2,default=default)); print(json.dumps(out,indent=2,default=default)); return 0
if __name__=="__main__": raise SystemExit(main())
