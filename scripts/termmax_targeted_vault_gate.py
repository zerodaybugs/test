#!/usr/bin/env python3
"""Read-only same-block state gate for the two officially documented Ethereum TermMax vaults."""
import json
import os
import time
import urllib.request
from pathlib import Path

OUT = Path(os.environ.get("OUT_DIR", "termmax-targeted-vault-gate"))
OUT.mkdir(parents=True, exist_ok=True)
VAULTS = {
    "TMX-USDC": "0x984408C88a9B042BF3e2ddf921Cd1fAFB4b735D1",
    "TMX-WETH": "0xDEB8a9C0546A01b7e5CeE8e44Fd0C8D8B96a1f6e",
}
START_BLOCK = int(os.environ.get("START_BLOCK", "22000000"))
ENDPOINTS = [
    "https://eth.llamarpc.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://ethereum.publicnode.com",
]
TOPIC_NEW_ORDER = "0x3ca4bef6cb680238d8c3dcdcca83a5aadcadff2571d3a2c67ee85b2750944b97"
TOPIC_REDEEM_ORDER = "0x21f71f6609f50b01dbe90a67add86958b134ef6fa7e8c668df45730004806242"
TOPIC_WITHDRAW_FTS = "0x53239297447654f3a1c8342314051bc2fe9134b7bbe4a390eade008bb5eca1f2"
SEL = {
    "asset":"0x38d52e0f","totalAssets":"0x01e1d114","totalSupply":"0x18160ddd",
    "name":"0x06fdde03","symbol":"0x95d89b41","decimals":"0x313ce567",
    "curator":"0xe66f53b7","guardian":"0x452a9320","paused":"0x5c975abb",
    "performanceFeeRate":"0x0ffbfda4","pool":"0x16f0115b","tokens":"0x9d63848a",
    "config":"0x79502c55","market":"0x80f55605","tokenReserves":"0x4bad9510",
    "getRealReserves":"0xd5501b0b","virtualXtReserve":"0x07e470f3",
    "orderExpiryTimestamp":"0x3a0d3561","totalFt":"0x60dbe99d","accretingPrincipal":"0x33c739a0",
    "annualizedInterest":"0x62925a0e","performanceFee":"0x42f6fa18",
}
SEL_ADDR = {"maxDeposit":"0x402d267d","badDebtMapping":"0x618f9694","orderMaturity":"0xac33207f","balanceOf":"0x70a08231"}
raw = {"endpointTests":[],"progress":{}}
req_id = 0


def rpc(url, method, params, timeout=60):
    global req_id
    req_id += 1
    body = json.dumps({"jsonrpc":"2.0","id":req_id,"method":method,"params":params}).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type":"application/json","User-Agent":"termmax-targeted-gate/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        obj = json.loads(response.read().decode())
    if "error" in obj:
        raise RuntimeError(f"{method}: {obj['error']}")
    return obj["result"]


def choose_endpoint():
    for url in ENDPOINTS:
        try:
            chain = rpc(url,"eth_chainId",[])
            latest = int(rpc(url,"eth_blockNumber",[]),16)
            # Require historical log support, not merely eth_call support.
            test_filter = {"fromBlock":hex(max(latest-5,0)),"toBlock":hex(latest),"address":list(VAULTS.values())[0],"topics":[[TOPIC_NEW_ORDER,TOPIC_REDEEM_ORDER,TOPIC_WITHDRAW_FTS]]}
            rpc(url,"eth_getLogs",[test_filter],timeout=30)
            raw["endpointTests"].append({"url":url,"chainId":chain,"latest":latest,"logCapable":True})
            if int(chain,16)==1:
                return url, latest
        except Exception as exc:
            raw["endpointTests"].append({"url":url,"logCapable":False,"error":repr(exc)})
    raise RuntimeError("No log-capable Ethereum RPC")


def chunks(data):
    if not data or data == "0x": return []
    x=data[2:]
    return [x[i:i+64] for i in range(0,len(x),64)]


def addr_word(word): return "0x"+word[-40:]
def addr_topic(topic): return "0x"+topic[-40:]
def u(data,index=0):
    w=chunks(data); return int(w[index],16) if len(w)>index else None
def a(data,index=0):
    w=chunks(data); return addr_word(w[index]) if len(w)>index else None

def s(data):
    if not data or data=="0x": return None
    blob=bytes.fromhex(data[2:])
    try:
        if len(blob)>=64:
            off=int.from_bytes(blob[:32],"big")
            if off+32<=len(blob):
                ln=int.from_bytes(blob[off:off+32],"big")
                return blob[off+32:off+32+ln].decode("utf-8","replace").strip("\x00")
        return blob[:32].rstrip(b"\x00").decode("utf-8","replace")
    except Exception: return None

def arg(selector,address): return selector+address.lower().replace("0x","").rjust(64,"0")
def call(url,to,data,block): return rpc(url,"eth_call",[{"to":to,"data":data},hex(block)])
def safe(url,to,data,block):
    try: return call(url,to,data,block)
    except Exception as exc: return {"error":repr(exc)}
def cu(url,to,selector,block):
    x=safe(url,to,selector,block); return x if isinstance(x,dict) else u(x)
def ca(url,to,selector,block):
    x=safe(url,to,selector,block); return x if isinstance(x,dict) else a(x)
def cs(url,to,selector,block):
    x=safe(url,to,selector,block); return x if isinstance(x,dict) else s(x)
def cau(url,to,selector,address,block):
    x=safe(url,to,arg(selector,address),block); return x if isinstance(x,dict) else u(x)

def clone_impl(code):
    body=(code or "0x")[2:].lower(); marker="363d3d373d3d3d363d73"; p=body.find(marker)
    return "0x"+body[p+len(marker):p+len(marker)+40] if p>=0 and len(body)>=p+len(marker)+40 else None

def scan_logs(url,address,start,end,label):
    current=start; span=100000; logs=[]; progress=[]
    while current<=end:
        to=min(current+span-1,end)
        filt={"fromBlock":hex(current),"toBlock":hex(to),"address":address,"topics":[[TOPIC_NEW_ORDER,TOPIC_REDEEM_ORDER,TOPIC_WITHDRAW_FTS]]}
        try:
            part=rpc(url,"eth_getLogs",[filt],timeout=90)
            logs.extend(part); progress.append({"from":current,"to":to,"count":len(part),"span":span}); current=to+1
            if len(part)<100 and span<200000: span=min(span*2,200000)
        except Exception as exc:
            progress.append({"from":current,"to":to,"span":span,"error":repr(exc)})
            if span<=100: raise
            span=max(span//2,100)
        if len(progress)%10==0: (OUT/f"{label}_progress.json").write_text(json.dumps(progress,indent=2))
    raw["progress"][label]=progress
    return logs

def token_info(url,token,block):
    if not isinstance(token,str): return None
    return {"address":token,"name":cs(url,token,SEL["name"],block),"symbol":cs(url,token,SEL["symbol"],block),"decimals":cu(url,token,SEL["decimals"],block),"totalSupply":cu(url,token,SEL["totalSupply"],block)}

url, latest = choose_endpoint()
block_obj=rpc(url,"eth_getBlockByNumber",[hex(latest),False])
snapshot={"endpoint":url,"block":latest,"blockHash":block_obj["hash"],"timestamp":int(block_obj["timestamp"],16),"startBlock":START_BLOCK}
result={"snapshot":snapshot,"vaults":[]}

for label,vault in VAULTS.items():
    logs=scan_logs(url,vault,START_BLOCK,latest,label.lower())
    (OUT/f"{label}_EVENTS_RAW.json").write_text(json.dumps(logs,indent=2))
    orders=[]; redeems=[]; withdrawals=[]
    for log in logs:
        t0=log["topics"][0].lower()
        if t0==TOPIC_NEW_ORDER.lower() and len(log["topics"])>=4:
            orders.append({"caller":addr_topic(log["topics"][1]),"market":addr_topic(log["topics"][2]),"order":addr_topic(log["topics"][3]),"block":int(log["blockNumber"],16),"tx":log["transactionHash"]})
        elif t0==TOPIC_REDEEM_ORDER.lower() and len(log["topics"])>=3:
            w=chunks(log.get("data","0x")); redeems.append({"caller":addr_topic(log["topics"][1]),"order":addr_topic(log["topics"][2]),"badDebt":int(w[0],16) if len(w)>0 else None,"deliveryAmount":int(w[1],16) if len(w)>1 else None,"block":int(log["blockNumber"],16),"tx":log["transactionHash"]})
        elif t0==TOPIC_WITHDRAW_FTS.lower() and len(log["topics"])>=4:
            w=chunks(log.get("data","0x")); withdrawals.append({"caller":addr_topic(log["topics"][1]),"recipient":addr_topic(log["topics"][2]),"order":addr_topic(log["topics"][3]),"amount":int(w[0],16) if len(w)>0 else None,"shares":int(w[1],16) if len(w)>1 else None,"block":int(log["blockNumber"],16),"tx":log["transactionHash"]})
    code=rpc(url,"eth_getCode",[vault,hex(latest)])
    paused_raw=safe(url,vault,SEL["paused"],latest)
    asset=ca(url,vault,SEL["asset"],latest)
    vi={
        "label":label,"vault":vault,"name":cs(url,vault,SEL["name"],latest),"symbol":cs(url,vault,SEL["symbol"],latest),
        "asset":asset,"assetInfo":token_info(url,asset,latest),"totalAssets":cu(url,vault,SEL["totalAssets"],latest),
        "totalSupply":cu(url,vault,SEL["totalSupply"],latest),"maxDeposit":cau(url,vault,SEL_ADDR["maxDeposit"],"0x"+"0"*40,latest),
        "paused":paused_raw if isinstance(paused_raw,dict) else bool(u(paused_raw)),"curator":ca(url,vault,SEL["curator"],latest),
        "guardian":ca(url,vault,SEL["guardian"],latest),"performanceFeeRate":cu(url,vault,SEL["performanceFeeRate"],latest),
        "pool":ca(url,vault,SEL["pool"],latest),"totalFt":cu(url,vault,SEL["totalFt"],latest),
        "accretingPrincipal":cu(url,vault,SEL["accretingPrincipal"],latest),"annualizedInterest":cu(url,vault,SEL["annualizedInterest"],latest),
        "performanceFee":cu(url,vault,SEL["performanceFee"],latest),"codeBytes":max((len(code)-2)//2,0),"cloneImplementation":clone_impl(code),
        "orderCount":len(orders),"redeemOrderEventCount":len(redeems),"withdrawFtsEventCount":len(withdrawals),
        "redeemOrderEvents":redeems,"withdrawFtsEvents":withdrawals,"orders":[]
    }
    for om in orders:
        market=om["market"]; order=om["order"]
        tr=safe(url,market,SEL["tokens"],latest); tw=chunks(tr) if isinstance(tr,str) else []
        toks=[addr_word(x) for x in tw[:5]] if len(tw)>=5 else [None]*5
        ft,xt,gt,collateral,debt=toks
        cfg=safe(url,market,SEL["config"],latest); cw=chunks(cfg) if isinstance(cfg,str) else []
        maturity=int(cw[1],16) if len(cw)>1 else None
        rr=safe(url,order,SEL["tokenReserves"],latest); rw=chunks(rr) if isinstance(rr,str) else []
        real=safe(url,order,SEL["getRealReserves"],latest); realw=chunks(real) if isinstance(real,str) else []
        ocode=rpc(url,"eth_getCode",[order,hex(latest)])
        oi={
            **om,"marketName":cs(url,market,SEL["name"],latest),"tokens":{"ft":ft,"xt":xt,"gt":gt,"collateral":collateral,"debt":debt},
            "debtInfo":token_info(url,debt,latest),"collateralInfo":token_info(url,collateral,latest),"maturity":maturity,
            "matured":maturity is not None and snapshot["timestamp"]>=maturity,"marketGetter":ca(url,order,SEL["market"],latest),
            "ftReserve":int(rw[0],16) if len(rw)>0 else None,"xtReserve":int(rw[1],16) if len(rw)>1 else None,
            "realFtReserve":int(realw[0],16) if len(realw)>0 else None,"realXtReserve":int(realw[1],16) if len(realw)>1 else None,
            "ftBalance":cau(url,ft,SEL_ADDR["balanceOf"],order,latest) if ft else None,"virtualXtReserve":cu(url,order,SEL["virtualXtReserve"],latest),
            "orderExpiryTimestamp":cu(url,order,SEL["orderExpiryTimestamp"],latest),"pool":ca(url,order,SEL["pool"],latest),
            "vaultBadDebtForCollateral":cau(url,vault,SEL_ADDR["badDebtMapping"],collateral,latest) if collateral else None,
            "vaultOrderMaturity":cau(url,vault,SEL_ADDR["orderMaturity"],order,latest),"codeBytes":max((len(ocode)-2)//2,0),"cloneImplementation":clone_impl(ocode),
            "redeemEvents":[x for x in redeems if x["order"].lower()==order.lower()],"withdrawFtsEvents":[x for x in withdrawals if x["order"].lower()==order.lower()]
        }
        vi["orders"].append(oi)
    result["vaults"].append(vi)

result["summary"]={
    "vaultCount":len(result["vaults"]),"multiOrderVaults":[v["vault"] for v in result["vaults"] if v["orderCount"]>=2],
    "positiveTvlVaults":[v["vault"] for v in result["vaults"] if isinstance(v["totalAssets"],int) and v["totalAssets"]>0],
    "currentBadDebtVaults":[v["vault"] for v in result["vaults"] if any(isinstance(o["vaultBadDebtForCollateral"],int) and o["vaultBadDebtForCollateral"]>0 for o in v["orders"])],
    "withdrawFtsUsedVaults":[v["vault"] for v in result["vaults"] if v["withdrawFtsEventCount"]>0]
}
(OUT/"TARGETED_VAULT_STATE.json").write_text(json.dumps(result,indent=2))
(OUT/"SUMMARY.json").write_text(json.dumps(result["summary"],indent=2))
(OUT/"RPC_PROGRESS.json").write_text(json.dumps(raw,indent=2))
print(json.dumps(result["summary"],indent=2))
