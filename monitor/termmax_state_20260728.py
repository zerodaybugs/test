#!/usr/bin/env python3
"""Public, read-only TermMax vault state monitor.

The script uses only public JSON-RPC eth_call/getBlock and indexed explorer GET
requests. It loads no private key and cannot sign or broadcast a transaction.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from eth_abi import decode as abi_decode
from hexbytes import HexBytes
from web3 import Web3
from web3._utils.events import get_event_data

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
VAULT = Web3.to_checksum_address("0xF488ccdf04079cC03183cDB6A147d12Cf97F9317")
START_BLOCK = 23_490_022
PREVIOUS_BLOCK = 25_597_355
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/1"
RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://rpc.flashbots.net",
]

VAULT_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"totalFt","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"maxDeposit","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"badDebtMapping","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewWithdraw","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"withdrawFts","stateMutability":"nonpayable","inputs":[{"type":"address"},{"type":"uint256"},{"type":"address"},{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ORDER_ABI = [
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"orderExpiryTimestamp","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]},
]
MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"},{"type":"bytes"}]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}]}]}]},
]
GT_ABI = [
    {"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"address"},{"type":"uint32"},{"type":"uint32"},{"type":"bool"}]}]}]},
]
ORACLE_ABI = [{"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]}]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
EVENTS = {
    "NewOrderCreated": {"anonymous":False,"type":"event","name":"NewOrderCreated","inputs":[{"indexed":True,"name":"caller","type":"address"},{"indexed":True,"name":"market","type":"address"},{"indexed":True,"name":"order","type":"address"}]},
    "RedeemOrder": {"anonymous":False,"type":"event","name":"RedeemOrder","inputs":[{"indexed":True,"name":"caller","type":"address"},{"indexed":True,"name":"order","type":"address"},{"indexed":False,"name":"badDebt","type":"uint256"},{"indexed":False,"name":"deliveryAmount","type":"uint256"}]},
    "WithdrawFts": {"anonymous":False,"type":"event","name":"WithdrawFts","inputs":[{"indexed":True,"name":"caller","type":"address"},{"indexed":True,"name":"recipient","type":"address"},{"indexed":True,"name":"order","type":"address"},{"indexed":False,"name":"amount","type":"uint256"},{"indexed":False,"name":"shares","type":"uint256"}]},
    "DealBadDebt": {"anonymous":False,"type":"event","name":"DealBadDebt","inputs":[{"indexed":True,"name":"caller","type":"address"},{"indexed":True,"name":"recipient","type":"address"},{"indexed":True,"name":"collateral","type":"address"},{"indexed":False,"name":"badDebt","type":"uint256"},{"indexed":False,"name":"shares","type":"uint256"},{"indexed":False,"name":"collateralOut","type":"uint256"}]},
}


def default(o: Any) -> Any:
    if isinstance(o, (bytes, bytearray, HexBytes)):
        return "0x" + bytes(o).hex()
    return str(o)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        v = fn(*args, **kwargs)
        return {"ok": True, "value": list(v) if isinstance(v, tuple) else v}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def val(r: dict[str, Any], d: Any = None) -> Any:
    return r.get("value", d) if r.get("ok") else d


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts = []
    for url in RPCS:
        try:
            w = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
            cid, bn = w.eth.chain_id, w.eth.block_number
            if cid != 1:
                raise RuntimeError(f"chainId={cid}")
            attempts.append({"url":url,"ok":True,"block":bn})
            return w, url, attempts
        except Exception as e:
            attempts.append({"url":url,"ok":False,"error":f"{type(e).__name__}: {e}"})
    raise RuntimeError(json.dumps(attempts))


def get_json(path: str, params: dict[str, Any]) -> Any:
    url = f"{ROUTESCAN}/{path.lstrip('/')}"
    last = None
    for i in range(6):
        try:
            r = requests.get(url, params=params, timeout=60, headers={"User-Agent":"public-state-monitor/1"})
            if r.status_code == 429:
                time.sleep(2 * (i + 1)); continue
            r.raise_for_status(); return r.json()
        except Exception as e:
            last = e; time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"GET {url}: {last}")


def sig(abi: dict[str, Any]) -> str:
    return Web3.keccak(text=f"{abi['name']}({','.join(x['type'] for x in abi['inputs'])})").hex()


def logs(w3: Web3, name: str, latest: int) -> list[dict[str, Any]]:
    abi = EVENTS[name]; page = 1; raw = []
    while True:
        p = get_json("etherscan/api", {"module":"logs","action":"getLogs","address":VAULT,"fromBlock":START_BLOCK,"toBlock":latest,"topic0":sig(abi),"page":page,"offset":1000})
        rows = p.get("result", []) if isinstance(p, dict) else []
        if isinstance(rows, str):
            if "No" in rows: break
            raise RuntimeError(str(p))
        if not rows: break
        raw += rows
        if len(rows) < 1000: break
        page += 1
    out = []
    for r in raw:
        obj = {"address":Web3.to_checksum_address(r["address"]),"topics":[HexBytes(x) for x in r["topics"]],"data":HexBytes(r["data"]),"blockNumber":int(r["blockNumber"],16) if str(r["blockNumber"]).startswith("0x") else int(r["blockNumber"]),"transactionHash":HexBytes(r["transactionHash"]),"transactionIndex":int(r.get("transactionIndex","0x0"),16),"blockHash":HexBytes(r["blockHash"]),"logIndex":int(r.get("logIndex","0x0"),16),"removed":False}
        d = get_event_data(w3.codec, abi, obj)
        out.append({"event":name,"blockNumber":obj["blockNumber"],"blockHash":"0x"+obj["blockHash"].hex(),"transactionHash":"0x"+obj["transactionHash"].hex(),"logIndex":obj["logIndex"],"args":dict(d["args"])})
    return out


def token(w3: Web3, a: str, block: int) -> dict[str, Any]:
    a = Web3.to_checksum_address(a); c = w3.eth.contract(address=a, abi=ERC20_ABI)
    return {"address":a,"symbol":safe(c.functions.symbol().call,block_identifier=block),"decimals":safe(c.functions.decimals().call,block_identifier=block)}


def inspect_order(w3: Web3, vault, address: str, block: int, ts: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address); o = w3.eth.contract(address=address,abi=ORDER_ABI)
    row = {"order":address,"orderMaturity":safe(vault.functions.orderMaturity(address).call,block_identifier=block),"market":safe(o.functions.market().call,block_identifier=block),"pool":safe(o.functions.pool().call,block_identifier=block),"orderExpiry":safe(o.functions.orderExpiryTimestamp().call,block_identifier=block)}
    market_addr = val(row["market"])
    if not market_addr: return row
    market_addr = Web3.to_checksum_address(market_addr); m = w3.eth.contract(address=market_addr,abi=MARKET_ABI)
    row["tokens"] = safe(m.functions.tokens().call,block_identifier=block); toks = val(row["tokens"])
    row["marketConfig"] = safe(m.functions.config().call,block_identifier=block); cfg = val(row["marketConfig"])
    if not toks: return row
    ft,xt,gt,collateral,debt = [Web3.to_checksum_address(x) for x in toks]
    row["addresses"]={"ft":ft,"xt":xt,"gt":gt,"collateral":collateral,"debt":debt}
    row["collateralMeta"] = token(w3,collateral,block); row["debtMeta"] = token(w3,debt,block)
    ftc=w3.eth.contract(address=ft,abi=ERC20_ABI); row["ftBalance"]=safe(ftc.functions.balanceOf(address).call,block_identifier=block)
    maturity = int(cfg[1]) if cfg else int(val(row["orderMaturity"],0) or 0); row["marketMaturity"]=maturity; row["matured"]=bool(maturity and ts>=maturity)
    amount=int(val(row["ftBalance"],0) or 0)
    if amount<=0: return row
    row["previewRedeem"]=safe(m.functions.previewRedeem(amount).call,block_identifier=block); preview=val(row["previewRedeem"])
    if not preview: return row
    debt_out=int(preview[0]); delivery=bytes(preview[1]); delivery_amt=int.from_bytes(delivery,"big") if len(delivery)==32 else None
    gt_c=w3.eth.contract(address=gt,abi=GT_ABI); cv=safe(gt_c.functions.getCollateralValue(delivery).call,block_identifier=block); gc=safe(gt_c.functions.getGtConfig().call,block_identifier=block)
    row["collateralValue1e8"]=cv; row["gtConfig"]=gc
    cv_debt=None; config=val(gc); debt_dec=int(val(row["debtMeta"]["decimals"],6))
    if config and val(cv) is not None:
        oracle=Web3.to_checksum_address(config[5][0]); oc=w3.eth.contract(address=oracle,abi=ORACLE_ABI); pr=safe(oc.functions.getPrice(debt).call,block_identifier=block); row["debtPrice"]=pr
        if val(pr):
            price,pdec=map(int,val(pr)); cv_debt=int(val(cv))*10**debt_dec*10**pdec//(price*10**8)
    recovery=debt_out+(cv_debt or 0) if cv_debt is not None else None
    row["economics"]={"nominal":amount,"debtOut":debt_out,"deliveryData":"0x"+delivery.hex(),"deliveryAmount":delivery_amt,"collateralValueDebt":cv_debt,"recovery":recovery,"loss":max(0,amount-recovery) if recovery is not None else None,"quality1e18":recovery*10**18//amount if recovery is not None else None}
    return row


def holders() -> dict[str, Any]:
    try:
        p=get_json(f"erc20/{VAULT}/holders",{"limit":100,"count":"true"}); out=[]
        for x in p.get("items",[]):
            a=x.get("address") or x.get("holder") or x.get("id"); b=x.get("balance") or x.get("value") or 0
            if a: out.append({"address":Web3.to_checksum_address(a),"balance":int(str(b),16) if str(b).startswith("0x") else int(b),"percentage":x.get("percentage")})
        return {"ok":True,"count":p.get("count"),"items":out}
    except Exception as e: return {"ok":False,"error":f"{type(e).__name__}: {e}"}


def simulate(w3: Web3, vault, order: str, amount: int, owner: str, block: int) -> dict[str, Any]:
    recipient=Web3.to_checksum_address("0x1111111111111111111111111111111111111111"); owner=Web3.to_checksum_address(owner)
    fn=vault.functions.withdrawFts(Web3.to_checksum_address(order),amount,recipient,owner)
    try:
        raw=w3.eth.call({"from":owner,"to":VAULT,"data":fn._encode_transaction_data()},block_identifier=block)
        return {"ok":True,"owner":owner,"order":order,"amount":amount,"shares":int(abi_decode(["uint256"],raw)[0]),"raw":"0x"+raw.hex()}
    except Exception as e: return {"ok":False,"owner":owner,"order":order,"amount":amount,"error":f"{type(e).__name__}: {e}"}


def main() -> int:
    w3,rpc,attempts=connect(); latest=w3.eth.block_number; b=w3.eth.get_block(latest); ts=int(b.timestamp)
    vault=w3.eth.contract(address=VAULT,abi=VAULT_ABI)
    ev={k:logs(w3,k,latest) for k in EVENTS}; orders=list(dict.fromkeys(Web3.to_checksum_address(x["args"]["order"]) for x in ev["NewOrderCreated"]))
    rows=[inspect_order(w3,vault,a,latest,ts) for a in orders]
    active=[x for x in rows if int(val(x["orderMaturity"],0) or 0)>0]; resolved=[x for x in active if x.get("economics",{}).get("recovery") is not None]
    loss=[x for x in resolved if int(x["economics"]["loss"] or 0)>0]; good=[x for x in resolved if int(x["economics"]["quality1e18"] or 0)>=999_900_000_000_000_000]
    state={n:safe(getattr(vault.functions,n)().call,block_identifier=latest) for n in ["name","symbol","asset","pool","totalFt","totalAssets","totalSupply","paused"]}; state["maxDeposit"]=safe(vault.functions.maxDeposit("0x0000000000000000000000000000000000000000").call,block_identifier=latest)
    hs=holders(); good_capacity=sum(int(x["economics"]["nominal"]) for x in good); latent=sum(int(x["economics"]["loss"]) for x in loss); nominal=int(val(state["totalAssets"],0) or 0); shares_needed=int(vault.functions.previewWithdraw(good_capacity).call(block_identifier=latest)) if good_capacity else 0
    capable=[h for h in hs.get("items",[]) if h["balance"]>=shares_needed]
    sims=[]; best=max(good,key=lambda x:int(x["economics"]["quality1e18"]),default=None)
    if best and hs.get("ok"):
        amount=min(1_000_000,int(best["economics"]["nominal"])); need=int(vault.functions.previewWithdraw(amount).call(block_identifier=latest)); h=next((x for x in hs["items"] if x["balance"]>=need),None)
        if h: sims=[simulate(w3,vault,best["order"],amount,h["address"],latest),simulate(w3,vault,best["order"],amount,"0x2222222222222222222222222222222222222222",latest)]
    order_coll={x["order"].lower():x.get("addresses",{}).get("collateral") for x in rows}; cols={order_coll.get(str(e["args"]["order"]).lower()) for e in ev["RedeemOrder"]}; buckets=[]
    for c in sorted(x for x in cols if x):
        ec=w3.eth.contract(address=Web3.to_checksum_address(c),abi=ERC20_ABI); buckets.append({"collateral":c,"meta":token(w3,c,latest),"badDebt":safe(vault.functions.badDebtMapping(c).call,block_identifier=latest),"vaultBalance":safe(ec.functions.balanceOf(VAULT).call,block_identifier=latest)})
    full={"schema":"termmax-public-state/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),"safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},"rpc":rpc,"rpcAttempts":attempts,"block":{"number":latest,"hash":"0x"+b.hash.hex(),"timestamp":ts,"timestampUtc":datetime.fromtimestamp(ts,tz=timezone.utc).isoformat()},"vault":str(VAULT),"state":state,"events":{"counts":{k:len(v) for k,v in ev.items()},"sincePrevious":{k:[x for x in v if x["blockNumber"]>PREVIOUS_BLOCK] for k,v in ev.items()},"all":ev},"orders":rows,"holders":hs,"badDebtBuckets":buckets,"economics":{"activeOrders":len(active),"resolvedOrders":len(resolved),"lossOrders":len(loss),"goodOrders":len(good),"knownLatentLoss":latent,"knownGoodCapacity":good_capacity,"maxProRataExcess":good_capacity*latent//nominal if nominal else 0,"sharesNeeded":shares_needed,"capableHolders":capable,"worst":max(loss,key=lambda x:int(x["economics"]["loss"]),default=None),"best":best},"withdrawFtsReadOnlySimulations":sims}
    compact={"generatedAtUtc":full["generatedAtUtc"],"block":full["block"],"state":state,"eventCounts":full["events"]["counts"],"eventsSincePrevious":{k:len(v) for k,v in full["events"]["sincePrevious"].items()},"economics":full["economics"],"nonzeroBadDebtBuckets":[x for x in buckets if int(val(x["badDebt"],0) or 0)>0],"simulations":sims}
    (OUT/"FULL.json").write_text(json.dumps(full,indent=2,default=default),encoding="utf-8"); (OUT/"COMPACT.json").write_text(json.dumps(compact,indent=2,default=default),encoding="utf-8"); print(json.dumps(compact,indent=2,default=default)); return 0

if __name__ == "__main__": raise SystemExit(main())
