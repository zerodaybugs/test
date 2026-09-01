#!/usr/bin/env python3
"""Read-only diagnostics and valuation for the live Prime Yield wstrBTC recovery bucket."""
from __future__ import annotations
import datetime as dt
import json
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("termmax-prime-yield-bucket")
RPCS = ["https://rpc.mevblocker.io","https://eth.drpc.org","https://1rpc.io/eth","https://ethereum-rpc.publicnode.com"]
VAULT = "0x17337c22cf8b7c1b6fc86f0ef7fcf05a7fa93f48"
MARKET = "0xd7e6c4fd81b72449ba2bb4cc4ca6670b31189f49"
ORDER = "0x385429223ddc9921f2491c4a16b79c0b0717c431"
GT = "0xe5a490b3438b213bb65971c4344e68f59dbfafc1"
COLLATERAL = "0xa3ca88cfb7bbe9cfbd47df053ffa2130c7e6f770"
DEBT_TOKEN = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
BAD_DEBT_RAW = 939_875
COLLATERAL_RAW = 9_267
SETTLEMENT_BLOCK = 24_826_646
SETTLEMENT_TX = "0x0d94a01690d1c246365a439a6a049e678df8003d1d7800c8ded7f42bed697c57"

S = {
    "getCollateralValue":"0x1b2b5fad","getGtConfig":"0xeef5777c","getPrice":"0x41976e09",
    "badDebtMapping":"0x618f9694","balanceOf":"0x70a08231","totalAssets":"0x01e1d114",
    "totalSupply":"0x18160ddd","maxDeposit":"0x402d267d","paused":"0x5c975abb",
    "asset":"0x38d52e0f","convertToAssets":"0x07a2d13a","decimals":"0x313ce567","symbol":"0x95d89b41",
}


def rpc_one(url: str, method: str, params: list[Any]) -> Any:
    req=urllib.request.Request(url,data=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode(),headers={"content-type":"application/json","user-agent":"termmax-prime-bucket-readonly/1.0"},method="POST")
    with urllib.request.urlopen(req,timeout=45) as response: body=json.load(response)
    if body.get("error"): raise RuntimeError(body["error"])
    return body.get("result")


def rpc(method: str, params: list[Any]) -> tuple[Any,str]:
    errors=[]
    for url in RPCS:
        try: return rpc_one(url,method,params),url
        except Exception as exc: errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(" | ".join(errors))


def word(data: str,i: int=0)->str:
    raw=(data or "0x").removeprefix("0x"); return raw[i*64:(i+1)*64].ljust(64,"0")

def uint(data: str,i: int=0)->int: return int(word(data,i) or "0",16)
def address_word(data: str,i: int=0)->str: return "0x"+word(data,i)[-40:].lower()
def arg_address(a: str)->str: return a.removeprefix("0x").lower().rjust(64,"0")
def arg_uint(v: int)->str: return f"{v:064x}"
def arg_bytes_uint(v: int)->str: return f"{32:064x}{32:064x}{v:064x}"


def raw_call(to: str,data: str,block: int|str="latest")->dict[str,Any]:
    tag=hex(block) if isinstance(block,int) else block
    raw,url=rpc("eth_call",[{"to":to,"data":data},tag])
    return {"ok":True,"raw":raw,"rpc":url,"blockTag":tag}

def safe_raw_call(to: str,data: str,block: int|str="latest")->dict[str,Any]:
    try: return raw_call(to,data,block)
    except Exception as exc: return {"ok":False,"error":f"{type(exc).__name__}: {exc}","blockTag":hex(block) if isinstance(block,int) else block}

def uint_call(to: str,data: str,block: int|str="latest")->dict[str,Any]:
    x=raw_call(to,data,block); x["uint"]=uint(x["raw"]); return x

def address_call(to: str,data: str,block: int|str="latest")->dict[str,Any]:
    x=raw_call(to,data,block); x["address"]=address_word(x["raw"]); return x


def block_meta(number: int)->dict[str,Any]:
    b,url=rpc("eth_getBlockByNumber",[hex(number),False]); ts=int(b["timestamp"],16)
    return {"number":number,"hash":b.get("hash"),"timestamp":ts,"timestampUtc":dt.datetime.fromtimestamp(ts,tz=dt.timezone.utc).isoformat(),"rpc":url}


def gt_config(block: int|str="latest")->dict[str,Any]:
    c=safe_raw_call(GT,S["getGtConfig"],block)
    if not c.get("ok"): return c
    raw=c["raw"]
    return {**c,"decoded":{"collateral":address_word(raw,0),"debtToken":address_word(raw,1),"ft":address_word(raw,2),"treasurer":address_word(raw,3),"maturity":uint(raw,4),"oracle":address_word(raw,5),"liquidationLtv":uint(raw,6),"maxLtv":uint(raw,7),"liquidatable":bool(uint(raw,8))}}


def oracle_price(oracle: str,asset: str,block: int|str="latest")->dict[str,Any]:
    p=safe_raw_call(oracle,S["getPrice"]+arg_address(asset),block)
    if p.get("ok"): p["price"]=uint(p["raw"],0); p["decimals"]=uint(p["raw"],1)
    return p


def snapshot(block: int|str)->dict[str,Any]:
    tag=hex(block) if isinstance(block,int) else block
    total_assets=uint_call(VAULT,S["totalAssets"],block); total_supply=uint_call(VAULT,S["totalSupply"],block)
    max_deposit=uint_call(VAULT,S["maxDeposit"]+arg_address(VAULT),block); paused=uint_call(VAULT,S["paused"],block)
    bad=uint_call(VAULT,S["badDebtMapping"]+arg_address(COLLATERAL),block); bal=uint_call(COLLATERAL,S["balanceOf"]+arg_address(VAULT),block)
    value={"ok":True,"uint":0,"blockTag":tag} if bal["uint"]==0 else safe_raw_call(GT,S["getCollateralValue"]+arg_bytes_uint(bal["uint"]),block)
    if value.get("ok") and "uint" not in value: value["uint"]=uint(value["raw"])
    return {"blockTag":tag,"totalAssetsRaw":total_assets["uint"],"totalSupplyRaw":total_supply["uint"],"maxDepositRaw":max_deposit["uint"],"paused":bool(paused["uint"]),"badDebtRaw":bad["uint"],"collateralRaw":bal["uint"],"collateralValueCall":value,"collateralUsdBase1e8":value.get("uint") if value.get("ok") else None,"badDebtUsdAssumingUSDCParBase1e8":bad["uint"]*100}


def main()->int:
    OUT.mkdir(parents=True,exist_ok=True)
    latest_hex,_=rpc("eth_blockNumber",[]); latest=int(latest_hex,16)
    receipt,_=rpc("eth_getTransactionReceipt",[SETTLEMENT_TX]); receipt_block=int(receipt["blockNumber"],16)
    cfg=gt_config(latest); oracle=cfg.get("decoded",{}).get("oracle") if cfg.get("ok") else None
    wrapper_asset=safe_raw_call(COLLATERAL,S["asset"],latest)
    if wrapper_asset.get("ok"): wrapper_asset["address"]=address_word(wrapper_asset["raw"])
    converted=safe_raw_call(COLLATERAL,S["convertToAssets"]+arg_uint(COLLATERAL_RAW),latest)
    if converted.get("ok"): converted["assetsRaw"]=uint(converted["raw"])
    diagnostics={
        "gtConfig":cfg,
        "oracleCollateralPrice":oracle_price(oracle,COLLATERAL,latest) if oracle else {"ok":False,"error":"no oracle"},
        "oracleDebtPrice":oracle_price(oracle,DEBT_TOKEN,latest) if oracle else {"ok":False,"error":"no oracle"},
        "wrapperAsset":wrapper_asset,
        "wrapperConvertToAssets":converted,
        "wrapperTotalAssets":safe_raw_call(COLLATERAL,S["totalAssets"],latest),
        "wrapperTotalSupply":safe_raw_call(COLLATERAL,S["totalSupply"],latest),
    }
    for key in ("wrapperTotalAssets","wrapperTotalSupply"):
        if diagnostics[key].get("ok"): diagnostics[key]["uint"]=uint(diagnostics[key]["raw"])
    result={"schema":"termmax-prime-yield-bucket-value/v3","generatedAtUtc":dt.datetime.now(dt.timezone.utc).isoformat(),"safety":{"signedTransactions":0,"broadcastTransactions":0},"addresses":{"vault":VAULT,"market":MARKET,"order":ORDER,"gt":GT,"collateral":COLLATERAL},"event":{"tx":SETTLEMENT_TX,"expectedBlock":SETTLEMENT_BLOCK,"receiptBlock":receipt_block,"badDebtRaw":BAD_DEBT_RAW,"deliveryAmountRaw":COLLATERAL_RAW},"blocks":{"beforeSettlement":block_meta(receipt_block-1),"settlement":block_meta(receipt_block),"latest":block_meta(latest)},"snapshots":{"beforeSettlement":snapshot(receipt_block-1),"afterSettlement":snapshot(receipt_block),"latest":snapshot(latest)},"diagnostics":diagnostics}
    latest_s=result["snapshots"]["latest"]
    value=latest_s["collateralUsdBase1e8"]; bad=latest_s["badDebtUsdAssumingUSDCParBase1e8"]
    if value is None:
        op=diagnostics["oracleCollateralPrice"]
        if op.get("ok"):
            value=COLLATERAL_RAW*op["price"]*10**8//(10**8*10**op["decimals"])
            latest_s["collateralUsdBase1e8FromDirectOracle"]=value
    if value is None:
        result["classification"]="ORACLE_VALUE_UNAVAILABLE"; result["status"]="INCOMPLETE"
    else:
        result["classification"]="SNAV1_UNDERRECOVERY" if value<bad else "TMV1_OVERRECOVERY" if value>bad else "PAR_RECOVERY"; result["status"]="PASS"
        latest_s["recoveryMinusBadDebtUsdBase1e8"]=value-bad; latest_s["recoveryRatio1e8"]=value*10**8//bad if bad else None
    (OUT/"SUMMARY.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps({"status":result["status"],"classification":result["classification"],"latest":latest_s,"diagnostics":diagnostics},indent=2))
    return 0 if result["status"]=="PASS" else 2

if __name__=="__main__": raise SystemExit(main())
