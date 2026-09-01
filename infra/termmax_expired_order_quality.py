#!/usr/bin/env python3
"""Read-only current recovery-quality scan for active but expired TermMax vault orders.

Calls each market's previewRedeem for the vault order's full FT balance, then values
physical-delivery collateral through the market GT's configured oracle when available.
No transaction is signed or broadcast.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("termmax-expired-order-quality")

CHAINS = {
    "ethereum": {
        "chainId": 1,
        "rpcs": ["https://rpc.mevblocker.io", "https://eth.drpc.org", "https://1rpc.io/eth", "https://ethereum-rpc.publicnode.com"],
    },
    "arbitrum": {
        "chainId": 42161,
        "rpcs": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com", "https://1rpc.io/arb"],
    },
}

ORDERS = [
    {"chain":"ethereum","vaultLabel":"termmax-usdc-v2","vault":"0xf488ccdf04079cc03183cdb6a147d12cf97f9317","order":"0x93257038ecc1337d296ec61b2629704fe89acfa5","market":"0x1f5feef78d7186a718f779a4282cad33d43825e5","ft":"0xb44f795ef22e5cf3df69cdac7cb6e7e91a597028","gt":"0xbeabd241853b217660788694125e1809465d6393","collateral":"0x29fd7180e5cced14ad148c7997e6b6857a8be86e","debtToken":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","collateralSymbol":"PT-RLP-9APR2026"},
    {"chain":"ethereum","vaultLabel":"termmax-usdc-v2","vault":"0xf488ccdf04079cc03183cdb6a147d12cf97f9317","order":"0x667ddd85358e8765814f07efd1c4a9cad67521d7","market":"0xc894b068d99376d6abf8a9625667cad2d6e5eab7","ft":"0x23f4546984a0b9d36b9eb7566bbd01054935870f","gt":"0xf6234b44ef4b42ce7d8dd9ae073947b536b0b376","collateral":"0x01ba69727e2860b37bc1a2bd56999c1afb4c15d8","debtToken":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","collateralSymbol":"ynRWAx"},
    {"chain":"ethereum","vaultLabel":"termmax-usdc-v2","vault":"0xf488ccdf04079cc03183cdb6a147d12cf97f9317","order":"0xd8409caa2497dfee072722a8155503f744514ca7","market":"0x0ecbb252647721115985451b793c986fcba843e6","ft":"0xeca55208906fa7b802601a389bc86a349d9bb1d7","gt":"0x7f318cd8c3b7f1ef43a5296008fdcb25f46ecb4e","collateral":"0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf","debtToken":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","collateralSymbol":"cbBTC"},
    {"chain":"ethereum","vaultLabel":"termmax-usdc-v2","vault":"0xf488ccdf04079cc03183cdb6a147d12cf97f9317","order":"0xe7059ddd2dc6f7d54088628655d8c3a096804448","market":"0x38f35b56d4666013096b7aed555b82eab13ac87a","ft":"0x33c33f7b05fd5b459272f5aa6c1802eeea867bcd","gt":"0x8db6b09abed3e3e639fbd28ce8e5e842cb52a156","collateral":"0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0","debtToken":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","collateralSymbol":"wstETH"},
    {"chain":"ethereum","vaultLabel":"termmax-usdc-v2","vault":"0xf488ccdf04079cc03183cdb6a147d12cf97f9317","order":"0x66197a8bb9621a6da48e9c28fd6f23341901af8d","market":"0x598f6decdf9b414f1a7ead76307aadc8682a8c70","ft":"0x1ce06305ba4805eee0a7689a3924f5d8e7cf7da3","gt":"0x99c205c6ae5fd3315677e1f8c4837023c1db4467","collateral":"0x2260fac5e5542a773aa44fbcfedf7c193bc2c599","debtToken":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","collateralSymbol":"WBTC"},
    {"chain":"ethereum","vaultLabel":"prime-yield","vault":"0x17337c22cf8b7c1b6fc86f0ef7fcf05a7fa93f48","order":"0xdad9be9ab9d089ba7135483671d758134a80c5c7","market":"0xd7e6c4fd81b72449ba2bb4cc4ca6670b31189f49","ft":"0xf768a16a6b89e2baa23008eb3f1f75a9b55d2094","gt":"0xe5a490b3438b213bb65971c4344e68f59dbfafc1","collateral":"0xa3ca88cfb7bbe9cfbd47df053ffa2130c7e6f770","debtToken":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","collateralSymbol":"wstrBTC"},
    {"chain":"ethereum","vaultLabel":"prime-yield","vault":"0x17337c22cf8b7c1b6fc86f0ef7fcf05a7fa93f48","order":"0xb40b652117ad7782db84036d07902a6c9530111b","market":"0x5e4c27280f25fa416e47a150e95c0b517e6d7157","ft":"0x594fa0ce05ca84cdd0613a00109511e2c12c119e","gt":"0x3d2caca6562fc42a4c6e282afd9abd4e32d8207a","collateral":"0x92a6a01b07984de46c24e8eba248449beb8b1dcb","debtToken":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","collateralSymbol":"PT-apxUSD-18JUN2026"},
    {"chain":"ethereum","vaultLabel":"edge-usdc","vault":"0xbbf747e83f2f1650f7b303f6166fc3fe8a5b0ce5","order":"0xef9473244e4ae81526f680e07fff4133eb2c6f9f","market":"0xcb81fc813e09d090781305ba71f0075c01a3a762","ft":"0x950cb3934b261dc87d96e2a46e37e81c7ab27fa6","gt":"0x9a41459e256998616a68261f4eab5dad38dce06d","collateral":"0x9d39a5de30e57443bff2a8307a4256c8797a3497","debtToken":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","collateralSymbol":"sUSDe"},
    {"chain":"arbitrum","vaultLabel":"termmax-usdc-v2","vault":"0xcb94abcffbf5cc76a55f9c1496632a26d19f9947","order":"0x198ea3feb403c0738ec856f1caf3d78c27a15529","market":"0x5462cfcd9616a1dca7b5df13414fcc2634ced893","ft":"0x801a6d5385531a7a31e8f0a417d22c0221bf25b8","gt":"0xff8024528362a216712386a2db8f567f945a9e00","collateral":"0x5979d7b546e38e414f7e9822514be443a4800529","debtToken":"0xaf88d065e77c8cc2239327c5edb3a432268e5831","collateralSymbol":"wstETH"},
]

S = {
    "balanceOf":"0x70a08231","decimals":"0x313ce567","previewRedeem":"0x4cdad506",
    "getCollateralValue":"0x1b2b5fad","getGtConfig":"0xeef5777c","getPrice":"0x41976e09",
}


def rpc_one(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(url, data=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode(), headers={"content-type":"application/json","user-agent":"termmax-order-quality-readonly/1.0"}, method="POST")
    with urllib.request.urlopen(request, timeout=45) as response:
        body=json.load(response)
    if body.get("error"): raise RuntimeError(body["error"])
    return body.get("result")


def rpc(chain: str, method: str, params: list[Any]) -> tuple[Any,str]:
    errors=[]
    for url in CHAINS[chain]["rpcs"]:
        try: return rpc_one(url,method,params),url
        except Exception as exc: errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(" | ".join(errors))


def word(data: str,i: int=0)->str:
    raw=(data or "0x").removeprefix("0x"); return raw[i*64:(i+1)*64].ljust(64,"0")
def uint(data: str,i: int=0)->int: return int(word(data,i) or "0",16)
def address_word(data: str,i: int=0)->str: return "0x"+word(data,i)[-40:].lower()
def arg_address(a: str)->str: return a.removeprefix("0x").lower().rjust(64,"0")
def arg_uint(v: int)->str: return f"{v:064x}"


def call(chain: str,to: str,data: str,block: int)->dict[str,Any]:
    try:
        raw,url=rpc(chain,"eth_call",[{"to":to,"data":data},hex(block)])
        return {"ok":True,"raw":raw,"rpc":url,"blockTag":hex(block)}
    except Exception as exc:
        return {"ok":False,"error":f"{type(exc).__name__}: {exc}","blockTag":hex(block)}


def decode_preview(raw: str)->dict[str,Any]:
    debt=uint(raw,0); offset=uint(raw,1); h=raw.removeprefix("0x"); at=offset*2
    length=int(h[at:at+64] or "0",16); payload=h[at+64:at+64+length*2]
    delivery="0x"+payload
    delivery_amount=int(payload[:64] or "0",16) if length>=32 else 0
    return {"debtTokenAmt":debt,"deliveryData":delivery,"deliveryDataLength":length,"deliveryAmount":delivery_amount}


def encode_bytes_arg(payload: str)->str:
    raw=payload.removeprefix("0x"); length=len(raw)//2; padded=raw+"0"*((64-len(raw)%64)%64)
    return f"{32:064x}{length:064x}{padded}"


def inspect(item: dict[str,Any],block: int)->dict[str,Any]:
    chain=item["chain"]
    ftbal=call(chain,item["ft"],S["balanceOf"]+arg_address(item["order"]),block)
    ft_balance=uint(ftbal["raw"]) if ftbal.get("ok") else None
    debtdec=call(chain,item["debtToken"],S["decimals"],block); debt_decimals=uint(debtdec["raw"]) if debtdec.get("ok") else None
    colldec=call(chain,item["collateral"],S["decimals"],block); collateral_decimals=uint(colldec["raw"]) if colldec.get("ok") else None
    result={**item,"ftBalanceCall":ftbal,"ftBalance":ft_balance,"debtDecimals":debt_decimals,"collateralDecimals":collateral_decimals}
    if not ft_balance:
        result["status"]="NO_FT"; return result
    preview=call(chain,item["market"],S["previewRedeem"]+arg_uint(ft_balance),block); result["previewCall"]=preview
    if not preview.get("ok"):
        result["status"]="PREVIEW_REVERT"; return result
    decoded=decode_preview(preview["raw"]); result["preview"]=decoded
    debt_out=decoded["debtTokenAmt"]; result["nominalShortfallRaw"]=max(0,ft_balance-debt_out)
    collateral_value=call(chain,item["gt"],S["getCollateralValue"]+encode_bytes_arg(decoded["deliveryData"]),block) if decoded["deliveryDataLength"] else {"ok":True,"raw":"0x"+"0"*64}
    result["collateralValueCall"]=collateral_value
    collateral_usd=uint(collateral_value["raw"]) if collateral_value.get("ok") else None
    result["collateralUsdBase1e8"]=collateral_usd
    cfg=call(chain,item["gt"],S["getGtConfig"],block); result["gtConfigCall"]=cfg
    oracle=address_word(cfg["raw"],5) if cfg.get("ok") else None; result["oracle"]=oracle
    debt_price=None; debt_price_dec=None
    if oracle:
        price=call(chain,oracle,S["getPrice"]+arg_address(item["debtToken"]),block); result["debtPriceCall"]=price
        if price.get("ok"): debt_price=uint(price["raw"],0); debt_price_dec=uint(price["raw"],1)
    result["debtPrice"]=debt_price; result["debtPriceDecimals"]=debt_price_dec
    collateral_debt_raw=None
    if collateral_usd is not None and debt_price and debt_decimals is not None:
        collateral_debt_raw=collateral_usd*(10**debt_decimals)*(10**debt_price_dec)//(10**8*debt_price)
    result["collateralValueDebtRaw"]=collateral_debt_raw
    result["totalRecoveryDebtRaw"]=None if collateral_debt_raw is None else debt_out+collateral_debt_raw
    result["qualityRatio1e8"]=None if result["totalRecoveryDebtRaw"] is None else result["totalRecoveryDebtRaw"]*10**8//ft_balance
    result["economicGainLossRaw"]=None if result["totalRecoveryDebtRaw"] is None else result["totalRecoveryDebtRaw"]-ft_balance
    result["status"]="RESOLVED" if result["totalRecoveryDebtRaw"] is not None else "ORACLE_UNRESOLVED"
    return result


def main()->int:
    OUT.mkdir(parents=True,exist_ok=True)
    blocks={}
    for chain in CHAINS:
        latest,_=rpc(chain,"eth_blockNumber",[]); number=int(latest,16)
        b,_=rpc(chain,"eth_getBlockByNumber",[latest,False]); ts=int(b["timestamp"],16)
        blocks[chain]={"number":number,"hash":b.get("hash"),"timestamp":ts,"timestampUtc":dt.datetime.fromtimestamp(ts,tz=dt.timezone.utc).isoformat()}
    rows=[inspect(item,blocks[item["chain"]]["number"]) for item in ORDERS]
    by_vault={}
    for row in rows: by_vault.setdefault(f"{row['chain']}:{row['vault']}",[]).append(row)
    differentials=[]
    for key,group in by_vault.items():
        resolved=[r for r in group if r.get("qualityRatio1e8") is not None]
        if len(resolved)>=2:
            best=max(resolved,key=lambda r:r["qualityRatio1e8"]); worst=min(resolved,key=lambda r:r["qualityRatio1e8"])
            differentials.append({"vaultKey":key,"bestOrder":best["order"],"bestQualityRatio1e8":best["qualityRatio1e8"],"bestFtBalance":best["ftBalance"],"worstOrder":worst["order"],"worstQualityRatio1e8":worst["qualityRatio1e8"],"worstFtBalance":worst["ftBalance"],"qualitySpread1e8":best["qualityRatio1e8"]-worst["qualityRatio1e8"]})
    result={"schema":"termmax-expired-order-quality/v1","generatedAtUtc":dt.datetime.now(dt.timezone.utc).isoformat(),"safety":{"signedTransactions":0,"broadcastTransactions":0},"blocks":blocks,"orders":rows,"vaultDifferentials":differentials,"status":"PASS"}
    (OUT/"SUMMARY.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    concise={"status":"PASS","resolved":sum(r["status"]=="RESOLVED" for r in rows),"oracleUnresolved":sum(r["status"]=="ORACLE_UNRESOLVED" for r in rows),"previewReverts":sum(r["status"]=="PREVIEW_REVERT" for r in rows),"orders":[{k:r.get(k) for k in ["chain","vaultLabel","order","collateralSymbol","ftBalance","status","preview","nominalShortfallRaw","collateralValueDebtRaw","totalRecoveryDebtRaw","qualityRatio1e8","economicGainLossRaw"]} for r in rows],"vaultDifferentials":differentials}
    (OUT/"CONCISE.json").write_text(json.dumps(concise,indent=2),encoding="utf-8")
    print(json.dumps(concise,indent=2)); return 0

if __name__=="__main__": raise SystemExit(main())
