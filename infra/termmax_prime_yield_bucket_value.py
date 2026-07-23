#!/usr/bin/env python3
"""Read-only oracle valuation for the live Prime Yield wstrBTC recovery bucket."""
from __future__ import annotations
import datetime as dt
import json
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("termmax-prime-yield-bucket")
RPCS = [
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://ethereum-rpc.publicnode.com",
]
VAULT = "0x17337c22cf8b7c1b6fc86f0ef7fcf05a7fa93f48"
MARKET = "0xd7e6c4fd81b72449ba2bb4cc4ca6670b31189f49"
ORDER = "0x385429223ddc9921f2491c4a16b79c0b0717c431"
GT = "0xe5a490b3438b213bb65971c4344e68f59dbfafc1"
COLLATERAL = "0xa3ca88cfb7bbe9cfbd47df053ffa2130c7e6f770"
BAD_DEBT_RAW = 939_875
COLLATERAL_RAW = 9_267
SETTLEMENT_BLOCK = 24_826_646
SETTLEMENT_TX = "0x0d94a01690d1c246365a439a6a049e678df8003d1d7800c8ded7f42bed697c57"

SELECTORS = {
    "getCollateralValue": "0x1b2b5fad",
    "badDebtMapping": "0x618f9694",
    "balanceOf": "0x70a08231",
    "totalAssets": "0x01e1d114",
    "totalSupply": "0x18160ddd",
    "maxDeposit": "0x402d267d",
    "paused": "0x5c975abb",
}


def rpc_one(url: str, method: str, params: list[Any]) -> Any:
    req = urllib.request.Request(url, data=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode(), headers={"content-type":"application/json","user-agent":"termmax-prime-bucket-readonly/1.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=45) as response:
        body = json.load(response)
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body.get("result")


def rpc(method: str, params: list[Any]) -> tuple[Any, str]:
    errors=[]
    for url in RPCS:
        try:
            return rpc_one(url, method, params), url
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(" | ".join(errors))


def word(data: str, i: int=0) -> str:
    raw=data.removeprefix("0x")
    return raw[i*64:(i+1)*64].ljust(64,"0")


def uint(data: str, i: int=0) -> int:
    return int(word(data,i) or "0",16)


def arg_address(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64,"0")


def arg_bytes_uint(value: int) -> str:
    return f"{32:064x}{32:064x}{value:064x}"


def call(to: str, data: str, block: int|str="latest") -> dict[str,Any]:
    tag=hex(block) if isinstance(block,int) else block
    raw,url=rpc("eth_call",[{"to":to,"data":data},tag])
    return {"ok":True,"raw":raw,"uint":uint(raw),"rpc":url,"blockTag":tag}


def safe_call(to: str, data: str, block: int|str="latest") -> dict[str,Any]:
    try:
        return call(to,data,block)
    except Exception as exc:
        return {"ok":False,"error":f"{type(exc).__name__}: {exc}","blockTag":hex(block) if isinstance(block,int) else block}


def block_meta(number: int) -> dict[str,Any]:
    b,url=rpc("eth_getBlockByNumber",[hex(number),False])
    ts=int(b["timestamp"],16)
    return {"number":number,"hash":b.get("hash"),"timestamp":ts,"timestampUtc":dt.datetime.fromtimestamp(ts,tz=dt.timezone.utc).isoformat(),"rpc":url}


def snapshot(block: int|str) -> dict[str,Any]:
    tag=hex(block) if isinstance(block,int) else block
    total_assets=call(VAULT,SELECTORS["totalAssets"],block)
    total_supply=call(VAULT,SELECTORS["totalSupply"],block)
    max_deposit=call(VAULT,SELECTORS["maxDeposit"]+arg_address(VAULT),block)
    paused=call(VAULT,SELECTORS["paused"],block)
    bad=call(VAULT,SELECTORS["badDebtMapping"]+arg_address(COLLATERAL),block)
    bal=call(COLLATERAL,SELECTORS["balanceOf"]+arg_address(VAULT),block)
    value={"ok":True,"uint":0,"rpc":bal["rpc"],"blockTag":tag} if bal["uint"]==0 else safe_call(GT,SELECTORS["getCollateralValue"]+arg_bytes_uint(bal["uint"]),block)
    value_uint=value.get("uint") if value.get("ok") else None
    bad_usd=bad["uint"]*100
    return {
        "blockTag":tag,
        "totalAssetsRaw":total_assets["uint"],
        "totalSupplyRaw":total_supply["uint"],
        "maxDepositRaw":max_deposit["uint"],
        "paused":bool(paused["uint"]),
        "badDebtRaw":bad["uint"],
        "collateralRaw":bal["uint"],
        "collateralValueCall":value,
        "collateralUsdBase1e8":value_uint,
        "badDebtUsdAssumingUSDCParBase1e8":bad_usd,
        "recoveryMinusBadDebtUsdBase1e8":None if value_uint is None else value_uint-bad_usd,
        "recoveryRatio1e8":None if value_uint is None or bad_usd==0 else value_uint*10**8//bad_usd,
    }


def main() -> int:
    OUT.mkdir(parents=True,exist_ok=True)
    latest_hex,_=rpc("eth_blockNumber",[])
    latest=int(latest_hex,16)
    receipt,_=rpc("eth_getTransactionReceipt",[SETTLEMENT_TX])
    receipt_block=int(receipt["blockNumber"],16)
    result={
        "schema":"termmax-prime-yield-bucket-value/v2",
        "generatedAtUtc":dt.datetime.now(dt.timezone.utc).isoformat(),
        "safety":{"signedTransactions":0,"broadcastTransactions":0},
        "addresses":{"vault":VAULT,"market":MARKET,"order":ORDER,"gt":GT,"collateral":COLLATERAL},
        "event":{"tx":SETTLEMENT_TX,"expectedBlock":SETTLEMENT_BLOCK,"receiptBlock":receipt_block,"badDebtRaw":BAD_DEBT_RAW,"deliveryAmountRaw":COLLATERAL_RAW},
        "blocks":{"beforeSettlement":block_meta(receipt_block-1),"settlement":block_meta(receipt_block),"latest":block_meta(latest)},
        "snapshots":{"beforeSettlement":snapshot(receipt_block-1),"afterSettlement":snapshot(receipt_block),"latest":snapshot(latest)},
    }
    latest_s=result["snapshots"]["latest"]
    value=latest_s["collateralUsdBase1e8"]
    bad=latest_s["badDebtUsdAssumingUSDCParBase1e8"]
    if value is None:
        result["classification"]="ORACLE_VALUE_UNAVAILABLE"
        result["status"]="INCOMPLETE"
    else:
        result["classification"]="SNAV1_UNDERRECOVERY" if value<bad else "TMV1_OVERRECOVERY" if value>bad else "PAR_RECOVERY"
        result["status"]="PASS"
    (OUT/"SUMMARY.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps({"status":result["status"],"classification":result["classification"],"latest":latest_s},indent=2))
    return 0 if result["status"]=="PASS" else 2

if __name__=="__main__":
    raise SystemExit(main())
