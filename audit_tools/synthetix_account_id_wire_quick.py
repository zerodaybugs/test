#!/usr/bin/env python3
"""Exact wire-format check for official Synthetix production/test subaccount IDs.

Unsigned getSubAccountIds only. Retains exact response hashes, parsed types, quoted-vs-unquoted ID
lexemes, and IEEE-754 round-trip metadata. No private data or state mutation.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import urllib.error
import urllib.request
from typing import Any

OUT = pathlib.Path("synthetix_account_id_wire_quick")
OUT.mkdir(parents=True, exist_ok=True)
PROD = "https://papi.synthetix.io/v1/info"
TEST = "https://api.test.synthetix.io/v1/info"
WALLETS = (
    "0x0d3DABaF73BE51E2C4b7BA17C1106Fb52b6C74B4",
    "0x5AF764190593a723EC89B9C3e3e5a2627a3f0Bb4",
    "0x797D183C50bbbaE9DA061488d2Ecb61ec915756B",
    "0x8e474E776c2493EE997Ea772cE0155215eBfAFbA",
    "0xC0e65F1429Cf4204B1D81D41aa626BB0139FaBfB",
    "0xDA807318571Cd0d256654889f96E2867A79E680d",
    "0xF911f95D32677a171BACB6d4E4FD29168a3D978f",
    "0xc3Cf311e04c1f8C74eCF6a795Ae760dc6312F345",
)
ID_TOKEN = re.compile(rb'(?P<quoted>"?)(?P<id>\d{15,22})(?P=quoted)')
MAX_SAFE = 2**53 - 1


def sha(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def post(url: str, wallet: str) -> tuple[int, bytes]:
    body = json.dumps({"params":{"action":"getSubAccountIds","walletAddress":wallet,"includeDelegations":True}},separators=(",",":")).encode()
    req=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json","Accept":"application/json","User-Agent":"authorized-read-only-review"},method="POST")
    try:
        with urllib.request.urlopen(req,timeout=45) as response:
            return response.status,response.read(2*1024*1024)
    except urllib.error.HTTPError as exc:
        return exc.code,exc.read(2*1024*1024)


def collect(value: Any, path: str = "$", out: list[dict[str,Any]] | None = None) -> list[dict[str,Any]]:
    if out is None: out=[]
    if isinstance(value,dict):
        for key,item in value.items(): collect(item,f"{path}.{key}",out)
    elif isinstance(value,list):
        for index,item in enumerate(value): collect(item,f"{path}[{index}]",out)
    elif isinstance(value,(str,int)) and not isinstance(value,bool):
        text=str(value)
        if text.isdigit() and 10**15<=int(text)<=10**22:
            number=int(float(int(text)))
            out.append({
                "path":path,"pythonType":type(value).__name__,"decimal":text,
                "aboveMaxSafe":int(text)>MAX_SAFE,"numberRoundTrip":str(number),
                "numberRoundTripExact":number==int(text),"numberDelta":number-int(text),
                "mod256":int(text)%256,"mod1024":int(text)%1024,
            })
    return out


def main() -> None:
    rows=[]; unique={}
    for wallet in WALLETS:
        for env,url in (("production",PROD),("test",TEST)):
            status,body=post(url,wallet)
            try: parsed=json.loads(body)
            except Exception: parsed=None
            records=collect(parsed)
            tokens=[]
            for match in ID_TOKEN.finditer(body):
                decimal=match.group("id").decode()
                if not (10**15<=int(decimal)<=10**22): continue
                tokens.append({"decimal":decimal,"quoted":bool(match.group("quoted")),"offset":match.start()})
            for record in records:
                flags=[item["quoted"] for item in tokens if item["decimal"]==record["decimal"]]
                record["wireQuotedFlags"]=flags
                item=unique.setdefault(record["decimal"],{"environments":set(),"types":set(),"quoted":set(),**{k:v for k,v in record.items() if k not in {"path","pythonType","wireQuotedFlags"}}})
                item["environments"].add(env); item["types"].add(record["pythonType"]); item["quoted"].update(flags)
            rows.append({
                "walletSha256":sha(wallet.lower()),"environment":env,"httpStatus":status,
                "bodyBytes":len(body),"bodySha256":sha(body),
                "apiStatus":parsed.get("status") if isinstance(parsed,dict) else None,
                "records":records,"wireTokens":tokens,
                "bodyExcerpt":body.decode(errors="replace")[:2000].replace(wallet,"<wallet>"),
            })
    normalized=[]
    for decimal,item in sorted(unique.items(),key=lambda pair:int(pair[0])):
        normalized.append({**{k:v for k,v in item.items() if k not in {"environments","types","quoted"}},"decimal":decimal,"environments":sorted(item["environments"]),"pythonTypes":sorted(item["types"]),"wireQuotedFlags":sorted(item["quoted"])})
    buckets={}
    for item in normalized: buckets.setdefault(item["numberRoundTrip"],[]).append(item["decimal"])
    collisions={k:v for k,v in buckets.items() if len(v)>1}
    result={
        "safety":"Unsigned public account discovery only.","walletCount":len(WALLETS),
        "uniqueAccountIdCount":len(normalized),"accountIds":normalized,"rows":rows,
        "aboveMaxSafeCount":sum(x["aboveMaxSafe"] for x in normalized),
        "inexactNumberCount":sum(not x["numberRoundTripExact"] for x in normalized),
        "quotedStringCount":sum(True in x["wireQuotedFlags"] for x in normalized),
        "unquotedNumberCount":sum(False in x["wireQuotedFlags"] for x in normalized),
        "numberCollisionBucketCount":len(collisions),"numberCollisions":collisions,
    }
    result["verdict"]=("MATERIAL_PRECISION_LOSS" if result["inexactNumberCount"] or collisions else "WIRE_IDS_EXACTLY_PRESERVED")
    (OUT/"summary.json").write_text(json.dumps(result,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps({k:result[k] for k in ("walletCount","uniqueAccountIdCount","aboveMaxSafeCount","inexactNumberCount","quotedStringCount","unquotedNumberCount","numberCollisionBucketCount","verdict")},indent=2))


if __name__=="__main__": main()
