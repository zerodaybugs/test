#!/usr/bin/env python3
"""Read-only binding and exposure inventory for the latest observed delegated new-GT TermMax flow."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from hexbytes import HexBytes
from web3 import Web3
from web3._utils.events import get_event_data

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
TX_HASH = "0x3ee2d77dc72af42c7bf71564b6093bf4ea5c8f8e4bdbd2598c924e0a57a7fe72"
MARKET = Web3.to_checksum_address("0x1d6B083288Fb63B5F3A32FDb6157bE5FD32940E8")
EXPECTED_ORDER = Web3.to_checksum_address("0x8C2854aEe2fF77d1a6404c1E8E2eC503A2028b94")
EXPECTED_GT = Web3.to_checksum_address("0x63009034Ffac57EF0e5f1caF3F43BA077281Ec9B")
DELEGATOR = Web3.to_checksum_address("0xF82f8d46B175827Fb4f6bEbeFF846cE0c4d0A90e")
PINNED = "e314f3f849577dfecd4614f148c4df81fdf8c72d"
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
EIP1967_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
RPC_URLS = [u for u in [os.environ.get("ETH_RPC_URL", "").strip(), "https://ethereum-rpc.publicnode.com", "https://rpc.mevblocker.io", "https://eth.drpc.org", "https://1rpc.io/eth"] if u]

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}]}]}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
]
GT_ABI = [
    {"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"address"},{"type":"uint128"},{"type":"bytes"}]},
    {"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"isDelegate","stateMutability":"view","inputs":[{"type":"address"},{"type":"address"}],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"nonces","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ORDER_ABI = [
    {"type":"function","name":"maker","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"tokenReserves","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"},{"type":"uint256"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ORDER_PLACED = {"anonymous":False,"type":"event","name":"OrderPlaced","inputs":[{"indexed":True,"name":"maker","type":"address"},{"indexed":True,"name":"market","type":"address"},{"indexed":False,"name":"order","type":"address"},{"indexed":False,"name":"gtId","type":"uint256"},{"indexed":False,"name":"debtTokenToDeposit","type":"uint256"},{"indexed":False,"name":"ftToDeposit","type":"uint256"},{"indexed":False,"name":"xtToDeposit","type":"uint256"}]}
ISSUE_FT = {"anonymous":False,"type":"event","name":"IssueFt","inputs":[{"indexed":True,"name":"caller","type":"address"},{"indexed":True,"name":"recipient","type":"address"},{"indexed":True,"name":"gtId","type":"uint256"},{"indexed":False,"name":"debtAmt","type":"uint128"},{"indexed":False,"name":"ftAmt","type":"uint128"},{"indexed":False,"name":"fee","type":"uint128"},{"indexed":False,"name":"collateralData","type":"bytes"}]}
SOURCE_PATHS = {"TermMaxMarketV2":"contracts/v2/TermMaxMarketV2.sol", "TermMaxOrderV2":"contracts/v2/TermMaxOrderV2.sol", "GearingTokenWithERC20V2":"contracts/v2/tokens/GearingTokenWithERC20V2.sol"}


def default(x: Any) -> Any:
    if isinstance(x, (bytes, bytearray, HexBytes)): return "0x" + bytes(x).hex()
    if hasattr(x, "items"): return dict(x)
    return str(x)


def safe(fn, block: int | str = "latest") -> dict[str, Any]:
    try:
        v = fn.call(block_identifier=block)
        return {"ok":True,"value":list(v) if isinstance(v, tuple) else v}
    except Exception as exc:
        return {"ok":False,"error":f"{type(exc).__name__}: {exc}"}


def value(r: dict[str, Any], fallback: Any = None) -> Any:
    return r.get("value", fallback) if r.get("ok") else fallback


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts=[]
    for url in RPC_URLS:
        try:
            w3=Web3(Web3.HTTPProvider(url, request_kwargs={"timeout":40}))
            cid=w3.eth.chain_id; block=w3.eth.block_number
            if cid != 1: raise RuntimeError(f"chainId={cid}")
            attempts.append({"url":url,"ok":True,"chainId":cid,"block":block})
            return w3,url,attempts
        except Exception as exc:
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def decode_event(w3: Web3, receipt: Any, abi: dict[str, Any]) -> list[dict[str, Any]]:
    sig=Web3.keccak(text=f"{abi['name']}({','.join(i['type'] for i in abi['inputs'])})")
    out=[]
    for raw in receipt.logs:
        if raw["topics"] and bytes(raw["topics"][0]) == bytes(sig):
            d=get_event_data(w3.codec, abi, raw)
            out.append({"address":raw["address"],"logIndex":int(raw["logIndex"]),"args":dict(d["args"])})
    return out


def token_meta(w3: Web3, address: str, block: int | str) -> dict[str, Any]:
    address=Web3.to_checksum_address(address); c=w3.eth.contract(address=address,abi=ERC20_ABI)
    return {"address":address,"symbol":safe(c.functions.symbol(),block),"name":safe(c.functions.name(),block),"decimals":safe(c.functions.decimals(),block)}


def binding(w3: Web3, address: str) -> dict[str, Any]:
    address=Web3.to_checksum_address(address); code=bytes(w3.eth.get_code(address)); impl=address; kind="direct"
    m=re.fullmatch(r"363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3",code.hex())
    if m:
        impl=Web3.to_checksum_address("0x"+m.group(1)); kind="eip1167"
    else:
        raw=bytes(w3.eth.get_storage_at(address,EIP1967_SLOT))
        if any(raw):
            candidate=Web3.to_checksum_address("0x"+raw[-20:].hex())
            if bytes(w3.eth.get_code(candidate)): impl=candidate; kind="eip1967"
    impl_code=bytes(w3.eth.get_code(impl))
    return {"address":address,"kind":kind,"implementation":impl,"runtimeBytes":len(code),"runtimeKeccak256":Web3.keccak(code).hex(),"implementationRuntimeBytes":len(impl_code),"implementationRuntimeKeccak256":Web3.keccak(impl_code).hex()}


def explorer(params: dict[str, Any]) -> Any:
    last=None
    for i in range(7):
        try:
            r=requests.get(ROUTESCAN,params=params,timeout=60,headers={"User-Agent":"termmax-public-binding/2"})
            if r.status_code==429: time.sleep(2*(i+1)); continue
            r.raise_for_status(); return r.json()
        except Exception as exc:
            last=exc; time.sleep(1.5*(i+1))
    raise RuntimeError(str(last))


def parse_json_source(text: str) -> dict[str, Any] | None:
    text=text.strip()
    for candidate in ([text[1:-1],text] if text.startswith("{{") and text.endswith("}}") else [text]):
        try:
            obj=json.loads(candidate)
            if isinstance(obj,dict): return obj
        except Exception: pass
    return None


def source_match(implementation: str) -> dict[str, Any]:
    payload=explorer({"module":"contract","action":"getsourcecode","address":implementation})
    rows=payload.get("result",[]) if isinstance(payload,dict) else []; row=rows[0] if isinstance(rows,list) and rows else {}
    name=str(row.get("ContractName") or ""); source=str(row.get("SourceCode") or "")
    result={"implementation":implementation,"contractName":name,"compilerVersion":row.get("CompilerVersion"),"optimizationUsed":row.get("OptimizationUsed"),"runs":row.get("Runs"),"evmVersion":row.get("EVMVersion"),"verifiedSourceEnvelopeSha256":hashlib.sha256(source.encode()).hexdigest() if source else None}
    parsed=parse_json_source(source); path=SOURCE_PATHS.get(name)
    if parsed and path:
        entry=parsed.get("sources",{}).get(path,{}); deployed=str(entry.get("content") or "") if isinstance(entry,dict) else ""
        pinned=requests.get(f"https://raw.githubusercontent.com/term-structure/termmax-contract-v2/{PINNED}/{path}",timeout=60).text
        result.update({"relevantSourcePath":path,"deployedRelevantSha256":hashlib.sha256(deployed.encode()).hexdigest() if deployed else None,"pinnedRelevantSha256":hashlib.sha256(pinned.encode()).hexdigest(),"relevantSourceEqualsPinned":bool(deployed) and deployed==pinned})
    return result


def main() -> int:
    w3,rpc,attempts=connect(); latest=w3.eth.block_number; latest_block=w3.eth.get_block(latest)
    receipt=w3.eth.get_transaction_receipt(TX_HASH); block=int(receipt.blockNumber); pre=block-1
    placed=decode_event(w3,receipt,ORDER_PLACED); issued=decode_event(w3,receipt,ISSUE_FT)
    if not placed or not issued: raise RuntimeError("required events missing")
    order=Web3.to_checksum_address(placed[0]["args"]["order"]); gt_id=int(placed[0]["args"]["gtId"])
    market=w3.eth.contract(address=MARKET,abi=MARKET_ABI); tokens=list(market.functions.tokens().call(block_identifier=block)); ft,xt,gt,coll,debt=[Web3.to_checksum_address(x) for x in tokens]
    gt_c=w3.eth.contract(address=gt,abi=GT_ABI); order_c=w3.eth.contract(address=order,abi=ORDER_ABI)
    loan_at=gt_c.functions.loanInfo(gt_id).call(block_identifier=block); current_loan=safe(gt_c.functions.loanInfo(gt_id),latest)
    cv_at=gt_c.functions.getCollateralValue(loan_at[2]).call(block_identifier=block); cv_current=safe(gt_c.functions.getCollateralValue(current_loan["value"][2]),latest) if current_loan.get("ok") else {"ok":False,"error":"loan unavailable"}
    cmeta=token_meta(w3,coll,block); dmeta=token_meta(w3,debt,block); cdec=int(value(cmeta["decimals"],18))
    cfg=list(market.functions.config().call(block_identifier=block)); maturity=int(cfg[1])
    bindings={"market":binding(w3,MARKET),"order":binding(w3,order),"gt":binding(w3,gt)}
    for b in bindings.values(): b["source"]=source_match(b["implementation"])
    result={
        "schema":"termmax-latest-delegated-new-gt-binding/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "rpc":rpc,"rpcAttempts":attempts,"latestBlock":{"number":latest,"hash":latest_block.hash.hex(),"timestamp":int(latest_block.timestamp),"timestampUtc":datetime.fromtimestamp(latest_block.timestamp,timezone.utc).isoformat()},
        "transaction":{"hash":TX_HASH,"blockNumber":block,"status":int(receipt.status),"gasUsed":int(receipt.gasUsed),"OrderPlaced":placed,"IssueFt":issued},
        "assertions":{"marketMatches":MARKET==Web3.to_checksum_address(placed[0]["args"]["market"]),"orderMatchesExpected":order==EXPECTED_ORDER,"gtMatchesExpected":gt==EXPECTED_GT,"delegateeEqualsOrder":EXPECTED_ORDER==order,"gtIdWasNextBeforeTransaction":int(gt_c.functions.totalSupply().call(block_identifier=pre))+1==gt_id,"delegatorNonceIncremented":int(gt_c.functions.nonces(DELEGATOR).call(block_identifier=block))==int(gt_c.functions.nonces(DELEGATOR).call(block_identifier=pre))+1,"delegationSetAtBlock":bool(gt_c.functions.isDelegate(DELEGATOR,order).call(block_identifier=block))},
        "addresses":{"market":MARKET,"order":order,"gt":gt,"ft":ft,"xt":xt,"collateral":coll,"debtToken":debt},
        "tokenMetadata":{"collateral":cmeta,"debtToken":dmeta},
        "stateAtCreation":{"marketConfig":cfg,"maturityUtc":datetime.fromtimestamp(maturity,timezone.utc).isoformat(),"loanInfo":loan_at,"collateralAmountHuman":int.from_bytes(bytes(loan_at[2]),"big")/(10**cdec) if len(bytes(loan_at[2]))==32 else None,"collateralValueUsd":int(cv_at)/1e8,"orderMaker":order_c.functions.maker().call(block_identifier=block),"orderMarket":order_c.functions.market().call(block_identifier=block),"orderReserves":list(order_c.functions.tokenReserves().call(block_identifier=block))},
        "currentState":{"marketPaused":safe(market.functions.paused(),latest),"activeBeforeMaturity":int(latest_block.timestamp)<maturity,"loanInfo":current_loan,"currentCollateralValueUsd":int(value(cv_current,0))/1e8 if cv_current.get("ok") else None,"delegationStillSet":safe(gt_c.functions.isDelegate(DELEGATOR,order),latest),"orderReserves":safe(order_c.functions.tokenReserves(),latest)},
        "bindings":bindings,
    }
    (OUT/"LATEST_DELEGATED_FLOW_BINDING.json").write_text(json.dumps(result,indent=2,default=default),encoding="utf-8")
    print(json.dumps(result,indent=2,default=default)); return 0

if __name__=="__main__": raise SystemExit(main())
