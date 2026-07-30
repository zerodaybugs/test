#!/usr/bin/env python3
"""Read-only TermMax V2 bad-debt recovery bucket profitability census.

For every discovered current V2 vault, the scanner resolves historical
RedeemOrder events, current badDebtMapping balances and current collateral held
by the vault. For ERC20 GT markets it computes the collateral recovery value in
vault debt-token units and compares it with the assets required to mint the
shares burned by dealBadDebt.

No signing, transaction construction, simulation, or state mutation is used.
"""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eth_abi import encode as abi_encode
from web3 import Web3

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("vault_base",HERE/"termmax_vault_asset_binding_census_20260730.py")
if SPEC is None or SPEC.loader is None: raise RuntimeError("cannot load vault scanner base")
base=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(base)
OUT=Path(os.environ.get("OUT_DIR","evidence")); OUT.mkdir(parents=True,exist_ok=True)
CHAIN_FILTER=os.environ.get("CHAIN","all").strip().lower()

REDEEM_ORDER_TOPIC=Web3.keccak(text="RedeemOrder(address,address,uint256,uint256)").hex()
VAULT_EXTRA_ABI=[
 {"type":"function","name":"badDebtMapping","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"previewWithdraw","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"previewMint","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
]
GT_ABI=[
 {"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"address"},{"type":"uint32"},{"type":"uint32"},{"type":"bool"}]}]}]},
]
ORACLE_ABI=[
 {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
ERC20_BALANCE_ABI=[
 {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]

base.VAULT_ABI.extend(VAULT_EXTRA_ABI)


def parse_log_order(log:Any)->str|None:
 topics=log.get("topics",[]) if isinstance(log,dict) else log["topics"]
 if len(topics)<3: return None
 raw=topics[2].hex() if hasattr(topics[2],"hex") else str(topics[2])
 try: return base.topic_address(raw)
 except Exception: return None

def decode_data_words(log:Any)->tuple[int,int]:
 data=log.get("data","0x") if isinstance(log,dict) else log["data"].hex()
 raw=bytes.fromhex(str(data).replace("0x", ""))
 if len(raw)<64: return 0,0
 return int.from_bytes(raw[:32],"big"),int.from_bytes(raw[32:64],"big")

def order_context(w3:Web3,order_address:str,block:int)->dict[str,Any]:
 order=w3.eth.contract(address=Web3.to_checksum_address(order_address),abi=base.ORDER_ABI)
 market_r=base.safe(order.functions.market().call,block_identifier=block); market_address=base.val(market_r)
 row={"order":Web3.to_checksum_address(order_address),"market":market_r}
 if not market_address: return row
 market_address=Web3.to_checksum_address(market_address); market=w3.eth.contract(address=market_address,abi=base.MARKET_ABI)
 tokens_r=base.safe(market.functions.tokens().call,block_identifier=block); tokens=base.val(tokens_r); row["marketAddress"]=market_address; row["tokens"]=tokens_r
 if not tokens or len(tokens)!=5: return row
 ft,xt,gt,collateral,debt=[Web3.to_checksum_address(x) for x in tokens]
 row.update({"ft":ft,"xt":xt,"gt":gt,"collateral":base.token_meta(w3,collateral,block),"debtToken":base.token_meta(w3,debt,block)})
 return row

def bucket_economics(w3:Web3,vault_c,vault_address:str,context:dict[str,Any],block:int)->dict[str,Any]:
 collateral=(context.get("collateral") or {}).get("address"); debt=(context.get("debtToken") or {}).get("address"); gt=context.get("gt")
 row={"collateral":context.get("collateral"),"debtToken":context.get("debtToken"),"gt":gt,"orders":[]}
 if not collateral or not debt or not gt: return row
 bad_r=base.safe(vault_c.functions.badDebtMapping(collateral).call,block_identifier=block); bad=int(base.val(bad_r,0) or 0)
 collateral_c=w3.eth.contract(address=Web3.to_checksum_address(collateral),abi=ERC20_BALANCE_ABI)
 bal_r=base.safe(collateral_c.functions.balanceOf(Web3.to_checksum_address(vault_address)).call,block_identifier=block); bal=int(base.val(bal_r,0) or 0)
 shares_r=base.safe(vault_c.functions.previewWithdraw(bad).call,block_identifier=block) if bad else {"ok":True,"value":0}; shares=int(base.val(shares_r,0) or 0)
 assets_r=base.safe(vault_c.functions.previewMint(shares).call,block_identifier=block) if shares else {"ok":True,"value":0}; assets=int(base.val(assets_r,0) or 0)
 gt_c=w3.eth.contract(address=Web3.to_checksum_address(gt),abi=GT_ABI); gt_cfg_r=base.safe(gt_c.functions.getGtConfig().call,block_identifier=block); gt_cfg=base.val(gt_cfg_r)
 collateral_value_r=base.safe(gt_c.functions.getCollateralValue(abi_encode(["uint256"],[bal])).call,block_identifier=block) if bal else {"ok":True,"value":0}
 collateral_value_1e8=base.val(collateral_value_r); recovery_debt_raw=None; price_r=None
 debt_dec=base.val((context.get("debtToken") or {}).get("decimals",{}))
 if gt_cfg and collateral_value_1e8 is not None and debt_dec is not None:
  try:
   oracle_address=Web3.to_checksum_address(gt_cfg[5][0]); oracle=w3.eth.contract(address=oracle_address,abi=ORACLE_ABI); price_r=base.safe(oracle.functions.getPrice(debt).call,block_identifier=block); price=base.val(price_r)
   if price and int(price[0])>0:
    recovery_debt_raw=int(collateral_value_1e8)*(10**int(debt_dec))*(10**int(price[1]))//(int(price[0])*10**8)
  except Exception: pass
 profit=None; ratio=None
 if recovery_debt_raw is not None:
  profit=recovery_debt_raw-assets; ratio=recovery_debt_raw*10**18//bad if bad else None
 row.update({"badDebt":bad_r,"collateralBalanceAtVault":bal_r,"sharesRequired":shares_r,"assetsRequired":assets_r,"gtConfig":gt_cfg_r,"collateralValue1e8":collateral_value_r,"debtPrice":price_r,"recoveryDebtRaw":recovery_debt_raw,"profitRaw":profit,"recoveryRatio1e18":ratio,"profitable":bool(profit is not None and profit>0 and bad>0)})
 return row

def inspect_vault(w3:Web3,config:dict[str,Any],vault_address:str,start_block:int,block:int,timestamp:int)->dict[str,Any]:
 vault_address=Web3.to_checksum_address(vault_address); vault=w3.eth.contract(address=vault_address,abi=base.VAULT_ABI)
 row={"vault":vault_address,"name":base.safe(vault.functions.name().call,block_identifier=block),"asset":base.safe(vault.functions.asset().call,block_identifier=block),"totalAssets":base.safe(vault.functions.totalAssets().call,block_identifier=block),"totalSupply":base.safe(vault.functions.totalSupply().call,block_identifier=block),"buckets":[]}
 logs=base.get_logs(w3,config,vault_address,start_block,block,REDEEM_ORDER_TOPIC); contexts:dict[str,dict[str,Any]]={}; event_rows=[]
 for log in logs:
  order=parse_log_order(log)
  if not order: continue
  bad,delivery=decode_data_words(log); event_rows.append({"order":order,"badDebtEvent":bad,"deliveryAmountEvent":delivery})
  if order.lower() not in contexts:
   try: contexts[order.lower()]=order_context(w3,order,block)
   except Exception: contexts[order.lower()]={"order":order}
 by_collateral:dict[str,dict[str,Any]]={}
 for context in contexts.values():
  collateral=(context.get("collateral") or {}).get("address")
  if not collateral: continue
  bucket=by_collateral.setdefault(collateral.lower(),bucket_economics(w3,vault,vault_address,context,block)); bucket["orders"].append(context)
 row["redeemEvents"]=event_rows; row["buckets"]=list(by_collateral.values()); row["nonzeroBuckets"]=[x for x in row["buckets"] if int(base.val(x.get("badDebt",{}),0) or 0)>0]; row["profitableBuckets"]=[x for x in row["buckets"] if x.get("profitable")]
 row["profitableBucketCount"]=len(row["profitableBuckets"]); row["maxProfitRaw"]=max([int(x.get("profitRaw") or 0) for x in row["profitableBuckets"]] or [0])
 return row

def inspect_chain(config:dict[str,Any])->dict[str,Any]:
 w3,rpc,attempts=base.connect(config); latest=w3.eth.block_number; block=w3.eth.get_block(latest); timestamp=int(block.timestamp); vaults={}
 for factory,start in config["factories"]:
  factory=Web3.to_checksum_address(factory)
  try:
   logs=base.get_logs(w3,config,factory,start,latest,base.VAULT_CREATED_TOPIC)
   for log in logs:
    topics=log.get("topics",[]) if isinstance(log,dict) else log["topics"]
    if len(topics)>=2:
     raw=topics[1].hex() if hasattr(topics[1],"hex") else str(topics[1]); address=base.topic_address(raw); bn=base.parse_int(log.get("blockNumber") if isinstance(log,dict) else log["blockNumber"]); vaults[address.lower()]=(address,bn,"factory")
  except Exception as exc: (OUT/f"{config['name']}_factory_errors.log").open("a").write(f"{factory}: {exc}\n")
 minimum=min(x[1] for x in config["factories"])
 for address in base.llama_vaults(config): vaults.setdefault(address.lower(),(address,minimum,"defillama"))
 rows=[]
 for address,start,source in vaults.values():
  try:
   item=inspect_vault(w3,config,address,start,latest,timestamp); item["discoverySource"]=source; rows.append(item)
  except Exception as exc: rows.append({"vault":address,"fatalError":f"{type(exc).__name__}: {exc}"})
 profitable=[{"vault":v.get("vault"),"vaultName":base.val(v.get("name",{})),"bucket":b} for v in rows for b in v.get("profitableBuckets",[])]
 return {"chain":config["name"],"chainId":config["chainId"],"rpc":rpc,"rpcAttempts":attempts,"block":{"number":latest,"hash":block.hash.hex(),"timestamp":timestamp,"timestampUtc":datetime.fromtimestamp(timestamp,tz=timezone.utc).isoformat()},"vaultCount":len(rows),"nonzeroBucketCount":sum(len(v.get("nonzeroBuckets",[])) for v in rows),"profitableBucketCount":len(profitable),"profitableBuckets":profitable,"vaults":rows}

def main()->int:
 selected=[c for c in base.CHAINS if CHAIN_FILTER in {"all",c["name"]}]; chains=[]
 for config in selected:
  try: chains.append(inspect_chain(config))
  except Exception as exc: chains.append({"chain":config["name"],"chainId":config["chainId"],"fatalError":f"{type(exc).__name__}: {exc}"})
 profitable=[{"chain":c.get("chain"),**x} for c in chains for x in c.get("profitableBuckets",[])]
 result={"schema":"termmax-bad-debt-bucket-census/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),"safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},"chainFilter":CHAIN_FILTER,"chainCount":len(chains),"vaultCount":sum(c.get("vaultCount",0) for c in chains),"nonzeroBucketCount":sum(c.get("nonzeroBucketCount",0) for c in chains),"profitableBucketCount":len(profitable),"profitableBuckets":profitable,"nextStep":"CURRENT_FORK_DEAL_BAD_DEBT_EXPLOIT" if profitable else "KILL_NO_CURRENT_PROFITABLE_BUCKET","chains":chains}
 (OUT/"BAD_DEBT_BUCKET_CENSUS_FULL.json").write_text(json.dumps(result,indent=2,default=base.default),encoding="utf-8"); compact={k:result[k] for k in ["generatedAtUtc","chainFilter","chainCount","vaultCount","nonzeroBucketCount","profitableBucketCount","profitableBuckets","nextStep"]}; (OUT/"BAD_DEBT_BUCKET_CENSUS_COMPACT.json").write_text(json.dumps(compact,indent=2,default=base.default),encoding="utf-8"); print(json.dumps(compact,indent=2,default=base.default)); return 0
if __name__=="__main__": raise SystemExit(main())
