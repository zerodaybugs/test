#!/usr/bin/env python3
"""Read-only zero-price configuration gate for the active Arbitrum TermMax market."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from web3 import Web3

OUT=Path('evidence'); OUT.mkdir(parents=True,exist_ok=True)
MARKET=Web3.to_checksum_address('0xDaCbD08EEB61eE3c1Ed02297343675b259d7Ec91')
RPCS=['https://arbitrum-one-rpc.publicnode.com','https://arb1.arbitrum.io/rpc','https://arbitrum.drpc.org']
MARKET_ABI=[
 {'type':'function','name':'tokens','stateMutability':'view','inputs':[],'outputs':[{'type':'address'},{'type':'address'},{'type':'address'},{'type':'address'},{'type':'address'}]},
 {'type':'function','name':'config','stateMutability':'view','inputs':[],'outputs':[{'type':'tuple','components':[{'type':'address'},{'type':'uint64'},{'type':'tuple','components':[{'type':'uint32'},{'type':'uint32'},{'type':'uint32'},{'type':'uint32'},{'type':'uint32'},{'type':'uint32'}]}]}]},
]
GT_ABI=[
 {'type':'function','name':'getGtConfig','stateMutability':'view','inputs':[],'outputs':[{'type':'tuple','components':[{'type':'address'},{'type':'address'},{'type':'address'},{'type':'address'},{'type':'uint64'},{'type':'tuple','components':[{'type':'address'},{'type':'uint32'},{'type':'uint32'},{'type':'bool'}]}]}]},
 {'type':'function','name':'totalSupply','stateMutability':'view','inputs':[],'outputs':[{'type':'uint256'}]},
]
ORACLE_ABI=[
 {'type':'function','name':'oracles','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'address'},{'type':'address'},{'type':'int256'},{'type':'int256'},{'type':'uint32'},{'type':'uint32'}]},
 {'type':'function','name':'getPrice','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'uint256'},{'type':'uint8'}]},
]
ROUND_ABI=[{'type':'function','name':'latestRoundData','stateMutability':'view','inputs':[],'outputs':[{'type':'uint80'},{'type':'int256'},{'type':'uint256'},{'type':'uint256'},{'type':'uint80'}]}]
ERC20_ABI=[{'type':'function','name':'symbol','stateMutability':'view','inputs':[],'outputs':[{'type':'string'}]}]

def safe(fn,*args,**kwargs)->dict[str,Any]:
 try:
  v=fn(*args,**kwargs)
  if isinstance(v,tuple): v=list(v)
  return {'ok':True,'value':v}
 except Exception as e: return {'ok':False,'error':f'{type(e).__name__}: {e}'}

def main()->int:
 attempts=[]; w3=None; rpc=None
 for u in RPCS:
  try:
   c=Web3(Web3.HTTPProvider(u,request_kwargs={'timeout':30}))
   if c.eth.chain_id!=42161: raise RuntimeError(f'wrong chain {c.eth.chain_id}')
   latest=c.eth.block_number; w3=c; rpc=u; attempts.append({'url':u,'ok':True,'latest':latest}); break
  except Exception as e: attempts.append({'url':u,'ok':False,'error':f'{type(e).__name__}: {e}'})
 if w3 is None: raise RuntimeError(json.dumps(attempts))
 block=w3.eth.get_block(latest); m=w3.eth.contract(address=MARKET,abi=MARKET_ABI)
 tokens=m.functions.tokens().call(block_identifier=latest); ft,xt,gt,coll,debt=tokens
 config=m.functions.config().call(block_identifier=latest); maturity=int(config[1])
 g=w3.eth.contract(address=gt,abi=GT_ABI); gcfg=g.functions.getGtConfig().call(block_identifier=latest); oracle_addr=gcfg[5][0]
 oracle=w3.eth.contract(address=oracle_addr,abi=ORACLE_ABI)
 def side(asset:str)->dict[str,Any]:
  cfg=safe(oracle.functions.oracles(asset).call,block_identifier=latest); price=safe(oracle.functions.getPrice(asset).call,block_identifier=latest)
  row={'asset':asset,'symbol':safe(w3.eth.contract(address=asset,abi=ERC20_ABI).functions.symbol().call,block_identifier=latest),'config':cfg,'price':price}
  if cfg.get('ok'):
   agg,backup,maxp,minp,hb,bhb=cfg['value']; row.update({'aggregator':agg,'backup':backup,'maxPrice':int(maxp),'minPrice':int(minp),'heartbeat':int(hb),'backupHeartbeat':int(bhb),'zeroFloor':int(minp)==0})
   if agg.lower()!='0x0000000000000000000000000000000000000000': row['round']=safe(w3.eth.contract(address=agg,abi=ROUND_ABI).functions.latestRoundData().call,block_identifier=latest)
  return row
 result={'schema':'termmax-arbitrum-zero-price-gate/v1','generatedAtUtc':datetime.now(timezone.utc).isoformat(),'safety':{'privateKeys':0,'signedTransactions':0,'broadcastTransactions':0,'stateChanges':0},'rpc':rpc,'rpcAttempts':attempts,'block':{'number':latest,'hash':block.hash.hex(),'timestamp':int(block.timestamp)},'market':MARKET,'maturity':maturity,'active':maturity>int(block.timestamp),'tokens':{'ft':ft,'xt':xt,'gt':gt,'collateral':coll,'debtToken':debt},'gtSupply':safe(g.functions.totalSupply().call,block_identifier=latest),'oracle':oracle_addr,'collateralOracle':side(coll),'debtOracle':side(debt)}
 summary={'active':result['active'],'gtSupply':result['gtSupply'].get('value'),'collateralMinPrice':result['collateralOracle'].get('minPrice'),'debtMinPrice':result['debtOracle'].get('minPrice'),'zeroFloorSideCount':sum(1 for x in (result['collateralOracle'],result['debtOracle']) if x.get('zeroFloor'))}
 result['summary']=summary
 (OUT/'ARBITRUM_ZERO_PRICE_GATE_FULL.json').write_text(json.dumps(result,indent=2),encoding='utf-8'); (OUT/'SUMMARY.json').write_text(json.dumps(summary,indent=2),encoding='utf-8'); print(json.dumps(summary,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
