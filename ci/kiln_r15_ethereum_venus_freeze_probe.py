#!/usr/bin/env python3
"""Kiln R15 Ethereum VENUS registry/freeze proof. Read-only JSON-RPC only."""
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from typing import Any
from web3 import Web3

OUT=Path('r15_results'); OUT.mkdir(exist_ok=True)
RPCS=['https://ethereum-rpc.publicnode.com','https://eth.llamarpc.com','https://1rpc.io/eth']
REG=Web3.to_checksum_address('0xdE63817c82e93499357aE198518f90Ac1bE93A72')
VAULTS=[
 ('Yield Bearing Venus USDT','0xCcDed4b9D47F7F248bfe3F49a9C70A5F1E6EA4c4','0xdAC17F958D2ee523a2206206994597C13D831ec7'),
 ('Yield Bearing Venus USDC','0xDa273908A3f837091774164E2821ba8Ee8238501','0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48')]
VAULTS=[(n,Web3.to_checksum_address(v),Web3.to_checksum_address(a)) for n,v,a in VAULTS]
VENUS=b'VENUS'.ljust(32,b'\0'); VTOP='0x'+VENUS.hex(); ZERO='0x'+'0'*40
ABI_REG=[
 {'type':'function','name':'connectorInfo','stateMutability':'view','inputs':[{'name':'','type':'bytes32'}],'outputs':[{'name':'addr','type':'address'},{'name':'pause','type':'uint88'},{'name':'frozen','type':'bool'}]},
 {'type':'function','name':'connectorAddress','stateMutability':'view','inputs':[{'name':'name','type':'bytes32'}],'outputs':[{'name':'','type':'address'}]},
 {'type':'function','name':'connectorExists','stateMutability':'view','inputs':[{'name':'name','type':'bytes32'}],'outputs':[{'name':'','type':'bool'}]},
 {'type':'function','name':'getOrRevert','stateMutability':'view','inputs':[{'name':'name','type':'bytes32'}],'outputs':[{'name':'','type':'address'}]}]
ABI_V=[
 {'type':'function','name':'asset','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'address'}]},
 {'type':'function','name':'connectorRegistry','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'address'}]},
 {'type':'function','name':'connectorName','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'bytes32'}]},
 {'type':'function','name':'totalAssets','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'totalSupply','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'decimals','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'uint8'}]},
 {'type':'function','name':'balanceOf','stateMutability':'view','inputs':[{'name':'a','type':'address'}],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'maxRedeem','stateMutability':'view','inputs':[{'name':'a','type':'address'}],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'previewRedeem','stateMutability':'view','inputs':[{'name':'x','type':'uint256'}],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'redeem','stateMutability':'nonpayable','inputs':[{'name':'x','type':'uint256'},{'name':'r','type':'address'},{'name':'o','type':'address'}],'outputs':[{'name':'','type':'uint256'}]}]
ABI_ERC=[
 {'type':'function','name':'balanceOf','stateMutability':'view','inputs':[{'name':'a','type':'address'}],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'decimals','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'uint8'}]},
 {'type':'function','name':'symbol','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'string'}]}]
ABI_C=[
 {'type':'function','name':'totalAssets','stateMutability':'view','inputs':[{'name':'asset','type':'address'}],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'venusMarketRegistry','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'address'}]},
 {'type':'function','name':'marketRegistry','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'address'}]}]
ABI_MR=[{'type':'function','name':'getMarket','stateMutability':'view','inputs':[{'name':'a','type':'address'}],'outputs':[{'name':'','type':'address'}]}]
ABI_VT=[
 {'type':'function','name':'underlying','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'address'}]},
 {'type':'function','name':'balanceOf','stateMutability':'view','inputs':[{'name':'a','type':'address'}],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'balanceOfUnderlying','stateMutability':'nonpayable','inputs':[{'name':'a','type':'address'}],'outputs':[{'name':'','type':'uint256'}]},
 {'type':'function','name':'exchangeRateStored','stateMutability':'view','inputs':[],'outputs':[{'name':'','type':'uint256'}]}]
EV={n:Web3.keccak(text=s).hex() for n,s in {
 'Added':'ConnectorAdded(bytes32,address)','Updated':'ConnectorUpdated(bytes32,address)',
 'Removed':'ConnectorRemoved(bytes32)','Paused':'Paused(bytes32,uint256)',
 'Unpaused':'Unpaused(bytes32)','Frozen':'Frozen(bytes32)',
 'Transfer':'Transfer(address,address,uint256)'}.items()}
REV={v.lower():k for k,v in EV.items()}
ERRS={'0x'+Web3.keccak(text=s)[:4].hex():s for s in ['ConnectorDoesNotExist(bytes32)','ConnectorPaused(bytes32)']}

def connect():
 for u in RPCS:
  try:
   w=Web3(Web3.HTTPProvider(u,request_kwargs={'timeout':30}))
   if w.is_connected() and w.eth.chain_id==1: return w,u
  except Exception: pass
 raise RuntimeError('no Ethereum RPC')

def norm(x:Any):
 if isinstance(x,(bytes,bytearray)): return '0x'+bytes(x).hex()
 if isinstance(x,(list,tuple)): return [norm(v) for v in x]
 return x

def safe(fn,tx=None,block='latest'):
 try:return {'ok':True,'value':norm(fn.call(tx or {},block_identifier=block))}
 except Exception as e:
  s=str(e); import re; hits=re.findall(r'0x[0-9a-fA-F]{8,}',s); d=hits[-1] if hits else None; sel=d[:10].lower() if d else None
  return {'ok':False,'error':s,'revert_data':d,'decoded_error':ERRS.get(sel)}

def codehash(w,a):
 b=bytes(w.eth.get_code(a)); return hashlib.sha256(b).hexdigest() if b else None

def logs(w,address,start,end,topics):
 out=[]; pos=start; step=100000
 while pos<=end:
  stop=min(end,pos+step-1)
  try:
   part=w.eth.get_logs({'address':address,'fromBlock':pos,'toBlock':stop,'topics':topics}); out+=part; pos=stop+1
   if len(part)<200 and step<500000: step*=2
  except Exception:
   if step<=1000: raise
   step//=2
 return out

def topic_addr(t):
 h=t.hex() if hasattr(t,'hex') else str(t).removeprefix('0x'); return Web3.to_checksum_address('0x'+h[-40:])

def find_deploy(w,a,latest):
 lo=max(0,latest-8000000); hi=latest
 try:
  if not w.eth.get_code(a,block_identifier=lo):
   while lo<hi:
    m=(lo+hi)//2
    if w.eth.get_code(a,block_identifier=m):hi=m
    else:lo=m+1
   return lo
 except Exception: pass
 return max(0,latest-8000000)

def reg_history(w,latest):
 start=find_deploy(w,REG,latest); topics=[[EV[k] for k in ['Added','Updated','Removed','Paused','Unpaused','Frozen']],VTOP]
 out=[]
 for l in logs(w,REG,start,latest,topics):
  event=REV.get(l['topics'][0].hex().lower(),'Unknown'); item={'event':event,'block':int(l['blockNumber']),'tx':l['transactionHash'].hex()}
  if event in ('Added','Updated') and len(l['topics'])>2:item['connector']=topic_addr(l['topics'][2])
  b=w.eth.get_block(l['blockNumber']); item['timestamp']=int(b['timestamp']); out.append(item)
 return {'scan_start':start,'events':out}

def holders(w,vault,latest):
 start=find_deploy(w,vault,latest); ls=logs(w,vault,start,latest,[EV['Transfer']]); addrs={vault}
 for l in ls:
  if len(l['topics'])>=3:
   for t in l['topics'][1:3]:
    a=topic_addr(t)
    if a.lower()!=ZERO: addrs.add(a)
 c=w.eth.contract(vault,abi=ABI_V); hs=[]
 for a in addrs:
  r=safe(c.functions.balanceOf(a))
  if r['ok'] and int(r['value'])>0:hs.append({'address':a,'shares':int(r['value'])})
 return {'scan_start':start,'transfer_events':len(ls),'holders':sorted(hs,key=lambda x:x['shares'],reverse=True)}

def old_connector(w,addr):
 c=w.eth.contract(addr,abi=ABI_C); x={'address':addr,'code_sha256':codehash(w,addr),'vaults':[]}; mr=None
 for g in ['venusMarketRegistry','marketRegistry']:
  r=safe(getattr(c.functions,g)()); x[g]=r
  if r['ok'] and r['value'].lower()!=ZERO: mr=r['value']; break
 for _,v,a in VAULTS:
  z={'vault':v,'asset':a,'connector_totalAssets_from_vault':safe(c.functions.totalAssets(a),{'from':v})}
  if mr:
   m=safe(w.eth.contract(mr,abi=ABI_MR).functions.getMarket(a)); z['market']=m
   if m['ok'] and m['value'].lower()!=ZERO:
    vt=w.eth.contract(m['value'],abi=ABI_VT); z['market_code_sha256']=codehash(w,m['value'])
    for n,fn in [('underlying',vt.functions.underlying()),('vtoken_balance',vt.functions.balanceOf(v)),('underlying_claim',vt.functions.balanceOfUnderlying(v)),('exchange_rate_stored',vt.functions.exchangeRateStored())]:z[n]=safe(fn,{'from':v})
  x['vaults'].append(z)
 return x

def main():
 w,rpc=connect(); latest=w.eth.block_number; now=int(w.eth.get_block(latest)['timestamp']); reg=w.eth.contract(REG,abi=ABI_REG)
 state={n:safe(getattr(reg.functions,n)(VENUS)) for n in ['connectorInfo','connectorAddress','connectorExists','getOrRevert']}
 hist=reg_history(w,latest); old=[]
 for e in hist['events']:
  if e.get('connector') and e['connector'].lower()!=ZERO and e['connector'] not in old:old.append(e['connector'])
 vr=[]
 for label,v,a in VAULTS:
  c=w.eth.contract(v,abi=ABI_V); tok=w.eth.contract(a,abi=ABI_ERC); h=holders(w,v,latest); probes={
   'asset':safe(c.functions.asset()),'connectorRegistry':safe(c.functions.connectorRegistry()),'connectorName':safe(c.functions.connectorName()),
   'totalAssets':safe(c.functions.totalAssets()),'totalSupply':safe(c.functions.totalSupply()),'decimals':safe(c.functions.decimals()),
   'asset_balance_at_vault':safe(tok.functions.balanceOf(v)),'asset_decimals':safe(tok.functions.decimals()),'asset_symbol':safe(tok.functions.symbol())}
  for q in h['holders']:
   q['maxRedeem']=safe(c.functions.maxRedeem(q['address'])); q['previewRedeem']=safe(c.functions.previewRedeem(q['shares']))
   q['redeem_eth_call']=safe(c.functions.redeem(q['shares'],q['address'],q['address']),{'from':q['address']})
  vr.append({'label':label,'vault':v,'expected_asset':a,'code_sha256':codehash(w,v),'history':h,'probes':probes})
 rem=[e for e in hist['events'] if e['event']=='Removed']; seconds=now-rem[-1]['timestamp'] if rem else None
 evidence={'schema':'kiln-r15-eth-venus-v1','generated_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'rpc':rpc,'block':latest,
  'safety':{'read_only':True,'transactions_signed':0,'transactions_sent':0,'private_keys':0},'registry':state,'registry_history':hist,
  'old_connectors':[old_connector(w,a) for a in old],'vaults':vr,'metrics':{'seconds_since_last_remove':seconds,'remove_events':len(rem)}}
 (OUT/'R15_EVIDENCE.json').write_text(json.dumps(evidence,indent=2,sort_keys=True))
 absent=state['connectorExists'].get('ok') and state['connectorExists'].get('value') is False
 failures=sum(not v['probes']['totalAssets']['ok'] for v in vr); holders_n=sum(len(v['history']['holders']) for v in vr)
 old_claim=sum(int(z['connector_totalAssets_from_vault']['value']) for x in evidence['old_connectors'] for z in x['vaults'] if z['connector_totalAssets_from_vault']['ok'])
 direct=sum(int(v['probes']['asset_balance_at_vault']['value']) for v in vr if v['probes']['asset_balance_at_vault']['ok'])
 gate={'decision':'HOLD_CURRENT_FREEZE_SIGNAL_PRIVILEGED_TRIGGER_NOT_ELIGIBLE','submit_ready':False,'validated_critical':0,'validated_high':0,
  'facts':{'registry_entry_absent':absent,'vault_totalAssets_failures':failures,'nonzero_holder_records':holders_n,'old_connector_claim_raw_mixed_decimals':old_claim,'direct_asset_raw_mixed_decimals':direct,'seconds_since_last_remove':seconds},
  'blocking_gates':['no permissionless trigger or role bypass','bounty excludes privileged-role-dependent issues','duplicate clearance incomplete']}
 (OUT/'R15_MASTER_GATE.json').write_text(json.dumps(gate,indent=2,sort_keys=True))
 (OUT/'R15_PROOF_CARD.json').write_text(json.dumps({'candidate':'active Ethereum VENUS vaults reference absent registry entry','root_cause':'registry removal can orphan immutable connectorName vaults','live_state':gate['facts'],'eligibility':'blocked by privileged trigger','submit_ready':False},indent=2,sort_keys=True))
 sums=[]
 for p in sorted(OUT.glob('*.json')):sums.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n")
 (OUT/'SHA256SUMS.txt').write_text(''.join(sums)); print(json.dumps(gate,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
