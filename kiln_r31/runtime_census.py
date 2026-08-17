#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,time
from pathlib import Path
from typing import Any
from web3 import Web3
try: from web3.middleware import ExtraDataToPOAMiddleware
except ImportError: ExtraDataToPOAMiddleware=None
O=Path('r31_results');O.mkdir(exist_ok=True);S=Path('r30_scope/SCOPE.json');Z='0x'+'00'*20;C=Web3.to_checksum_address('0x000000000000000000000000000000000000bEEF')
BS=int('a3f0ad74e5423aebfd80d3ef4346578335a9a72aeeee59ff6cb3582b35133d50',16)
N={'ethereum':(1,['https://ethereum-rpc.publicnode.com','https://rpc.flashbots.net','https://eth.llamarpc.com']),'optimism':(10,['https://optimism-rpc.publicnode.com','https://optimism.llamarpc.com','https://mainnet.optimism.io']),'bnb':(56,['https://bsc-rpc.publicnode.com','https://binance.llamarpc.com','https://bsc-dataseed.binance.org']),'polygon':(137,['https://polygon-bor-rpc.publicnode.com','https://polygon.llamarpc.com','https://polygon-rpc.com']),'base':(8453,['https://base-rpc.publicnode.com','https://base.llamarpc.com','https://mainnet.base.org']),'arbitrum':(42161,['https://arb1.arbitrum.io/rpc','https://arbitrum-one-rpc.publicnode.com','https://arbitrum.llamarpc.com'])}
V=[{'type':'function','name':n,'stateMutability':'view','inputs':i,'outputs':[{'type':o}]} for n,i,o in [('asset',[],'address'),('connectorRegistry',[],'address'),('connectorName',[],'bytes32'),('additionalRewardsStrategy',[],'uint8'),('depositFee',[],'uint256'),('rewardFee',[],'uint256'),('totalAssets',[],'uint256'),('totalSupply',[],'uint256'),('pendingDepositFee',[],'uint256'),('pendingRewardFee',[],'uint256'),('collectableRewardFees',[],'uint256'),('blockList',[],'address'),('transferable',[],'bool'),('decimals',[],'uint8'),('maxDeposit',[{'type':'address'}],'uint256'),('maxWithdraw',[{'type':'address'}],'uint256')]]
R=[{'type':'function','name':n,'stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':o}]} for n,o in [('get','address'),('paused','bool'),('frozen','bool'),('pauseTimestamp','uint256')]]
E=[{'type':'function','name':'symbol','stateMutability':'view','inputs':[],'outputs':[{'type':'string'}]},{'type':'function','name':'decimals','stateMutability':'view','inputs':[],'outputs':[{'type':'uint8'}]},{'type':'function','name':'balanceOf','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'uint256'}]}]
B=[{'type':'function','name':'implementation','stateMutability':'view','inputs':[],'outputs':[{'type':'address'}]}]
G=['aave()','poolAddressesProvider()','rewardsController()','swapTarget()','compoundMarketRegistry()','cometRewards()','comp()','metamorpho()','sDAI()','sUSDS()','stakingVault()','fluidFactory()','venusMarketRegistry()','marketRegistry()','vToken()','vtoken()','venus()','pool()','fToken()']
def norm(x:Any)->Any:
 if isinstance(x,(bytes,bytearray)):return '0x'+bytes(x).hex()
 if isinstance(x,(list,tuple)):return [norm(y) for y in x]
 return x
def sf(f,b,tx=None):
 try:return {'ok':True,'value':norm(f.call(tx or {},block_identifier=b))}
 except Exception as e:return {'ok':False,'error':f'{type(e).__name__}: {e}'}
def vl(x):return x.get('value') if x.get('ok') else None
def ad(x):
 try:return Web3.to_checksum_address(x)
 except:return None
def ch(w,a,b):
 try:
  c=bytes(w.eth.get_code(Web3.to_checksum_address(a),block_identifier=b));return hashlib.sha256(c).hexdigest() if c else None
 except:return None
def rg(w,t,s,b):
 try:
  q=bytes(w.eth.call({'to':Web3.to_checksum_address(t),'data':Web3.keccak(text=s)[:4]},block_identifier=b))
  if len(q)<32:raise RuntimeError('short')
  a=Web3.to_checksum_address('0x'+q[-20:].hex());return {'ok':True,'value':a,'code_sha256':ch(w,a,b) if a!=Z else None}
 except Exception as e:return {'ok':False,'error':f'{type(e).__name__}: {e}'}
def cn(n,p):
 cid,us=N[n];cs=[];er=[]
 for u in us:
  try:
   w=Web3(Web3.HTTPProvider(u,request_kwargs={'timeout':30}))
   if n in {'bnb','polygon'} and ExtraDataToPOAMiddleware:w.middleware_onion.inject(ExtraDataToPOAMiddleware,layer=0)
   if not w.is_connected() or int(w.eth.chain_id)!=cid:raise RuntimeError('chain')
   h=int(w.eth.block_number);q=bytes(w.eth.call({'to':Web3.to_checksum_address(p),'data':Web3.keccak(text='asset()')[:4]},block_identifier=h))
   if len(q)<32:raise RuntimeError('probe')
   cs.append((w,u,h))
   if len(cs)==2:break
  except Exception as e:er.append(f'{u}: {type(e).__name__}: {e}')
 if not cs:raise RuntimeError('no RPC | '+' | '.join(er))
 b=max(1,min(x[2] for x in cs)-5);bh=cs[0][0].eth.get_block(b)['hash'].hex()
 if len(cs)>1 and cs[1][0].eth.get_block(b)['hash'].hex().lower()!=bh.lower():raise RuntimeError('block hash mismatch')
 return cs,b,bh
def qv(w,n,r,b,bh):
 a=Web3.to_checksum_address(r['address']);v=w.eth.contract(a,abi=V);x={'network':n,'label':r['label'],'scope_connector':r['connector'],'vault':a,'block':b,'block_hash':bh,'vault_code_sha256':ch(w,a,b)}
 for k in ['asset','connectorRegistry','connectorName','additionalRewardsStrategy','depositFee','rewardFee','totalAssets','totalSupply','pendingDepositFee','pendingRewardFee','collectableRewardFees','blockList','transferable','decimals']:x[k]=sf(getattr(v.functions,k)(),b)
 x['maxDeposit_probe']=sf(v.functions.maxDeposit(C),b);x['maxWithdraw_probe']=sf(v.functions.maxWithdraw(C),b)
 aa=ad(vl(x['asset']));ra=ad(vl(x['connectorRegistry']));nr=vl(x['connectorName'])
 if not aa or not ra or not isinstance(nr,str):raise RuntimeError('vault binding')
 nb=bytes.fromhex(nr[2:]);x['connector_name_ascii']=nb.rstrip(b'\0').decode(errors='replace');reg=w.eth.contract(ra,abi=R)
 x['registry']={'address':ra,'code_sha256':ch(w,ra,b),'connector':sf(reg.functions.get(nb),b),'paused':sf(reg.functions.paused(nb),b),'frozen':sf(reg.functions.frozen(nb),b),'pauseTimestamp':sf(reg.functions.pauseTimestamp(nb),b)}
 ca=ad(vl(x['registry']['connector']))
 if not ca or ca==Z:raise RuntimeError('connector')
 x['connector_address']=ca;x['connector_code_sha256']=ch(w,ca,b);x['connector_getters']={s:rg(w,ca,s,b) for s in G}
 t=w.eth.contract(aa,abi=E);x['asset_token']={'address':aa,'code_sha256':ch(w,aa,b),'symbol':sf(t.functions.symbol(),b),'decimals':sf(t.functions.decimals(),b),'balance_at_vault':sf(t.functions.balanceOf(a),b)}
 raw=bytes(w.eth.get_storage_at(a,BS,block_identifier=b));be=Web3.to_checksum_address('0x'+raw[-20:].hex()) if len(raw)>=20 else None;x['beacon']={'address':be,'code_sha256':ch(w,be,b) if be and be!=Z else None}
 if be and be!=Z:
  bc=w.eth.contract(be,abi=B);x['beacon']['implementation']=sf(bc.functions.implementation(),b);im=ad(vl(x['beacon']['implementation']));x['beacon']['implementation_code_sha256']=ch(w,im,b) if im else None
 ta=vl(x['totalAssets']);ts=vl(x['totalSupply']);pd=int(vl(x['pendingDepositFee']) or 0);pr=int(vl(x['pendingRewardFee']) or 0);db=int(vl(x['asset_token']['balance_at_vault']) or 0);sg=[]
 if ts and not x['totalAssets']['ok']:sg+=['positive_supply_totalAssets_reverts']
 if int(ts or 0)>0 and int(ta or 0)==0:sg+=['positive_supply_zero_totalAssets']
 if db<pd+pr:sg+=['direct_asset_below_pending_fee_reserve']
 if db>pd+pr:sg+=['direct_asset_exceeds_pending_fee_reserve']
 if vl(x['registry']['paused']) and int(ts or 0)>0:sg+=['connector_paused_with_positive_supply']
 if vl(x['registry']['frozen']):sg+=['connector_frozen']
 if x['connector_name_ascii']!=r['connector']:sg+=['scope_connector_name_runtime_mismatch']
 x['accounting']={'direct_asset_balance':db,'pending_deposit_fee':pd,'pending_reward_fee':pr,'pending_fee_total':pd+pr,'direct_minus_pending':db-pd-pr};x['signals']=sorted(set(sg));return x
def qs(w,x,b):
 a=Web3.to_checksum_address(x['vault']);v=w.eth.contract(a,abi=V);z={k:sf(getattr(v.functions,k)(),b) for k in ['asset','connectorRegistry','connectorName','additionalRewardsStrategy','totalAssets','totalSupply','pendingDepositFee','pendingRewardFee']};aa=ad(vl(z['asset']))
 if aa:z['direct_asset_balance']=sf(w.eth.contract(aa,abi=E).functions.balanceOf(a),b)
 z['matches_primary']=all(norm(vl(z[k]))==norm(vl(x[k])) for k in ['asset','connectorRegistry','connectorName','additionalRewardsStrategy','totalAssets','totalSupply','pendingDepositFee','pendingRewardFee']);z['direct_matches']=norm(vl(z.get('direct_asset_balance',{})))==norm(x['accounting']['direct_asset_balance']);return z
def main():
 n=os.environ['TARGET_NETWORK'].lower();si=int(os.getenv('SHARD_INDEX','0'));sc=int(os.getenv('SHARD_COUNT','1'));d=json.loads(S.read_text());nr=[x for x in d['rows'] if x['network']==n];sel=[x for i,x in enumerate(nr) if i%sc==si]
 if not sel:raise RuntimeError('empty shard')
 cs,b,bh=cn(n,sel[0]['address']);w=cs[0][0];rows=[];ers=[]
 for r in sel:
  try:
   x=qv(w,n,r,b,bh)
   if x['signals'] and len(cs)>1:
    x['secondary_quorum']=qs(cs[1][0],x,b)
    if not x['secondary_quorum']['matches_primary'] or not x['secondary_quorum']['direct_matches']:x['signals']+=['killed_rpc_quorum_mismatch']
   elif x['signals']:x['signals']+=['unconfirmed_single_rpc_only']
   rows.append(x)
  except Exception as e:ers.append({'vault':r['address'],'label':r['label'],'error':f'{type(e).__name__}: {e}'})
 uc={}
 for x in rows:uc[(x['connector_name_ascii'],x['connector_address'].lower())]={'name':x['connector_name_ascii'],'address':x['connector_address'],'code_sha256':x['connector_code_sha256'],'getters':x['connector_getters']}
 sr=[x for x in rows if x['signals']];ss=sorted({s for x in rows for s in x['signals']});res={'schema':'kiln-r31-runtime-config-census-v1','generated_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'matrix':{'network':n,'shard_index':si,'shard_count':sc},'source_scope_sha256':hashlib.sha256(S.read_bytes()).hexdigest(),'chain':{'chain_id':N[n][0],'rpc_urls':[x[1] for x in cs],'pinned_block':b,'pinned_block_hash':bh,'rpc_quorum_size':len(cs)},'safety':{'read_only':True,'public_chain_state_changes':0,'transactions_signed':0,'transactions_sent':0,'private_keys_loaded':0},'rows':rows,'errors':ers,'unique_connectors':list(uc.values()),'summary':{'selected_count':len(sel),'inspected_count':len(rows),'error_count':len(ers),'signal_row_count':len(sr),'signal_counts':{s:sum(s in x['signals'] for x in rows) for s in ss},'unique_connector_count':len(uc)}}
 (O/'EVIDENCE.json').write_text(json.dumps(res,indent=2,sort_keys=True));g={'schema':'kiln-r31-public-gate-v1','decision':'HOLD_PRIVATE_SIGNAL_REVIEW' if sr else ('INCONCLUSIVE_RUNTIME_ERRORS' if ers else 'KILL_NO_RUNTIME_CONFIG_SIGNAL'),'submit_ready':False,'validated_critical':0,'validated_high':0,'network':n,'shard_index':si,'shard_count':sc,'selected_count':len(sel),'inspected_count':len(rows),'error_count':len(ers),'signal_row_count':len(sr),'unique_connector_count':len(uc),'public_chain_state_changes':0,'transactions_signed':0,'transactions_sent':0};(O/'PUBLIC_GATE.json').write_text(json.dumps(g,indent=2,sort_keys=True));fs=[p for p in sorted(O.iterdir()) if p.is_file() and p.name!='SHA256SUMS.txt'];(O/'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in fs));print(json.dumps(g,sort_keys=True));return 0 if rows else 2
if __name__=='__main__':raise SystemExit(main())
