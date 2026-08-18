#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,time
from pathlib import Path
from typing import Any
from web3 import Web3
try:
 from web3.middleware import ExtraDataToPOAMiddleware
except ImportError:
 ExtraDataToPOAMiddleware=None
O=Path('r34_results');O.mkdir(exist_ok=True)
C=Web3.to_checksum_address('0x000000000000000000000000000000000000bEEF')
Z=Web3.to_checksum_address('0x0000000000000000000000000000000000000000')
B=int('a3f0ad74e5423aebfd80d3ef4346578335a9a72aeeee59ff6cb3582b35133d50',16)
N={
 'ethereum':(1,['https://ethereum-rpc.publicnode.com','https://rpc.flashbots.net','https://eth.llamarpc.com','https://1rpc.io/eth']),
 'base':(8453,['https://base-rpc.publicnode.com','https://base.llamarpc.com','https://mainnet.base.org','https://1rpc.io/base'])}
T=[
 ('ethereum','0xCcDed4b9D47F7F248bfe3F49a9C70A5F1E6EA4c4','Yield Bearing Venus USDT','VENUS'),
 ('ethereum','0xDa273908A3f837091774164E2821ba8Ee8238501','Yield Bearing Venus USDC','VENUS'),
 ('base','0x4b2A4368544E276780342750D6678dC30368EF35','Bitpanda Morpho Steakhouse USDC','METAMORPHO_STEAKHOUSE_USDC'),
 ('base','0xEeE56Dc1fb5eD6ebC596da2ea1d1ECd83409f4e4','Trust Wallet Morpho Steakhouse USDC','METAMORPHO_STEAKHOUSE_USDC'),
 ('base','0xFa043C890C3C54a147E847E1C97a2C8a8115c1B3','Waltio Morpho Steakhouse USDC','METAMORPHO_STEAKHOUSE_USDC')]
V=[{'type':'function','name':n,'stateMutability':'view','inputs':i,'outputs':[{'type':o}]} for n,i,o in [
 ('asset',[],'address'),('totalAssets',[],'uint256'),('totalSupply',[],'uint256'),
 ('connectorRegistry',[],'address'),('connectorName',[],'bytes32'),('vaultFactory',[],'address'),
 ('blockList',[],'address'),('decimals',[],'uint8'),('maxDeposit',[{'type':'address'}],'uint256'),
 ('maxWithdraw',[{'type':'address'}],'uint256'),('previewRedeem',[{'type':'uint256'}],'uint256')]]
R=[
 {'type':'function','name':'get','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'address'}]},
 {'type':'function','name':'getOrRevert','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'address'}]},
 {'type':'function','name':'paused','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'bool'}]},
 {'type':'function','name':'frozen','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'bool'}]},
 {'type':'function','name':'connectorInfo','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'address'},{'type':'uint88'},{'type':'bool'}]}]
E=[
 {'type':'function','name':'symbol','stateMutability':'view','inputs':[],'outputs':[{'type':'string'}]},
 {'type':'function','name':'decimals','stateMutability':'view','inputs':[],'outputs':[{'type':'uint8'}]},
 {'type':'function','name':'balanceOf','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'uint256'}]}]
BE=[{'type':'function','name':'implementation','stateMutability':'view','inputs':[],'outputs':[{'type':'address'}]}]
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
def code(w,a,b):
 try:
  q=bytes(w.eth.get_code(Web3.to_checksum_address(a),block_identifier=b));return {'bytes':len(q),'sha256':hashlib.sha256(q).hexdigest() if q else None}
 except Exception as e:return {'bytes':None,'sha256':None,'error':f'{type(e).__name__}: {e}'}
def sa(w,a,s,b):
 try:
  q=bytes(w.eth.get_storage_at(Web3.to_checksum_address(a),s,block_identifier=b));x=Web3.to_checksum_address('0x'+q[-20:].hex());return None if x==Z else x
 except:return None
def connect(n,probe):
 cid,urls=N[n];cs=[];er=[];sel=Web3.keccak(text='asset()')[:4]
 for u in urls:
  try:
   w=Web3(Web3.HTTPProvider(u,request_kwargs={'timeout':30}))
   if not w.is_connected() or int(w.eth.chain_id)!=cid:raise RuntimeError('chain')
   h=int(w.eth.block_number);q=bytes(w.eth.call({'to':Web3.to_checksum_address(probe),'data':sel},block_identifier=h))
   if len(q)<32:raise RuntimeError('probe')
   cs.append((w,u,h))
   if len(cs)==2:break
  except Exception as e:er.append(f'{u}: {type(e).__name__}: {e}')
 if not cs:raise RuntimeError('no RPC | '+' | '.join(er))
 b=max(1,min(x[2] for x in cs)-5);bh=cs[0][0].eth.get_block(b)['hash'].hex()
 if len(cs)>1 and cs[1][0].eth.get_block(b)['hash'].hex().lower()!=bh.lower():raise RuntimeError('block hash mismatch')
 return cs,b,bh
def query(w,n,a,label,scope,b,bh):
 a=Web3.to_checksum_address(a);v=w.eth.contract(a,abi=V);x={'network':n,'vault':a,'label':label,'scope_connector':scope,'block':b,'block_hash':bh,'code':code(w,a,b)}
 for k in ['asset','totalAssets','totalSupply','connectorRegistry','connectorName','vaultFactory','blockList','decimals']:
  x[k]=sf(getattr(v.functions,k)(),b)
 x['maxDeposit_probe']=sf(v.functions.maxDeposit(C),b);x['maxWithdraw_probe']=sf(v.functions.maxWithdraw(C),b)
 ts=int(vl(x['totalSupply']) or 0);x['previewRedeem_totalSupply']=sf(v.functions.previewRedeem(ts),b) if ts else {'ok':True,'value':0}
 aa=ad(vl(x['asset']));ra=ad(vl(x['connectorRegistry']));nr=vl(x['connectorName']);x['signals']=[]
 if aa:
  t=w.eth.contract(aa,abi=E);x['asset_token']={'address':aa,'code':code(w,aa,b),'symbol':sf(t.functions.symbol(),b),'decimals':sf(t.functions.decimals(),b),'direct_balance':sf(t.functions.balanceOf(a),b)}
 else:x['asset_token']={'address':None}
 if ra and isinstance(nr,str) and nr.startswith('0x'):
  nb=bytes.fromhex(nr[2:]);r=w.eth.contract(ra,abi=R);x['registry']={'address':ra,'code':code(w,ra,b),'get':sf(r.functions.get(nb),b),'getOrRevert':sf(r.functions.getOrRevert(nb),b),'paused':sf(r.functions.paused(nb),b),'frozen':sf(r.functions.frozen(nb),b),'connectorInfo':sf(r.functions.connectorInfo(nb),b)}
  ca=ad(vl(x['registry']['get']));x['connector']={'address':ca,'code':code(w,ca,b) if ca else None}
 else:x['registry']={'address':ra,'error':'binding unavailable'};x['connector']={'address':None}
 be=sa(w,a,B,b);x['beacon']={'address':be,'code':code(w,be,b) if be else None}
 if be:
  z=w.eth.contract(be,abi=BE);x['beacon']['implementation']=sf(z.functions.implementation(),b);im=ad(vl(x['beacon']['implementation']));x['beacon']['implementation_code']=code(w,im,b) if im else None
 if x['code'].get('sha256') is None:x['signals'].append('vault_code_missing')
 if ts>0 and not x['totalAssets'].get('ok'):x['signals'].append('positive_supply_totalAssets_reverts')
 if ts>0 and int(vl(x['totalAssets']) or 0)==0:x['signals'].append('positive_supply_zero_totalAssets')
 if ts>0 and not x['connector'].get('address'):x['signals'].append('positive_supply_missing_connector')
 if ra is None or aa is None or not isinstance(nr,str):x['signals'].append('vault_binding_incomplete')
 return x
def compact(x):
 return {k:norm(vl(x[k])) for k in ['asset','totalAssets','totalSupply','connectorRegistry','connectorName','vaultFactory','blockList']}
def main():
 by={}
 for n,a,l,c in T:by.setdefault(n,[]).append((a,l,c))
 ev={'schema':'kiln-r34-targeted-liveness-v1','generated_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'safety':{'read_only':True,'public_chain_state_changes':0,'transactions_signed':0,'transactions_sent':0,'private_keys_loaded':0},'chains':{},'rows':[],'errors':[]}
 for n,targets in by.items():
  try:cs,b,bh=connect(n,targets[0][0]);ev['chains'][n]={'chain_id':N[n][0],'rpc_urls':[q[1] for q in cs],'block':b,'block_hash':bh,'quorum_size':len(cs)}
  except Exception as e:ev['errors'].append({'network':n,'stage':'connect','error':f'{type(e).__name__}: {e}'});continue
  for a,l,c in targets:
   try:
    x=query(cs[0][0],n,a,l,c,b,bh)
    if len(cs)>1:
     y=query(cs[1][0],n,a,l,c,b,bh);x['secondary']={'state':compact(y),'signals':y['signals'],'matches_primary':compact(y)==compact(x),'signals_match':y['signals']==x['signals']}
     if not x['secondary']['matches_primary'] or not x['secondary']['signals_match']:x['signals'].append('rpc_quorum_mismatch')
    else:x['signals'].append('single_rpc_only')
    ev['rows'].append(x)
   except Exception as e:ev['errors'].append({'network':n,'vault':a,'label':l,'error':f'{type(e).__name__}: {e}'})
 sig=[x for x in ev['rows'] if any(s not in {'single_rpc_only'} for s in x['signals'])]
 ev['summary']={'target_count':len(T),'inspected_count':len(ev['rows']),'error_count':len(ev['errors']),'signal_row_count':len(sig),'signal_types':sorted({s for x in sig for s in x['signals'] if s!='single_rpc_only'}),'positive_supply_signal_count':sum(any(s.startswith('positive_supply_') for s in x['signals']) for x in sig)}
 (O/'EVIDENCE.json').write_text(json.dumps(ev,indent=2,sort_keys=True))
 q=ev['summary'];decision='HOLD_POSITIVE_SUPPLY_LIVENESS_SIGNAL_REQUIRES_FIXED_BLOCK_POC' if q['positive_supply_signal_count'] else ('INCONCLUSIVE_TARGET_ERRORS' if q['error_count'] else 'KILL_NO_MATERIAL_LIVENESS_SIGNAL')
 gate={'schema':'kiln-r34-public-gate-v1','decision':decision,'submit_ready':False,'validated_critical':0,'validated_high':0,**q,'public_chain_state_changes':0,'transactions_signed':0,'transactions_sent':0}
 (O/'PUBLIC_GATE.json').write_text(json.dumps(gate,indent=2,sort_keys=True));fs=sorted(p for p in O.iterdir() if p.is_file() and p.name!='SHA256SUMS.txt');(O/'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in fs));print(json.dumps(gate,sort_keys=True));return 0 if ev['rows'] else 2
if __name__=='__main__':raise SystemExit(main())
