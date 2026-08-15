#!/usr/bin/env python3
"""Kiln R15: exact Ethereum VENUS registry/holder/value census; read-only only."""
import hashlib,json,re,time
from pathlib import Path
import requests
from web3 import Web3
O=Path('r15_routescan_results');O.mkdir(exist_ok=True)
API='https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api'
RPCS=['https://eth.llamarpc.com','https://1rpc.io/eth','https://eth.drpc.org','https://rpc.flashbots.net','https://ethereum-rpc.publicnode.com']
R=Web3.to_checksum_address('0xdE63817c82e93499357aE198518f90Ac1bE93A72');Z='0x'+'0'*40;CALLER=Web3.to_checksum_address('0x000000000000000000000000000000000000bEEF')
VN=b'VENUS'.ljust(32,b'\0');VT='0x'+VN.hex()
VS=[('Yield Bearing Venus USDT',Web3.to_checksum_address('0xCcDed4b9D47F7F248bfe3F49a9C70A5F1E6EA4c4'),Web3.to_checksum_address('0xdAC17F958D2ee523a2206206994597C13D831ec7')),('Yield Bearing Venus USDC',Web3.to_checksum_address('0xDa273908A3f837091774164E2821ba8Ee8238501'),Web3.to_checksum_address('0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48'))]
RA=[{'type':'function','name':'connectorInfo','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'address'},{'type':'uint88'},{'type':'bool'}]},{'type':'function','name':'connectorAddress','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'address'}]},{'type':'function','name':'connectorExists','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'bool'}]},{'type':'function','name':'getOrRevert','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'address'}]},{'type':'function','name':'CONNECTOR_MANAGER_ROLE','stateMutability':'view','inputs':[],'outputs':[{'type':'bytes32'}]},{'type':'function','name':'hasRole','stateMutability':'view','inputs':[{'type':'bytes32'},{'type':'address'}],'outputs':[{'type':'bool'}]},{'type':'function','name':'remove','stateMutability':'nonpayable','inputs':[{'type':'bytes32'}],'outputs':[]}]
VA=[{'type':'function','name':n,'stateMutability':'view','inputs':i,'outputs':o} for n,i,o in [('asset',[],[{'type':'address'}]),('connectorRegistry',[],[{'type':'address'}]),('connectorName',[],[{'type':'bytes32'}]),('totalAssets',[],[{'type':'uint256'}]),('totalSupply',[],[{'type':'uint256'}]),('decimals',[],[{'type':'uint8'}]),('balanceOf',[{'type':'address'}],[{'type':'uint256'}]),('maxRedeem',[{'type':'address'}],[{'type':'uint256'}]),('previewRedeem',[{'type':'uint256'}],[{'type':'uint256'}])]]+[{'type':'function','name':'redeem','stateMutability':'nonpayable','inputs':[{'type':'uint256'},{'type':'address'},{'type':'address'}],'outputs':[{'type':'uint256'}]}]
EA=[{'type':'function','name':'balanceOf','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'uint256'}]},{'type':'function','name':'decimals','stateMutability':'view','inputs':[],'outputs':[{'type':'uint8'}]},{'type':'function','name':'symbol','stateMutability':'view','inputs':[],'outputs':[{'type':'string'}]}]
CA=[{'type':'function','name':'totalAssets','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'uint256'}]}]
ES={'ConnectorAdded':'ConnectorAdded(bytes32,address)','ConnectorUpdated':'ConnectorUpdated(bytes32,address)','ConnectorRemoved':'ConnectorRemoved(bytes32)','Paused':'Paused(bytes32,uint256)','Unpaused':'Unpaused(bytes32)','Frozen':'Frozen(bytes32)','Transfer':'Transfer(address,address,uint256)'}
TP={n:Web3.keccak(text=s).hex() for n,s in ES.items()};NT={v.lower():k for k,v in TP.items()}
ER={Web3.keccak(text=s)[:4].hex().lower():s for s in ['ConnectorDoesNotExist(bytes32)','ConnectorPaused(bytes32)','AccessControlUnauthorizedAccount(address,bytes32)']}
def norm(x):
 if isinstance(x,(bytes,bytearray)):return '0x'+bytes(x).hex()
 if isinstance(x,(tuple,list)):return [norm(y) for y in x]
 return x
def call(f,tx=None,b='latest'):
 try:return {'ok':True,'value':norm(f.call(tx or {},block_identifier=b))}
 except Exception as e:
  s=str(e);h=re.findall(r'0x[0-9a-fA-F]{8,}',s);d=h[-1] if h else None
  return {'ok':False,'error':s,'revert_data':d,'decoded_error':ER.get(d[:10].lower()) if d else None}
def rpc():
 es=[]
 for u in RPCS:
  try:
   w=Web3(Web3.HTTPProvider(u,request_kwargs={'timeout':25}))
   if w.is_connected() and w.eth.chain_id==1:w.eth.get_code(R);return w,u
  except Exception as e:es.append(f'{u}: {e}')
 raise RuntimeError('no RPC | '+' | '.join(es))
def rs(p):
 for i in range(6):
  try:
   q=requests.get(API,params=p,headers={'User-Agent':'Kiln-R15-ReadOnly/1.0'},timeout=45);q.raise_for_status();return q.json()
  except Exception as e:
   last=e;time.sleep(i+1)
 raise RuntimeError(f'Routescan failed: {last}')
def logs(a,t0=None,t1=None):
 out=[];pg=1
 while True:
  p={'module':'logs','action':'getLogs','address':a,'fromBlock':0,'toBlock':'latest','page':pg,'offset':1000}
  if t0:p['topic0']=t0
  if t1:p['topic1']=t1
  d=rs(p);r=d.get('result')
  if isinstance(r,str):
   if d.get('status')=='0' or 'No records' in r:break
   raise RuntimeError(str(d))
  if not isinstance(r,list):raise RuntimeError(str(d))
  out+=r
  if len(r)<1000:break
  pg+=1
  if pg>100:raise RuntimeError('pagination guard')
 return out
def addr(t):return Web3.to_checksum_address('0x'+t.removeprefix('0x')[-40:])
def ch(w,a):
 x=bytes(w.eth.get_code(a));return hashlib.sha256(x).hexdigest() if x else None
def hist(w):
 out=[]
 for x in logs(R,t1=VT):
  ts=x.get('topics',[]);n=NT.get(ts[0].lower(),'Unknown');z={'event':n,'block':int(x['blockNumber'],16),'timestamp':int(x.get('timeStamp','0x0'),16),'tx':x['transactionHash']}
  if n in ('ConnectorAdded','ConnectorUpdated') and len(ts)>2:z['connector']=addr(ts[2])
  try:
   q=w.eth.get_transaction(x['transactionHash']);z.update(sender=q['from'],input_selector=q['input'].hex()[:10])
  except Exception as e:z['tx_lookup_error']=str(e)
  out.append(z)
 return sorted(out,key=lambda z:z['block'])
def holders(w,v):
 c=w.eth.contract(v,abi=VA);aa={v};ll=logs(v,t0=TP['Transfer'])
 for x in ll:
  t=x.get('topics',[])
  if len(t)>2:
   for y in t[1:3]:
    a=addr(y)
    if a.lower()!=Z:aa.add(a)
 hs=[]
 for a in aa:
  b=call(c.functions.balanceOf(a))
  if b.get('ok') and int(b['value'])>0:
   s=int(b['value']);hs.append({'address':a,'shares':s,'maxRedeem':call(c.functions.maxRedeem(a)),'previewRedeem':call(c.functions.previewRedeem(s)),'redeem_eth_call':call(c.functions.redeem(s,a,a),{'from':a})})
 return {'transfer_logs':len(ll),'holders':sorted(hs,key=lambda z:z['shares'],reverse=True)}
def main():
 w,u=rpc();bn=w.eth.block_number;now=int(w.eth.get_block(bn)['timestamp']);rg=w.eth.contract(R,abi=RA);role=call(rg.functions.CONNECTOR_MANAGER_ROLE())
 st={'connectorInfo':call(rg.functions.connectorInfo(VN)),'connectorAddress':call(rg.functions.connectorAddress(VN)),'connectorExists':call(rg.functions.connectorExists(VN)),'getOrRevert':call(rg.functions.getOrRevert(VN)),'unprivileged_remove_eth_call':call(rg.functions.remove(VN),{'from':CALLER}),'managerRole':role}
 hh=hist(w)
 if role.get('ok'):
  rb=bytes.fromhex(role['value'][2:])
  for z in hh:
   if z.get('sender'):z['sender_had_manager_role_post_event']=call(rg.functions.hasRole(rb,z['sender']),b=z['block'])
 old=[]
 for z in hh:
  a=z.get('connector')
  if a and a.lower()!=Z and a not in old:old.append(a)
 vv=[]
 for lab,v,a in VS:
  c=w.eth.contract(v,abi=VA);t=w.eth.contract(a,abi=EA);de=call(t.functions.decimals());sy=call(t.functions.symbol());db=call(t.functions.balanceOf(v))
  vv.append({'label':lab,'vault':v,'asset_expected':a,'code_sha256':ch(w,v),'asset':call(c.functions.asset()),'registry':call(c.functions.connectorRegistry()),'connectorName':call(c.functions.connectorName()),'totalAssets':call(c.functions.totalAssets()),'totalSupply':call(c.functions.totalSupply()),'shareDecimals':call(c.functions.decimals()),'assetSymbol':sy,'assetDecimals':de,'directAssetBalance':db,'directAssetHuman':int(db['value'])/10**int(de['value']) if db.get('ok') and de.get('ok') else None,'holder_census':holders(w,v)})
 cc=[]
 for a in old:
  c=w.eth.contract(a,abi=CA);x={'address':a,'code_sha256':ch(w,a),'claims':[]}
  for lab,v,tok in VS:
   t=w.eth.contract(tok,abi=EA);de=call(t.functions.decimals());sy=call(t.functions.symbol());q=call(c.functions.totalAssets(tok),{'from':v})
   x['claims'].append({'label':lab,'vault':v,'asset':tok,'symbol':sy,'decimals':de,'raw':q,'human':int(q['value'])/10**int(de['value']) if q.get('ok') and de.get('ok') else None})
  cc.append(x)
 rm=[z for z in hh if z['event']=='ConnectorRemoved'];last=rm[-1] if rm else None
 ext=sum(1 for x in vv for h in x['holder_census']['holders'] if h['address'].lower()!=x['vault'].lower());nz=sum(1 for x in cc for q in x['claims'] if q['raw'].get('ok') and int(q['raw']['value'])>0);fail=sum(not x['totalAssets'].get('ok') for x in vv)
 m={'registry_absent':st['connectorExists'].get('ok') and st['connectorExists'].get('value') is False,'unprivileged_remove_blocked':not st['unprivileged_remove_eth_call'].get('ok'),'remove_events':len(rm),'last_remove':last,'seconds_since_remove':now-last['timestamp'] if last else None,'totalAssets_failures':fail,'external_holder_count':ext,'nonzero_old_claim_count':nz}
 ev={'schema':'kiln-r15-routescan-v1','generated_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'rpc':u,'block':bn,'safety':{'read_only':True,'transactions_signed':0,'transactions_sent':0,'private_keys':0,'log_source':'Routescan'},'registry':{'address':R,'state':st,'history':hh},'old_connectors':cc,'vaults':vv,'metrics':m}
 (O/'R15_EVIDENCE.json').write_text(json.dumps(ev,indent=2,sort_keys=True))
 freeze=m['registry_absent'] and fail==len(VS);mat=nz>0 and ext>0;priv=bool(rm) and m['unprivileged_remove_blocked']
 dec='HOLD_REAL_FREEZE_BUT_PRIVILEGED_TRIGGER_OUT_OF_SCOPE' if freeze and mat and priv else ('KILL_OR_ICEBOX_NO_MATERIAL_USER_VALUE_PROVEN' if freeze and not mat else ('HOLD_FREEZE_SIGNAL_MATERIALITY_INCOMPLETE' if freeze else 'KILL_NO_CURRENT_FREEZE'))
 gate={'decision':dec,'submit_ready':False,'validated_critical':0,'validated_high':0,'facts':m,'blocking_gates':['no permissionless removal/authorization bypass','trusted privileged role dependency excluded','known-audit/duplicate clearance not passed','material user value required']}
 (O/'R15_MASTER_GATE.json').write_text(json.dumps(gate,indent=2,sort_keys=True));(O/'R15_PROOF_CARD.json').write_text(json.dumps({'candidate':'active Ethereum VENUS vaults orphaned by absent registry entry','unique_wedge':'current registry history + holder/value census','eligibility':'blocked absent permissionless trigger','submit_ready':False},indent=2,sort_keys=True))
 (O/'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(O.glob('*.json'))));print(json.dumps(gate,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
