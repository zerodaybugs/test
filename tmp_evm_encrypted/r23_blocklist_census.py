#!/usr/bin/env python3
"""Active Kiln BlockList initialization/authorization census; read-only only."""
from __future__ import annotations
import hashlib,json,re,time
from collections import defaultdict
from pathlib import Path
from typing import Any
import requests
from eth_abi import decode,encode
from web3 import Web3

OUT=Path('r23_blocklist_results');OUT.mkdir(exist_ok=True)
SCOPE_URL='https://raw.githubusercontent.com/zerodaybugs/test/agent/kiln-omnivault-r11-readonly/r13_persisted_results/31910466827/r13_generation/SCOPE.json'
CFG={
1:('ethereum',['https://rpc.flashbots.net','https://eth.llamarpc.com','https://eth.drpc.org']),
10:('optimism',['https://optimism-rpc.publicnode.com','https://optimism.llamarpc.com']),
56:('bnb',['https://bsc-rpc.publicnode.com','https://binance.llamarpc.com']),
137:('polygon',['https://polygon-bor-rpc.publicnode.com','https://polygon.llamarpc.com']),
8453:('base',['https://base-rpc.publicnode.com','https://base.llamarpc.com']),
42161:('arbitrum',['https://arb1.arbitrum.io/rpc','https://arbitrum-one-rpc.publicnode.com'])}
ZERO='0x'+'00'*20
CALLER=Web3.to_checksum_address('0x000000000000000000000000000000000000bEEF')
SENTINEL=Web3.to_checksum_address('0x0000000000000000000000000000000000000001')
OPERATOR=b'OPERATOR'.ljust(32,b'\0')
DEFAULT_ADMIN=b'\0'*32
BEACON_SLOT='0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
EVENTS={n:'0x'+Web3.keccak(text=s).hex().removeprefix('0x') for n,s in {
'RoleGranted':'RoleGranted(bytes32,address,address)','RoleRevoked':'RoleRevoked(bytes32,address,address)'}.items()}
ERRORS={'0x'+Web3.keccak(text=s)[:4].hex().removeprefix('0x'):s for s in [
'InvalidInitialization()','AccessControlUnauthorizedAccount(address,bytes32)','AddressNotContract(address)','AddressNotBlocked(address)']}

def cs(x:str|None)->str|None:return Web3.to_checksum_address(x) if x else None
def sel(s:str)->bytes:return Web3.keccak(text=s)[:4]
def data(sig:str,types:list[str]|None=None,values:list[Any]|None=None)->str:
 r=sel(sig)
 if types:r+=encode(types,values or [])
 return '0x'+r.hex()
def norm(x:Any)->Any:
 if isinstance(x,bytes):return '0x'+x.hex()
 if isinstance(x,tuple):return [norm(v) for v in x]
 if isinstance(x,list):return [norm(v) for v in x]
 return x
def rev(e:Any)->str|None:
 h=re.findall(r'0x[0-9a-fA-F]{8,}',json.dumps(e,default=str));return max(h,key=len) if h else None
class RPC:
 def __init__(self,c:int,urls:list[str]):
  self.c=c;self.urls=urls;self.s=requests.Session();self.s.headers.update({'User-Agent':'Kiln-R23-ReadOnly/1.0'});self.i=0;self.idx=0;self.url=self.pick()
 def post(self,u,m,p):
  self.i+=1;r=self.s.post(u,json={'jsonrpc':'2.0','id':self.i,'method':m,'params':p},timeout=35);r.raise_for_status();return r.json()
 def pick(self):
  es=[]
  for i,u in enumerate(self.urls):
   try:
    if int(self.post(u,'eth_chainId',[])['result'],16)!=self.c:raise RuntimeError('wrong chain')
    self.post(u,'eth_blockNumber',[])['result'];self.idx=i;return u
   except Exception as e:es.append(f'{u}:{type(e).__name__}:{e}')
  raise RuntimeError('|'.join(es))
 def q(self,m,p,revert_ok=False):
  es=[]
  for o in range(len(self.urls)):
   i=(self.idx+o)%len(self.urls);u=self.urls[i]
   try:b=self.post(u,m,p)
   except Exception as e:es.append(f'{u}:{type(e).__name__}:{e}');continue
   if 'result' in b:self.idx=i;self.url=u;return {'ok':True,'raw':b['result'],'provider':u}
   er=b.get('error',{});d=rev(er);msg=str(er.get('message','')).lower()
   if revert_ok and ('revert' in msg or d):return {'ok':False,'kind':'contract_revert','error':er,'revert_data':d,'decoded_error':ERRORS.get(d[:10].lower()) if d else None,'provider':u}
   es.append(f'{u}:{er}')
  return {'ok':False,'kind':'provider_failure','errors':es}
 def call(self,to,calldata,outs=None,sender=None):
  tx={'to':cs(to),'data':calldata}
  if sender:tx['from']=cs(sender)
  r=self.q('eth_call',[tx,'latest'],True)
  if not r['ok']:return r
  if not outs:return {'ok':True,'value':r['raw'],'provider':r['provider']}
  try:
   v=decode(outs,bytes.fromhex(r['raw'].removeprefix('0x')));return {'ok':True,'value':norm(v[0] if len(v)==1 else v),'provider':r['provider']}
  except Exception as e:return {'ok':False,'kind':'decode','error':str(e),'raw':r['raw']}
 def code(self,a):
  r=self.q('eth_getCode',[cs(a),'latest']);return r['raw'] if r['ok'] else '0x'
 def storage(self,a,slot):
  r=self.q('eth_getStorageAt',[cs(a),slot,'latest']);return r['raw'] if r['ok'] else None

def probe(r,to,sig,types=None,vals=None,outs=None,sender=None):return r.call(to,data(sig,types,vals),outs,sender)
def safe(r,a):
 th=probe(r,a,'getThreshold()',outs=['uint256'])
 if not th.get('ok'):return {'is_safe':False,'threshold':th}
 return {'is_safe':True,'threshold':th,'owners':probe(r,a,'getOwners()',outs=['address[]']),
 'modules':probe(r,a,'getModulesPaginated(address,uint256)',['address','uint256'],[SENTINEL,50],['address[]','address']),
 'guard':probe(r,a,'getGuard()',outs=['address'])}
def api_logs(chain,address,topic0,topic1):
 url=f'https://api.routescan.io/v2/network/mainnet/evm/{chain}/etherscan/api';out=[]
 for page in range(1,30):
  p={'module':'logs','action':'getLogs','address':address,'fromBlock':0,'toBlock':'latest','page':page,'offset':1000,'topic0':topic0,'topic1':topic1}
  q=requests.get(url,params=p,timeout=45,headers={'User-Agent':'Kiln-R23-ReadOnly/1.0'}).json();x=q.get('result')
  if isinstance(x,str):break
  if not isinstance(x,list):break
  out+=x
  if len(x)<1000:break
 return out
def topic_addr(x):return cs('0x'+x.removeprefix('0x')[-40:])
def role_candidates(chain,blocklist,role):
 out=[];t1='0x'+role.hex()
 for ev in ['RoleGranted','RoleRevoked']:
  for x in api_logs(chain,blocklist,EVENTS[ev],t1):
   ts=x.get('topics',[])
   if len(ts)>=3:out.append({'event':ev,'block':int(x['blockNumber'],16),'tx':x['transactionHash'],'account':topic_addr(ts[2])})
 return sorted(out,key=lambda z:z['block'])

def main():
 scope=requests.get(SCOPE_URL,timeout=45,headers={'User-Agent':'Kiln-R23-ReadOnly/1.0'}).json();by=defaultdict(list)
 for row in scope:by[int(row['chain_id'])].append(row)
 ev={'schema':'kiln-r23-blocklist-authz-v1','generated_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
 'safety':{'read_only':True,'transactions_signed':0,'transactions_sent':0,'private_keys':0},'chains':{},'vault_bindings':[],'blocklists':[],'errors':[]}
 groups={}
 for chain,rows in sorted(by.items()):
  try:r=RPC(chain,CFG[chain][1])
  except Exception as e:ev['errors'].append(f'chain {chain}:{e}');continue
  ev['chains'][str(chain)]={'network':CFG[chain][0],'rpc':r.url,'scope_vaults':len(rows)}
  for row in rows:
   v=cs(row['vault']);b=probe(r,v,'blockList()',outs=['address']);item={'chain_id':chain,'network':CFG[chain][0],'vault':v,'label':row['label'],'blockList':b};ev['vault_bindings'].append(item)
   if b.get('ok') and cs(b['value']).lower()!=ZERO:
    groups.setdefault((chain,cs(b['value']).lower()),{'chain':chain,'network':CFG[chain][0],'address':cs(b['value']),'vaults':[],'rpc':r})['vaults'].append(v)
 for _,g in sorted(groups.items()):
  r=g.pop('rpc');a=g['address'];code=r.code(a);beacon_raw=r.storage(a,BEACON_SLOT);beacon=cs(beacon_raw[-40:]) if beacon_raw and int(beacon_raw,16) else None
  state={'name':probe(r,a,'name()',outs=['string']),'underlyingSanctionsList':probe(r,a,'underlyingSanctionsList()',outs=['address']),
   'operatorRole':probe(r,a,'OPERATOR_ROLE()',outs=['bytes32']),'defaultAdmin':probe(r,a,'defaultAdmin()',outs=['address']),
   'pendingDefaultAdmin':probe(r,a,'pendingDefaultAdmin()',outs=['address','uint48']),'isBlockedCanary':probe(r,a,'isBlocked(address)',['address'],[CALLER],['bool'])}
  init=probe(r,a,'initialize((string,address,address,address,uint48))',['(string,address,address,address,uint48)'],[('R23',a,CALLER,CALLER,0)],sender=CALLER)
  auth={'initialize':init,'grantRole':probe(r,a,'grantRole(bytes32,address)',['bytes32','address'],[OPERATOR,CALLER],sender=CALLER),
   'addToBlockList':probe(r,a,'addToBlockList(address[])',['address[]'],[[CALLER]],sender=CALLER),
   'setUnderlyingSanctionsList':probe(r,a,'setUnderlyingSanctionsList(address)',['address'],[a],sender=CALLER)}
  successes=[k for k,v in auth.items() if v.get('ok')]
  hist=role_candidates(g['chain'],a,OPERATOR);holders=[]
  for account in sorted({x['account'] for x in hist}):
   has=probe(r,a,'hasRole(bytes32,address)',['bytes32','address'],[OPERATOR,account],['bool'])
   if has.get('ok') and has['value']:
    c=r.code(account);z={'account':account,'is_contract':c!='0x','code_sha256':hashlib.sha256(bytes.fromhex(c[2:])).hexdigest() if c!='0x' else None}
    if c!='0x':z['safe']=safe(r,account)
    holders.append(z)
  underlying=cs(state['underlyingSanctionsList']['value']) if state['underlyingSanctionsList'].get('ok') else None
  g.update({'code_sha256':hashlib.sha256(bytes.fromhex(code[2:])).hexdigest() if code!='0x' else None,'beacon':beacon,'beacon_code':bool(beacon and r.code(beacon)!='0x'),
   'state':state,'underlying_code':bool(underlying and r.code(underlying)!='0x'),'authz_gate':auth,'unexpected_successes':successes,
   'operator_role_history':hist,'current_operator_holders':holders})
  ev['blocklists'].append(g)
 bypass=[b for b in ev['blocklists'] if b['unexpected_successes']]
 modules=[]
 for b in ev['blocklists']:
  for h in b['current_operator_holders']:
   s=h.get('safe',{});m=s.get('modules',{})
   if s.get('is_safe') and m.get('ok'):
    enabled=[cs(x) for x in m['value'][0] if cs(x).lower() not in {ZERO,SENTINEL.lower()}]
    if enabled:modules.append({'chain_id':b['chain'],'blocklist':b['address'],'safe':h['account'],'modules':enabled})
 master={'decision':'ESCALATE_BLOCKLIST_TAKEOVER' if bypass else ('HOLD_OPERATOR_SAFE_MODULE_REVIEW' if modules else 'KILL_NO_BLOCKLIST_INIT_OR_ROLE_BYPASS'),
 'submit_ready':False,'validated_critical':0,'validated_high':0,'metrics':{'scope_vaults':len(scope),'unique_blocklists':len(ev['blocklists']),'errors':len(ev['errors']),'unexpected_authz_successes':len(bypass),'operator_safes_with_modules':len(modules)},
 'blocking_gates':['permissionless initialization or role bypass','material active-holder impact','fixed-block exploit/control','duplicate clearance']}
 for n,x in [('R23_EVIDENCE.json',ev),('R23_MASTER_GATE.json',master),('R23_CANDIDATES.json',{'authz_bypasses':bypass,'operator_safes_with_modules':modules})]:OUT.joinpath(n).write_text(json.dumps(norm(x),indent=2,sort_keys=True))
 OUT.joinpath('SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(OUT.glob('*.json'))))
 print(json.dumps(master,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
