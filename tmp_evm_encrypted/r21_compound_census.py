#!/usr/bin/env python3
"""Read-only current-state gate for Kiln Compound reward pre-claim candidate."""
import hashlib,json,time
from pathlib import Path
from web3 import Web3

O=Path('r21_compound_results');O.mkdir(exist_ok=True)
CFG={
 1:('ethereum',['https://eth.llamarpc.com','https://1rpc.io/eth','https://rpc.flashbots.net','https://ethereum-rpc.publicnode.com']),
 137:('polygon',['https://polygon.llamarpc.com','https://polygon-bor-rpc.publicnode.com','https://polygon-rpc.com']),
 8453:('base',['https://base.llamarpc.com','https://base-rpc.publicnode.com','https://mainnet.base.org']),
 42161:('arbitrum',['https://arbitrum.llamarpc.com','https://arbitrum-one-rpc.publicnode.com','https://arb1.arbitrum.io/rpc'])}
VS=[
 (137,'Bifrost Compound v3 USDT','0xE194d6De7E9499116A9E7E923696A92d6944D2B2'),
 (8453,'Bifrost Compound v3 USDC','0xd92249507B3ECe9600a3b1DaDC1e4DAc3B80128F'),
 (42161,'Bifrost Compound v3 USDT','0xAd231a5aAc991089F1A4FEbFD95eE571A9826054'),
 (42161,'Bitnovo Compound v3 USDC','0x19A0F016Ac3989e754ab8216810beD8503bDA37e'),
 (42161,'Crypto.com Compound USDC.e','0xAB3aC228Cac84a8a1C855C3E08F869B65836c962'),
 (42161,'Crypto.com Compound USDC','0x1C107c4233Ab3056254e717c7a67F9917079b615'),
 (42161,'Bifrost Compound v3 USDC','0x1eB3061F96Ff927EA7CAeF216bB5872622052C1C'),
 (1,'Bifrost Compound v3 USDT','0x96D595D35a0203d6e218852190b3E981ADEeab0B'),
 (1,'Bifrost Compound v3 USDS','0x91422083A9947De4f0423c6829888BE7B83f06F5'),
 (1,'Bifrost Compound v3 USDC','0x754A34e2f4582925F5E384c371f78db01A869572'),
 (1,'Yield Bearing Compound USDC','0xB9E62Cb9b4cE8ec13c886FaE67369Da417EE2714'),
 (1,'Trust Wallet Compound v3 USDC','0x804EE40b227B9003BB7bf2880cF502466544F208'),
 (1,'Bitnovo Compound v3 USDC','0x4bf3499072103e9A4afC2Ce4ea09afccF163CD87')]
VA=[{'type':'function','name':n,'stateMutability':'view','inputs':i,'outputs':o} for n,i,o in [
 ('asset',[],[{'type':'address'}]),('connectorRegistry',[],[{'type':'address'}]),('connectorName',[],[{'type':'bytes32'}]),
 ('additionalRewardsStrategy',[],[{'type':'uint8'}]),('rewardFee',[],[{'type':'uint256'}]),
 ('totalAssets',[],[{'type':'uint256'}]),('totalSupply',[],[{'type':'uint256'}]),
 ('collectableRewardFees',[],[{'type':'uint256'}])]]
RA=[{'type':'function','name':'get','stateMutability':'view','inputs':[{'type':'bytes32'}],'outputs':[{'type':'address'}]}]
CA=[{'type':'function','name':n,'stateMutability':'view','inputs':[],'outputs':[{'type':'address'}]} for n in ['compoundMarketRegistry','cometRewards','comp','swapTarget']]
MA=[{'type':'function','name':'getMarket','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'address'}]}]
CMA=[{'type':'function','name':n,'stateMutability':'view','inputs':i,'outputs':o} for n,i,o in [
 ('baseToken',[],[{'type':'address'}]),('balanceOf',[{'type':'address'}],[{'type':'uint256'}]),
 ('baseTrackingAccrued',[{'type':'address'}],[{'type':'uint64'}]),('isSupplyPaused',[],[{'type':'bool'}]),('isWithdrawPaused',[],[{'type':'bool'}])]]
RWA=[
 {'type':'function','name':'rewardConfig','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'address'},{'type':'uint64'},{'type':'bool'},{'type':'uint256'}]},
 {'type':'function','name':'rewardsClaimed','stateMutability':'view','inputs':[{'type':'address'},{'type':'address'}],'outputs':[{'type':'uint256'}]},
 {'type':'function','name':'getRewardOwed','stateMutability':'nonpayable','inputs':[{'type':'address'},{'type':'address'}],'outputs':[{'components':[{'type':'address','name':'token'},{'type':'uint256','name':'owed'}],'type':'tuple'}]}]
EA=[{'type':'function','name':'balanceOf','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'uint256'}]},
 {'type':'function','name':'decimals','stateMutability':'view','inputs':[],'outputs':[{'type':'uint8'}]},
 {'type':'function','name':'symbol','stateMutability':'view','inputs':[],'outputs':[{'type':'string'}]}]

def norm(x):
 if isinstance(x,(bytes,bytearray)):return '0x'+bytes(x).hex()
 if isinstance(x,(list,tuple)):return [norm(y) for y in x]
 return x

def safe(fn,tx=None):
 try:return {'ok':True,'value':norm(fn.call(tx or {}))}
 except Exception as e:return {'ok':False,'error':f'{type(e).__name__}: {e}'}

def connect(cid):
 es=[]
 for u in CFG[cid][1]:
  try:
   w=Web3(Web3.HTTPProvider(u,request_kwargs={'timeout':25}))
   if w.is_connected() and w.eth.chain_id==cid:return w,u
  except Exception as e:es.append(f'{u}: {e}')
 raise RuntimeError(' | '.join(es))

def tok(w,a):
 if not a or int(a,16)==0:return None
 c=w.eth.contract(Web3.to_checksum_address(a),abi=EA)
 return {'address':a,'decimals':safe(c.functions.decimals()),'symbol':safe(c.functions.symbol())}

def main():
 ws={};rows=[];errors=[]
 for cid,label,v0 in VS:
  try:
   if cid not in ws:ws[cid]=connect(cid)
   w,u=ws[cid];v=Web3.to_checksum_address(v0);vc=w.eth.contract(v,abi=VA)
   r={'chain_id':cid,'network':CFG[cid][0],'rpc':u,'block':w.eth.block_number,'label':label,'vault':v,
      'code_sha256':hashlib.sha256(bytes(w.eth.get_code(v))).hexdigest()}
   for n in ['asset','connectorRegistry','connectorName','additionalRewardsStrategy','rewardFee','totalAssets','totalSupply','collectableRewardFees']:
    r[n]=safe(getattr(vc.functions,n)())
   asset=r['asset'].get('value') if r['asset'].get('ok') else None
   reg=r['connectorRegistry'].get('value') if r['connectorRegistry'].get('ok') else None
   name=r['connectorName'].get('value') if r['connectorName'].get('ok') else None
   if not asset or not reg or not name:raise RuntimeError('vault binding unresolved')
   rc=w.eth.contract(Web3.to_checksum_address(reg),abi=RA);con=safe(rc.functions.get(bytes.fromhex(name[2:])))
   r['connector']=con;ca=con.get('value') if con.get('ok') else None
   if not ca:raise RuntimeError('connector unresolved')
   cc=w.eth.contract(Web3.to_checksum_address(ca),abi=CA)
   for n in ['compoundMarketRegistry','cometRewards','comp','swapTarget']:r[n]=safe(getattr(cc.functions,n)())
   mr=r['compoundMarketRegistry'].get('value') if r['compoundMarketRegistry'].get('ok') else None
   rw=r['cometRewards'].get('value') if r['cometRewards'].get('ok') else None
   if not mr or not rw:raise RuntimeError('connector immutables unresolved')
   mc=w.eth.contract(Web3.to_checksum_address(mr),abi=MA);r['comet']=safe(mc.functions.getMarket(Web3.to_checksum_address(asset)))
   comet=r['comet'].get('value') if r['comet'].get('ok') else None
   if not comet:raise RuntimeError('comet unresolved')
   cm=w.eth.contract(Web3.to_checksum_address(comet),abi=CMA)
   for n,args in [('baseToken',()),('balanceOf',(v,)),('baseTrackingAccrued',(v,)),('isSupplyPaused',()),('isWithdrawPaused',())]:r[n]=safe(getattr(cm.functions,n)(*args))
   rwc=w.eth.contract(Web3.to_checksum_address(rw),abi=RWA)
   r['rewardConfig']=safe(rwc.functions.rewardConfig(Web3.to_checksum_address(comet)))
   r['rewardsClaimed']=safe(rwc.functions.rewardsClaimed(Web3.to_checksum_address(comet),v))
   r['rewardOwed']=safe(rwc.functions.getRewardOwed(Web3.to_checksum_address(comet),v),{'from':'0x000000000000000000000000000000000000bEEF'})
   reward=None;owed=None
   if r['rewardOwed'].get('ok'):
    q=r['rewardOwed']['value'];reward=q[0];owed=int(q[1])
   elif r['rewardConfig'].get('ok'):reward=r['rewardConfig']['value'][0]
   r['rewardToken']=tok(w,reward)
   if reward:
    ec=w.eth.contract(Web3.to_checksum_address(reward),abi=EA);r['rewardBalance']=safe(ec.functions.balanceOf(v))
   strategy=int(r['additionalRewardsStrategy']['value']) if r['additionalRewardsStrategy'].get('ok') else None
   bal=int(r.get('rewardBalance',{}).get('value',0)) if r.get('rewardBalance',{}).get('ok') else 0
   r['gate']={'strategy':strategy,'strategy_name':{0:'None',1:'Claim',2:'Reinvest'}.get(strategy,'Unknown'),
              'owed_raw':owed,'preexisting_reward_raw':bal,
              'claim_with_value':strategy==1 and ((owed or 0)>0 or bal>0)}
   rows.append(r)
  except Exception as e:
   errors.append({'chain_id':cid,'label':label,'vault':v0,'error':f'{type(e).__name__}: {e}'})
 candidates=[x for x in rows if x['gate']['claim_with_value']]
 counts={}
 for x in rows:counts[x['gate']['strategy_name']]=counts.get(x['gate']['strategy_name'],0)+1
 result={'schema':'kiln-r21-compound-current-gate-v1','generated_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
  'safety':{'public_chain_mutations':0,'transactions_signed':0,'transactions_sent':0,'methods':['eth_call','eth_getCode','eth_blockNumber']},
  'rows':rows,'errors':errors,'summary':{'scope':len(VS),'inspected':len(rows),'errors':len(errors),'strategy_counts':counts,
  'claim_with_value_count':len(candidates),'candidate_vaults':[x['vault'] for x in candidates]}}
 (O/'EVIDENCE.json').write_text(json.dumps(result,indent=2,sort_keys=True))
 gate={'decision':'PROMOTE_LOCAL_FORK' if candidates else 'KILL_CURRENT_COMPOUND_PRECLAIM_GATE','submit_ready':False,
  'validated_critical':0,'validated_high':0,'validated_medium':0,'candidate_count':len(candidates),
  'blocking_gates':['fixed-block local fork','materiality','duplicate clearance','patched control'] if candidates else ['no active Claim-strategy value']}
 (O/'MASTER_GATE.json').write_text(json.dumps(gate,indent=2,sort_keys=True))
 (O/'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in sorted(O.glob('*.json'))))
 print('R21_COMPOUND_CURRENT_GATE_COMPLETE')
 return 0 if rows else 1
if __name__=='__main__':raise SystemExit(main())
