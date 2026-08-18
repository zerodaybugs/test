#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, time
from pathlib import Path
from typing import Any
from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware
except ImportError:
    ExtraDataToPOAMiddleware = None

OUT=Path('r37_results'); OUT.mkdir(exist_ok=True)
SCOPE=Path('r30_scope/SCOPE.json')
TARGET=os.environ['TARGET_NETWORK'].lower()
SHARD_INDEX=int(os.getenv('SHARD_INDEX','0'))
SHARD_COUNT=int(os.getenv('SHARD_COUNT','1'))
CALLER=Web3.to_checksum_address('0x000000000000000000000000000000000000bEEF')
ZERO='0x0000000000000000000000000000000000000000'
VAULT_SLOT=int('6bb5a2a0ae924c2ea94f037035a09f65614421e2a7d96c9bcbd59acdd32e6000',16)
NETWORKS={
 'ethereum':(1,['https://ethereum-rpc.publicnode.com','https://rpc.flashbots.net','https://eth.llamarpc.com','https://1rpc.io/eth']),
 'optimism':(10,['https://optimism-rpc.publicnode.com','https://optimism.llamarpc.com','https://mainnet.optimism.io']),
 'bnb':(56,['https://bsc-rpc.publicnode.com','https://binance.llamarpc.com','https://bsc-dataseed.binance.org']),
 'polygon':(137,['https://polygon-bor-rpc.publicnode.com','https://polygon.llamarpc.com','https://polygon-rpc.com']),
 'base':(8453,['https://base-rpc.publicnode.com','https://base.llamarpc.com','https://mainnet.base.org']),
 'arbitrum':(42161,['https://arb1.arbitrum.io/rpc','https://arbitrum-one-rpc.publicnode.com','https://arbitrum.llamarpc.com']),
}
VABI=[
 {'type':'function','name':n,'stateMutability':'view','inputs':i,'outputs':[{'type':o}]}
 for n,i,o in [
  ('asset',[],'address'),('totalAssets',[],'uint256'),('totalSupply',[],'uint256'),
  ('depositFee',[],'uint256'),('rewardFee',[],'uint256'),('pendingDepositFee',[],'uint256'),
  ('pendingRewardFee',[],'uint256'),('collectableRewardFees',[],'uint256'),
  ('connectorName',[],'bytes32'),('connectorRegistry',[],'address'),('decimals',[],'uint8')
 ]
]+[{'type':'function','name':'dispatchFees','stateMutability':'nonpayable','inputs':[],'outputs':[]}]
ERC20=[
 {'type':'function','name':'balanceOf','stateMutability':'view','inputs':[{'type':'address'}],'outputs':[{'type':'uint256'}]},
 {'type':'function','name':'allowance','stateMutability':'view','inputs':[{'type':'address'},{'type':'address'}],'outputs':[{'type':'uint256'}]},
 {'type':'function','name':'decimals','stateMutability':'view','inputs':[],'outputs':[{'type':'uint8'}]},
 {'type':'function','name':'symbol','stateMutability':'view','inputs':[],'outputs':[{'type':'string'}]},
]
FDABI=[
 {'type':'function','name':'pendingDepositFee','stateMutability':'view','inputs':[],'outputs':[{'type':'uint256'}]},
 {'type':'function','name':'pendingRewardFee','stateMutability':'view','inputs':[],'outputs':[{'type':'uint256'}]},
 {'type':'function','name':'feeRecipients','stateMutability':'view','inputs':[],'outputs':[{'type':'tuple[]','components':[{'name':'recipient','type':'address'},{'name':'depositFeeSplit','type':'uint256'},{'name':'rewardFeeSplit','type':'uint256'}]}]},
 {'type':'function','name':'dispatchFees','stateMutability':'nonpayable','inputs':[{'type':'address'},{'type':'uint8'}],'outputs':[]},
]

def norm(v:Any)->Any:
    if isinstance(v,(bytes,bytearray)): return '0x'+bytes(v).hex()
    if isinstance(v,(tuple,list)): return [norm(x) for x in v]
    return v

def safe(fn,block:int,tx:dict[str,Any]|None=None)->dict[str,Any]:
    try: return {'ok':True,'value':norm(fn.call(tx or {},block_identifier=block))}
    except Exception as e: return {'ok':False,'error':f'{type(e).__name__}: {e}'}

def val(x:dict[str,Any])->Any: return x.get('value') if x.get('ok') else None

def checksum(v:Any)->str|None:
    try: return Web3.to_checksum_address(v)
    except Exception: return None

def codehash(w3:Web3,a:str,b:int)->str|None:
    try:
        raw=bytes(w3.eth.get_code(Web3.to_checksum_address(a),block_identifier=b))
        return hashlib.sha256(raw).hexdigest() if raw else None
    except Exception: return None

def connect(network:str,probe:str)->tuple[list[tuple[Web3,str,int]],int,str]:
    cid,urls=NETWORKS[network]; out=[]; errs=[]
    for url in urls:
        try:
            w3=Web3(Web3.HTTPProvider(url,request_kwargs={'timeout':30}))
            if network in {'bnb','polygon'} and ExtraDataToPOAMiddleware:
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware,layer=0)
            if not w3.is_connected() or int(w3.eth.chain_id)!=cid: raise RuntimeError('chain mismatch')
            h=int(w3.eth.block_number)
            raw=bytes(w3.eth.call({'to':Web3.to_checksum_address(probe),'data':Web3.keccak(text='asset()')[:4]},block_identifier=h))
            if len(raw)<32: raise RuntimeError('probe getter short')
            out.append((w3,url,h))
            if len(out)==2: break
        except Exception as e: errs.append(f'{url}: {type(e).__name__}: {e}')
    if not out: raise RuntimeError('no usable RPC | '+' | '.join(errs))
    block=max(1,min(x[2] for x in out)-5)
    bh=out[0][0].eth.get_block(block)['hash'].hex()
    if len(out)>1 and out[1][0].eth.get_block(block)['hash'].hex().lower()!=bh.lower():
        raise RuntimeError('block hash quorum mismatch')
    return out,block,bh

def read_dispatcher(w3:Web3,vault:str,block:int)->str|None:
    raw=bytes(w3.eth.get_storage_at(Web3.to_checksum_address(vault),VAULT_SLOT+9,block_identifier=block))
    if len(raw)<20: return None
    a=Web3.to_checksum_address('0x'+raw[-20:].hex())
    return None if a==ZERO else a

def query(w3:Web3,row:dict[str,Any],block:int,bh:str)->dict[str,Any]:
    vault=Web3.to_checksum_address(row['address']); v=w3.eth.contract(vault,abi=VABI)
    x={'network':TARGET,'label':row['label'],'scope_connector':row['connector'],'vault':vault,'block':block,'block_hash':bh,'vault_code_sha256':codehash(w3,vault,block)}
    getters=['asset','totalAssets','totalSupply','depositFee','rewardFee','pendingDepositFee','pendingRewardFee','collectableRewardFees','connectorName','connectorRegistry','decimals']
    for n in getters: x[n]=safe(getattr(v.functions,n)(),block)
    asset=checksum(val(x['asset'])); share_decimals=val(x['decimals'])
    if not asset or share_decimals is None: raise RuntimeError('asset/share decimals unresolved')
    share_decimals=int(share_decimals); token=w3.eth.contract(asset,abi=ERC20)
    x['asset_token']={'address':asset,'symbol':safe(token.functions.symbol(),block),'decimals':safe(token.functions.decimals(),block),'balance_at_vault':safe(token.functions.balanceOf(vault),block),'code_sha256':codehash(w3,asset,block)}
    underlying_decimals=val(x['asset_token']['decimals'])
    if underlying_decimals is None: raise RuntimeError('underlying decimals unresolved')
    underlying_decimals=int(underlying_decimals)
    fd=read_dispatcher(w3,vault,block)
    if not fd: raise RuntimeError('fee dispatcher storage unresolved')
    x['fee_dispatcher']={'address':fd,'code_sha256':codehash(w3,fd,block)}
    f=w3.eth.contract(fd,abi=FDABI)
    tx={'from':vault}
    x['fee_dispatcher']['pendingDepositFee_as_vault']=safe(f.functions.pendingDepositFee(),block,tx)
    x['fee_dispatcher']['pendingRewardFee_as_vault']=safe(f.functions.pendingRewardFee(),block,tx)
    x['fee_dispatcher']['feeRecipients_as_vault']=safe(f.functions.feeRecipients(),block,tx)
    x['asset_token']['allowance_to_dispatcher']=safe(token.functions.allowance(vault,fd),block)
    # Permissionless Vault wrapper call, simulated only.
    x['vault_dispatch_eth_call']=safe(v.functions.dispatchFees(),block,{'from':CALLER,'gas':30_000_000})
    pd=int(val(x['pendingDepositFee']) or 0); pr=int(val(x['pendingRewardFee']) or 0)
    fpd=val(x['fee_dispatcher']['pendingDepositFee_as_vault']); fpr=val(x['fee_dispatcher']['pendingRewardFee_as_vault'])
    direct=int(val(x['asset_token']['balance_at_vault']) or 0); allowance=int(val(x['asset_token']['allowance_to_dispatcher']) or 0)
    total_assets=int(val(x['totalAssets']) or 0); supply=int(val(x['totalSupply']) or 0); collectable=int(val(x['collectableRewardFees']) or 0)
    recipients=val(x['fee_dispatcher']['feeRecipients_as_vault']) or []
    normalized=[]
    for r in recipients:
        if isinstance(r,(list,tuple)) and len(r)>=3: normalized.append({'recipient':checksum(r[0]),'depositFeeSplit':int(r[1]),'rewardFeeSplit':int(r[2])})
        elif isinstance(r,dict): normalized.append({'recipient':checksum(r.get('recipient')),'depositFeeSplit':int(r.get('depositFeeSplit',0)),'rewardFeeSplit':int(r.get('rewardFeeSplit',0))})
    denominator=100*(10**underlying_decimals)
    dep_sum=sum(r['depositFeeSplit'] for r in normalized); rew_sum=sum(r['rewardFeeSplit'] for r in normalized)
    pending=pd+pr; excess=direct-pending
    signals=[]
    if not x['fee_dispatcher']['code_sha256']: signals.append('fee_dispatcher_has_no_code')
    if fpd is None or int(fpd)!=pd or fpr is None or int(fpr)!=pr: signals.append('vault_dispatcher_pending_mismatch')
    if pending>direct: signals.append('pending_fee_reserve_insolvent')
    if pending>allowance: signals.append('allowance_below_pending_fee')
    if pending>0 and not normalized: signals.append('pending_fee_without_recipients')
    if normalized and (dep_sum!=denominator or rew_sum!=denominator): signals.append('recipient_split_sum_mismatch')
    if pending>0 and not x['vault_dispatch_eth_call']['ok']: signals.append('dispatch_reverts_with_pending_fee')
    if collectable>total_assets and total_assets>0: signals.append('collectable_reward_fee_exceeds_total_assets')
    if supply>0 and total_assets==0: signals.append('positive_supply_zero_total_assets')
    material_excess=max(10**underlying_decimals, total_assets//10_000 if total_assets else 10**underlying_decimals)
    if excess>material_excess: signals.append('material_direct_asset_excess_over_pending')
    if any(r['recipient'] in {vault,fd,ZERO,None} for r in normalized): signals.append('unsafe_fee_recipient_address')
    x['fee_state']={'pending_deposit':pd,'pending_reward':pr,'pending_total':pending,'direct_balance':direct,'direct_minus_pending':excess,'allowance':allowance,'collectable_reward_fees':collectable,'total_assets':total_assets,'total_supply':supply,'asset_decimals':underlying_decimals,'share_decimals':share_decimals,'recipient_count':len(normalized),'deposit_split_sum':dep_sum,'reward_split_sum':rew_sum,'expected_split_sum':denominator,'recipients':normalized}
    x['signals']=sorted(set(signals)); return x

def secondary(w3:Web3,x:dict[str,Any],block:int)->dict[str,Any]:
    vault=Web3.to_checksum_address(x['vault']); v=w3.eth.contract(vault,abi=VABI)
    fields={n:safe(getattr(v.functions,n)(),block) for n in ['asset','totalAssets','totalSupply','pendingDepositFee','pendingRewardFee','collectableRewardFees']}
    fd=read_dispatcher(w3,vault,block); fields['fee_dispatcher']=fd
    asset=checksum(val(fields['asset']))
    if asset: fields['direct_balance']=safe(w3.eth.contract(asset,abi=ERC20).functions.balanceOf(vault),block)
    checks=['asset','totalAssets','totalSupply','pendingDepositFee','pendingRewardFee','collectableRewardFees']
    fields['matches_primary']=all(norm(val(fields[n]))==norm(val(x[n])) for n in checks)
    fields['dispatcher_matches']=fd and fd.lower()==x['fee_dispatcher']['address'].lower()
    fields['direct_matches']=norm(val(fields.get('direct_balance',{})))==norm(x['fee_state']['direct_balance'])
    return fields

def main()->int:
    scope=json.loads(SCOPE.read_text())['rows']; network_rows=[r for r in scope if r['network']==TARGET]
    selected=[r for i,r in enumerate(network_rows) if i%SHARD_COUNT==SHARD_INDEX]
    if not selected: raise RuntimeError('empty shard')
    clients,block,bh=connect(TARGET,selected[0]['address']); primary=clients[0][0]
    rows=[]; errors=[]
    for row in selected:
        try:
            x=query(primary,row,block,bh)
            if x['signals'] and len(clients)>1:
                x['secondary_quorum']=secondary(clients[1][0],x,block)
                if not (x['secondary_quorum']['matches_primary'] and x['secondary_quorum']['dispatcher_matches'] and x['secondary_quorum']['direct_matches']):
                    x['signals'].append('killed_rpc_quorum_mismatch')
            elif x['signals']:
                x['signals'].append('unconfirmed_single_rpc_only')
            rows.append(x)
        except Exception as e: errors.append({'vault':row['address'],'label':row['label'],'error':f'{type(e).__name__}: {e}'})
    candidates=[r for r in rows if r['signals'] and 'killed_rpc_quorum_mismatch' not in r['signals']]
    counts={s:sum(s in r['signals'] for r in candidates) for s in sorted({s for r in candidates for s in r['signals']})}
    result={'schema':'kiln-r37-fee-invariant-census-v1','generated_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'matrix':{'network':TARGET,'shard_index':SHARD_INDEX,'shard_count':SHARD_COUNT},'source_scope_sha256':hashlib.sha256(SCOPE.read_bytes()).hexdigest(),'chain':{'chain_id':NETWORKS[TARGET][0],'rpc_urls':[x[1] for x in clients],'pinned_block':block,'pinned_block_hash':bh,'rpc_quorum_size':len(clients)},'safety':{'read_only':True,'public_chain_state_changes':0,'transactions_signed':0,'transactions_sent':0,'private_keys_loaded':0},'rows':rows,'errors':errors,'summary':{'selected_count':len(selected),'inspected_count':len(rows),'error_count':len(errors),'candidate_count':len(candidates),'signal_counts':counts}}
    (OUT/'EVIDENCE.json').write_text(json.dumps(result,indent=2,sort_keys=True))
    gate={'schema':'kiln-r37-public-gate-v1','decision':'HOLD_PRIVATE_FEE_SIGNAL_REVIEW' if candidates else ('INCONCLUSIVE_RUNTIME_ERRORS' if errors else 'KILL_NO_LIVE_FEE_INVARIANT_SIGNAL'),'submit_ready':False,'validated_critical':0,'validated_high':0,'network':TARGET,'shard_index':SHARD_INDEX,'shard_count':SHARD_COUNT,'selected_count':len(selected),'inspected_count':len(rows),'error_count':len(errors),'candidate_count':len(candidates),'public_chain_state_changes':0,'transactions_signed':0,'transactions_sent':0}
    (OUT/'PUBLIC_GATE.json').write_text(json.dumps(gate,indent=2,sort_keys=True))
    files=sorted(p for p in OUT.iterdir() if p.is_file() and p.name!='SHA256SUMS.txt')
    (OUT/'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
    print(json.dumps(gate,sort_keys=True)); return 0 if rows else 2
if __name__=='__main__': raise SystemExit(main())
