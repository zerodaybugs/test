#!/usr/bin/env python3
"""Pinned read-only audit of queue/accountant generation drift.

No wallet, signing, transaction construction, eth_estimateGas, or broadcast code.
"""
from __future__ import annotations
import json, random, sys, time, urllib.parse, urllib.request
from pathlib import Path

EOA='0x000000000000000000000000000000000000dead'
ALLOWED={'eth_chainId','eth_blockNumber','eth_getBlockByNumber','eth_getCode','eth_call'}
FORBIDDEN={'eth_sendTransaction','eth_sendRawTransaction','personal_sendTransaction','eth_signTransaction'}
S={
 'authority':'bf7e214f','accountant':'4fb3ccc5','vault':'fbfa77cf','boringVault':'f3b97784','oneShare':'b7d122b5',
 'getRate':'679aefce','getRateSafe':'282a8700','base':'5001f3b5','decimals':'313ce567','isPaused':'b187bd26',
 'canCall':'b7009613','getUserRoles':'06a36aee','isCapabilityPublic':'2f47571f','excess':'6b9f9fef','getRequestIds':'ac33a273',
 'request':'6bb3b476','requestPermit':'581b4920','queueSolve':'412638dc',
 'selfRedeem':'72faf4a4','selfRedeemMint':'8f386608','adminRedeem':'5ff8a71f','adminRedeemMint':'bc9961f7',
 'bulkWithdraw':'3e64ce99','bulkDeposit':'9d574420'
}
TARGETS=[
 {'id':'mainnet-lbtcv-katana','chainId':1,'urls':['https://ethereum-rpc.publicnode.com','https://eth.llamarpc.com','https://rpc.flashbots.net'],
  'deployment':'deployments/addresses/Mainnet/LBTCvKatanaDeployment.json','vault':'0x75231079973C23e9eB6180fa3D2fc21334565aB5','oldAccountant':'0x90e864A256E58DBCe034D9C43C3d8F18A00f55B6','queue':'0xa0fE75799583F4591552cd26c605e0FD3a763682','solver':'0xC11A4ab52b242B52c251eB34927aF40DB9b12AE6','currentTeller':'0x634d53643b497bb614b4b6c8f3a58a5d564c2825'},
 {'id':'berachain-prime-btc','chainId':80094,'urls':['https://rpc.berachain.com','https://berachain-rpc.publicnode.com','https://berachain.drpc.org'],
  'deployment':'deployments/addresses/BeraChain/PrimeLiquidBeraBTC.json','vault':'0x46fcd35431f5B371224ACC2e2E91732867B1A77e','oldAccountant':'0x4faE50B524e0D05BD73fDF28b273DB7D4A57CCe9','queue':'0x185373a9877BF1b555bcb8e82e46d63EB84c4C60','solver':'0xb5964B325A916cAC21FeE31C4bc3F483b0d8E911','currentTeller':'0xcd20c63ddafac686d311b40f24dcad316dde8d9c'},
 {'id':'berachain-prime-eth','chainId':80094,'urls':['https://rpc.berachain.com','https://berachain-rpc.publicnode.com','https://berachain.drpc.org'],
  'deployment':'deployments/addresses/BeraChain/PrimeLiquidBeraETH.json','vault':'0xB83742330443f7413DBD2aBdfc046dB0474a944e','oldAccountant':'0x0B24A469d7c155a588C8a4ee24020F9f27090B0d','queue':'0xb188a72c8058e1393eBDAEDaC903C516A04f0c96','solver':'0x8c3658C39F79c6FB8ac51dDbeA21A31da4332f6B','currentTeller':'0xb745b293468df7b06330472fbcee5412ff44750b'},
 {'id':'tac-turtle-btc','chainId':239,'urls':['https://rpc.tac.build','https://tac-mainnet.rpc.thirdweb.com'],
  'deployment':'deployments/addresses/TAC/TurtleTACBTC.json','vault':'0x6Bf340dB729d82af1F6443A0Ea0d79647b1c3DDf','oldAccountant':'0xe4858a89d5602Ad30de2018C408d33d101F53d53','queue':'0x9A214cDD8967d7616cfaf7b92A10B2116a0c39A7','solver':'0x3F2aa9BF29b031B2C5a18EBa95f202F288a82c39','currentTeller':'0x834e313cb01e8badeaad269fceecb5a1e98041e3'}
]

def norm(a):
 a=a.lower().removeprefix('0x')
 if len(a)!=40 or any(c not in '0123456789abcdef' for c in a): raise ValueError(a)
 return '0x'+a
def a32(a): return norm(a)[2:].rjust(64,'0')
def b4(x): return x.removeprefix('0x').ljust(64,'0')
def call0(s): return '0x'+s
def call_can(u,t,s): return '0x'+S['canCall']+a32(u)+a32(t)+b4(s)
def call_public(t,s): return '0x'+S['isCapabilityPublic']+a32(t)+b4(s)
def uint(x): return int(x,16)
def boolean(x): return bool(uint(x))
def address(x): return '0x'+x[-40:].lower()
def bytes32(x): return '0x'+x[-64:].lower()
def short(e): return str(e).replace('\n',' ')[:800]
def array_b32(x):
 h=x[2:]
 if len(h)<128: raise ValueError('short dynamic array')
 off=int(h[:64],16)*2; n=int(h[off:off+64],16); start=off+64
 if len(h)<start+64*n: raise ValueError('truncated dynamic array')
 return ['0x'+h[start+64*i:start+64*(i+1)] for i in range(n)]

class RPC:
 def __init__(self,cid,urls): self.cid=cid; self.urls=urls; self.good=None; self.ok=set(); self.i=random.randint(1,99999); self.block=None; self.hash=None
 def raw(self,u,m,p):
  if m not in ALLOWED or m in FORBIDDEN: raise RuntimeError('blocked method '+m)
  self.i+=1; body=json.dumps({'jsonrpc':'2.0','id':self.i,'method':m,'params':p}).encode(); q=urllib.request.Request(u,data=body,headers={'Content-Type':'application/json','User-Agent':'QueueGenerationAudit/1.0'},method='POST')
  with urllib.request.urlopen(q,timeout=25) as r: z=json.loads(r.read().decode())
  if 'error' in z: raise RuntimeError(z['error'])
  return z.get('result')
 def req(self,m,p):
  errs=[]; order=([self.good] if self.good else [])+[u for u in self.urls if u!=self.good]
  for _ in range(2):
   for u in order:
    try:
     if u not in self.ok:
      if int(self.raw(u,'eth_chainId',[]),16)!=self.cid: raise RuntimeError('wrong chain')
      self.ok.add(u)
     v=self.raw(u,m,p); self.good=u; return v
    except Exception as e: errs.append(urllib.parse.urlparse(u).netloc+':'+short(e))
   time.sleep(1)
  raise RuntimeError(' | '.join(errs[-6:]))
 def pin(self): self.block=self.req('eth_blockNumber',[]); self.hash=self.req('eth_getBlockByNumber',[self.block,False])['hash']
 def code(self,a): return self.req('eth_getCode',[norm(a),self.block])
 def call(self,to,data,who=EOA): return self.req('eth_call',[{'from':norm(who),'to':norm(to),'data':data},self.block])

def safe(fn,decode=lambda x:x):
 try:
  x=fn()
  if x in (None,'0x','0x0'): return {'ok':False,'error':'empty return','raw':x}
  return {'ok':True,'value':decode(x),'raw':x}
 except Exception as e: return {'ok':False,'error':short(e)}
def val(x,d=None): return x.get('value',d) if isinstance(x,dict) and x.get('ok') else d
def code(r,a):
 x=safe(lambda:r.code(a)); raw=x.get('raw','') if x.get('ok') else ''
 return {**x,'hasCode':bool(x.get('ok') and raw not in ('0x','0x0')),'bytes':max(0,(len(raw)-2)//2) if raw else 0}
def view(r,a,s,d=uint): return safe(lambda:r.call(a,call0(s)),d)
def can(r,auth,u,t,s): return safe(lambda:r.call(auth,call_can(u,t,s)),boolean)
def public(r,auth,t,s): return safe(lambda:r.call(auth,call_public(t,s)),boolean)

def contract(r,a):
 return {'address':norm(a),'code':code(r,a),'authority':view(r,a,S['authority'],address),'accountant':view(r,a,S['accountant'],address),'vault':view(r,a,S['vault'],address),'boringVault':view(r,a,S['boringVault'],address),'isPaused':view(r,a,S['isPaused'],boolean)}
def accountant(r,a):
 return {'address':norm(a),'code':code(r,a),'getRate':view(r,a,S['getRate']),'getRateSafe':view(r,a,S['getRateSafe']),'base':view(r,a,S['base'],address),'decimals':view(r,a,S['decimals'])}

def audit(t):
 r=RPC(t['chainId'],t['urls']); out={'id':t['id'],'deployment':t['deployment'],'chainId':t['chainId']}
 try: r.pin()
 except Exception as e: return {**out,'status':'RPC_PIN_FAILED','error':short(e)}
 out['block']={'number':int(r.block,16),'hex':r.block,'hash':r.hash,'endpointHost':urllib.parse.urlparse(r.good).netloc}
 q=contract(r,t['queue']); s=contract(r,t['solver']); teller=contract(r,t['currentTeller']); vaultAuth=val(view(r,t['vault'],S['authority'],address)); qAuth=val(q['authority']); sAuth=val(s['authority']); tAuth=val(teller['authority'])
 currentAcct=val(teller['accountant']); queueAcct=val(q['accountant']); out.update({'vault':norm(t['vault']),'oldAccountantConfigured':norm(t['oldAccountant']),'queue':q,'solver':s,'currentTeller':teller,'vaultAuthority':vaultAuth})
 out['queueAccountant']=accountant(r,queueAcct) if queueAcct else {'address':None}; out['currentAccountant']=accountant(r,currentAcct) if currentAcct else {'address':None}
 out['queueState']={'oneShare':view(r,t['queue'],S['oneShare']),'activeRequests':view(r,t['queue'],S['getRequestIds'],array_b32),'excessToSolverNonSelfSolve':view(r,t['solver'],S['excess'],boolean)}
 caps={'randomQueue':{},'randomSolver':{},'solverToQueue':{},'solverToTeller':{},'publicFlags':{}}
 if qAuth:
  for n in ['request','requestPermit','queueSolve']:
   caps['randomQueue'][n]=can(r,qAuth,EOA,t['queue'],S[n]); caps['publicFlags']['queue.'+n]=public(r,qAuth,t['queue'],S[n])
  caps['solverToQueue']['queueSolve']=can(r,qAuth,t['solver'],t['queue'],S['queueSolve'])
 if sAuth:
  for n in ['selfRedeem','selfRedeemMint','adminRedeem','adminRedeemMint']:
   caps['randomSolver'][n]=can(r,sAuth,EOA,t['solver'],S[n]); caps['publicFlags']['solver.'+n]=public(r,sAuth,t['solver'],S[n])
 if tAuth:
  for n in ['bulkWithdraw','bulkDeposit']:
   caps['solverToTeller'][n]=can(r,tAuth,t['solver'],t['currentTeller'],S[n])
 out['capabilities']=caps
 old=norm(t['oldAccountant']); qa=norm(queueAcct) if queueAcct else None; ca=norm(currentAcct) if currentAcct else None
 qr=val(out['queueAccountant'].get('getRate')); cr=val(out['currentAccountant'].get('getRate')); qb=val(out['queueAccountant'].get('base')); cb=val(out['currentAccountant'].get('base')); qd=val(out['queueAccountant'].get('decimals')); cd=val(out['currentAccountant'].get('decimals'))
 comparable=bool(qr is not None and cr is not None and qb and cb and norm(qb)==norm(cb) and qd==cd); spread=cr-qr if comparable else None; spreadBps=(spread*10000//qr) if comparable and qr else None
 requestPublic=any(val(caps['randomQueue'].get(n),False) for n in ['request','requestPermit']); directSolvePublic=val(caps['randomQueue'].get('queueSolve'),False); selfPublic=any(val(caps['randomSolver'].get(n),False) for n in ['selfRedeem','selfRedeemMint']); adminPublic=any(val(caps['randomSolver'].get(n),False) for n in ['adminRedeem','adminRedeemMint']); solverQueue=val(caps['solverToQueue'].get('queueSolve'),False); solverWithdraw=val(caps['solverToTeller'].get('bulkWithdraw'),False); excess=val(out['queueState']['excessToSolverNonSelfSolve'],False); active=val(out['queueState']['activeRequests'],[]) or []
 queueUsesOld=bool(qa and qa==old); generationSplit=bool(qa and ca and qa!=ca); directCapture=bool(comparable and spread>0 and requestPublic and directSolvePublic); adminCapture=bool(comparable and spread>0 and requestPublic and adminPublic and solverQueue and solverWithdraw and excess); selfNoCapture=bool(comparable and spread>0 and requestPublic and selfPublic and solverQueue and solverWithdraw)
 if directCapture or adminCapture: verdict='PERMISSIONLESS_PERSISTENT_SPREAD_CAPTURE_CANDIDATE'
 elif generationSplit and comparable and spread>0 and selfNoCapture: verdict='STALE_QUEUE_RATE_SPLIT_SELF_SOLVE_EXCESS_RETURNS_TO_VAULT'
 elif generationSplit and comparable and spread<0: verdict='STALE_QUEUE_RATE_SPLIT_DEFICIT_REVERT_DIRECTION'
 elif generationSplit: verdict='QUEUE_ACCOUNTANT_GENERATION_SPLIT_NO_PERMISSIONLESS_CAPTURE'
 else: verdict='QUEUE_ACCOUNTANT_UPDATED_OR_NO_GENERATION_SPLIT'
 out['analysis']={'verdict':verdict,'queueUsesRecordedOldAccountant':queueUsesOld,'accountantGenerationSplit':generationSplit,'comparableRateUnits':comparable,'queueRate':qr,'currentRate':cr,'currentMinusQueue':spread,'spreadBps':spreadBps,'requestPublic':requestPublic,'directQueueSolvePublic':directSolvePublic,'selfSolvePublic':selfPublic,'adminBoringSolvePublic':adminPublic,'solverCanCallQueue':solverQueue,'solverCanBulkWithdrawCurrentTeller':solverWithdraw,'excessToSolverNonSelfSolve':excess,'activeRequestCount':len(active),'permissionlessDirectCapture':directCapture,'permissionlessBoringSolverCapture':adminCapture,'selfSolveSpreadNoCapture':selfNoCapture}; out['status']='COMPLETE'; return out

def main():
 p=Path('probe-output'); p.mkdir(exist_ok=True); rows=[]
 for t in TARGETS: print('[read-only]',t['id'],flush=True); rows.append(audit(t))
 z={'schemaVersion':1,'safety':{'readOnly':True,'allowedMethods':sorted(ALLOWED),'forbiddenMethods':sorted(FORBIDDEN),'transactionsSigned':0,'transactionsBroadcast':0},'selectors':S,'rows':rows}; (p/'queue-drift-results.json').write_text(json.dumps(z,indent=2,sort_keys=True)+'\n')
 complete=[x for x in rows if x.get('status')=='COMPLETE']; cand=[x for x in complete if x['analysis']['permissionlessDirectCapture'] or x['analysis']['permissionlessBoringSolverCapture']]
 L=['# Queue / Accountant generation drift audit','','```text',f'Targets:                   {len(rows)}',f'Complete:                  {len(complete)}',f'Permissionless candidates:{len(cand):3d}','Broadcast methods:         0','```','','| Target | Queue uses old accountant | Split | Spread bps | Request public | Queue solve public | Admin solve public | Active requests | Verdict |','|---|---:|---:|---:|---:|---:|---:|---:|---|']
 for x in rows:
  if x.get('status')!='COMPLETE': L.append(f"| {x['id']} | — | — | — | — | — | — | — | {x.get('status')} |")
  else:
   a=x['analysis']; L.append(f"| {x['id']} | {a['queueUsesRecordedOldAccountant']} | {a['accountantGenerationSplit']} | {a['spreadBps']} | {a['requestPublic']} | {a['directQueueSolvePublic']} | {a['adminBoringSolvePublic']} | {a['activeRequestCount']} | {a['verdict']} |")
 L += ['','## Hard gate','',('At least one permissionless spread-capture path survived. A pinned fork balance-delta PoC is mandatory next.' if cand else 'No permissionless attacker can realize the persistent queue/accountant spread in this state. Do not submit this branch.')]
 (p/'QUEUE_DRIFT_SUMMARY.md').write_text('\n'.join(L)+'\n'); print(f'[read-only] complete={len(complete)}/{len(rows)} candidates={len(cand)}',flush=True); return 0 if complete else 2
if __name__=='__main__': sys.exit(main())
