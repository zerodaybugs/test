#!/usr/bin/env python3
"""Controlled Synthetix cancel-all / dead-man-switch / leverage differential.

Safety:
- deterministic EOA confirmed to have zero owned/managed/delegated accounts;
- deliberately nonexistent valid-range account ID;
- fresh nonces; no request can pass authorization or mutate state;
- no real account, order, position, balance, or credential.

The goal is to detect verifier/handler splits where a narrowly signed cancellation or leverage intent
is executed with broader or different semantics because omitted, aliased, wildcard, normalized, or
conflicting wire fields are decoded differently from the EIP-712 verifier.
"""
from __future__ import annotations

import hashlib, json, pathlib, re, time, urllib.error, urllib.request
from dataclasses import dataclass
from typing import Any, Callable
from eth_account import Account
from eth_account.messages import encode_typed_data

OUT=pathlib.Path('synthetix_cancelall_schedule_boundary'); OUT.mkdir(parents=True,exist_ok=True)
TRADE='https://papi.synthetix.io/v1/trade'; INFO='https://papi.synthetix.io/v1/info'
UA='Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)'
ACC=Account.from_key('0x'+'6d'*32); A=8_300_000_000_083_001; B=A+1
ZERO='0x0000000000000000000000000000000000000000'; MAX=2*1024*1024
DOMAIN={'name':'Synthetix','version':'1','chainId':1,'verifyingContract':ZERO}
DF=[{'name':'name','type':'string'},{'name':'version','type':'string'},{'name':'chainId','type':'uint256'},{'name':'verifyingContract','type':'address'}]
CAF=[{'name':'subAccountId','type':'uint256'},{'name':'symbols','type':'string[]'},{'name':'nonce','type':'uint256'},{'name':'expiresAfter','type':'uint256'}]
SCF=[{'name':'subAccountId','type':'uint256'},{'name':'timeoutSeconds','type':'uint256'},{'name':'nonce','type':'uint256'},{'name':'expiresAfter','type':'uint256'}]
ULF=[{'name':'subAccountId','type':'uint256'},{'name':'symbol','type':'string'},{'name':'leverage','type':'string'},{'name':'nonce','type':'uint256'},{'name':'expiresAfter','type':'uint256'}]
AR=re.compile(r'0x[a-fA-F0-9]{40}'); HR=re.compile(r'0x[a-fA-F0-9]{64,}')

def sha(x): return hashlib.sha256(x.encode() if isinstance(x,str) else x).hexdigest()
def red(x):
 if x is None:return None
 s=AR.sub('<address>',str(x)); s=HR.sub('<hex>',s); s=re.sub(r'\b\d{12,}\b','<large-number>',s); return s[:1000]
def ab(a):return a[:5]+'...'+a[-3:]
def post(url,p):
 b=json.dumps(p,separators=(',',':')).encode(); q=urllib.request.Request(url,data=b,headers={'User-Agent':UA,'Content-Type':'application/json','Accept':'application/json'},method='POST'); st=time.monotonic()
 try:
  with urllib.request.urlopen(q,timeout=45) as r: raw=r.read(MAX+1); status=r.status
 except urllib.error.HTTPError as e: raw=e.read(MAX+1); status=e.code
 if len(raw)>MAX: raise RuntimeError('response cap')
 return status,raw,round((time.monotonic()-st)*1000,2)
def sign(primary,fields,msg):
 e=encode_typed_data(full_message={'types':{'EIP712Domain':DF,primary:fields},'primaryType':primary,'domain':DOMAIN,'message':msg}); s=ACC.sign_message(e)
 return {'v':s.v,'r':'0x'+format(s.r,'064x'),'s':'0x'+format(s.s,'064x')}
def env(sig,n,ex,params):return {'signature':sig,'nonce':n,'expiresAfter':ex,'params':params}
def ca(n,symbols):
 ex=n+60000; return sign('CancelAllOrders',CAF,{'subAccountId':A,'symbols':symbols,'nonce':n,'expiresAfter':ex}),ex
def sc(n,timeout):
 ex=n+60000; return sign('ScheduleCancel',SCF,{'subAccountId':A,'timeoutSeconds':timeout,'nonce':n,'expiresAfter':ex}),ex
def ul(n,symbol,lev):
 ex=n+60000; return sign('UpdateLeverage',ULF,{'subAccountId':A,'symbol':symbol,'leverage':lev,'nonce':n,'expiresAfter':ex}),ex
@dataclass(frozen=True)
class Case: name:str; family:str; build:Callable[[int],dict]
def C(name,family,fn):return Case(name,family,fn)
def cab(signed,wire=None,action='cancelAllOrders',account=A):
 def f(n):
  sig,ex=ca(n,signed); p={'action':action,'subaccountId':str(account),'walletAddress':ACC.address};
  if wire is not None:p['symbols']=wire
  return env(sig,n,ex,p)
 return f
def scb(signed,wire_marker='same',action='scheduleCancel',account=A,key='timeoutSeconds'):
 def f(n):
  sig,ex=sc(n,signed); p={'action':action,'subaccountId':str(account),'walletAddress':ACC.address}
  if wire_marker!='omit': p[key]=signed if wire_marker=='same' else wire_marker
  return env(sig,n,ex,p)
 return f
def ulb(sym,lev,wire_sym='same',wire_lev='same',account=A):
 def f(n):
  sig,ex=ul(n,sym,lev); p={'action':'updateLeverage','subaccountId':str(account),'walletAddress':ACC.address,'symbol':sym if wire_sym=='same' else wire_sym,'leverage':lev if wire_lev=='same' else wire_lev}; return env(sig,n,ex,p)
 return f
CASES=[
 C('cancel_specific_canonical','cancel',cab(['BTC-USDT'],['BTC-USDT'])),
 C('cancel_specific_omitted','cancel',cab(['BTC-USDT'],None)),
 C('cancel_specific_empty','cancel',cab(['BTC-USDT'],[])),
 C('cancel_specific_wildcard','cancel',cab(['BTC-USDT'],['*'])),
 C('cancel_specific_other','cancel',cab(['BTC-USDT'],['ETH-USDT'])),
 C('cancel_specific_lowercase','cancel',cab(['BTC-USDT'],['btc-usdt'])),
 C('cancel_specific_duplicate','cancel',cab(['BTC-USDT'],['BTC-USDT','BTC-USDT'])),
 C('cancel_empty_omitted','cancel',cab([],None)),
 C('cancel_empty_explicit','cancel',cab([],[])),
 C('cancel_empty_wildcard','cancel',cab([],['*'])),
 C('cancel_empty_specific','cancel',cab([],['BTC-USDT'])),
 C('cancel_wildcard_canonical','cancel',cab(['*'],['*'])),
 C('cancel_wildcard_omitted','cancel',cab(['*'],None)),
 C('cancel_account_mismatch','cancel',cab(['BTC-USDT'],['BTC-USDT'],account=B)),
 C('cancel_action_alias','cancel',cab(['BTC-USDT'],['BTC-USDT'],action='cancelOrders')),
 C('schedule_zero_canonical','schedule',scb(0)),
 C('schedule_60_canonical','schedule',scb(60)),
 C('schedule_60_omitted','schedule',scb(60,'omit')),
 C('schedule_60_zero','schedule',scb(60,0)),
 C('schedule_60_large','schedule',scb(60,86400)),
 C('schedule_60_string','schedule',scb(60,'60')),
 C('schedule_timeout_alias','schedule',scb(60,'same',key='timeout')),
 C('schedule_time_alias','schedule',scb(60,'same',key='time')),
 C('schedule_account_mismatch','schedule',scb(60,'same',account=B)),
 C('schedule_cancelall_action','schedule',scb(60,'same',action='cancelAllOrders')),
 C('leverage_canonical','leverage',ulb('BTC-USDT','1')),
 C('leverage_value_mismatch','leverage',ulb('BTC-USDT','1',wire_lev='50')),
 C('leverage_decimal_alias','leverage',ulb('BTC-USDT','1',wire_lev='1.0')),
 C('leverage_symbol_mismatch','leverage',ulb('BTC-USDT','1',wire_sym='ETH-USDT')),
 C('leverage_symbol_lowercase','leverage',ulb('BTC-USDT','1',wire_sym='btc-usdt')),
 C('leverage_account_mismatch','leverage',ulb('BTC-USDT','1',account=B)),
]
def count(resp):
 if isinstance(resp,list):return len(resp)
 if isinstance(resp,dict):
  vals=[]; seen=False
  for k in ('subAccountIds','managedSubAccountIds','delegatedSubAccountIds'):
   if isinstance(resp.get(k),list):seen=True; vals+=resp[k]
  return len(vals) if seen else None
 return None
def summary(c,status,raw,ms):
 try:p=json.loads(raw)
 except:p=None
 er=p.get('error') if isinstance(p,dict) else None; msg=er.get('message') if isinstance(er,dict) else er; code=er.get('code') if isinstance(er,dict) else None; txt=str(msg or '')
 return {'name':c.name,'family':c.family,'httpStatus':status,'apiStatus':p.get('status') if isinstance(p,dict) else None,'errorCode':code,'messageRedacted':red(msg),'messageSha256':sha(txt) if txt else None,'mentionsSyntheticSigner':ab(ACC.address).lower() in txt.lower(),'bodySha256':sha(raw),'bodyBytes':len(raw),'elapsedMs':ms}
def main():
 st,raw,_=post(INFO,{'params':{'action':'getSubAccountIds','walletAddress':ACC.address,'includeDelegations':True}}); p=json.loads(raw); n=count(p.get('response'))
 if st!=200 or n!=0:raise RuntimeError(f'preflight {st} {n}')
 base=int(time.time()*1000); rows=[]
 for i,c in enumerate(CASES): rows.append(summary(c,*post(TRADE,c.build(base+i*13+1)))); time.sleep(.3)
 fam={}
 for f in sorted({r['family'] for r in rows}):
  x=[r for r in rows if r['family']==f]; fam[f]={'caseCount':len(x),'statuses':sorted({r['httpStatus'] for r in x}),'errorCodes':sorted({str(r['errorCode']) for r in x}),'syntheticSignerRecoveryCases':[r['name'] for r in x if r['mentionsSyntheticSigner']],'uniqueMessages':len({r['messageSha256'] for r in x})}
 out={'safety':'zero-account synthetic signer and nonexistent account IDs; no state mutation possible','caseCount':len(rows),'syntheticAccountCount':n,'families':fam,'results':rows}; (OUT/'summary.json').write_text(json.dumps(out,indent=2,sort_keys=True)); print(json.dumps({'caseCount':len(rows),'families':fam},indent=2))
if __name__=='__main__':main()
