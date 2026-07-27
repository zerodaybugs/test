#!/usr/bin/env python3
"""Exact signed-vs-wire binding differential for voluntaryCollateralExchange.

Safety: deterministic zero-account signer, nonexistent account IDs, fresh nonces, and no request can
pass account authorization or mutate state. Output stores only redacted status/error fingerprints.
"""
from __future__ import annotations
import hashlib, json, pathlib, re, time, urllib.error, urllib.request
from eth_account import Account
from eth_account.messages import encode_typed_data

OUT=pathlib.Path('synthetix_vce_field_binding'); OUT.mkdir(parents=True,exist_ok=True)
INFO='https://papi.synthetix.io/v1/info'; TRADE='https://papi.synthetix.io/v1/trade'
UA='Mozilla/5.0 (compatible; authorized-synthetic-security-review/1.0)'; MAX=2*1024*1024
A=Account.from_key('0x'+'b5'*32); SID=8_300_000_000_050_001; OTHER=8_300_000_000_050_002
ZERO='0x0000000000000000000000000000000000000000'
DOMAIN={'name':'Synthetix','version':'1','chainId':1,'verifyingContract':ZERO}
FIELDS=[{'name':'subAccountId','type':'uint256'},{'name':'sourceAsset','type':'string'},{'name':'targetUSDTAmount','type':'string'},{'name':'nonce','type':'uint256'},{'name':'expiresAfter','type':'uint256'}]
ADDR=re.compile(r'0x[a-fA-F0-9]{40}'); HEX=re.compile(r'0x[a-fA-F0-9]{64,}')

def sha(x):
    if isinstance(x,str): x=x.encode()
    return hashlib.sha256(x).hexdigest()

def redact(x):
    if x is None:return None
    s=ADDR.sub('<address>',str(x)); s=HEX.sub('<hex>',s); s=re.sub(r'\b\d{12,}\b','<large-number>',s)
    return s[:1200]

def post(url,payload):
    body=json.dumps(payload,separators=(',',':')).encode(); req=urllib.request.Request(url,data=body,headers={'User-Agent':UA,'Content-Type':'application/json','Accept':'application/json'},method='POST')
    t=time.monotonic()
    try:
        with urllib.request.urlopen(req,timeout=45) as r: raw,status=r.read(MAX+1),r.status
    except urllib.error.HTTPError as e: raw,status=e.read(MAX+1),e.code
    if len(raw)>MAX: raise RuntimeError('response too large')
    return status,raw,time.monotonic()-t

def parse(raw):
    try:return json.loads(raw)
    except:return None

def count(resp):
    if isinstance(resp,list):return len(resp)
    if isinstance(resp,dict):return sum(len(resp.get(k) or []) for k in ('subAccountIds','managedSubAccountIds','delegatedSubAccountIds'))
    return None

def sig(nonce):
    msg={'subAccountId':SID,'sourceAsset':'WETH','targetUSDTAmount':'1','nonce':nonce,'expiresAfter':nonce+60000}
    enc=encode_typed_data(full_message={'types':{'VoluntaryCollateralExchange':FIELDS},'primaryType':'VoluntaryCollateralExchange','domain':DOMAIN,'message':msg})
    s=A.sign_message(enc)
    return {'v':s.v,'r':'0x'+format(s.r,'064x'),'s':'0x'+format(s.s,'064x')}

def payload(nonce,**overrides):
    p={'action':'voluntaryCollateralExchange','subaccountId':str(SID),'walletAddress':A.address,'sourceAsset':'WETH','targetUSDTAmount':'1'}; p.update(overrides)
    return {'signature':sig(nonce),'nonce':nonce,'expiresAfter':nonce+60000,'params':p}

def summary(name,status,raw,elapsed):
    d=parse(raw); e=d.get('error') if isinstance(d,dict) else None
    if isinstance(e,dict): code=e.get('code'); m=e.get('message') or e.get('error')
    else: code=None; m=e
    text=str(m) if m is not None else ''
    return {'name':name,'httpStatus':status,'apiStatus':d.get('status') if isinstance(d,dict) else None,'errorCode':code,'messageRedacted':redact(m),'messageSha256':sha(text) if text else None,'bodySha256':sha(raw),'bodyBytes':len(raw),'elapsedMs':round(elapsed*1000,2)}

def main():
    st,raw,_=post(INFO,{'params':{'action':'getSubAccountIds','walletAddress':A.address,'includeDelegations':True}}); d=parse(raw); resp=d.get('response') if isinstance(d,dict) else None
    if st!=200 or count(resp)!=0: raise RuntimeError(f'preflight failed status={st} count={count(resp)}')
    cases=[('canonical',{}),('amount_2',{'targetUSDTAmount':'2'}),('amount_1_decimal',{'targetUSDTAmount':'1.0'}),('source_CBBTC',{'sourceAsset':'CBBTC'}),('source_WETH_lower',{'sourceAsset':'weth'}),('other_account',{'subaccountId':str(OTHER)}),('extra_targetAmount',{'targetAmount':'1000000'}),('extra_sourceSymbol',{'sourceSymbol':'CBBTC'})]
    base=int(time.time()*1000); out=[]
    for i,(name,ov) in enumerate(cases):
        n=base+i*10+1; out.append(summary(name,*post(TRADE,payload(n,**ov)))); time.sleep(.3)
    baseline=out[0]
    result={'safety':'Synthetic zero-account signer and nonexistent IDs; no state mutation possible.','results':out,'baseline':baseline,'exactBaselineFingerprint':[x['name'] for x in out[1:] if x['httpStatus']==baseline['httpStatus'] and x['errorCode']==baseline['errorCode'] and x['messageSha256']==baseline['messageSha256']]}
    (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
    print(json.dumps({'results':out,'exactBaselineFingerprint':result['exactBaselineFingerprint']},indent=2))
if __name__=='__main__':main()
