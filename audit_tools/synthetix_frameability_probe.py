#!/usr/bin/env python3
"""Safe cross-origin frameability probe for Synthetix Exchange.

An attacker-origin page is fulfilled locally and embeds the in-scope Exchange. The workflow records
response security headers and whether the application renders in the cross-origin frame. All PAPI
writes, private WebSockets, telemetry submissions, transaction RPC calls, and non-GET third-party
requests are blocked. No wallet, account, signature, trade, or state is touched.
"""
from __future__ import annotations
import asyncio,json,pathlib,urllib.parse
from playwright.async_api import Request,Route,async_playwright
OUT=pathlib.Path('synthetix_frameability_probe');OUT.mkdir(parents=True,exist_ok=True)
ATTACKER='https://attacker.invalid/'
TARGET='https://exchange.synthetix.io/?market=BTC-USDT'
TELEMETRY=('sentry.io','segment.io','segment.com','posthog.com','intercom.io')
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(headless=True)
  context=await browser.new_context(viewport={'width':1365,'height':900})
  page=await context.new_page();requests=[];responses=[];console=[]
  page.on('console',lambda m:console.append({'type':m.type,'text':m.text[:1000]}))
  async def handler(route:Route,request:Request):
   u=urllib.parse.urlparse(request.url);host=(u.hostname or '').lower();method=request.method.upper()
   try:body=request.post_data or ''
   except Exception:body=''
   if host=='attacker.invalid':
    html=f'''<!doctype html><meta charset="utf-8"><style>html,body{{margin:0}}iframe{{width:1280px;height:800px;border:0}}</style><iframe id="target" src="{TARGET}"></iframe>'''
    await route.fulfill(status=200,content_type='text/html',body=html);return
   tx=any(x in body for x in ('eth_sendTransaction','eth_sendRawTransaction'))
   papi=host=='papi.synthetix.io' and (method!='GET' or u.path.rstrip('/').endswith('/trade'))
   pws=request.url.startswith('wss://papi.synthetix.io/v1/ws/trade')
   telemetry=any(x in host for x in TELEMETRY) and method!='GET'
   thirdwrite=host not in {'exchange.synthetix.io','attacker.invalid',''} and method!='GET'
   blocked=tx or papi or pws or telemetry or thirdwrite
   if blocked or host in {'exchange.synthetix.io','papi.synthetix.io'}:requests.append({'method':method,'host':host,'path':u.path,'blocked':blocked,'resourceType':request.resource_type})
   if blocked:await route.abort('blockedbyclient')
   else:await route.continue_()
  await page.route('**/*',handler)
  page.on('response',lambda r:responses.append({'url':r.url,'status':r.status,'headers':{k:v for k,v in r.headers.items() if k.lower() in {'content-security-policy','x-frame-options','referrer-policy','cross-origin-opener-policy','cross-origin-resource-policy','permissions-policy'}}}) if r.url.startswith('https://exchange.synthetix.io') else None)
  err=None
  try:
   await page.goto(ATTACKER,wait_until='domcontentloaded',timeout=60000);await page.wait_for_timeout(12000)
  except Exception as e:err=f'{type(e).__name__}: {e}'[:500]
  frames=[]
  for f in page.frames:
   item={'url':f.url,'name':f.name}
   try:item['title']=await f.title();item['bodyText']=((await f.locator('body').inner_text(timeout=3000)) or '')[:5000]
   except Exception as e:item['readError']=f'{type(e).__name__}: {e}'[:300]
   frames.append(item)
  target=[x for x in frames if x['url'].startswith('https://exchange.synthetix.io')]
  result={'safety':'Local attacker page + target GET frame only; all writes/private WS/telemetry blocked.','navigationError':err,'frameCount':len(frames),'targetFrameCount':len(target),'targetRendered':any(bool(x.get('bodyText','').strip()) for x in target),'frames':frames,'targetResponses':responses[:50],'requestMetadata':requests[:300],'console':console[:300],'verdict':'FRAMEABLE' if target else 'FRAME_BLOCKED'}
  (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
  await page.screenshot(path=str(OUT/'attacker_parent.png'),full_page=True)
  print(json.dumps({k:result[k] for k in ('frameCount','targetFrameCount','targetRendered','verdict')},indent=2))
  await context.close();await browser.close()
if __name__=='__main__':asyncio.run(main())
