#!/usr/bin/env python3
"""Safe cross-origin postMessage differential for Synthetix Exchange.

A synthetic EIP-6963 wallet rejects every signing and transaction method. The probe instruments message
listeners, provider calls, DOM sinks, storage changes, and outgoing postMessages, then injects bounded
structured canaries from an opaque-origin sandboxed iframe. All PAPI writes, private WebSockets,
telemetry submissions, transaction RPC calls, and canary-bearing cross-origin requests are blocked.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import re
import urllib.parse
from typing import Any

from playwright.async_api import Browser, Page, Request, Route, async_playwright

OUT = pathlib.Path("synthetix_postmessage_fuzz")
OUT.mkdir(parents=True, exist_ok=True)
BASE = "https://exchange.synthetix.io/?market=BTC-USDT"
TARGET_HOST = "exchange.synthetix.io"
CANARY = "ZDB_PM_61c83e"
TELEMETRY_PARTS = ("sentry.io", "segment.io", "segment.com", "posthog.com", "intercom.io")
MESSAGE_TYPES = [
    "getWallets", "signMessage", "signTypedData", "signTransaction", "sendTransaction",
    "exportPrivateKey", "importPrivateKey", "sendAuthToken", "cleanup", "connect", "disconnect",
    "authenticate", "authorize", "delegate", "addDelegatedSigner", "removeDelegatedSigner",
    "session", "sessionHandoff", "wallet", "walletConnected", "accountsChanged", "chainChanged",
    "request", "response", "success", "error", "ready", "initialize", "open", "close",
]


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


INSTRUMENT = f"""
(() => {{
  const C={json.dumps(CANARY)};
  const state={{listeners:[],events:[],outgoing:[],providerCalls:[],sinkHits:[],storageBefore:{{}},errors:[]}};
  Object.defineProperty(window,'__zdbPM',{{value:state}});
  const safe=(v)=>{{try{{return JSON.stringify(v).slice(0,2000)}}catch(_){{return String(v).slice(0,2000)}}}};
  const recSink=(sink,v)=>{{const s=safe(v);if(s.includes(C))state.sinkHits.push({{sink,value:s}})}};
  const wrapAdd=(target,name)=>{{
    const orig=target.addEventListener.bind(target);
    target.addEventListener=function(type,listener,options){{
      if(type==='message'&&listener){{let src='';try{{src=Function.prototype.toString.call(listener)}}catch(_){{}};state.listeners.push({{target:name,sourcePrefix:src.slice(0,2000),sourceLength:src.length}})}}
      return orig(type,listener,options);
    }};
  }};
  wrapAdd(window,'window');wrapAdd(document,'document');
  window.addEventListener('message',e=>state.events.push({{origin:e.origin,data:safe(e.data),sourceSelf:e.source===window}}),true);
  try{{const op=Window.prototype.postMessage;Window.prototype.postMessage=function(m,o,t){{state.outgoing.push({{targetOrigin:String(o),data:safe(m)}});return op.call(this,m,o,t)}}}}catch(e){{}}
  try{{const d=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');if(d&&d.set)Object.defineProperty(Element.prototype,'innerHTML',{{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){{recSink('innerHTML',v);return d.set.call(this,v)}}}})}}catch(e){{}}
  try{{const d=Object.getOwnPropertyDescriptor(Element.prototype,'outerHTML');if(d&&d.set)Object.defineProperty(Element.prototype,'outerHTML',{{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){{recSink('outerHTML',v);return d.set.call(this,v)}}}})}}catch(e){{}}
  try{{const o=Element.prototype.insertAdjacentHTML;Element.prototype.insertAdjacentHTML=function(p,v){{recSink('insertAdjacentHTML',v);return o.call(this,p,v)}}}}catch(e){{}}
  try{{const o=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){{if(/^(src|href|action|srcdoc|data)$/i.test(String(n)))recSink('setAttribute:'+n,v);return o.call(this,n,v)}}}}catch(e){{}}
  const listeners=new Map();
  const provider={{
    selectedAddress:'0x1563915e194D8CfBA1943570603F7606A3115508',chainId:'0x1',networkVersion:'1',isConnected:()=>true,
    request:async(args)=>{{const method=args&&args.method||'';state.providerCalls.push({{method,params:safe(args&&args.params)}});if(method==='eth_requestAccounts'||method==='eth_accounts')return [provider.selectedAddress];if(method==='eth_chainId')return '0x1';if(method==='net_version')return '1';if(method==='wallet_switchEthereumChain'||method==='wallet_addEthereumChain')return null;if(method==='eth_getBalance'||method==='eth_getTransactionCount'||method==='eth_blockNumber')return '0x0';if(method==='eth_estimateGas')return '0x5208';if(method==='eth_gasPrice')return '0x0';if(method==='eth_call')return '0x';if(method.toLowerCase().includes('sign')||method.toLowerCase().includes('sendtransaction'))throw new Error('Synthetic provider refuses signing and transactions');return null}},
    on:(e,cb)=>{{const s=listeners.get(e)||new Set();s.add(cb);listeners.set(e,s);return provider}},removeListener:(e,cb)=>{{const s=listeners.get(e);if(s)s.delete(cb);return provider}}
  }};
  const detail={{info:{{uuid:'0a6ddfe2-f22f-4b74-bd73-2123ea7cdd8c',name:'Audit Injected Wallet',icon:'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"/>',rdns:'io.zerodaybugs.audit'}},provider}};
  const announce=()=>window.dispatchEvent(new CustomEvent('eip6963:announceProvider',{{detail}}));
  window.addEventListener('eip6963:requestProvider',announce);Object.defineProperty(window,'ethereum',{{value:provider,configurable:true}});queueMicrotask(announce);setTimeout(announce,50);setTimeout(announce,500);
  try{{for(let i=0;i<localStorage.length;i++){{const k=localStorage.key(i);state.storageBefore['local:'+k]=String(localStorage.getItem(k)).slice(0,200)}};for(let i=0;i<sessionStorage.length;i++){{const k=sessionStorage.key(i);state.storageBefore['session:'+k]=String(sessionStorage.getItem(k)).slice(0,200)}}}}catch(e){{}}
}})();
"""


async def click_connect(page: Page) -> dict[str, Any]:
    buttons=page.locator('button')
    for i in range(min(await buttons.count(),300)):
        b=buttons.nth(i)
        try:
            if not await b.is_visible() or await b.is_disabled(): continue
            text=((await b.inner_text()) or '').strip()
            aria=(await b.get_attribute('aria-label')) or ''
            if re.search(r'connect',text+' '+aria,re.I):
                await b.click(timeout=3000);return {'clicked':True,'text':text[:100]}
        except Exception: continue
    return {'clicked':False}


async def inject(page: Page) -> dict[str, Any]:
    payloads=[]
    for typ in MESSAGE_TYPES:
        base={{'type':typ,'origin':'webview','messageSessionId':CANARY+'-'+typ,'action':typ,'method':typ,'event':typ,'args':[{{'canary':CANARY,'privateKey':CANARY,'delegateAddress':'0x000000000000000000000000000000000000dEaD'}}],'params':{{'canary':CANARY}},'data':{{'canary':CANARY}}}}
        payloads.append(base)
        payloads.append({{'event':typ,'data':base}})
        payloads.append({{'method':typ,'params':[base],'id':CANARY+'-'+typ}})
    return await page.evaluate("""async ({payloads,canary})=>{
      const frame=document.createElement('iframe');frame.id='zdb-pm-frame';frame.setAttribute('sandbox','allow-scripts');frame.style.display='none';
      frame.srcdoc=`<!doctype html><script>const ps=${JSON.stringify(payloads)};setTimeout(()=>{for(const p of ps)parent.postMessage(p,'*')},50);<\/script>`;
      document.body.appendChild(frame);await new Promise(r=>setTimeout(r,2500));return {inserted:true,payloadCount:payloads.length};
    }""", {{'payloads':payloads,'canary':CANARY}})


async def run(browser: Browser) -> None:
    context=await browser.new_context(viewport={{'width':1365,'height':900}})
    await context.add_init_script(INSTRUMENT)
    page=await context.new_page()
    requests=[]
    async def route_handler(route: Route, request: Request) -> None:
        parsed=urllib.parse.urlparse(request.url);host=(parsed.hostname or '').lower();method=request.method.upper()
        try: body=request.post_data or ''
        except Exception: body=''
        canary=CANARY in request.url or CANARY in body
        tx=any(x in body for x in ('eth_sendTransaction','eth_sendRawTransaction'))
        papi=host=='papi.synthetix.io' and (method!='GET' or parsed.path.rstrip('/').endswith('/trade'))
        pws=request.url.startswith('wss://papi.synthetix.io/v1/ws/trade')
        telemetry=any(x in host for x in TELEMETRY_PARTS) and method!='GET'
        thirdwrite=host not in {{TARGET_HOST,''}} and method!='GET'
        blocked=tx or papi or pws or telemetry or thirdwrite or (canary and host!=TARGET_HOST)
        if blocked or canary: requests.append({{'method':method,'host':host,'path':parsed.path,'blocked':blocked,'canaryBearing':canary,'resourceType':request.resource_type}})
        if blocked: await route.abort('blockedbyclient')
        else: await route.continue_()
    await page.route('**/*',route_handler)
    nav_error=None
    try:
        await page.goto(BASE,wait_until='domcontentloaded',timeout=60000);await page.wait_for_timeout(7000)
    except Exception as exc: nav_error=f'{{type(exc).__name__}}: {{exc}}'[:500]
    connect=await click_connect(page);await page.wait_for_timeout(2500)
    injection=await inject(page);await page.wait_for_timeout(1500)
    state=await page.evaluate("""() => {
      const s=window.__zdbPM||{};const after={};try{for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);after['local:'+k]=String(localStorage.getItem(k)).slice(0,200)}for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);after['session:'+k]=String(sessionStorage.getItem(k)).slice(0,200)}}catch(e){}
      return {...s,storageAfter:after};
    }""")
    sensitive_provider=[x for x in state.get('providerCalls',[]) if any(k in str(x.get('method','')).lower() for k in ('sign','sendtransaction','wallet_'))]
    canary_out=[x for x in state.get('outgoing',[]) if CANARY in str(x)]
    storage_changed=state.get('storageBefore')!=state.get('storageAfter')
    result={{
      'safety':'Opaque-origin postMessage only; synthetic refusing wallet; all writes/private WS/telemetry/canary cross-origin blocked.',
      'navigationError':nav_error,'connect':connect,'injection':injection,
      'messageListenerCount':len(state.get('listeners',[])),'messageEventCount':len(state.get('events',[])),
      'outgoingMessageCount':len(state.get('outgoing',[])),'canaryOutgoingCount':len(canary_out),
      'providerCallCount':len(state.get('providerCalls',[])),'sensitiveProviderCallCount':len(sensitive_provider),
      'sinkHitCount':len(state.get('sinkHits',[])),'storageChanged':storage_changed,
      'listeners':state.get('listeners',[])[:200],'canaryOutgoing':canary_out[:100],
      'sensitiveProviderCalls':sensitive_provider[:100],'sinkHits':state.get('sinkHits',[])[:100],
      'requestMetadata':requests[:300],
      'verdict':'CANDIDATE_REQUIRES_MANUAL_REVIEW' if (canary_out or sensitive_provider or state.get('sinkHits')) else 'NO_CROSS_ORIGIN_MESSAGE_TO_SENSITIVE_ACTION_FOUND'
    }}
    (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
    print(json.dumps({{k:result[k] for k in ('messageListenerCount','messageEventCount','canaryOutgoingCount','sensitiveProviderCallCount','sinkHitCount','storageChanged','verdict')}},indent=2))
    await context.close()
    if sensitive_provider: raise SystemExit(2)


async def main_async() -> None:
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True)
        try: await run(browser)
        finally: await browser.close()

if __name__=='__main__': asyncio.run(main_async())
