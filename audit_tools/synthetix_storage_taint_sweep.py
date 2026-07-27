#!/usr/bin/env python3
"""Safe local/session-storage taint sweep for the current Synthetix Exchange frontend.

Storage keys are derived from the current full frontend artifact. Each case preloads one inert canary,
instruments dangerous DOM/navigation sinks, and blocks all PAPI writes, private WebSockets,
transaction RPC methods, telemetry ingestion, and canary-bearing cross-origin requests.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import pathlib
import re
import urllib.parse
import urllib.request
import zipfile
from typing import Any

from playwright.async_api import Browser, Request, Route, async_playwright

OUT = pathlib.Path("synthetix_storage_taint_sweep")
OUT.mkdir(parents=True, exist_ok=True)
ARTIFACT_ID = 8660005480
REPO = "zerodaybugs/test"
BASE = "https://exchange.synthetix.io/?market=BTC-USDT"
TARGET_HOST = "exchange.synthetix.io"
MAX_KEYS = 70
WAIT_MS = 1800
CANARY = "ZDB_ST_82d91a"
ATTACKER = "https://attacker.invalid/zdb-st-82d91a"
TELEMETRY_PARTS = ("sentry.io", "segment.io", "segment.com", "posthog.com", "intercom.io")
PATTERNS = [
    re.compile(r"(localStorage|sessionStorage)\.(?:getItem|setItem|removeItem)\(\s*['\"]([^'\"]{1,100})['\"]"),
    re.compile(r"(localStorage|sessionStorage)\[['\"]([^'\"]{1,100})['\"]\]"),
    re.compile(r"(localStorage|sessionStorage)\.([A-Za-z_$][A-Za-z0-9_$-]{0,99})"),
]
DEFAULTS = {
    ("localStorage", "UNSAFE_IMPORT"),
    ("localStorage", "session-storage"),
    ("localStorage", "referralCode"),
    ("localStorage", "selectedMarket"),
    ("localStorage", "walletAddress"),
    ("sessionStorage", "redirect"),
}


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def download_graph() -> bytes:
    token = os.environ["GITHUB_TOKEN"]
    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/actions/artifacts/{ARTIFACT_ID}/zip",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "synthetix-authorized-storage-taint/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=90) as response:
        return response.read(30 * 1024 * 1024)


def derive_keys(raw: bytes) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    keys = set(DEFAULTS)
    files = 0
    scanned = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in archive.namelist():
            if not name.lower().endswith((".js", ".mjs", ".json", ".map", ".html")):
                continue
            try:
                data = archive.read(name)
            except Exception:
                continue
            if len(data) > 8 * 1024 * 1024:
                continue
            files += 1
            scanned += len(data)
            text = data.decode("utf-8", errors="ignore")
            for pattern in PATTERNS:
                for match in pattern.finditer(text):
                    store, key = match.group(1), match.group(2)
                    if key not in {"length", "key", "clear"}:
                        keys.add((store, key))
    priority = [
        ("localStorage", "session-storage"), ("localStorage", "UNSAFE_IMPORT"),
        ("localStorage", "referralCode"), ("localStorage", "selectedMarket"),
        ("localStorage", "walletAddress"), ("sessionStorage", "redirect"),
    ]
    ordered: list[tuple[str, str]] = []
    for item in priority + sorted(keys):
        if item not in ordered:
            ordered.append(item)
    return ordered[:MAX_KEYS], {"filesScanned": files, "bytesScanned": scanned, "derivedPairCount": len(keys)}


def init_script(store: str, key: str, value: str) -> str:
    return f"""
(() => {{
  const C={json.dumps(CANARY)};
  const V={json.dumps(value)};
  const state={{hits:[],executed:false,errors:[]}};
  Object.defineProperty(window,'__zdbStorageTaint',{{value:state}});
  window.__ZDB_ST_EXEC=()=>{{state.executed=true;}};
  try {{ window[{json.dumps(store)}].setItem({json.dumps(key)}, V); }} catch(e) {{ state.errors.push('storage:'+String(e)); }}
  const rec=(sink,v,extra={{}})=>{{let s='';try{{s=String(v)}}catch(_){{}};if(s.includes(C)||s.includes('attacker.invalid'))state.hits.push({{sink,value:s.slice(0,800),...extra}})}};
  try{{const d=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');if(d&&d.set)Object.defineProperty(Element.prototype,'innerHTML',{{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){{rec('innerHTML',v,{{tag:this.tagName}});return d.set.call(this,v)}}}})}}catch(e){{}}
  try{{const d=Object.getOwnPropertyDescriptor(Element.prototype,'outerHTML');if(d&&d.set)Object.defineProperty(Element.prototype,'outerHTML',{{configurable:true,enumerable:d.enumerable,get:d.get,set:function(v){{rec('outerHTML',v,{{tag:this.tagName}});return d.set.call(this,v)}}}})}}catch(e){{}}
  for(const [p,n] of [[Element.prototype,'insertAdjacentHTML'],[Document.prototype,'write'],[Document.prototype,'writeln']]){{try{{const o=p[n];if(typeof o==='function')p[n]=function(...a){{a.forEach(v=>rec(n,v));return o.apply(this,a)}}}}catch(e){{}}}}
  try{{const o=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){{if(/^(src|href|action|srcdoc|data)$/i.test(String(n)))rec('setAttribute:'+n,v,{{tag:this.tagName}});return o.call(this,n,v)}}}}catch(e){{}}
  try{{window.open=function(u){{rec('window.open',u);return null}}}}catch(e){{}}
  try{{const o=history.pushState;history.pushState=function(s,t,u){{rec('history.pushState',u);return o.call(this,s,t,u)}}}}catch(e){{}}
  try{{const o=history.replaceState;history.replaceState=function(s,t,u){{rec('history.replaceState',u);return o.call(this,s,t,u)}}}}catch(e){{}}
  try{{const o=window.eval;window.eval=function(v){{rec('eval',v);return o.call(this,v)}}}}catch(e){{}}
  try{{const F=window.Function;window.Function=function(...a){{a.forEach(v=>rec('Function',v));return F(...a)}};window.Function.prototype=F.prototype}}catch(e){{}}
  window.addEventListener('message',e=>{{try{{rec('message',JSON.stringify(e.data),{{origin:e.origin}})}}catch(_){{}}}},true);
}})();
"""


async def run_case(browser: Browser, store: str, key: str, value: str) -> dict[str, Any]:
    context = await browser.new_context(viewport={"width":1280,"height":800})
    await context.add_init_script(init_script(store, key, value))
    page = await context.new_page()
    requests: list[dict[str, Any]] = []

    async def route_handler(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        method = request.method.upper()
        try: body = request.post_data or ""
        except Exception: body = ""
        canary = CANARY in request.url or "attacker.invalid" in request.url or CANARY in body
        tx_rpc = any(x in body for x in ("eth_sendTransaction","eth_sendRawTransaction"))
        papi_write = host == "papi.synthetix.io" and (method != "GET" or parsed.path.rstrip('/').endswith('/trade'))
        private_ws = request.url.startswith("wss://papi.synthetix.io/v1/ws/trade")
        telemetry = any(x in host for x in TELEMETRY_PARTS) and method != "GET"
        third_write = host not in {TARGET_HOST,""} and method != "GET"
        blocked = tx_rpc or papi_write or private_ws or telemetry or third_write or (canary and host != TARGET_HOST)
        if blocked or canary:
            requests.append({"method":method,"host":host,"path":parsed.path,"blocked":blocked,"canaryBearing":canary,"resourceType":request.resource_type})
        if blocked: await route.abort("blockedbyclient")
        else: await route.continue_()

    await page.route("**/*", route_handler)
    nav_error = None
    try:
        await page.goto(BASE, wait_until="domcontentloaded", timeout=45_000)
        await page.wait_for_timeout(WAIT_MS)
    except Exception as exc:  # noqa: BLE001
        nav_error = f"{type(exc).__name__}: {exc}"[:500]
    state = await page.evaluate("() => window.__zdbStorageTaint || {hits:[],executed:false,errors:['missing']}" )
    result = {
        "store": store,
        "key": key,
        "navigationError": nav_error,
        "sinkHits": state.get("hits", [])[:100],
        "canaryExecuted": bool(state.get("executed")),
        "instrumentationErrors": state.get("errors", [])[:20],
        "requestMetadata": requests[:100],
    }
    await context.close()
    return result


async def main_async() -> None:
    pairs, derivation = derive_keys(download_graph())
    payload = f"<svg id='{CANARY}' onload='window.__ZDB_ST_EXEC&&window.__ZDB_ST_EXEC()'></svg>{ATTACKER}"
    results=[]
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True)
        try:
            for store,key in pairs:
                results.append(await run_case(browser,store,key,payload))
        finally:
            await browser.close()
    execution=[r for r in results if r["canaryExecuted"]]
    sink=[r for r in results if r["sinkHits"]]
    cross=[r for r in results if any(i.get("canaryBearing") and i.get("host") not in {TARGET_HOST,""} for i in r["requestMetadata"])]
    output={
        "safety":"Storage canaries only; no wallet/account/signature/trade/state; all writes and canary-bearing cross-origin requests blocked.",
        "derivation":derivation,
        "testedPairs":[{"store":s,"key":k} for s,k in pairs],
        "caseCount":len(results),
        "highConfidenceExecutionCount":len(execution),
        "dangerousSinkCaseCount":len(sink),
        "crossOriginCanaryAttemptCaseCount":len(cross),
        "results":results,
        "verdict":"CANDIDATE_REQUIRES_MANUAL_REVIEW" if (execution or sink or cross) else "NO_STORAGE_TO_DANGEROUS_SINK_OR_CROSS_ORIGIN_FLOW_FOUND",
    }
    (OUT/"summary.json").write_text(json.dumps(output,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps({k:output[k] for k in ("caseCount","highConfidenceExecutionCount","dangerousSinkCaseCount","crossOriginCanaryAttemptCaseCount","verdict")},indent=2))
    if execution:
        raise SystemExit(2)


def main() -> None:
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
