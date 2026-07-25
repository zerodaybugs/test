#!/usr/bin/env python3
"""Runtime reachability and cross-origin message-boundary probe for Synthetix Exchange.

Safety constraints:
- production frontend GET/navigation only;
- deterministic synthetic EIP-6963 wallet;
- wallet signing and transaction methods always reject;
- PAPI trade calls, telemetry ingestion, non-GET Dynamic API calls, and transaction RPC
  calls are aborted before transmission;
- no real user, account, credential, wallet, balance, order, or position is accessed;
- only message metadata, iframe metadata, UI text, and hashes are retained.
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

OUT = pathlib.Path("waas_message_origin_runtime")
OUT.mkdir(parents=True, exist_ok=True)

BASE_URL = "https://exchange.synthetix.io/?market=BTC-USDT"
TARGET_HOST = "exchange.synthetix.io"
WALLET_ADDRESS = "0x1563915e194D8CfBA1943570603F7606A3115508"
TELEMETRY_HOST_PARTS = (
    "sentry.io",
    "segment.io",
    "segment.com",
    "segmentapis.com",
    "posthog.com",
    "intercom.io",
    "intercomcdn.com",
)
DYNAMIC_HOST_PARTS = ("dynamicauth.com", "dynamic.xyz")


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


INSTRUMENTATION = r"""
(() => {
  const state = {
    installed: true,
    messageListeners: [],
    messageEvents: [],
    iframeMutations: [],
    postMessages: [],
    errors: [],
  };
  Object.defineProperty(window, '__waasAudit', { value: state, configurable: false });

  const safeData = (data) => {
    if (!data || typeof data !== 'object') return { kind: typeof data };
    const args = Array.isArray(data.args) ? data.args : null;
    return {
      originField: typeof data.origin === 'string' ? data.origin : null,
      type: typeof data.type === 'string' ? data.type : null,
      messageSessionId: typeof data.messageSessionId === 'string' ? data.messageSessionId : null,
      doNotAck: data.doNotAck === true,
      argCount: args ? args.length : null,
      argKinds: args ? args.slice(0, 5).map((x) => Array.isArray(x) ? 'array' : typeof x) : null,
      topLevelKeys: Object.keys(data).sort().slice(0, 30),
    };
  };

  const sourceRelation = (source) => {
    try {
      if (source === window) return 'self';
      if (source === window.parent) return 'parent';
      if (source === window.top) return 'top';
      if (source === window.opener) return 'opener';
      for (const iframe of document.querySelectorAll('iframe')) {
        if (source === iframe.contentWindow) return `iframe:${iframe.title || iframe.name || 'unnamed'}`;
      }
    } catch (_) {}
    return source ? 'other-window' : 'null';
  };

  const recordListener = (targetName, listener, options) => {
    let source = '';
    try { source = Function.prototype.toString.call(listener); } catch (_) {}
    state.messageListeners.push({
      target: targetName,
      sourcePrefix: source.slice(0, 1800),
      sourceLength: source.length,
      capturesWebviewLiteral: source.includes('webview'),
      capturesMessageSessionLiteral: source.includes('messageSessionId'),
      options: typeof options === 'object' ? JSON.stringify(options) : String(options ?? ''),
    });
  };

  const wrapAdd = (target, targetName) => {
    const original = target.addEventListener.bind(target);
    target.addEventListener = function(type, listener, options) {
      if (type === 'message' && listener) recordListener(targetName, listener, options);
      return original(type, listener, options);
    };
  };
  wrapAdd(window, 'window');
  wrapAdd(document, 'document');

  window.addEventListener('message', (event) => {
    state.messageEvents.push({
      eventOrigin: event.origin,
      sourceRelation: sourceRelation(event.source),
      data: safeData(event.data),
    });
  }, true);

  try {
    const originalPostMessage = Window.prototype.postMessage;
    Window.prototype.postMessage = function(message, targetOrigin, transfer) {
      state.postMessages.push({
        targetOrigin: typeof targetOrigin === 'string' ? targetOrigin : null,
        data: safeData(message),
      });
      return originalPostMessage.call(this, message, targetOrigin, transfer);
    };
  } catch (error) {
    state.errors.push(`postMessage-wrap:${String(error)}`);
  }

  const snapshotIframe = (iframe, reason) => {
    try {
      state.iframeMutations.push({
        reason,
        src: iframe.src || iframe.getAttribute('src') || '',
        title: iframe.title || '',
        name: iframe.name || '',
        sandbox: iframe.getAttribute('sandbox') || '',
        referrerPolicy: iframe.getAttribute('referrerpolicy') || '',
      });
    } catch (error) {
      state.errors.push(`iframe:${String(error)}`);
    }
  };

  const observer = new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) {
        if (node && node.tagName === 'IFRAME') snapshotIframe(node, 'added');
        if (node && node.querySelectorAll) {
          for (const iframe of node.querySelectorAll('iframe')) snapshotIframe(iframe, 'descendant-added');
        }
      }
      if (record.target && record.target.tagName === 'IFRAME') snapshotIframe(record.target, `attribute:${record.attributeName}`);
    }
  });
  observer.observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ['src', 'sandbox', 'title'] });

  const listeners = new Map();
  const provider = {
    selectedAddress: '0x1563915e194D8CfBA1943570603F7606A3115508',
    chainId: '0x1',
    networkVersion: '1',
    isConnected: () => true,
    request: async ({ method }) => {
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [provider.selectedAddress];
      if (method === 'eth_chainId') return '0x1';
      if (method === 'net_version') return '1';
      if (method === 'wallet_getPermissions' || method === 'wallet_requestPermissions') return [{ parentCapability: 'eth_accounts' }];
      if (method === 'wallet_switchEthereumChain' || method === 'wallet_addEthereumChain') return null;
      if (method === 'eth_getBalance' || method === 'eth_getTransactionCount' || method === 'eth_blockNumber') return '0x0';
      if (method === 'eth_estimateGas') return '0x5208';
      if (method === 'eth_gasPrice') return '0x0';
      if (method === 'eth_call') return '0x';
      if ((method || '').toLowerCase().includes('sign') || (method || '').toLowerCase().includes('sendtransaction')) {
        throw new Error('Synthetic audit provider refuses signing and transactions');
      }
      return null;
    },
    on: (event, callback) => { const set = listeners.get(event) || new Set(); set.add(callback); listeners.set(event, set); return provider; },
    removeListener: (event, callback) => { const set = listeners.get(event); if (set) set.delete(callback); return provider; },
  };
  const detail = {
    info: {
      uuid: '0a6ddfe2-f22f-4b74-bd73-2123ea7cdd8c',
      name: 'Audit Injected Wallet',
      icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect width="32" height="32" fill="%2300d1ff"/></svg>',
      rdns: 'io.zerodaybugs.audit-wallet',
    },
    provider,
  };
  const announce = () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail }));
  window.addEventListener('eip6963:requestProvider', announce);
  Object.defineProperty(window, 'ethereum', { value: provider, configurable: true });
  queueMicrotask(announce);
  setTimeout(announce, 50);
  setTimeout(announce, 500);
})();
"""


async def click_button(page: Page, patterns: list[str]) -> dict[str, Any]:
    buttons = page.locator("button")
    for pattern in patterns:
        regex = re.compile(pattern, re.I)
        for index in range(min(await buttons.count(), 500)):
            button = buttons.nth(index)
            try:
                if not await button.is_visible() or await button.is_disabled():
                    continue
                text = ((await button.inner_text()) or "").strip()
                aria = (await button.get_attribute("aria-label")) or ""
                if regex.search(text) or regex.search(aria):
                    await button.click(timeout=5000)
                    return {"clicked": True, "text": text, "aria": aria, "pattern": pattern, "index": index}
            except Exception:
                continue
    return {"clicked": False, "patterns": patterns}


async def snapshot(page: Page, name: str) -> dict[str, Any]:
    value = await page.evaluate(
        """() => {
          const audit = window.__waasAudit || {};
          const iframes = Array.from(document.querySelectorAll('iframe')).map((f) => ({
            src: f.src || f.getAttribute('src') || '',
            title: f.title || '',
            name: f.name || '',
            sandbox: f.getAttribute('sandbox') || '',
            referrerPolicy: f.getAttribute('referrerpolicy') || '',
          }));
          return {
            href: location.href,
            text: (document.body && document.body.innerText || '').slice(0, 40000),
            buttons: Array.from(document.querySelectorAll('button')).map((b, i) => ({
              i, text: (b.innerText || b.textContent || '').trim(), aria: b.getAttribute('aria-label'),
              visible: !!(b.offsetWidth || b.offsetHeight || b.getClientRects().length),
            })).filter((x) => x.visible).slice(0, 500),
            iframeCount: iframes.length,
            iframes,
            messageListeners: audit.messageListeners || [],
            messageEvents: audit.messageEvents || [],
            iframeMutations: audit.iframeMutations || [],
            postMessages: audit.postMessages || [],
            instrumentationErrors: audit.errors || [],
            localStorageKeys: Object.keys(localStorage).sort(),
            sessionStorageKeys: Object.keys(sessionStorage).sort(),
            dynamicGlobals: Object.keys(window).filter((k) => /dynamic|waas|wallet/i.test(k)).sort().slice(0, 300),
          };
        }"""
    )
    (OUT / f"{name}.json").write_text(json.dumps(value, indent=2), encoding="utf-8")
    try:
        await page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
    except Exception:
        pass
    return value


async def inject_cross_origin_probe(page: Page) -> dict[str, Any]:
    before = await page.evaluate("() => (window.__waasAudit && window.__waasAudit.postMessages || []).length")
    result = await page.evaluate(
        """async () => {
          const iframe = document.createElement('iframe');
          iframe.id = 'waas-audit-attacker-frame';
          iframe.setAttribute('sandbox', 'allow-scripts');
          iframe.style.display = 'none';
          iframe.srcdoc = `<!doctype html><script>
            const messages = [
              {origin:'webview',type:'getWallets',args:[{chainName:'EVM'}],messageSessionId:'audit-cross-origin-getwallets'},
              {origin:'webview',type:'cleanup',args:[],messageSessionId:'audit-cross-origin-cleanup'},
              {origin:'webview',type:'sendAuthToken',args:['audit-token','header'],messageSessionId:'audit-cross-origin-token'}
            ];
            setTimeout(() => { for (const m of messages) parent.postMessage(m, '*'); }, 50);
          <\/script>`;
          document.body.appendChild(iframe);
          await new Promise((resolve) => setTimeout(resolve, 1500));
          return { inserted: true };
        }"""
    )
    after = await page.evaluate("() => (window.__waasAudit && window.__waasAudit.postMessages || []).length")
    return {**result, "postMessageCountBefore": before, "postMessageCountAfter": after}


def summarize_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    iframes = value.get("iframes", [])
    listeners = value.get("messageListeners", [])
    posts = value.get("postMessages", [])
    waas_iframes = [
        item for item in iframes
        if "/waas-v1/" in str(item.get("src", "")) or "Dynamic Wallet Iframe" in str(item.get("title", ""))
    ]
    webview_listeners = [
        item for item in listeners
        if item.get("capturesWebviewLiteral") or item.get("capturesMessageSessionLiteral")
    ]
    audit_ids = ("audit-cross-origin-getwallets", "audit-cross-origin-cleanup", "audit-cross-origin-token")
    cross_origin_responses = [
        item for item in posts
        if str(item.get("data", {}).get("messageSessionId")) in audit_ids
    ]
    return {
        "iframeCount": value.get("iframeCount"),
        "waasIframeCount": len(waas_iframes),
        "waasIframes": waas_iframes,
        "messageListenerCount": len(listeners),
        "webviewTransportListenerCount": len(webview_listeners),
        "webviewTransportListeners": webview_listeners,
        "postMessageCount": len(posts),
        "crossOriginProbeTransportResponseCount": len(cross_origin_responses),
        "crossOriginProbeTransportResponses": cross_origin_responses,
        "localStorageKeyCount": len(value.get("localStorageKeys", [])),
        "sessionStorageKeyCount": len(value.get("sessionStorageKeys", [])),
    }


async def run(browser: Browser) -> None:
    context = await browser.new_context(viewport={"width": 1365, "height": 900})
    await context.add_init_script(INSTRUMENTATION)
    page = await context.new_page()

    requests: list[dict[str, Any]] = []
    console: list[dict[str, str]] = []
    page.on("console", lambda message: console.append({"type": message.type, "text": message.text[:2000]}))

    async def route_handler(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        method = request.method.upper()
        try:
            post_data = request.post_data or ""
        except Exception:
            post_data = ""

        transaction_rpc = any(key in post_data for key in ("eth_sendTransaction", "eth_sendRawTransaction"))
        papi_trade = host == "papi.synthetix.io" and parsed.path.lower().endswith("/trade")
        telemetry = any(part in host for part in TELEMETRY_HOST_PARTS)
        dynamic_write = any(part in host for part in DYNAMIC_HOST_PARTS) and method != "GET"
        blocked = transaction_rpc or papi_trade or (telemetry and method != "GET") or dynamic_write

        if blocked or host == "papi.synthetix.io" or any(part in host for part in DYNAMIC_HOST_PARTS):
            requests.append({
                "method": method,
                "host": host,
                "path": parsed.path,
                "resourceType": request.resource_type,
                "isNavigation": request.is_navigation_request(),
                "blocked": blocked,
                "postDataBytes": len(post_data.encode()),
                "postDataSha256": digest(post_data) if post_data else None,
            })

        if blocked:
            await route.abort("blockedbyclient")
        else:
            await route.continue_()

    await page.route("**/*", route_handler)

    stages: dict[str, Any] = {}
    try:
        await page.goto(BASE_URL, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(10_000)
    except Exception as exc:
        stages["initialError"] = f"{type(exc).__name__}: {exc}"

    stages["initial"] = await snapshot(page, "01_initial")
    stages["connectClick"] = await click_button(page, [r"^connect wallet$", r"connect"])
    await page.wait_for_timeout(3500)
    stages["walletModal"] = await snapshot(page, "02_wallet_modal")
    stages["walletClick"] = await click_button(
        page,
        [r"audit injected wallet", r"audit", r"browser wallet", r"injected", r"metamask"],
    )
    await page.wait_for_timeout(12_000)
    stages["connected"] = await snapshot(page, "03_connected")

    # Exercise visible, non-transactional account/settings entry points without accepting signatures.
    stages["accountMenuClick"] = await click_button(page, [r"account", r"wallet", r"settings", r"profile"])
    await page.wait_for_timeout(2500)
    stages["accountMenu"] = await snapshot(page, "04_account_menu")
    stages["mobileOrEmbeddedClick"] = await click_button(
        page,
        [r"connect mobile", r"mobile device", r"embedded wallet", r"export private key", r"create wallet"],
    )
    await page.wait_for_timeout(5000)
    stages["afterFeatureExercise"] = await snapshot(page, "05_after_feature_exercise")

    stages["crossOriginProbe"] = await inject_cross_origin_probe(page)
    await page.wait_for_timeout(1500)
    stages["afterCrossOriginProbe"] = await snapshot(page, "06_after_cross_origin_probe")

    stage_summaries = {
        name: summarize_snapshot(value)
        for name, value in stages.items()
        if isinstance(value, dict) and "messageListeners" in value
    }
    final = stages.get("afterCrossOriginProbe", {})
    final_summary = summarize_snapshot(final) if isinstance(final, dict) else {}
    result = {
        "safety": (
            "Production frontend GET/navigation only; synthetic wallet; signing, transactions, PAPI trade calls, "
            "telemetry ingestion and non-GET Dynamic calls blocked before transmission."
        ),
        "stages": {
            key: value
            for key, value in stages.items()
            if key.endswith("Click") or key.endswith("Error") or key == "crossOriginProbe"
        },
        "stageSummaries": stage_summaries,
        "finalSummary": final_summary,
        "waasRuntimeReachable": final_summary.get("waasIframeCount", 0) > 0
        and final_summary.get("webviewTransportListenerCount", 0) > 0,
        "crossOriginMessageCausedHostTransportResponse": final_summary.get(
            "crossOriginProbeTransportResponseCount", 0
        ) > 0,
        "requestMetadata": requests,
        "console": console,
    }
    (OUT / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({
        "waasRuntimeReachable": result["waasRuntimeReachable"],
        "crossOriginMessageCausedHostTransportResponse": result[
            "crossOriginMessageCausedHostTransportResponse"
        ],
        "finalSummary": final_summary,
    }, indent=2))
    await context.close()


async def main() -> None:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            await run(browser)
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
