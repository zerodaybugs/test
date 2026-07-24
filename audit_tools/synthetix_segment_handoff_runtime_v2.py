#!/usr/bin/env python3
"""Intercepted Segment/session-handoff probe with a synthetic EIP-6963 wallet.

Secret-bearing GET requests to the intended in-scope Exchange origin are allowed
and recorded so the page can load normally. Every cross-origin secret-bearing
request, telemetry ingestion request, PAPI trade request, or transaction RPC
request is aborted before transmission.
"""

from __future__ import annotations

import asyncio
import base64
import json
import pathlib
import re
import time
import urllib.parse
from typing import Any

from playwright.async_api import Browser, Page, Request, Route, async_playwright

OUT = pathlib.Path("segment_handoff_runtime")
OUT.mkdir(parents=True, exist_ok=True)
TARGET_HOST = "exchange.synthetix.io"
BASE_URL = "https://exchange.synthetix.io/?market=BTC-USDT"
WALLET_ADDRESS = "0x1563915e194D8CfBA1943570603F7606A3115508"
WALLET_PRIVATE_KEY = "0x" + "22" * 32
HANDOFF_PRIVATE_KEY = "0x" + "11" * 32
HANDOFF_ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"
MARKER = "SYNTHETIX_SEGMENT_HANDOFF_MARKER_20260724"
TELEMETRY_PARTS = (
    "segment.io", "segment.com", "segmentapis.com", "sentry.io",
    "posthog.com", "intercom.io", "intercomcdn.com", "walletconnect",
    "reown.com", "dynamicauth.com",
)


def handoff() -> tuple[str, str, dict[str, Any]]:
    now = int(time.time() * 1000)
    payload = {
        "subAccountId": 999_999_999,
        "address": HANDOFF_ADDRESS,
        "walletAddress": WALLET_ADDRESS,
        "privateKey": HANDOFF_PRIVATE_KEY,
        "createdAt": now,
        "expiresAt": now + 30 * 24 * 60 * 60 * 1000,
        "sessionId": MARKER,
        "status": "active",
        "chainId": 1,
        "handoffContext": {"mode": "owned"},
    }
    token = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    return BASE_URL + "&sessionHandoff=" + urllib.parse.quote(token, safe=""), token, payload


def matches(blob: str, token: str) -> list[str]:
    values = {
        "parameter": "sessionHandoff",
        "token": token,
        "encoded_token": urllib.parse.quote(token, safe=""),
        "handoff_key": HANDOFF_PRIVATE_KEY,
        "wallet_key": WALLET_PRIVATE_KEY,
        "marker": MARKER,
    }
    return [name for name, value in values.items() if value in blob]


def record(request: Request, disposition: str, token: str) -> dict[str, Any]:
    try:
        headers = dict(request.headers)
    except Exception:
        headers = {}
    try:
        post_data = request.post_data
    except Exception:
        post_data = None
    item = {
        "disposition": disposition,
        "method": request.method,
        "url": request.url,
        "resourceType": request.resource_type,
        "isNavigation": request.is_navigation_request(),
        "headers": headers,
        "postData": post_data,
    }
    item["secretMatches"] = matches(json.dumps(item, sort_keys=True), token)
    return item


PROVIDER = f"""
(() => {{
  const address = {json.dumps(WALLET_ADDRESS)};
  const listeners = new Map();
  const provider = {{
    selectedAddress: address, chainId: '0x1', networkVersion: '1',
    isConnected: () => true,
    request: async (args) => {{
      const method = args && args.method;
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [address];
      if (method === 'eth_chainId') return '0x1';
      if (method === 'net_version') return '1';
      if (method === 'wallet_getPermissions' || method === 'wallet_requestPermissions')
        return [{{parentCapability: 'eth_accounts'}}];
      if (method === 'wallet_switchEthereumChain' || method === 'wallet_addEthereumChain') return null;
      if (method === 'eth_getBalance' || method === 'eth_getTransactionCount' || method === 'eth_blockNumber') return '0x0';
      if (method === 'eth_estimateGas') return '0x5208';
      if (method === 'eth_gasPrice') return '0x0';
      if (method === 'eth_call') return '0x';
      if ((method || '').includes('sign') || (method || '').includes('sendTransaction'))
        throw new Error('Synthetic audit provider refuses signing and transactions');
      console.debug('[AuditProvider]', method);
      return null;
    }},
    on: (event, callback) => {{ const set = listeners.get(event) || new Set(); set.add(callback); listeners.set(event, set); return provider; }},
    removeListener: (event, callback) => {{ const set = listeners.get(event); if (set) set.delete(callback); return provider; }},
  }};
  const detail = {{
    info: {{
      uuid: '5fdc0b2a-2e6a-4ddd-87bc-5b4748c3d961',
      name: 'Audit Injected Wallet',
      icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect width="32" height="32" fill="%2300d1ff"/></svg>',
      rdns: 'io.openai.audit-wallet'
    }}, provider
  }};
  const announce = () => window.dispatchEvent(new CustomEvent('eip6963:announceProvider', {{detail}}));
  window.addEventListener('eip6963:requestProvider', announce);
  Object.defineProperty(window, 'ethereum', {{value: provider, configurable: true}});
  queueMicrotask(announce); setTimeout(announce, 50); setTimeout(announce, 500);
}})();
"""


async def snap(page: Page, name: str) -> dict[str, Any]:
    try:
        value = await page.evaluate("""() => ({
          href: location.href,
          search: location.search,
          text: document.body.innerText.slice(0, 30000),
          buttons: Array.from(document.querySelectorAll('button')).map((b, i) => ({
            i, text: (b.innerText || b.textContent || '').trim(),
            aria: b.getAttribute('aria-label'), visible: !!(b.offsetWidth || b.offsetHeight || b.getClientRects().length)
          })).filter(x => x.visible).slice(0, 400),
          localStorage: Object.fromEntries(Object.entries(localStorage)),
          selectedAddress: window.ethereum && window.ethereum.selectedAddress,
        })""")
    except Exception as exc:
        value = {"error": repr(exc)}
    (OUT / f"{name}.json").write_text(json.dumps(value, indent=2), encoding="utf-8")
    try:
        await page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
    except Exception:
        pass
    return value


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
                pass
    return {"clicked": False, "patterns": patterns}


async def run(browser: Browser) -> None:
    url, token, payload = handoff()
    (OUT / "payload.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    context = await browser.new_context(viewport={"width": 1280, "height": 900})
    await context.add_init_script(PROVIDER)
    page = await context.new_page()
    requests: list[dict[str, Any]] = []
    logs: list[dict[str, str]] = []
    page.on("console", lambda message: logs.append({"type": message.type, "text": message.text}))

    async def route_handler(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        method = request.method.upper()
        item = record(request, "observed", token)
        secret = bool(item["secretMatches"])
        same_origin_secret_get = secret and host == TARGET_HOST and method == "GET"
        telemetry = any(part in host for part in TELEMETRY_PARTS)
        papi_trade = host == "papi.synthetix.io" and parsed.path.lower().endswith("/trade")
        transaction = method == "POST" and any(
            key in (item.get("postData") or "") for key in ("eth_sendTransaction", "eth_sendRawTransaction")
        )
        if same_origin_secret_get:
            item["disposition"] = "allowed-target-same-origin-secret"
            requests.append(item)
            await route.continue_()
            return
        if secret or (telemetry and method != "GET") or papi_trade or transaction:
            item["disposition"] = "intercepted-before-transmission"
            requests.append(item)
            await route.abort("blockedbyclient")
            return
        if telemetry or host == "papi.synthetix.io" or method != "GET":
            requests.append(item)
        await route.continue_()

    await page.route("**/*", route_handler)
    stages: dict[str, Any] = {}
    try:
        await page.goto(BASE_URL, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(8_000)
    except Exception as exc:
        stages["initialError"] = repr(exc)
    for _ in range(4):
        try: await page.keyboard.press("Escape")
        except Exception: pass
    stages["initial"] = await snap(page, "01_initial")
    stages["connect"] = await click_button(page, [r"^connect wallet$", r"connect"])
    await page.wait_for_timeout(4_000)
    stages["modal"] = await snap(page, "02_modal")
    stages["wallet"] = await click_button(page, [r"audit injected wallet", r"audit", r"injected", r"browser wallet", r"metamask"])
    await page.wait_for_timeout(10_000)
    stages["connected"] = await snap(page, "03_connected")
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(30_000)
    except Exception as exc:
        stages["handoffError"] = repr(exc)
    stages["handoff"] = await snap(page, "04_handoff")
    await context.close()

    secret_records = [item for item in requests if item.get("secretMatches")]
    blocked = [item for item in secret_records if item.get("disposition") == "intercepted-before-transmission"]
    segment = [item for item in requests if "segment" in (urllib.parse.urlparse(item["url"]).hostname or "")]
    summary = {
        "safety": "Synthetic wallet/key only; cross-origin secrets, telemetry ingestion, trade requests and transactions blocked before transmission.",
        "stages": stages,
        "requestCount": len(requests),
        "secretRecordCount": len(secret_records),
        "blockedSecretAttemptCount": len(blocked),
        "secretRecords": secret_records,
        "segmentRecordCount": len(segment),
        "segmentRecords": segment,
        "console": logs,
    }
    (OUT / "requests.json").write_text(json.dumps(requests, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({
        "connect": stages.get("connect"), "wallet": stages.get("wallet"),
        "blockedSecretAttemptCount": len(blocked), "segmentRecordCount": len(segment)
    }, indent=2))


async def main() -> None:
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try: await run(browser)
        finally: await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
