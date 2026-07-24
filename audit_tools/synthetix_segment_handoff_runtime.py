#!/usr/bin/env python3
"""Intercepted browser probe for session-handoff exposure after wallet connection.

A deterministic synthetic EIP-1193 wallet and deterministic synthetic handoff
private key are used. Every request containing the synthetic secret, every
telemetry ingestion request, and every PAPI trade request is aborted before
transmission. The probe never signs or broadcasts a transaction.
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

WALLET_ADDRESS = "0x1563915e194D8CfBA1943570603F7606A3115508"
WALLET_PRIVATE_KEY = "0x" + "22" * 32
HANDOFF_PRIVATE_KEY = "0x" + "11" * 32
HANDOFF_ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"
HANDOFF_OWNER = WALLET_ADDRESS
MARKER = "SYNTHETIX_SEGMENT_HANDOFF_MARKER_20260724"
BASE_URL = "https://exchange.synthetix.io/?market=BTC-USDT"

TELEMETRY_HOST_PARTS = (
    "segment.io",
    "segment.com",
    "segmentapis.com",
    "sentry.io",
    "posthog.com",
    "intercom.io",
    "intercomcdn.com",
    "walletconnect.com",
    "walletconnect.org",
    "reown.com",
    "dynamicauth.com",
)


def build_handoff() -> tuple[str, str, dict[str, Any]]:
    now = int(time.time() * 1000)
    payload: dict[str, Any] = {
        "subAccountId": 999_999_999,
        "address": HANDOFF_ADDRESS,
        "walletAddress": HANDOFF_OWNER,
        "privateKey": HANDOFF_PRIVATE_KEY,
        "createdAt": now,
        "expiresAt": now + 30 * 24 * 60 * 60 * 1000,
        "sessionId": MARKER,
        "status": "active",
        "chainId": 1,
        "handoffContext": {"mode": "owned"},
    }
    token = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    url = BASE_URL + "&sessionHandoff=" + urllib.parse.quote(token, safe="")
    return url, token, payload


def secret_matches(blob: str, token: str) -> list[str]:
    needles = {
        "sessionHandoff_name": "sessionHandoff",
        "base64_handoff": token,
        "urlencoded_handoff": urllib.parse.quote(token, safe=""),
        "handoff_private_key": HANDOFF_PRIVATE_KEY,
        "wallet_private_key": WALLET_PRIVATE_KEY,
        "handoff_marker": MARKER,
    }
    return [label for label, needle in needles.items() if needle and needle in blob]


def request_record(request: Request, disposition: str, token: str) -> dict[str, Any]:
    try:
        headers = dict(request.headers)
    except Exception:
        headers = {}
    try:
        post_data = request.post_data
    except Exception:
        post_data = None
    record = {
        "disposition": disposition,
        "method": request.method,
        "url": request.url,
        "resourceType": request.resource_type,
        "headers": headers,
        "postData": post_data,
    }
    record["secretMatches"] = secret_matches(json.dumps(record, sort_keys=True), token)
    return record


PROVIDER_SCRIPT = f"""
(() => {{
  const address = {json.dumps(WALLET_ADDRESS)};
  const listeners = new Map();
  const provider = {{
    isMetaMask: true,
    isConnected: () => true,
    selectedAddress: address,
    chainId: '0x1',
    networkVersion: '1',
    _metamask: {{ isUnlocked: async () => true }},
    request: async (args) => {{
      const method = args && args.method;
      switch (method) {{
        case 'eth_requestAccounts':
        case 'eth_accounts': return [address];
        case 'eth_chainId': return '0x1';
        case 'net_version': return '1';
        case 'wallet_switchEthereumChain':
        case 'wallet_addEthereumChain': return null;
        case 'eth_getBalance': return '0x0';
        case 'eth_blockNumber': return '0x0';
        case 'eth_getTransactionCount': return '0x0';
        case 'eth_estimateGas': return '0x5208';
        case 'eth_gasPrice': return '0x0';
        case 'eth_feeHistory': return {{ oldestBlock: '0x0', baseFeePerGas: ['0x0'], gasUsedRatio: [0], reward: [['0x0']] }};
        case 'eth_call': return '0x';
        case 'personal_sign':
        case 'eth_sign':
        case 'eth_signTypedData':
        case 'eth_signTypedData_v3':
        case 'eth_signTypedData_v4':
          throw new Error('Synthetic probe refuses signing');
        case 'eth_sendTransaction':
        case 'eth_sendRawTransaction':
          throw new Error('Synthetic probe refuses transactions');
        default:
          console.debug('[SyntheticProvider] unsupported', method);
          return null;
      }}
    }},
    on: (event, callback) => {{
      const set = listeners.get(event) || new Set();
      set.add(callback); listeners.set(event, set); return provider;
    }},
    removeListener: (event, callback) => {{
      const set = listeners.get(event); if (set) set.delete(callback); return provider;
    }},
    emit: (event, ...args) => {{
      const set = listeners.get(event); if (set) for (const cb of set) cb(...args);
    }},
  }};
  Object.defineProperty(window, 'ethereum', {{ value: provider, configurable: true }});
  window.__SYNTHETIC_AUDIT_PROVIDER__ = provider;
}})();
"""


async def snapshot(page: Page, name: str) -> dict[str, Any]:
    try:
        data = await page.evaluate(
            """() => ({
              href: location.href,
              search: location.search,
              title: document.title,
              bodyText: document.body.innerText.slice(0, 20000),
              buttons: Array.from(document.querySelectorAll('button')).map((b, i) => ({
                i, text: (b.innerText || b.textContent || '').trim(),
                aria: b.getAttribute('aria-label'), disabled: b.disabled,
                visible: !!(b.offsetWidth || b.offsetHeight || b.getClientRects().length)
              })).filter(x => x.visible).slice(0, 250),
              localStorage: Object.fromEntries(Object.entries(localStorage)),
              sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
              ethereum: !!window.ethereum,
              selectedAddress: window.ethereum && window.ethereum.selectedAddress,
            })"""
        )
    except Exception as exc:
        data = {"error": repr(exc)}
    (OUT / f"{name}.snapshot.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        await page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
    except Exception:
        pass
    return data


async def dismiss_overlays(page: Page) -> None:
    for _ in range(4):
        try:
            await page.keyboard.press("Escape")
            await page.wait_for_timeout(300)
        except Exception:
            pass
    selectors = [
        "button[aria-label='Close']",
        "button[aria-label*='close' i]",
        "button:has-text(\"Got it\")",
        "button:has-text(\"Continue\")",
        "button:has-text(\"Skip\")",
        "button:has-text(\"Dismiss\")",
    ]
    for selector in selectors:
        try:
            loc = page.locator(selector)
            count = await loc.count()
            for index in range(min(count, 5)):
                if await loc.nth(index).is_visible():
                    await loc.nth(index).click(timeout=1500)
                    await page.wait_for_timeout(250)
        except Exception:
            pass


async def click_first(page: Page, patterns: list[str]) -> dict[str, Any]:
    buttons = page.locator("button")
    count = await buttons.count()
    for pattern in patterns:
        rx = re.compile(pattern, re.I)
        for index in range(min(count, 300)):
            button = buttons.nth(index)
            try:
                if not await button.is_visible() or await button.is_disabled():
                    continue
                text = ((await button.inner_text()) or "").strip()
                aria = (await button.get_attribute("aria-label")) or ""
                if rx.search(text) or rx.search(aria):
                    await button.click(timeout=4000)
                    return {"clicked": True, "index": index, "text": text, "aria": aria, "pattern": pattern}
            except Exception:
                continue
    return {"clicked": False, "patterns": patterns}


async def run_probe(browser: Browser) -> dict[str, Any]:
    handoff_url, token, payload = build_handoff()
    (OUT / "fake_payload.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    context = await browser.new_context(
        viewport={"width": 1280, "height": 900},
        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/138 Safari/537.36",
    )
    await context.add_init_script(PROVIDER_SCRIPT)
    page = await context.new_page()

    records: list[dict[str, Any]] = []
    console: list[dict[str, str]] = []
    errors: list[str] = []
    page.on("console", lambda msg: console.append({"type": msg.type, "text": msg.text}))
    page.on("pageerror", lambda exc: errors.append(str(exc)))

    async def route_handler(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        method = request.method.upper()
        path = parsed.path.lower()
        tentative = request_record(request, "observed", token)
        secret = bool(tentative["secretMatches"])
        telemetry = any(part in host for part in TELEMETRY_HOST_PARTS)
        papi_trade = host == "papi.synthetix.io" and path.endswith("/trade")
        transaction_rpc = method == "POST" and any(
            phrase in (tentative.get("postData") or "")
            for phrase in ('eth_sendTransaction', 'eth_sendRawTransaction')
        )
        if secret or (telemetry and method != "GET") or papi_trade or transaction_rpc:
            disposition = "intercepted-before-transmission"
            record = request_record(request, disposition, token)
            records.append(record)
            await route.abort("blockedbyclient")
            return
        if telemetry or host == "papi.synthetix.io" or method != "GET":
            records.append(tentative)
        await route.continue_()

    await page.route("**/*", route_handler)

    stages: dict[str, Any] = {}
    try:
        await page.goto(BASE_URL, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(8_000)
    except Exception as exc:
        stages["initialNavigationError"] = repr(exc)
    stages["initial"] = await snapshot(page, "01_initial")
    await dismiss_overlays(page)
    stages["afterDismiss"] = await snapshot(page, "02_after_dismiss")

    stages["connectClick"] = await click_first(
        page,
        [r"^connect wallet$", r"connect", r"wallet"],
    )
    await page.wait_for_timeout(3_000)
    stages["connectModal"] = await snapshot(page, "03_connect_modal")

    stages["walletOptionClick"] = await click_first(
        page,
        [r"metamask", r"browser wallet", r"injected", r"ethereum wallet", r"wallet"],
    )
    await page.wait_for_timeout(8_000)
    stages["afterWalletOption"] = await snapshot(page, "04_after_wallet_option")

    # If the first click selected a generic tab, make one more precise pass.
    if not stages["walletOptionClick"].get("clicked"):
        stages["walletOptionRetry"] = await click_first(page, [r"metamask", r"injected", r"browser"])
        await page.wait_for_timeout(5_000)

    try:
        await page.goto(handoff_url, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(25_000)
    except Exception as exc:
        stages["handoffNavigationError"] = repr(exc)
    stages["withHandoff"] = await snapshot(page, "05_with_handoff")

    await context.close()

    leak_records = [record for record in records if record.get("secretMatches")]
    segment_records = [
        record for record in records
        if "segment" in (urllib.parse.urlparse(record.get("url", "")).hostname or "").lower()
    ]
    summary = {
        "safety": (
            "Synthetic wallet and handoff key only. Secret-bearing requests, telemetry ingestion, PAPI trade, "
            "and transaction RPC requests were intercepted before transmission."
        ),
        "stages": stages,
        "recordCount": len(records),
        "secretBearingAttemptCount": len(leak_records),
        "secretBearingAttempts": leak_records,
        "segmentRecordCount": len(segment_records),
        "segmentRecords": segment_records,
        "console": console,
        "pageErrors": errors,
    }
    (OUT / "requests.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({
        "connectClick": stages.get("connectClick"),
        "walletOptionClick": stages.get("walletOptionClick"),
        "secretBearingAttemptCount": len(leak_records),
        "segmentRecordCount": len(segment_records),
    }, indent=2))
    return summary


async def main() -> None:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            await run_probe(browser)
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
