#!/usr/bin/env python3
"""Intercepted production-browser probe for Synthetix private WebSocket auth telemetry.

Safety constraints:
- imports a deterministic synthetic session whose owner/subaccount do not exist;
- locally fulfills account-discovery/private-read responses;
- replaces the private trade WebSocket before any network transmission;
- blocks/fulfills all telemetry ingestion, PAPI writes, transaction RPC and private WS;
- never touches a real account, credential, balance, order, position or protocol state;
- persists only hashes, schemas and boolean match metadata, never raw auth signatures/messages.

Goal: determine whether a naturally generated private WebSocket AuthMessage/signature is copied into
Sentry/Segment/PostHog/Intercom telemetry on server rejection, socket close or post-auth subscription
failure. A positive result would expose a replayable session authentication credential independently
of the already-reported sessionHandoff URL issue.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import pathlib
import re
import time
import urllib.parse
from typing import Any

from playwright.async_api import Browser, Page, Request, Route, async_playwright

OUT = pathlib.Path("synthetix_ws_auth_telemetry_runtime")
OUT.mkdir(parents=True, exist_ok=True)

BASE_URL = "https://exchange.synthetix.io/?market=BTC-USDT"
OWNER_WALLET = "0x000000000000000000000000000000000000dEaD"
SESSION_PRIVATE_KEY = "0x" + "11" * 32
SESSION_ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"
ACCOUNT_ID = 9_999_999_991
ACCOUNT_ID_TEXT = str(ACCOUNT_ID)
ACCOUNT_ID_HEX = hex(ACCOUNT_ID)
ERROR_CANARY = "ZDB_WS_AUTH_FAILURE_CANARY_20260727"
SUBSCRIBE_CANARY = "ZDB_WS_SUBSCRIBE_FAILURE_CANARY_20260727"

TELEMETRY_PARTS = (
    "sentry.io",
    "segment.io",
    "segment.com",
    "segmentapis.com",
    "posthog.com",
    "intercom.io",
    "intercomcdn.com",
    "amplitude.com",
    "mixpanel.com",
)

PRIVATE_INFO_ACTIONS = {
    "getSubAccount",
    "getSubAccounts",
    "getPositions",
    "getOpenOrders",
    "getOrderHistory",
    "getTrades",
    "getTradesForPosition",
    "getBalanceUpdates",
    "getFundingPayments",
    "getTransfers",
    "getDelegatedSigners",
    "getDelegationsForDelegate",
    "getWithdrawableAmounts",
    "getFeeRate",
    "getRateLimits",
    "getPortfolio",
    "getPerformanceHistory",
    "getReferral",
    "getSnaxpotMyWinningTickets",
}


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact_text(text: str) -> str:
    text = re.sub(r"0x[a-fA-F0-9]{130}", "<signature>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64}", "<secret-or-hash>", text)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"\b\d{8,}\b", "<large-number>", text)
    return text[:1500]


def response_for_action(action: str | None) -> dict[str, Any] | None:
    if action == "getSubAccountIds":
        return {
            "status": "ok",
            "response": {
                "subAccountIds": [ACCOUNT_ID_TEXT],
                "managedSubAccountIds": [],
                "delegatedSubAccountIds": [],
            },
        }
    if action == "getSubAccount":
        return {
            "status": "ok",
            "response": {
                "subAccountId": ACCOUNT_ID_TEXT,
                "name": "Synthetic Audit Account",
                "walletAddress": OWNER_WALLET,
                "accountValue": "0",
                "availableMargin": "0",
                "totalMargin": "0",
                "collateral": [],
                "positions": [],
            },
        }
    if action == "getWithdrawableAmounts":
        return {"status": "ok", "response": {"items": [], "totalWithdrawableUsdt": "0"}}
    if action == "getFeeRate":
        return {
            "status": "ok",
            "response": {
                "volume14d": "0",
                "makerFeeRate": "0",
                "takerFeeRate": "0",
                "referralDiscountApplied": False,
                "referralDiscount": "0",
                "tiers": [],
            },
        }
    if action == "getRateLimits":
        return {"status": "ok", "response": {"requestsUsed": 0, "requestsCap": 100}}
    if action == "getDelegatedSigners":
        return {"status": "ok", "response": {"delegatedSigners": []}}
    if action == "getDelegationsForDelegate":
        return {"status": "ok", "response": {"delegatedAccounts": []}}
    if action == "getPortfolio":
        return {"status": "ok", "response": {"totalAccountValue": "0", "items": []}}
    if action in PRIVATE_INFO_ACTIONS:
        return {"status": "ok", "response": []}
    return None


def init_script(mode: str) -> str:
    session_storage = {
        "state": {
            "sessionSigners": {},
            "importedSession": {
                "subAccountId": ACCOUNT_ID,
                "address": SESSION_ADDRESS,
                "walletAddress": OWNER_WALLET,
                "privateKey": SESSION_PRIVATE_KEY,
                "createdAt": int(time.time() * 1000),
                "expiresAt": int((time.time() + 86400 * 30) * 1000),
                "sessionId": "ZDB_SYNTHETIC_WS_AUTH_SESSION",
                "status": "active",
                "chainId": 1,
            },
        },
        "version": 4,
    }
    selected = {
        "state": {"selectedAccountIds": {OWNER_WALLET.lower(): ACCOUNT_ID}},
        "version": 0,
    }
    delegate_mode = {
        "state": {
            "selectedDelegatedAccount": None,
            "delegateWallet": None,
            "accountCreationContext": None,
        },
        "version": 1,
    }
    return f"""
(() => {{
  const MODE = {json.dumps(mode)};
  const AUTH_ERROR = {json.dumps(ERROR_CANARY)};
  const SUB_ERROR = {json.dumps(SUBSCRIBE_CANARY)};
  const state = {{
    mode: MODE,
    sockets: [],
    authFrames: [],
    subscriptionFrames: [],
    errors: [],
    unhandled: [],
  }};
  Object.defineProperty(window, '__zdbWsAuthAudit', {{ value: state, configurable: false }});
  window.addEventListener('error', (event) => state.errors.push(String(event.error || event.message || 'error')));
  window.addEventListener('unhandledrejection', (event) => state.unhandled.push(String(event.reason || 'rejection')));

  try {{
    localStorage.setItem('session-storage', {json.dumps(json.dumps(session_storage, separators=(',', ':')))});
    localStorage.setItem('selected-account-storage', {json.dumps(json.dumps(selected, separators=(',', ':')))});
    localStorage.setItem('delegate-mode-storage', {json.dumps(json.dumps(delegate_mode, separators=(',', ':')))});
  }} catch (error) {{ state.errors.push('storage:' + String(error)); }}

  const RealWebSocket = window.WebSocket;
  class FakeTradeWebSocket extends EventTarget {{
    constructor(url, protocols) {{
      super();
      this.url = String(url);
      this.protocols = protocols;
      this.readyState = FakeTradeWebSocket.CONNECTING;
      this.bufferedAmount = 0;
      this.extensions = '';
      this.protocol = '';
      this.binaryType = 'blob';
      this.onopen = null;
      this.onmessage = null;
      this.onerror = null;
      this.onclose = null;
      state.sockets.push({{ url: this.url, mode: MODE }});
      setTimeout(() => {{
        this.readyState = FakeTradeWebSocket.OPEN;
        const event = new Event('open');
        this.dispatchEvent(event);
        if (typeof this.onopen === 'function') this.onopen(event);
      }}, 10);
    }}
    send(data) {{
      const raw = typeof data === 'string' ? data : String(data);
      let parsed = null;
      try {{ parsed = JSON.parse(raw); }} catch (_) {{}}
      if (parsed && parsed.method === 'auth') {{
        state.authFrames.push({{
          raw,
          id: String(parsed.id || ''),
          message: parsed.params && parsed.params.message,
          signature: parsed.params && parsed.params.signature,
        }});
        if (MODE === 'auth_401') {{
          setTimeout(() => this._message({{
            id: String(parsed.id || ''),
            status: 401,
            error: {{ message: AUTH_ERROR }},
          }}), 30);
        }} else if (MODE === 'socket_close') {{
          setTimeout(() => this._close(4401, AUTH_ERROR), 30);
        }} else if (MODE === 'auth_success_subscribe_error') {{
          setTimeout(() => this._message({{
            id: String(parsed.id || ''),
            status: 200,
            result: {{ status: 'authenticated' }},
          }}), 30);
        }}
      }} else if (parsed && parsed.method === 'subscribe') {{
        state.subscriptionFrames.push({{ raw, type: parsed.params && parsed.params.type }});
        if (MODE === 'auth_success_subscribe_error') {{
          setTimeout(() => this._message({{
            id: String(parsed.id || ''),
            status: 400,
            error: {{ message: SUB_ERROR }},
          }}), 30);
        }}
      }}
    }}
    close(code = 1000, reason = '') {{ this._close(code, reason); }}
    _message(payload) {{
      if (this.readyState !== FakeTradeWebSocket.OPEN) return;
      const event = new MessageEvent('message', {{ data: JSON.stringify(payload) }});
      this.dispatchEvent(event);
      if (typeof this.onmessage === 'function') this.onmessage(event);
    }}
    _close(code, reason) {{
      if (this.readyState === FakeTradeWebSocket.CLOSED) return;
      this.readyState = FakeTradeWebSocket.CLOSED;
      const event = new CloseEvent('close', {{ code, reason, wasClean: false }});
      this.dispatchEvent(event);
      if (typeof this.onclose === 'function') this.onclose(event);
    }}
  }}
  FakeTradeWebSocket.CONNECTING = 0;
  FakeTradeWebSocket.OPEN = 1;
  FakeTradeWebSocket.CLOSING = 2;
  FakeTradeWebSocket.CLOSED = 3;

  function AuditWebSocket(url, protocols) {{
    if (String(url).includes('papi.synthetix.io/v1/ws/trade')) {{
      return new FakeTradeWebSocket(url, protocols);
    }}
    return protocols === undefined ? new RealWebSocket(url) : new RealWebSocket(url, protocols);
  }}
  AuditWebSocket.prototype = RealWebSocket.prototype;
  AuditWebSocket.CONNECTING = RealWebSocket.CONNECTING;
  AuditWebSocket.OPEN = RealWebSocket.OPEN;
  AuditWebSocket.CLOSING = RealWebSocket.CLOSING;
  AuditWebSocket.CLOSED = RealWebSocket.CLOSED;
  window.WebSocket = AuditWebSocket;
}})();
"""


async def click_if_visible(page: Page, selector: str) -> bool:
    try:
        locator = page.locator(selector)
        count = min(await locator.count(), 20)
        for index in range(count):
            item = locator.nth(index)
            if await item.is_visible() and not await item.is_disabled():
                await item.click(timeout=4000)
                return True
    except Exception:
        return False
    return False


async def run_case(browser: Browser, mode: str) -> dict[str, Any]:
    context = await browser.new_context(viewport={"width": 1365, "height": 900})
    await context.add_init_script(init_script(mode))
    page = await context.new_page()

    telemetry_bodies: list[dict[str, Any]] = []
    network: list[dict[str, Any]] = []
    console: list[dict[str, str]] = []
    page_errors: list[str] = []
    page.on("console", lambda message: console.append({"type": message.type, "text": message.text[:4000]}))
    page.on("pageerror", lambda error: page_errors.append(str(error)[:4000]))

    async def route_handler(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        path = parsed.path
        method = request.method.upper()
        try:
            post_data = request.post_data or ""
        except Exception:
            post_data = ""

        telemetry = any(part in host for part in TELEMETRY_PARTS)
        if telemetry and method in {"POST", "PUT", "PATCH"}:
            telemetry_bodies.append(
                {
                    "method": method,
                    "host": host,
                    "path": path,
                    "resourceType": request.resource_type,
                    "body": post_data,
                }
            )
            await route.fulfill(status=204, body="", headers={"Access-Control-Allow-Origin": "*"})
            return

        if host == "papi.synthetix.io" and path.endswith("/trade"):
            network.append({"method": method, "host": host, "path": path, "blocked": True})
            await route.fulfill(
                status=403,
                content_type="application/json",
                body=json.dumps({"status": "error", "error": {"message": "synthetic write blocked"}}),
            )
            return

        if host == "papi.synthetix.io" and path.endswith("/info") and method == "POST":
            action = None
            try:
                payload = json.loads(post_data)
                params = payload.get("params") if isinstance(payload, dict) else None
                action = params.get("action") if isinstance(params, dict) else None
            except Exception:
                pass
            synthetic = response_for_action(action)
            network.append({"method": method, "host": host, "path": path, "action": action, "synthetic": synthetic is not None})
            if synthetic is not None:
                await route.fulfill(
                    status=200,
                    content_type="application/json",
                    body=json.dumps(synthetic, separators=(",", ":")),
                    headers={"Access-Control-Allow-Origin": "https://exchange.synthetix.io"},
                )
                return

        if host == "papi.synthetix.io" and path.endswith("/status"):
            await route.fulfill(
                status=200,
                content_type="application/json",
                body='{"exchange_status":"RUNNING","timestamp_ms":0}',
                headers={"Access-Control-Allow-Origin": "https://exchange.synthetix.io"},
            )
            return

        # Never allow transaction RPC methods.
        if "eth_sendTransaction" in post_data or "eth_sendRawTransaction" in post_data:
            network.append({"method": method, "host": host, "path": path, "transactionRpcBlocked": True})
            await route.abort("blockedbyclient")
            return

        await route.continue_()

    await page.route("**/*", route_handler)

    navigation_error = None
    try:
        await page.goto(BASE_URL, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(18_000)
        await click_if_visible(page, 'button[aria-label="Dismiss announcements"]')
        await page.wait_for_timeout(5_000)
    except Exception as exc:
        navigation_error = f"{type(exc).__name__}: {exc}"

    runtime = await page.evaluate(
        """() => {
          const s = window.__zdbWsAuthAudit || {};
          return {
            mode: s.mode,
            sockets: s.sockets || [],
            authFrames: s.authFrames || [],
            subscriptionFrames: s.subscriptionFrames || [],
            errors: s.errors || [],
            unhandled: s.unhandled || [],
            href: location.href,
            text: (document.body && document.body.innerText || '').slice(0, 10000),
            localStorageKeys: Object.keys(localStorage).sort(),
          };
        }"""
    )

    auth_frames = runtime.pop("authFrames", [])
    subscription_frames = runtime.pop("subscriptionFrames", [])
    auth = auth_frames[0] if auth_frames else {}
    auth_message = str(auth.get("message") or "")
    signature = str(auth.get("signature") or "")
    try:
        auth_parsed = json.loads(auth_message) if auth_message else None
    except Exception:
        auth_parsed = None

    candidate_tokens: dict[str, str] = {
        "authSignature": signature,
        "authMessage": auth_message,
        "authMessageBase64": base64.b64encode(auth_message.encode()).decode() if auth_message else "",
        "sessionPrivateKey": SESSION_PRIVATE_KEY,
        "sessionPrivateKeyNoPrefix": SESSION_PRIVATE_KEY[2:],
        "sessionAddress": SESSION_ADDRESS,
        "ownerWallet": OWNER_WALLET,
        "accountIdDecimal": ACCOUNT_ID_TEXT,
        "accountIdHex": ACCOUNT_ID_HEX,
        "authFailureCanary": ERROR_CANARY,
        "subscribeFailureCanary": SUBSCRIBE_CANARY,
    }

    aggregate: dict[str, list[int]] = {key: [] for key in candidate_tokens}
    telemetry_summary: list[dict[str, Any]] = []
    for index, item in enumerate(telemetry_bodies):
        body = item.pop("body")
        matches: dict[str, bool] = {}
        for key, token in candidate_tokens.items():
            found = bool(token) and token.lower() in body.lower()
            matches[key] = found
            if found:
                aggregate[key].append(index)
        telemetry_summary.append(
            {
                **item,
                "bodyBytes": len(body.encode()),
                "bodySha256": digest(body),
                "matches": matches,
                "authLiteral": "AuthMessage" in body,
                "websocketAuthLiteral": "websocket_auth" in body,
            }
        )

    console_text = "\n".join(item["text"] for item in console)
    console_matches = {key: bool(token) and token.lower() in console_text.lower() for key, token in candidate_tokens.items()}
    page_error_text = "\n".join(page_errors)
    page_error_matches = {key: bool(token) and token.lower() in page_error_text.lower() for key, token in candidate_tokens.items()}

    result = {
        "mode": mode,
        "safety": "Synthetic imported session and fake account; private WS and telemetry intercepted before transmission; PAPI writes blocked.",
        "navigationError": navigation_error,
        "runtime": {
            **runtime,
            "text": redact_text(runtime.get("text", "")),
            "errors": [redact_text(str(x)) for x in runtime.get("errors", [])],
            "unhandled": [redact_text(str(x)) for x in runtime.get("unhandled", [])],
        },
        "authFrameCount": len(auth_frames),
        "subscriptionFrameCount": len(subscription_frames),
        "auth": {
            "signaturePresent": bool(signature),
            "signatureSha256": digest(signature) if signature else None,
            "messagePresent": bool(auth_message),
            "messageSha256": digest(auth_message) if auth_message else None,
            "messagePrimaryType": auth_parsed.get("primaryType") if isinstance(auth_parsed, dict) else None,
            "messageDomain": auth_parsed.get("domain") if isinstance(auth_parsed, dict) else None,
            "messageKeys": sorted((auth_parsed.get("message") or {}).keys()) if isinstance(auth_parsed, dict) and isinstance(auth_parsed.get("message"), dict) else [],
            "messageAction": (auth_parsed.get("message") or {}).get("action") if isinstance(auth_parsed, dict) and isinstance(auth_parsed.get("message"), dict) else None,
            "messageTimestamp": (auth_parsed.get("message") or {}).get("timestamp") if isinstance(auth_parsed, dict) and isinstance(auth_parsed.get("message"), dict) else None,
            "messageSubAccountId": str((auth_parsed.get("message") or {}).get("subAccountId")) if isinstance(auth_parsed, dict) and isinstance(auth_parsed.get("message"), dict) else None,
        },
        "telemetryRequestCount": len(telemetry_summary),
        "telemetryAggregateMatches": aggregate,
        "telemetry": telemetry_summary,
        "console": [{"type": item["type"], "text": redact_text(item["text"])} for item in console[-100:]],
        "consoleMatches": console_matches,
        "pageErrors": [redact_text(x) for x in page_errors],
        "pageErrorMatches": page_error_matches,
        "network": network,
    }
    await context.close()
    return result


async def main() -> None:
    modes = ("auth_401", "socket_close", "auth_success_subscribe_error")
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            cases = []
            for mode in modes:
                cases.append(await run_case(browser, mode))
        finally:
            await browser.close()

    positive = []
    for case in cases:
        matches = case["telemetryAggregateMatches"]
        if matches["authSignature"] or matches["authMessage"] or matches["authMessageBase64"] or matches["sessionPrivateKey"] or matches["sessionPrivateKeyNoPrefix"]:
            positive.append(case["mode"])

    verdict = "AUTH_CREDENTIAL_TELEMETRY_MATCH" if positive else "NO_AUTH_CREDENTIAL_TELEMETRY_MATCH"
    output = {"verdict": verdict, "positiveModes": positive, "cases": cases}
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "verdict": verdict,
                "positiveModes": positive,
                "cases": [
                    {
                        "mode": case["mode"],
                        "authFrameCount": case["authFrameCount"],
                        "subscriptionFrameCount": case["subscriptionFrameCount"],
                        "telemetryRequestCount": case["telemetryRequestCount"],
                        "matches": case["telemetryAggregateMatches"],
                    }
                    for case in cases
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
