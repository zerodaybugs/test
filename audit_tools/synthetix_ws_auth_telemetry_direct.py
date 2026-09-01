#!/usr/bin/env python3
"""Direct production-bundle WebSocket auth telemetry differential for Synthetix Exchange.

This harness imports the already-loaded production entry module and invokes its real
WebSocketManager singleton with a deterministic, correctly signed synthetic AuthMessage.
The private WebSocket is replaced before transmission and telemetry ingestion is intercepted.
No real account, credential, balance, order, position, subscription or protocol state is touched.
Raw auth messages/signatures are retained only in memory and never written to the artifact.
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

from eth_account import Account
from eth_account.messages import encode_typed_data
from playwright.async_api import Browser, Page, Request, Route, async_playwright

OUT = pathlib.Path("synthetix_ws_auth_telemetry_direct")
OUT.mkdir(parents=True, exist_ok=True)

BASE_URL = "https://exchange.synthetix.io/?market=BTC-USDT"
ENTRY_URL = "https://exchange.synthetix.io/assets/index-BJrW6h18.js"
PRIVATE_KEY = "0x" + "11" * 32
ACCOUNT = Account.from_key(PRIVATE_KEY)
OWNER_WALLET = ACCOUNT.address
SUBACCOUNT_ID = 8_800_000_000_000_321
AUTH_ERROR = "ZDB_DIRECT_WS_AUTH_REJECT_20260727"
SUB_ERROR = "ZDB_DIRECT_WS_SUBSCRIBE_REJECT_20260727"
FLUSH_ERROR = "ZDB_DIRECT_SENTRY_FLUSH_CONTROL_20260727"
ZERO = "0x0000000000000000000000000000000000000000"

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


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(text: str) -> str:
    text = re.sub(r"0x[a-fA-F0-9]{130}", "<signature>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64}", "<secret-or-hash>", text)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"\b\d{10,}\b", "<large-number>", text)
    return text[:1800]


def signed_credentials() -> tuple[str, str, dict[str, Any]]:
    timestamp = int(time.time())
    domain = {"name": "Synthetix", "version": "1", "chainId": 1, "verifyingContract": ZERO}
    message = {"subAccountId": SUBACCOUNT_ID, "timestamp": str(timestamp), "action": "WebSocketAuth"}
    types = {
        "AuthMessage": [
            {"name": "subAccountId", "type": "uint256"},
            {"name": "timestamp", "type": "uint256"},
            {"name": "action", "type": "string"},
        ]
    }
    encoded = encode_typed_data(
        full_message={"types": types, "primaryType": "AuthMessage", "domain": domain, "message": message}
    )
    signed = ACCOUNT.sign_message(encoded)
    signature = "0x" + format(signed.r, "064x") + format(signed.s, "064x") + format(signed.v, "02x")
    payload = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "AuthMessage": types["AuthMessage"],
        },
        "primaryType": "AuthMessage",
        "domain": {"name": "Synthetix", "version": "1", "chainId": "0x1", "verifyingContract": ZERO},
        "message": {"subAccountId": SUBACCOUNT_ID, "timestamp": str(timestamp), "action": "WebSocketAuth"},
    }
    return json.dumps(payload, separators=(",", ":")), signature, payload


def websocket_init(mode: str) -> str:
    return f"""
(() => {{
  const MODE = {json.dumps(mode)};
  const AUTH_ERROR = {json.dumps(AUTH_ERROR)};
  const SUB_ERROR = {json.dumps(SUB_ERROR)};
  const state = {{ mode: MODE, sockets: [], authFrames: [], subscribeFrames: [], errors: [], unhandled: [] }};
  Object.defineProperty(window, '__zdbDirectWsAudit', {{ value: state, configurable: false }});
  window.addEventListener('error', e => state.errors.push(String(e.error || e.message || 'error')));
  window.addEventListener('unhandledrejection', e => state.unhandled.push(String(e.reason || 'rejection')));

  const RealWebSocket = window.WebSocket;
  class FakeTradeSocket extends EventTarget {{
    constructor(url, protocols) {{
      super();
      this.url = String(url); this.protocols = protocols; this.readyState = 0;
      this.bufferedAmount = 0; this.extensions = ''; this.protocol = ''; this.binaryType = 'blob';
      this.onopen = null; this.onmessage = null; this.onerror = null; this.onclose = null;
      state.sockets.push({{ url: this.url }});
      setTimeout(() => {{ this.readyState = 1; const e = new Event('open'); this.dispatchEvent(e); if (this.onopen) this.onopen(e); }}, 10);
    }}
    send(data) {{
      const raw = typeof data === 'string' ? data : String(data);
      let value = null; try {{ value = JSON.parse(raw); }} catch (_) {{}}
      if (value && value.method === 'auth') {{
        state.authFrames.push({{ raw, id: String(value.id || ''), message: value.params && value.params.message, signature: value.params && value.params.signature }});
        if (MODE.includes('auth_401')) setTimeout(() => this._message({{ id: String(value.id || ''), status: 401, error: {{ message: AUTH_ERROR }} }}), 25);
        else if (MODE.includes('socket_close')) setTimeout(() => this._close(4401, AUTH_ERROR), 25);
        else if (MODE.includes('success_subscribe')) setTimeout(() => this._message({{ id: String(value.id || ''), status: 200, result: {{ status: 'authenticated' }} }}), 25);
      }} else if (value && value.method === 'subscribe') {{
        state.subscribeFrames.push({{ raw, id: String(value.id || ''), type: value.params && value.params.type }});
        if (MODE.includes('success_subscribe')) setTimeout(() => this._message({{ id: String(value.id || ''), status: 400, error: {{ message: SUB_ERROR }} }}), 25);
      }}
    }}
    close(code = 1000, reason = '') {{ this._close(code, reason); }}
    _message(value) {{ if (this.readyState !== 1) return; const e = new MessageEvent('message', {{data: JSON.stringify(value)}}); this.dispatchEvent(e); if (this.onmessage) this.onmessage(e); }}
    _close(code, reason) {{ if (this.readyState === 3) return; this.readyState = 3; const e = new CloseEvent('close', {{code, reason, wasClean:false}}); this.dispatchEvent(e); if (this.onclose) this.onclose(e); }}
  }}
  FakeTradeSocket.CONNECTING = 0; FakeTradeSocket.OPEN = 1; FakeTradeSocket.CLOSING = 2; FakeTradeSocket.CLOSED = 3;
  function AuditWebSocket(url, protocols) {{
    if (String(url).includes('papi.synthetix.io/v1/ws/trade')) return new FakeTradeSocket(url, protocols);
    return protocols === undefined ? new RealWebSocket(url) : new RealWebSocket(url, protocols);
  }}
  AuditWebSocket.prototype = RealWebSocket.prototype;
  AuditWebSocket.CONNECTING = RealWebSocket.CONNECTING; AuditWebSocket.OPEN = RealWebSocket.OPEN;
  AuditWebSocket.CLOSING = RealWebSocket.CLOSING; AuditWebSocket.CLOSED = RealWebSocket.CLOSED;
  window.WebSocket = AuditWebSocket;
}})();
"""


async def run_case(browser: Browser, mode: str, auth_message: str, signature: str) -> dict[str, Any]:
    context = await browser.new_context(viewport={"width": 1280, "height": 800})
    await context.add_init_script(websocket_init(mode))
    page = await context.new_page()

    telemetry: list[dict[str, Any]] = []
    network: list[dict[str, Any]] = []
    console: list[dict[str, str]] = []
    page_errors: list[str] = []
    page.on("console", lambda msg: console.append({"type": msg.type, "text": msg.text[:5000]}))
    page.on("pageerror", lambda err: page_errors.append(str(err)[:5000]))

    async def route_handler(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        method = request.method.upper()
        try:
            body = request.post_data or ""
        except Exception:
            body = ""
        if any(part in host for part in TELEMETRY_PARTS) and method in {"POST", "PUT", "PATCH"}:
            telemetry.append({"method": method, "host": host, "path": parsed.path, "resourceType": request.resource_type, "body": body})
            await route.fulfill(status=204, body="", headers={"Access-Control-Allow-Origin": "*"})
            return
        if host == "papi.synthetix.io" and parsed.path.endswith("/trade"):
            network.append({"method": method, "host": host, "path": parsed.path, "blocked": True})
            await route.fulfill(status=403, content_type="application/json", body='{"status":"error"}')
            return
        if "eth_sendTransaction" in body or "eth_sendRawTransaction" in body:
            network.append({"method": method, "host": host, "path": parsed.path, "transactionRpcBlocked": True})
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    await page.route("**/*", route_handler)
    nav_error = None
    invoke_result: dict[str, Any] = {}
    try:
        await page.goto(BASE_URL, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(6500)
        invoke_result = await page.evaluate(
            """async ({entryUrl, accountId, walletAddress, authMessage, signature, flush, flushError}) => {
              const mod = await import(entryUrl);
              const services = mod.I();
              const manager = services.accountService.webSocketManager;
              manager.clearAuth();
              manager.setAuthProvider({
                requestAuth: async () => ({message: authMessage, signature}),
                isAuthValid: () => true,
              });
              let result = 'resolved';
              let error = null;
              try {
                await manager.initializeTradeStream(accountId, walletAddress);
              } catch (e) {
                result = 'rejected';
                error = String(e && (e.message || e));
              }
              await new Promise(r => setTimeout(r, 1200));
              if (flush) setTimeout(() => { throw new Error(flushError); }, 0);
              return {result, error, moduleKeys: Object.keys(mod).sort(), hasServices: !!services.accountService, connectionState: manager.getConnectionState()};
            }""",
            {
                "entryUrl": ENTRY_URL,
                "accountId": SUBACCOUNT_ID,
                "walletAddress": OWNER_WALLET,
                "authMessage": auth_message,
                "signature": signature,
                "flush": mode.endswith("_flush"),
                "flushError": FLUSH_ERROR,
            },
        )
        await page.wait_for_timeout(7000)
    except Exception as exc:
        nav_error = f"{type(exc).__name__}: {exc}"

    runtime = await page.evaluate(
        """() => {
          const s = window.__zdbDirectWsAudit || {};
          return {mode:s.mode, sockets:s.sockets||[], authFrames:s.authFrames||[], subscribeFrames:s.subscribeFrames||[], errors:s.errors||[], unhandled:s.unhandled||[]};
        }"""
    )
    frames = runtime.pop("authFrames", [])
    subs = runtime.pop("subscribeFrames", [])
    captured = frames[0] if frames else {}
    captured_message = str(captured.get("message") or "")
    captured_signature = str(captured.get("signature") or "")

    tokens = {
        "signature": signature,
        "authMessage": auth_message,
        "authMessageBase64": base64.b64encode(auth_message.encode()).decode(),
        "privateKey": PRIVATE_KEY,
        "privateKeyNoPrefix": PRIVATE_KEY[2:],
        "walletAddress": OWNER_WALLET,
        "subAccountDecimal": str(SUBACCOUNT_ID),
        "subAccountHex": hex(SUBACCOUNT_ID),
        "authError": AUTH_ERROR,
        "subscribeError": SUB_ERROR,
        "flushError": FLUSH_ERROR,
    }
    aggregate = {key: [] for key in tokens}
    telemetry_summary = []
    for index, item in enumerate(telemetry):
        body = item.pop("body")
        matches = {}
        for key, token in tokens.items():
            found = token.lower() in body.lower()
            matches[key] = found
            if found:
                aggregate[key].append(index)
        telemetry_summary.append({**item, "bodyBytes":len(body.encode()), "bodySha256":digest(body), "matches":matches, "authLiteral":"AuthMessage" in body, "websocketAuthLiteral":"WebSocketAuth" in body})

    console_text = "\n".join(item["text"] for item in console)
    page_error_text = "\n".join(page_errors)
    result = {
        "mode": mode,
        "safety": "Production module and manager; synthetic signed auth; private WS and telemetry intercepted before transmission.",
        "navigationError": nav_error,
        "invoke": {**invoke_result, "error": redact(str(invoke_result.get("error") or ""))},
        "runtime": {**runtime, "errors":[redact(str(x)) for x in runtime.get("errors",[])], "unhandled":[redact(str(x)) for x in runtime.get("unhandled",[])]},
        "authFrameCount": len(frames),
        "subscribeFrameCount": len(subs),
        "capturedMatchesInput": {"message": captured_message == auth_message, "signature": captured_signature.lower() == signature.lower()},
        "authHashes": {"inputMessage":digest(auth_message), "inputSignature":digest(signature), "capturedMessage":digest(captured_message) if captured_message else None, "capturedSignature":digest(captured_signature) if captured_signature else None},
        "telemetryRequestCount": len(telemetry_summary),
        "telemetryAggregateMatches": aggregate,
        "telemetry": telemetry_summary,
        "consoleMatches": {key: token.lower() in console_text.lower() for key,token in tokens.items()},
        "pageErrorMatches": {key: token.lower() in page_error_text.lower() for key,token in tokens.items()},
        "console": [{"type":item["type"],"text":redact(item["text"])} for item in console[-120:]],
        "pageErrors": [redact(x) for x in page_errors],
        "network": network,
    }
    await context.close()
    return result


async def main() -> None:
    auth_message, signature, payload = signed_credentials()
    modes = (
        "auth_401_natural",
        "auth_401_flush",
        "socket_close_natural",
        "success_subscribe_natural",
        "success_subscribe_flush",
    )
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            cases = [await run_case(browser, mode, auth_message, signature) for mode in modes]
        finally:
            await browser.close()

    positive = []
    for case in cases:
        matches = case["telemetryAggregateMatches"]
        if matches["signature"] or matches["authMessage"] or matches["authMessageBase64"] or matches["privateKey"] or matches["privateKeyNoPrefix"]:
            positive.append(case["mode"])
    output = {
        "verdict": "AUTH_CREDENTIAL_TELEMETRY_MATCH" if positive else "NO_AUTH_CREDENTIAL_TELEMETRY_MATCH",
        "positiveModes": positive,
        "authSchema": {"primaryType":payload["primaryType"], "domain":payload["domain"], "messageKeys":sorted(payload["message"].keys()), "action":payload["message"]["action"]},
        "cases": cases,
    }
    (OUT / "summary.json").write_text(json.dumps(output,indent=2,sort_keys=True),encoding="utf-8")
    print(json.dumps({"verdict":output["verdict"],"positiveModes":positive,"cases":[{"mode":c["mode"],"authFrameCount":c["authFrameCount"],"subscribeFrameCount":c["subscribeFrameCount"],"telemetryRequestCount":c["telemetryRequestCount"],"matches":c["telemetryAggregateMatches"],"invoke":c["invoke"]} for c in cases]},indent=2))


if __name__ == "__main__":
    asyncio.run(main())
