#!/usr/bin/env python3
"""Browser-enforced Dynamic origin/OAuth probe for the Synthetix environment.

Safety constraints:
- no OTP request, login, user creation, wallet creation, signature, transaction, or key operation;
- only public settings/passkey-option GETs and ephemeral OAuth state initialization/polling;
- randomized states and non-resolving attacker callback URL;
- response bodies are reduced to schemas, selected public fields, sizes, and hashes.
"""
from __future__ import annotations

import asyncio
import hashlib
import http.server
import json
import pathlib
import secrets
import socketserver
import threading
from typing import Any

from playwright.async_api import BrowserContext, Page, async_playwright

OUT = pathlib.Path("dynamic_browser_origin")
OUT.mkdir(parents=True, exist_ok=True)

CURRENT_ENV = "d5f379e2-ec2d-4e7c-b541-8117684d3e98"
REDIRECT_ENV = "dca95954-81d8-4ef8-b20f-b1c3b6781cb6"
API = "https://app.dynamicauth.com/api/v0"
EXCHANGE = "https://exchange.synthetix.io/"


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 5:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def find_key(value: Any, wanted: set[str], path: str = "") -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            next_path = f"{path}.{key}" if path else str(key)
            if str(key).lower() in wanted:
                if str(key).lower() == "challenge" and isinstance(item, str):
                    selected: Any = {"sha256": digest(item), "length": len(item)}
                elif str(key).lower() in {"allowcredentials", "excludecredentials"} and isinstance(item, list):
                    selected = {"count": len(item)}
                elif isinstance(item, (str, int, float, bool)) or item is None:
                    selected = item
                else:
                    selected = schema(item)
                found.append({"path": next_path, "value": selected})
            found.extend(find_key(item, wanted, next_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(find_key(item, wanted, f"{path}[{index}]"))
    return found


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        body = b"<!doctype html><meta charset=utf-8><title>controlled origin</title>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


async def raw_fetch(page: Page, url: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    result = await page.evaluate(
        """
        async ({url, options}) => {
          try {
            const response = await fetch(url, options || {});
            const text = await response.text();
            return {
              succeeded: true,
              status: response.status,
              ok: response.ok,
              redirected: response.redirected,
              finalUrl: response.url,
              responseType: response.type,
              text,
            };
          } catch (error) {
            return {
              succeeded: false,
              errorName: error && error.name ? String(error.name) : null,
              errorMessage: error && error.message ? String(error.message).slice(0, 500) : String(error).slice(0, 500),
            };
          }
        }
        """,
        {"url": url, "options": options or {}},
    )
    text = result.pop("text", None)
    if isinstance(text, str):
        result["bodyBytes"] = len(text.encode())
        result["bodySha256"] = digest(text)
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
        result["jsonSchema"] = schema(parsed) if parsed is not None else None
        result["json"] = parsed
    return result


def reduce_settings(item: dict[str, Any]) -> dict[str, Any]:
    parsed = item.pop("json", None)
    if isinstance(parsed, dict):
        sdk = parsed.get("sdk") if isinstance(parsed.get("sdk"), dict) else {}
        embedded = sdk.get("embeddedWallets") if isinstance(sdk.get("embeddedWallets"), dict) else {}
        security = parsed.get("security") if isinstance(parsed.get("security"), dict) else {}
        mfa = security.get("mfa") if isinstance(security.get("mfa"), dict) else {}
        item["selected"] = {
            "environmentName": parsed.get("environmentName"),
            "environmentLocked": security.get("environmentLocked"),
            "automaticEmbeddedWalletCreation": sdk.get("automaticEmbeddedWalletCreation"),
            "embeddedWalletVersion": embedded.get("defaultWalletVersion"),
            "domainEnabledByProvider": embedded.get("domainEnabledByProvider"),
            "forceAuthenticatorAtSignup": embedded.get("forceAuthenticatorAtSignup"),
            "allowSkippingAuthenticatorAtSignup": embedded.get("allowSkippingAuthenticatorAtSignup"),
            "exportDisabled": ((sdk.get("waas") or {}).get("exportDisabled") if isinstance(sdk.get("waas"), dict) else None),
            "mfaEnabled": mfa.get("enabled"),
            "mfaRequired": mfa.get("required"),
        }
    return item


def reduce_passkey(item: dict[str, Any]) -> dict[str, Any]:
    parsed = item.pop("json", None)
    if parsed is not None:
        item["selectedFields"] = find_key(
            parsed,
            {
                "rpid",
                "rp",
                "challenge",
                "userverification",
                "timeout",
                "allowcredentials",
                "excludecredentials",
            },
        )
    return item


def reduce_oauth(item: dict[str, Any]) -> dict[str, Any]:
    parsed = item.pop("json", None)
    if isinstance(parsed, dict):
        error = parsed.get("error")
        item["selected"] = {
            "status": parsed.get("status"),
            "code": parsed.get("code"),
            "resultStatus": ((parsed.get("response") or {}).get("status") if isinstance(parsed.get("response"), dict) else None),
            "errorCode": error.get("code") if isinstance(error, dict) else None,
            "errorCategory": error.get("category") if isinstance(error, dict) else None,
        }
    return item


async def collect_origin(
    context: BrowserContext,
    *,
    label: str,
    page_url: str,
    callback_url: str,
    network_headers: list[dict[str, Any]],
) -> dict[str, Any]:
    page = await context.new_page()

    async def on_response(response: Any) -> None:
        if not response.url.startswith(API):
            return
        try:
            headers = {str(key).lower(): str(value) for key, value in (await response.all_headers()).items()}
        except Exception:
            headers = {}
        network_headers.append(
            {
                "originLabel": label,
                "url": response.url,
                "status": response.status,
                "accessControlAllowOrigin": headers.get("access-control-allow-origin"),
                "accessControlAllowCredentials": headers.get("access-control-allow-credentials"),
                "accessControlAllowMethods": headers.get("access-control-allow-methods"),
                "accessControlAllowHeaders": headers.get("access-control-allow-headers"),
                "vary": headers.get("vary"),
                "setCookieNames": sorted(
                    {
                        piece.split("=", 1)[0].strip()
                        for piece in headers.get("set-cookie", "").split("\n")
                        if "=" in piece
                    }
                ),
            }
        )

    page.on("response", on_response)
    await page.goto(page_url, wait_until="domcontentloaded", timeout=90_000)

    result: dict[str, Any] = {"label": label, "pageUrl": page.url, "pageOrigin": await page.evaluate("location.origin")}
    for environment_id in (CURRENT_ENV, REDIRECT_ENV):
        settings = await raw_fetch(
            page,
            f"{API}/sdk/{environment_id}/settings",
            {"method": "GET", "credentials": "include", "headers": {"Accept": "application/json"}},
        )
        result[f"settings_{environment_id}"] = reduce_settings(settings)

        passkey_cases: list[dict[str, Any]] = []
        for related_rp in (None, "exchange.synthetix.io", "attacker.invalid", "app.dynamicauth.com"):
            suffix = "" if related_rp is None else "?relatedOriginRpId=" + related_rp
            item = await raw_fetch(
                page,
                f"{API}/sdk/{environment_id}/users/passkeys/signin{suffix}",
                {"method": "GET", "credentials": "include", "headers": {"Accept": "application/json"}},
            )
            item["relatedOriginRpId"] = related_rp
            passkey_cases.append(reduce_passkey(item))
        result[f"passkey_{environment_id}"] = passkey_cases

    state = secrets.token_urlsafe(32)
    init = await raw_fetch(
        page,
        f"{API}/sdk/{CURRENT_ENV}/providers/google/initAuth",
        {
            "method": "POST",
            "credentials": "include",
            "headers": {"Accept": "application/json", "Content-Type": "application/json"},
            "body": json.dumps({"state": state, "redirectUrl": callback_url}),
        },
    )
    result["oauthInit"] = reduce_oauth(init)
    result["oauthStateSha256"] = digest(state)
    result["callbackUrlSha256"] = digest(callback_url)
    result["callbackOrigin"] = callback_url.split("/", 3)[:3]

    poll = await raw_fetch(
        page,
        f"{API}/sdk/{CURRENT_ENV}/providers/google/oauthResult",
        {
            "method": "POST",
            "credentials": "include",
            "headers": {"Accept": "application/json", "Content-Type": "application/json"},
            "body": json.dumps({"state": state}),
        },
    )
    result["oauthPoll"] = reduce_oauth(poll)
    await page.close()
    return result


async def run() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    local_url = f"http://127.0.0.1:{port}/"

    network_headers: list[dict[str, Any]] = []
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=False)
            attacker = await collect_origin(
                context,
                label="attacker_local_origin",
                page_url=local_url,
                callback_url="https://attacker.invalid/dynamic-callback",
                network_headers=network_headers,
            )
            legitimate = await collect_origin(
                context,
                label="synthetix_exchange_origin",
                page_url=EXCHANGE,
                callback_url=EXCHANGE,
                network_headers=network_headers,
            )
            cookies = await context.cookies()
            cookie_metadata = [
                {
                    "name": cookie.get("name"),
                    "domain": cookie.get("domain"),
                    "path": cookie.get("path"),
                    "secure": cookie.get("secure"),
                    "httpOnly": cookie.get("httpOnly"),
                    "sameSite": cookie.get("sameSite"),
                    "valueSha256": digest(str(cookie.get("value", ""))),
                }
                for cookie in cookies
                if "dynamic" in str(cookie.get("domain", "")) or "synthetix" in str(cookie.get("domain", ""))
            ]
            await context.close()
            await browser.close()
    finally:
        server.shutdown()
        server.server_close()

    output = {
        "safety": "No login, OTP, user, wallet, key, signature, transaction, or fund operation. Public GETs plus ephemeral OAuth state init/poll only.",
        "currentEnvironmentId": CURRENT_ENV,
        "redirectEnvironmentId": REDIRECT_ENV,
        "attackerOrigin": attacker,
        "legitimateOrigin": legitimate,
        "dynamicResponseHeaders": network_headers,
        "cookieMetadata": cookie_metadata,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "attackerSettingsFetch": attacker[f"settings_{CURRENT_ENV}"].get("succeeded"),
                "attackerOauthInit": attacker["oauthInit"].get("succeeded"),
                "attackerOauthInitStatus": attacker["oauthInit"].get("status"),
                "legitimateSettingsFetch": legitimate[f"settings_{CURRENT_ENV}"].get("succeeded"),
                "legitimateOauthInit": legitimate["oauthInit"].get("succeeded"),
                "legitimateOauthInitStatus": legitimate["oauthInit"].get("status"),
                "dynamicHeaderRecords": len(network_headers),
                "dynamicCookieRecords": len(cookie_metadata),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(run())
