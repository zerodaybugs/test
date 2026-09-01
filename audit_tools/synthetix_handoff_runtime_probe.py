#!/usr/bin/env python3
"""Passive runtime probe for the Synthetix session-handoff URL.

Uses only a deterministic fake private key. Requests to Synthetix API and
third-party telemetry ingestion endpoints are intercepted before transmission.
The probe observes what the production frontend attempts to send.
"""

from __future__ import annotations

import asyncio
import base64
import json
import pathlib
import time
import urllib.parse
from typing import Any

from playwright.async_api import Request, Route, async_playwright

OUT = pathlib.Path("handoff_runtime_probe")
OUT.mkdir(parents=True, exist_ok=True)

FAKE_PRIVATE_KEY = "0x" + "11" * 32
FAKE_SESSION_ADDRESS = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"
FAKE_OWNER = "0x000000000000000000000000000000000000dEaD"
MARKER = "SYNTHETIX_HANDOFF_FAKE_SECRET_MARKER_20260724"

TELEMETRY_HOST_PARTS = (
    "segment.io",
    "segment.com",
    "sentry.io",
    "posthog.com",
    "intercom.io",
    "intercomcdn.com",
)


def build_handoff() -> tuple[str, str, dict[str, Any]]:
    now = int(time.time() * 1000)
    payload: dict[str, Any] = {
        "subAccountId": 999999999,
        "address": FAKE_SESSION_ADDRESS,
        "walletAddress": FAKE_OWNER,
        "privateKey": FAKE_PRIVATE_KEY,
        "createdAt": now,
        "expiresAt": now + 30 * 24 * 60 * 60 * 1000,
        "sessionId": MARKER,
        "status": "active",
        "chainId": 1,
        "handoffContext": {"mode": "owned"},
    }
    token = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    url = (
        "https://exchange.synthetix.io/?market=BTC-USDT&sessionHandoff="
        + urllib.parse.quote(token, safe="")
    )
    return url, token, payload


def serialise_request(request: Request, disposition: str) -> dict[str, Any]:
    try:
        post_data = request.post_data
    except Exception:
        post_data = None
    try:
        headers = dict(request.headers)
    except Exception:
        headers = {}
    return {
        "disposition": disposition,
        "method": request.method,
        "url": request.url,
        "resource_type": request.resource_type,
        "headers": headers,
        "post_data": post_data,
    }


def contains_secret(record: dict[str, Any], token: str) -> list[str]:
    blob = json.dumps(record, sort_keys=True)
    needles = {
        "query_parameter_name": "sessionHandoff",
        "base64_handoff": token,
        "fake_private_key": FAKE_PRIVATE_KEY,
        "session_marker": MARKER,
        "urlencoded_handoff": urllib.parse.quote(token, safe=""),
    }
    return [label for label, needle in needles.items() if needle and needle in blob]


async def run_scenario(browser: Any, name: str, url: str, token: str) -> dict[str, Any]:
    context = await browser.new_context(
        viewport={"width": 390, "height": 844},
        user_agent=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 "
            "Mobile/15E148 Safari/604.1"
        ),
        ignore_https_errors=False,
    )
    page = await context.new_page()

    # Force Sentry's 5% trace sampler to select the page-load transaction.
    await page.add_init_script("Math.random = () => 0;")

    records: list[dict[str, Any]] = []
    console: list[dict[str, str]] = []
    page_errors: list[str] = []

    page.on("console", lambda msg: console.append({"type": msg.type, "text": msg.text}))
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))

    async def handle_route(route: Route, request: Request) -> None:
        parsed = urllib.parse.urlparse(request.url)
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        is_telemetry = any(part in host for part in TELEMETRY_HOST_PARTS)
        is_synthetix_api = host == "papi.synthetix.io"
        is_ingestion = is_telemetry and request.method.upper() != "GET"
        is_trade_api = is_synthetix_api and path.endswith("/trade")

        if is_ingestion or is_trade_api:
            records.append(serialise_request(request, "intercepted-before-transmission"))
            await route.abort("blockedbyclient")
            return

        # Keep telemetry loader/settings GETs observable, but do not block them;
        # they are required for the frontend to construct the attempted event.
        if is_telemetry or is_synthetix_api:
            records.append(serialise_request(request, "observed-and-continued"))
        await route.continue_()

    await page.route("**/*", handle_route)

    navigation_error = None
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=90_000)
        await page.wait_for_timeout(30_000)
    except Exception as exc:  # preserve diagnostics even if a third-party loader stalls
        navigation_error = repr(exc)

    try:
        final_url = page.url
    except Exception:
        final_url = ""

    try:
        storage = await page.evaluate(
            """() => ({
                localStorage: Object.fromEntries(Object.entries(localStorage)),
                sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
                href: location.href,
                search: location.search,
                referrer: document.referrer,
            })"""
        )
    except Exception as exc:
        storage = {"error": repr(exc)}

    try:
        await page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
    except Exception:
        pass

    enriched = []
    for record in records:
        item = dict(record)
        item["secret_matches"] = contains_secret(record, token)
        enriched.append(item)

    result = {
        "name": name,
        "initial_url": url,
        "final_url": final_url,
        "navigation_error": navigation_error,
        "storage": storage,
        "requests": enriched,
        "console": console,
        "page_errors": page_errors,
    }
    (OUT / f"{name}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    await context.close()
    return result


async def main() -> None:
    handoff_url, token, payload = build_handoff()
    (OUT / "fake_payload.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (OUT / "probe_metadata.json").write_text(
        json.dumps(
            {
                "marker": MARKER,
                "fake_private_key": FAKE_PRIVATE_KEY,
                "handoff_url": handoff_url,
                "safety": (
                    "Synthetic key only; trade and telemetry ingestion requests are "
                    "intercepted before transmission."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        with_secret = await run_scenario(browser, "with_handoff", handoff_url, token)
        baseline = await run_scenario(
            browser,
            "baseline",
            "https://exchange.synthetix.io/?market=BTC-USDT",
            token,
        )
        await browser.close()

    def leaks(result: dict[str, Any]) -> list[dict[str, Any]]:
        return [r for r in result["requests"] if r.get("secret_matches")]

    summary = {
        "with_handoff_attempted_secret_transmissions": leaks(with_secret),
        "baseline_attempted_secret_transmissions": leaks(baseline),
        "with_handoff_final_url": with_secret["final_url"],
        "baseline_final_url": baseline["final_url"],
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
