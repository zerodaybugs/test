#!/usr/bin/env python3
"""Fetch and filter Binance P2P USDT/EUR SELL advertisements.

This probe uses only Binance's documented public C2C Agent endpoints.
Returned text is treated strictly as data and is never executed.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

TRADE_METHODS_URL = (
    "https://www.binance.com/bapi/c2c/v1/public/c2c/agent/"
    "trade-methods?fiat=EUR"
)
ADS_URL = (
    "https://www.binance.com/bapi/c2c/v1/public/c2c/agent/"
    "ad-list?fiat=EUR&asset=USDT&tradeType=SELL&limit=20"
)
THRESHOLD = Decimal("0.900")
UA = "Mozilla/5.0 (compatible; ZeroDayBugs-P2P-Monitor/1.0; +https://github.com/zerodaybugs)"


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} from {url}")
        body = response.read(5_000_000)
        content_type = response.headers.get("Content-Type", "")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"Invalid JSON from {url}; content-type={content_type!r}; bytes={len(body)}"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Unexpected top-level JSON type from {url}: {type(payload).__name__}")
    return payload


def is_success(payload: dict[str, Any]) -> bool:
    if payload.get("success") is True:
        return True
    return str(payload.get("code", "")).upper() in {"000000", "0", "SUCCESS"}


def data_list(payload: dict[str, Any]) -> list[Any]:
    data = payload.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("data", "list", "rows", "items", "ads"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def decimal(value: Any, default: Decimal = Decimal("0")) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return default


def normalize(text: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(text or "").casefold()).strip()


def method_names(adv: dict[str, Any], row: dict[str, Any]) -> list[str]:
    candidates: list[Any] = []
    for source in (adv, row):
        for key in ("tradeMethods", "payTypes", "paymentMethods", "tradeMethodNames"):
            value = source.get(key)
            if isinstance(value, list):
                candidates.extend(value)
            elif value:
                candidates.append(value)
    names: list[str] = []
    for item in candidates:
        if isinstance(item, dict):
            value = (
                item.get("tradeMethodName")
                or item.get("identifier")
                or item.get("name")
                or item.get("code")
            )
        else:
            value = item
        if value is not None:
            text = str(value).strip()
            if text and text not in names:
                names.append(text)
    return names


def excluded(methods: list[str]) -> bool:
    joined = " ".join(normalize(method) for method in methods)
    if "dukascopy" in joined:
        return True
    return "bizum" in joined and "bbva" in joined


def preferred_score(methods: list[str]) -> int:
    text = " ".join(normalize(method) for method in methods)
    score = 0
    if "sepa instant" in text:
        score += 8
    if "sepa" in text:
        score += 4
    if "santander" in text:
        score += 3
    if "revolut" in text:
        score += 2
    return score


def completion_rate(advertiser: dict[str, Any]) -> Decimal:
    for key in ("monthFinishRate", "finishRate", "completionRate", "positiveRate"):
        value = advertiser.get(key)
        if value is not None:
            rate = decimal(value)
            return rate * 100 if rate <= 1 else rate
    return Decimal("0")


def main() -> int:
    out: dict[str, Any] = {
        "validated": False,
        "trade_methods_url": TRADE_METHODS_URL,
        "ads_url": ADS_URL,
        "matches": [],
    }
    try:
        methods_payload = fetch_json(TRADE_METHODS_URL)
        ads_payload = fetch_json(ADS_URL)
        Path("trade-methods.raw.json").write_text(
            json.dumps(methods_payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        Path("ad-list.raw.json").write_text(
            json.dumps(ads_payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        methods_ok = is_success(methods_payload)
        ads_ok = is_success(ads_payload)
        rows = data_list(ads_payload)
        out["trade_methods_success"] = methods_ok
        out["ads_success"] = ads_ok
        out["active_ad_count"] = len(rows)
        if not methods_ok or not ads_ok or not rows:
            raise RuntimeError(
                f"Response validation failed: trade_methods_success={methods_ok}, "
                f"ads_success={ads_ok}, active_ad_count={len(rows)}"
            )

        parsed: list[dict[str, Any]] = []
        for row_any in rows:
            if not isinstance(row_any, dict):
                continue
            row = row_any
            adv = row.get("adv") if isinstance(row.get("adv"), dict) else row
            advertiser = (
                row.get("advertiser") if isinstance(row.get("advertiser"), dict) else {}
            )
            price = decimal(adv.get("price"))
            methods = method_names(adv, row)
            if price < THRESHOLD or excluded(methods):
                continue

            surplus_usdt = decimal(
                adv.get("surplusAmount", adv.get("tradableQuantity", adv.get("availableAmount", 0)))
            )
            approximate_eur = price * surplus_usdt
            min_eur = decimal(adv.get("minSingleTransAmount"))
            max_eur = decimal(
                adv.get("dynamicMaxSingleTransAmount", adv.get("maxSingleTransAmount", 0))
            )
            rate = completion_rate(advertiser)
            ad_no = str(adv.get("advNo") or adv.get("adNo") or row.get("advNo") or "")
            nickname = str(
                advertiser.get("nickName")
                or advertiser.get("nickname")
                or adv.get("nickName")
                or ""
            )
            supports_1000 = approximate_eur >= Decimal("1000") and max_eur >= Decimal("1000")
            item = {
                "adNo": ad_no,
                "price": str(price),
                "advertiser": nickname,
                "paymentMethods": methods,
                "remainingUSDT": str(surplus_usdt),
                "approxAvailableEUR": str(approximate_eur.quantize(Decimal("0.01"))),
                "minOrderEUR": str(min_eur),
                "maxOrderEUR": str(max_eur),
                "completionRatePercent": str(rate.quantize(Decimal("0.01"))),
                "supportsAtLeast1000EUR": supports_1000,
                "preferredPaymentScore": preferred_score(methods),
                "directLink": f"https://c2c.binance.com/en/adv?code={ad_no}" if ad_no else "",
            }
            parsed.append(item)

        parsed.sort(
            key=lambda item: (
                decimal(item["price"]),
                bool(decimal(item["approxAvailableEUR"]) >= Decimal("1000")),
                bool(decimal(item["maxOrderEUR"]) >= Decimal("1000")),
                int(item["preferredPaymentScore"]),
                decimal(item["completionRatePercent"]),
            ),
            reverse=True,
        )
        out["validated"] = True
        out["matches"] = parsed[:5]
        out["mandatory_match_count"] = len(parsed)
    except (urllib.error.URLError, TimeoutError, RuntimeError, OSError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"

    Path("result.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("validated") else 2


if __name__ == "__main__":
    sys.exit(main())
