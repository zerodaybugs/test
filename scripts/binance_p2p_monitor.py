#!/usr/bin/env python3
"""Fetch and filter Binance P2P USDT/EUR advertisements.

The script is read-only. It never places or initiates a trade.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

METHODS_URL = "https://www.binance.com/bapi/c2c/v1/public/c2c/agent/trade-methods?fiat=EUR"
ADS_URL = "https://www.binance.com/bapi/c2c/v1/public/c2c/agent/ad-list?fiat=EUR&asset=USDT&tradeType=SELL&limit=20"
MIN_PRICE = Decimal("0.900")

HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://p2p.binance.com",
    "Referer": "https://p2p.binance.com/",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/127 Safari/537.36",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def dec(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        text = str(value).strip().replace(",", "")
        if not text:
            return None
        return Decimal(text)
    except (InvalidOperation, ValueError):
        return None


def dec_str(value: Decimal | None) -> str | None:
    if value is None:
        return None
    return format(value.normalize(), "f")


def fetch_json(url: str, attempts: int = 3) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            req = Request(url, headers=HEADERS, method="GET")
            with urlopen(req, timeout=25) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status}")
                raw = response.read(5_000_000)
                ctype = (response.headers.get("Content-Type") or "").lower()
                if "json" not in ctype and not raw.lstrip().startswith((b"{", b"[")):
                    raise RuntimeError(f"unexpected content type: {ctype or 'missing'}")
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise RuntimeError("top-level response is not a JSON object")
                return payload
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"request failed after {attempts} attempts: {last_error}")


def validate_response(payload: dict[str, Any], label: str) -> None:
    if payload.get("success") is False:
        raise RuntimeError(f"{label}: API success=false")
    code = payload.get("code")
    if code is not None and str(code) not in {"0", "000000", "0000000", "200"}:
        raise RuntimeError(f"{label}: API code={code!r}")
    if "data" not in payload:
        raise RuntimeError(f"{label}: missing data field")


def extract_list(payload: dict[str, Any], keys: Iterable[str]) -> list[Any]:
    data = payload.get("data")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def first(mapping_sources: Iterable[dict[str, Any]], *keys: str) -> Any:
    for source in mapping_sources:
        for key in keys:
            if key in source and source[key] not in (None, ""):
                return source[key]
    return None


def normalize_text(value: str) -> str:
    value = value.casefold()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return " ".join(value.split())


def method_map(method_items: list[Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in method_items:
        if not isinstance(item, dict):
            continue
        identifier = first([item], "identifier", "code", "tradeMethodIdentifier", "payType")
        name = first([item], "tradeMethodName", "name", "displayName", "tradeMethodShortName")
        if identifier:
            result[str(identifier)] = str(name or identifier)
    return result


def collect_methods(value: Any, known: dict[str, str], output: list[str]) -> None:
    if value is None:
        return
    if isinstance(value, str):
        for part in re.split(r"[,|;/]+", value):
            part = part.strip()
            if part:
                output.append(known.get(part, part))
        return
    if isinstance(value, list):
        for item in value:
            collect_methods(item, known, output)
        return
    if isinstance(value, dict):
        identifier = first([value], "identifier", "tradeMethodIdentifier", "payType", "code")
        display = first([value], "tradeMethodName", "tradeMethodShortName", "displayName", "name")
        if display:
            output.append(str(display))
        elif identifier:
            output.append(known.get(str(identifier), str(identifier)))


def unique_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        clean = " ".join(str(value).split())
        key = clean.casefold()
        if clean and key not in seen:
            seen.add(key)
            out.append(clean)
    return out


def completion_percent(sources: list[dict[str, Any]]) -> Decimal | None:
    raw = first(
        sources,
        "monthFinishRate",
        "completionRate",
        "finishRate",
        "positiveRate",
        "userGrade",
    )
    value = dec(raw)
    if value is None:
        return None
    if value <= 1:
        value *= 100
    return value


def parse_ad(item: Any, known_methods: dict[str, str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    adv = item.get("adv") if isinstance(item.get("adv"), dict) else {}
    advertiser = item.get("advertiser") if isinstance(item.get("advertiser"), dict) else {}
    sources = [adv, item]

    status = first(sources, "status", "advStatus", "adStatus")
    if status is not None and str(status).casefold() not in {"1", "online", "active", "true"}:
        return None
    trade_type = first(sources, "tradeType", "side")
    if trade_type is not None and str(trade_type).upper() not in {"SELL", "1"}:
        return None
    asset = first(sources, "asset", "assetCode")
    fiat = first(sources, "fiatUnit", "fiat", "fiatCode")
    if asset is not None and str(asset).upper() != "USDT":
        return None
    if fiat is not None and str(fiat).upper() != "EUR":
        return None

    price = dec(first(sources, "price", "advPrice", "unitPrice"))
    ad_no = first(sources, "adNo", "advNo", "advertisementNo", "id")
    if price is None or not ad_no:
        return None

    surplus = dec(first(sources, "surplusAmount", "surplus", "availableAmount", "tradableQuantity"))
    minimum = dec(first(sources, "minSingleTransAmount", "minAmount", "minLimit"))
    maximum = dec(first(sources, "maxSingleTransAmount", "maxAmount", "maxLimit"))

    methods_raw: list[str] = []
    for source in sources:
        for key in (
            "tradeMethods",
            "tradeMethodList",
            "tradeMethodIdentifiers",
            "tradeMethodNames",
            "paymentMethods",
            "payTypes",
            "payMethods",
        ):
            collect_methods(source.get(key), known_methods, methods_raw)
    methods = unique_strings(methods_raw)

    nickname = first(
        [advertiser, item, adv],
        "nickName",
        "nickname",
        "merchantName",
        "userName",
        "advertiserName",
    )
    completion = completion_percent([advertiser, item, adv])
    available_eur = price * surplus if surplus is not None else None
    supports_1000 = bool(
        available_eur is not None
        and available_eur >= 1000
        and maximum is not None
        and maximum >= 1000
        and (minimum is None or minimum <= 1000)
    )

    method_text = " | ".join(methods)
    normalized = normalize_text(method_text)
    excluded = "dukascopy" in normalized or ("bizum" in normalized and "bbva" in normalized)

    preferred = 0
    if "sepa instant" in normalized:
        preferred += 8
    if re.search(r"\bsepa\b", normalized):
        preferred += 4
    if "santander" in normalized:
        preferred += 3
    if "revolut" in normalized:
        preferred += 2

    return {
        "adNo": str(ad_no),
        "price": dec_str(price),
        "advertiser": str(nickname or "—"),
        "paymentMethods": methods,
        "surplusUSDT": dec_str(surplus),
        "availableEUR": dec_str(available_eur),
        "minOrderEUR": dec_str(minimum),
        "maxOrderEUR": dec_str(maximum),
        "completionRatePercent": dec_str(completion),
        "supports1000EUR": supports_1000,
        "preferredScore": preferred,
        "excluded": excluded,
        "directLink": f"https://c2c.binance.com/en/adv?code={ad_no}",
    }


def sortable_decimal(value: Any, default: str = "-1") -> Decimal:
    return dec(value) or Decimal(default)


def fingerprint(ad: dict[str, Any]) -> dict[str, Any]:
    available = sortable_decimal(ad.get("availableEUR"), "0")
    bucket = (available // Decimal("50")) * Decimal("50")
    return {
        "price": ad.get("price"),
        "paymentMethods": sorted(normalize_text(x) for x in ad.get("paymentMethods", [])),
        "minOrderEUR": ad.get("minOrderEUR"),
        "maxOrderEUR": ad.get("maxOrderEUR"),
        "availableBucketEUR": dec_str(bucket),
        "supports1000EUR": ad.get("supports1000EUR"),
    }


def load_json(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-in", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    checked_at = utc_now()
    previous_state = load_json(args.state_in)
    previous_ads = previous_state.get("ads") if isinstance(previous_state.get("ads"), dict) else {}

    try:
        methods_payload = fetch_json(METHODS_URL)
        ads_payload = fetch_json(ADS_URL)
        validate_response(methods_payload, "trade-methods")
        validate_response(ads_payload, "ad-list")

        methods_items = extract_list(methods_payload, ("tradeMethods", "methods", "rows", "items", "list"))
        ads_items = extract_list(ads_payload, ("ads", "rows", "items", "list", "advertisements"))
        if not methods_items:
            raise RuntimeError("trade-methods returned no payment methods")
        if not ads_items:
            raise RuntimeError("ad-list returned no active advertisement data")

        known_methods = method_map(methods_items)
        parsed = [parse_ad(item, known_methods) for item in ads_items]
        parsed = [ad for ad in parsed if ad is not None]
        if not parsed:
            raise RuntimeError("ad-list contained no parseable active USDT/EUR SELL advertisements")

        qualifying = [
            ad
            for ad in parsed
            if sortable_decimal(ad.get("price")) >= MIN_PRICE and not ad.get("excluded")
        ]
        qualifying.sort(
            key=lambda ad: (
                sortable_decimal(ad.get("price")),
                bool(ad.get("availableEUR") and sortable_decimal(ad.get("availableEUR"), "0") >= 1000),
                bool(ad.get("maxOrderEUR") and sortable_decimal(ad.get("maxOrderEUR"), "0") >= 1000),
                int(ad.get("preferredScore") or 0),
                sortable_decimal(ad.get("completionRatePercent"), "-1"),
            ),
            reverse=True,
        )

        current_ads = {ad["adNo"]: fingerprint(ad) for ad in qualifying}
        reasons: dict[str, str] = {}
        changed_ads: list[dict[str, Any]] = []
        for ad in qualifying:
            ad_no = ad["adNo"]
            old = previous_ads.get(ad_no)
            new = current_ads[ad_no]
            reason: str | None = None
            if not isinstance(old, dict):
                reason = "new qualifying advertisement"
            elif sortable_decimal(new.get("price")) > sortable_decimal(old.get("price")):
                reason = "price increased"
            elif new.get("paymentMethods") != old.get("paymentMethods"):
                reason = "payment methods changed"
            elif new.get("minOrderEUR") != old.get("minOrderEUR") or new.get("maxOrderEUR") != old.get("maxOrderEUR"):
                reason = "order limits changed"
            elif new.get("supports1000EUR") != old.get("supports1000EUR"):
                reason = "1,000 EUR eligibility changed"
            elif new.get("availableBucketEUR") != old.get("availableBucketEUR"):
                reason = "available amount changed materially"
            if reason:
                reasons[ad_no] = reason
                changed_ads.append(ad)

        event_payload = {
            "notify": bool(changed_ads),
            "createdAt": checked_at,
            "reasons": reasons,
            "matches": changed_ads[:5],
        }
        event_payload["eventId"] = hashlib.sha256(
            json.dumps(event_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()

        status = {
            "ok": True,
            "checkedAt": checked_at,
            "sourceURLs": [METHODS_URL, ADS_URL],
            "activeAdsReturned": len(ads_items),
            "parseableActiveAds": len(parsed),
            "qualifyingAds": len(qualifying),
            "topMatches": qualifying[:5],
            "error": None,
        }
        state = {"checkedAt": checked_at, "ads": current_ads}

    except Exception as exc:  # Fail closed: never notify from unverifiable data.
        status = {
            "ok": False,
            "checkedAt": checked_at,
            "sourceURLs": [METHODS_URL, ADS_URL],
            "activeAdsReturned": 0,
            "parseableActiveAds": 0,
            "qualifyingAds": 0,
            "topMatches": [],
            "error": str(exc),
        }
        event_payload = {
            "notify": False,
            "createdAt": checked_at,
            "eventId": None,
            "reasons": {},
            "matches": [],
        }
        state = previous_state or {"checkedAt": checked_at, "ads": {}}

    write_json(args.out_dir / "status.json", status)
    write_json(args.out_dir / "event.json", event_payload)
    write_json(args.out_dir / "state.json", state)
    print(json.dumps(status, ensure_ascii=False))
    return 0 if status["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
