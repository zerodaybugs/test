#!/usr/bin/env python3
"""Low-noise read-only boundary probe for the in-scope Exchange share-card renderer.

Safety:
- HTTPS GET only against https://exchange.synthetix.io/api/share-card;
- no login, wallet, signature, account, trade, transaction, or state mutation;
- fixed small case matrix with delays;
- no third-party callback or internal-network target is used;
- bodies are retained only for small non-image errors; images are represented by hashes/metadata.

Goals:
- establish the output media type and renderer behavior;
- detect raw reflected active markup/script in SVG/HTML responses;
- detect same-origin URL interpretation or local path traversal in imageId;
- detect stack traces, filesystem paths, or command/template errors;
- verify invalid numeric/enum values fail safely rather than exposing internals.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("share_card_boundary")
OUT.mkdir(parents=True, exist_ok=True)

ENDPOINT = "https://exchange.synthetix.io/api/share-card"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 8 * 1024 * 1024
DELAY_SECONDS = 0.45
CANARY = "ZDB_SHARECARD_CANARY_9f31c7"

BASE = {
    "symbol": "BTC-USDT",
    "side": "buy",
    "leverage": "2",
    "pnlPercent": "1.25",
    "entryPrice": "100000",
    "priceValue": "101250",
    "isPositive": "true",
    "imageId": "snx-3d",
    "timestamp": "2026-07-26",
    "variant": "mobile",
}

CASES: list[tuple[str, dict[str, str], list[tuple[str, str]] | None]] = [
    ("baseline", {}, None),
    ("markup_symbol", {"symbol": f'<svg onload="alert(1)">{CANARY}</svg>'}, None),
    ("markup_referral_link", {"referralLink": f'\"><svg onload="alert(1)">{CANARY}</svg>'}, None),
    ("javascript_referral_link", {"referralLink": f"javascript:alert('{CANARY}')"}, None),
    ("unknown_image", {"imageId": CANARY}, None),
    ("relative_image_path", {"imageId": "../../../../etc/passwd"}, None),
    ("file_image_url", {"imageId": "file:///etc/passwd"}, None),
    ("same_origin_image_url", {"imageId": "https://exchange.synthetix.io/favicon.svg"}, None),
    ("invalid_variant", {"variant": CANARY}, None),
    ("nan_numeric", {"pnlPercent": "NaN", "entryPrice": "NaN"}, None),
    ("infinite_numeric", {"pnlPercent": "Infinity", "leverage": "Infinity"}, None),
    ("huge_numeric", {"pnlPercent": "1e100000", "leverage": "1e100000"}, None),
    ("duplicate_symbol", {}, [("symbol", "BTC-USDT"), ("symbol", CANARY)]),
    ("empty_query", {}, []),
]

ACTIVE_PATTERNS = {
    "scriptTag": re.compile(rb"<script\b", re.I),
    "svgOnload": re.compile(rb"<svg[^>]+onload", re.I),
    "eventHandler": re.compile(rb"\bon[a-z]+\s*=", re.I),
    "javascriptScheme": re.compile(rb"javascript\s*:", re.I),
    "passwdMarker": re.compile(rb"root:[x*]:0:0", re.I),
    "stackTrace": re.compile(rb"(?:Traceback \(most recent call last\)|\bat [A-Za-z0-9_$./-]+\s*\([^\n]+:\d+:\d+\))"),
    "filesystemPath": re.compile(rb"(?:/var/task/|/home/[^/\s]+/|/usr/src/app/|[A-Z]:\\[^\r\n]+)", re.I),
    "templateError": re.compile(rb"(?:satori|resvg|react-dom/server|jsx|template|render).{0,80}(?:error|exception|failed)", re.I | re.S),
}


def sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def build_url(overrides: dict[str, str], explicit_pairs: list[tuple[str, str]] | None) -> str:
    if explicit_pairs is not None:
        pairs = explicit_pairs
    else:
        params = dict(BASE)
        params.update(overrides)
        pairs = list(params.items())
    query = urllib.parse.urlencode(pairs, doseq=True)
    return ENDPOINT + ("?" + query if query else "")


def get(url: str) -> tuple[int, bytes, dict[str, str], float, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "image/*,application/json,text/plain,*/*"},
        method="GET",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            headers = dict(response.headers.items())
            final_url = response.url
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        final_url = exc.url
    elapsed = time.monotonic() - started
    if len(body) > MAX_BODY:
        raise RuntimeError("response body exceeds safety cap")
    return status, body, headers, elapsed, final_url


def image_metadata(body: bytes) -> dict[str, Any] | None:
    if body.startswith(b"\x89PNG\r\n\x1a\n") and len(body) >= 24:
        width, height = struct.unpack(">II", body[16:24])
        return {"format": "png", "width": width, "height": height}
    if body.startswith(b"\xff\xd8"):
        i = 2
        while i + 9 < len(body):
            if body[i] != 0xFF:
                i += 1
                continue
            marker = body[i + 1]
            i += 2
            if marker in {0xD8, 0xD9}:
                continue
            if i + 2 > len(body):
                break
            length = int.from_bytes(body[i : i + 2], "big")
            if length < 2 or i + length > len(body):
                break
            if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF} and length >= 7:
                height = int.from_bytes(body[i + 3 : i + 5], "big")
                width = int.from_bytes(body[i + 5 : i + 7], "big")
                return {"format": "jpeg", "width": width, "height": height}
            i += length
        return {"format": "jpeg", "width": None, "height": None}
    if body.lstrip().startswith(b"<svg") or b"<svg" in body[:2048].lower():
        return {"format": "svg", "width": None, "height": None}
    if body.startswith((b"RIFF",)) and body[8:12] == b"WEBP":
        return {"format": "webp", "width": None, "height": None}
    return None


def safe_excerpt(body: bytes, content_type: str) -> str | None:
    if len(body) > 128_000:
        return None
    lower = content_type.lower()
    if not any(token in lower for token in ("text/", "json", "xml", "svg", "javascript")):
        return None
    return body.decode("utf-8", errors="replace")[:8000]


def main() -> None:
    results: list[dict[str, Any]] = []
    baseline_hash: str | None = None
    baseline_meta: dict[str, Any] | None = None
    for index, (name, overrides, explicit_pairs) in enumerate(CASES):
        url = build_url(overrides, explicit_pairs)
        status, body, headers, elapsed, final_url = get(url)
        content_type = headers.get("Content-Type", "")
        body_hash = sha256(body)
        meta = image_metadata(body)
        if name == "baseline":
            baseline_hash = body_hash
            baseline_meta = meta
        matches = {key: bool(pattern.search(body)) for key, pattern in ACTIVE_PATTERNS.items()}
        item = {
            "name": name,
            "requestUrlSha256": sha256(url),
            "finalUrlSameEndpoint": final_url.startswith(ENDPOINT),
            "httpStatus": status,
            "elapsedMs": round(elapsed * 1000, 2),
            "contentType": content_type,
            "contentDisposition": headers.get("Content-Disposition"),
            "cacheControl": headers.get("Cache-Control"),
            "xContentTypeOptions": headers.get("X-Content-Type-Options"),
            "contentSecurityPolicy": headers.get("Content-Security-Policy"),
            "bodyBytes": len(body),
            "bodySha256": body_hash,
            "sameAsBaseline": baseline_hash == body_hash if baseline_hash is not None else None,
            "image": meta,
            "activeOrSensitivePatternMatches": matches,
            "containsCanaryBytes": CANARY.encode() in body,
            "bodyExcerpt": safe_excerpt(body, content_type),
        }
        results.append(item)
        if index + 1 < len(CASES):
            time.sleep(DELAY_SECONDS)

    alerts = {
        "activeMarkupInExecutableResponse": [
            item["name"]
            for item in results
            if any(
                item["activeOrSensitivePatternMatches"][key]
                for key in ("scriptTag", "svgOnload", "eventHandler", "javascriptScheme")
            )
            and any(token in item["contentType"].lower() for token in ("html", "svg", "xml", "javascript"))
        ],
        "passwdDisclosure": [item["name"] for item in results if item["activeOrSensitivePatternMatches"]["passwdMarker"]],
        "stackOrFilesystemDisclosure": [
            item["name"]
            for item in results
            if item["activeOrSensitivePatternMatches"]["stackTrace"]
            or item["activeOrSensitivePatternMatches"]["filesystemPath"]
        ],
        "canaryReflectedInNonRasterResponse": [
            item["name"]
            for item in results
            if item["containsCanaryBytes"] and (item["image"] or {}).get("format") not in {"png", "jpeg", "webp"}
        ],
    }
    output = {
        "safety": "Fixed low-noise HTTPS GET matrix against the in-scope share-card endpoint only; no state change or third-party target.",
        "endpoint": ENDPOINT,
        "caseCount": len(results),
        "baselineBodySha256": baseline_hash,
        "baselineImage": baseline_meta,
        "alerts": alerts,
        "results": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "caseCount": output["caseCount"],
                "baselineImage": output["baselineImage"],
                "statuses": {item["name"]: item["httpStatus"] for item in results},
                "contentTypes": {item["name"]: item["contentType"] for item in results},
                "alerts": alerts,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
