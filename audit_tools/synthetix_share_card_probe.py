#!/usr/bin/env python3
"""Low-noise, read-only probe for the in-scope public share-card renderer.

The probe performs six GET requests: a baseline plus harmless input-handling
controls. It does not target internal networks, cloud metadata, or sensitive
filesystem paths, and it does not submit or mutate application state.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("share_card_probe")
OUT.mkdir(parents=True, exist_ok=True)
BASE = "https://exchange.synthetix.io/api/share-card"
UA = "Mozilla/5.0 (compatible; passive-security-review/1.0)"
MAX_BYTES = 12 * 1024 * 1024

BASE_PARAMS: dict[str, str] = {
    "symbol": "BTC-USDT",
    "side": "LONG",
    "leverage": "1",
    "pnlPercent": "+0.00%",
    "entryPrice": "100000.00",
    "priceValue": "100000.00",
    "isPositive": "true",
    "imageId": "snx-3d",
    "timestamp": "2026-07-24 18:00 UTC",
    "variant": "mobile",
}

CASES: dict[str, dict[str, str]] = {
    "baseline": {},
    "unknown_image_id": {"imageId": "synthetix-audit-unknown-image"},
    "relative_asset_canary": {"imageId": "../share-bg-dark"},
    "absolute_public_asset_canary": {"imageId": "/images/share-card/pepe.png"},
    "markup_text_canary": {"symbol": "AUDIT_<tag>&quoted", "side": "SHORT"},
    "referral_url_canary": {
        "referralCode": "AUDIT-CODE",
        "referralLink": "https://example.com/audit?x=1&y=2",
        "feeDiscountPercent": "5",
    },
}


def png_dimensions(body: bytes) -> dict[str, int] | None:
    if len(body) >= 24 and body[:8] == b"\x89PNG\r\n\x1a\n" and body[12:16] == b"IHDR":
        width, height = struct.unpack(">II", body[16:24])
        return {"width": width, "height": height}
    return None


def fetch(name: str, overrides: dict[str, str]) -> dict[str, Any]:
    params = dict(BASE_PARAMS)
    params.update(overrides)
    url = BASE + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "image/*,*/*;q=0.5"})
    record: dict[str, Any] = {"name": name, "url": url, "params": params}
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError(f"response exceeds {MAX_BYTES} bytes")
            path = OUT / f"{name}.bin"
            path.write_bytes(body)
            record.update(
                status=response.status,
                final_url=response.geturl(),
                content_type=response.headers.get("Content-Type", ""),
                content_length=response.headers.get("Content-Length"),
                cache_control=response.headers.get("Cache-Control"),
                bytes=len(body),
                sha256=hashlib.sha256(body).hexdigest(),
                png_dimensions=png_dimensions(body),
                prefix_hex=body[:32].hex(),
            )
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BYTES + 1)
        path = OUT / f"{name}.error.bin"
        path.write_bytes(body)
        record.update(
            status=exc.code,
            final_url=exc.geturl(),
            content_type=exc.headers.get("Content-Type", "") if exc.headers else "",
            bytes=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
            prefix_hex=body[:64].hex(),
            error=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        record["error"] = repr(exc)
    return record


def main() -> None:
    results: list[dict[str, Any]] = []
    for index, (name, overrides) in enumerate(CASES.items()):
        results.append(fetch(name, overrides))
        if index + 1 < len(CASES):
            time.sleep(1.0)

    baseline = next(item for item in results if item["name"] == "baseline")
    summary = {
        "request_count": len(results),
        "baseline_status": baseline.get("status"),
        "baseline_content_type": baseline.get("content_type"),
        "cases": [
            {
                "name": item["name"],
                "status": item.get("status"),
                "content_type": item.get("content_type"),
                "bytes": item.get("bytes"),
                "sha256": item.get("sha256"),
                "png_dimensions": item.get("png_dimensions"),
                "same_as_baseline": bool(item.get("sha256") and item.get("sha256") == baseline.get("sha256")),
                "error": item.get("error"),
            }
            for item in results
        ],
    }
    (OUT / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
