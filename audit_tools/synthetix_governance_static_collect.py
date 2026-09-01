#!/usr/bin/env python3
"""Read-only collector for the in-scope Synthetix governance website.

The site dynamically injects ``main.js`` rather than declaring a static script
``src`` in the initial HTML. This collector follows that runtime entry, saves
same-origin public assets, and produces a static attack-surface index.

Safety constraints:
- HTTPS GET/HEAD only against governance.synthetix.io;
- no wallet connection, signature, transaction, vote, credential, or mutation;
- bounded asset count and total bytes;
- source is stored exactly for offline review.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("governance_static")
ASSETS = OUT / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)

ORIGIN = "https://governance.synthetix.io"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 35 * 1024 * 1024
MAX_TOTAL = 120 * 1024 * 1024
MAX_ASSETS = 250

INTERESTING_PATHS = (
    "/",
    "/main.js",
    "/main.js.map",
    "/manifest.json",
    "/asset-manifest.json",
    "/service-worker.js",
    "/sw.js",
    "/favicon.ico",
    "/robots.txt",
)

URLISH_RE = re.compile(
    r"(?P<quote>['\"])(?P<value>(?:https://governance\.synthetix\.io)?/[A-Za-z0-9_./?=&%+#@~-]{1,300})(?P=quote)"
)
SOURCE_MAP_RE = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)")
HTTP_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,500}")
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
SELECTOR_RE = re.compile(r"0x[a-fA-F0-9]{8}")


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def safe_name(url: str, index: int) -> str:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.strip("/") or "index.html"
    path = re.sub(r"[^A-Za-z0-9._-]+", "_", path)
    if parsed.query:
        path += "_q_" + digest(parsed.query)[:12]
    return f"{index:03d}_{path[:180]}"


def get(url: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "*/*", "Cache-Control": "no-cache"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            final_url = response.url
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        final_url = exc.url
        headers = dict(exc.headers.items()) if exc.headers else {}
    if len(body) > MAX_BODY:
        raise RuntimeError(f"asset too large: {url}")
    return {
        "url": url,
        "status": status,
        "finalUrl": final_url,
        "headers": headers,
        "body": body,
    }


def same_origin(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.netloc == "governance.synthetix.io"


def canonical(value: str, base: str) -> str | None:
    try:
        result = urllib.parse.urljoin(base, value)
        parsed = urllib.parse.urlparse(result)
    except Exception:
        return None
    if parsed.scheme != "https" or parsed.netloc != "governance.synthetix.io":
        return None
    # Fragments do not affect the fetched resource.
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def textual(content_type: str | None, body: bytes) -> bool:
    lowered = (content_type or "").lower()
    if any(token in lowered for token in ("javascript", "json", "text/", "xml", "html", "css")):
        return True
    return body[:1] in (b"{", b"[", b"<") or b"sourceMappingURL" in body[-500:]


def extract_candidates(url: str, content_type: str | None, body: bytes) -> tuple[set[str], dict[str, Any]]:
    candidates: set[str] = set()
    metadata: dict[str, Any] = {
        "sourceMappingUrls": [],
        "sameOriginStringUrls": [],
        "externalOrigins": [],
        "addressCount": 0,
        "selectorCount": 0,
    }
    if not textual(content_type, body):
        return candidates, metadata
    text = body.decode("utf-8", "replace")
    for match in SOURCE_MAP_RE.finditer(text):
        value = match.group(1).strip().strip("'\"")
        target = canonical(value, url)
        if target:
            candidates.add(target)
            metadata["sourceMappingUrls"].append(target)
    for match in URLISH_RE.finditer(text):
        value = match.group("value")
        target = canonical(value, url)
        if not target:
            continue
        # Limit traversal to public assets or known runtime endpoints, not arbitrary SPA routes.
        suffix = urllib.parse.urlparse(target).path.lower()
        if any(
            suffix.endswith(ext)
            for ext in (
                ".js",
                ".mjs",
                ".json",
                ".css",
                ".map",
                ".wasm",
                ".svg",
                ".ico",
                ".png",
                ".jpg",
                ".jpeg",
                ".webp",
                ".woff",
                ".woff2",
                ".ttf",
            )
        ):
            candidates.add(target)
            metadata["sameOriginStringUrls"].append(target)
    external_origins: set[str] = set()
    for value in HTTP_RE.findall(text):
        try:
            parsed = urllib.parse.urlparse(value)
        except Exception:
            continue
        if parsed.scheme in {"http", "https"} and parsed.netloc and parsed.netloc != "governance.synthetix.io":
            external_origins.add(f"{parsed.scheme}://{parsed.netloc}")
    metadata["externalOrigins"] = sorted(external_origins)
    metadata["addressCount"] = len(set(ADDRESS_RE.findall(text)))
    metadata["selectorCount"] = len(set(SELECTOR_RE.findall(text)))
    return candidates, metadata


def main() -> None:
    queue: list[str] = [ORIGIN + path for path in INTERESTING_PATHS]
    queued = set(queue)
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    total_bytes = 0
    all_external_origins: set[str] = set()

    while queue and len(seen) < MAX_ASSETS:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        item = get(url)
        body = item.pop("body")
        headers = item.pop("headers")
        total_bytes += len(body)
        if total_bytes > MAX_TOTAL:
            raise RuntimeError(f"total asset budget exceeded after {url}")
        file_name = safe_name(url, len(records))
        (ASSETS / file_name).write_bytes(body)
        content_type = headers.get("Content-Type") or headers.get("content-type")
        candidates, extracted = extract_candidates(item["finalUrl"], content_type, body)
        all_external_origins.update(extracted["externalOrigins"])
        record = {
            **item,
            "contentType": content_type,
            "contentLengthHeader": headers.get("Content-Length") or headers.get("content-length"),
            "etag": headers.get("ETag") or headers.get("etag"),
            "lastModified": headers.get("Last-Modified") or headers.get("last-modified"),
            "cacheControl": headers.get("Cache-Control") or headers.get("cache-control"),
            "contentSecurityPolicy": headers.get("Content-Security-Policy")
            or headers.get("content-security-policy"),
            "crossOriginOpenerPolicy": headers.get("Cross-Origin-Opener-Policy")
            or headers.get("cross-origin-opener-policy"),
            "crossOriginResourcePolicy": headers.get("Cross-Origin-Resource-Policy")
            or headers.get("cross-origin-resource-policy"),
            "referrerPolicy": headers.get("Referrer-Policy") or headers.get("referrer-policy"),
            "bodyBytes": len(body),
            "bodySha256": digest(body),
            "storedAs": f"assets/{file_name}",
            "extracted": extracted,
        }
        records.append(record)
        for candidate in sorted(candidates):
            if candidate not in queued and candidate not in seen:
                queue.append(candidate)
                queued.add(candidate)

    main_records = [record for record in records if urllib.parse.urlparse(record["url"]).path == "/main.js"]
    summary = {
        "safety": "HTTPS GET only against the in-scope governance website; no wallet, vote, or mutation.",
        "origin": ORIGIN,
        "assetCount": len(records),
        "totalBytes": total_bytes,
        "queueRemaining": len(queue),
        "truncatedByAssetCap": bool(queue and len(seen) >= MAX_ASSETS),
        "mainJs": main_records,
        "externalOrigins": sorted(all_external_origins),
        "records": records,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "assetCount": summary["assetCount"],
                "totalBytes": summary["totalBytes"],
                "queueRemaining": summary["queueRemaining"],
                "truncatedByAssetCap": summary["truncatedByAssetCap"],
                "mainJsStatus": main_records[0]["status"] if main_records else None,
                "mainJsBytes": main_records[0]["bodyBytes"] if main_records else None,
                "externalOriginCount": len(all_external_origins),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
