#!/usr/bin/env python3
"""Read-only production frontend action-binding collector for Synthetix Exchange.

Collects the current same-origin JavaScript import graph and records exact contexts for collateral
exchange and order-modification action names/fields. This determines whether the production UI signs
one EIP-712 schema but submits a different action/field shape. HTTPS GET only; no wallet, account,
signature, telemetry, trade request, transaction, or state mutation.
"""
from __future__ import annotations

import hashlib
import html.parser
import json
import pathlib
import re
import urllib.parse
import urllib.request
from collections import deque
from typing import Any

OUT = pathlib.Path("synthetix_exchange_frontend_binding")
ASSETS = OUT / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)

ROOT = "https://exchange.synthetix.io/"
ORIGIN = "https://exchange.synthetix.io"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_FILES = 400
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 40 * 1024 * 1024

TERMS = (
    "exchangeCollateral",
    "voluntaryCollateralExchange",
    "ExchangeCollateral",
    "VoluntaryCollateralExchange",
    "fromSymbol",
    "toSymbol",
    "fromAmount",
    "sourceAsset",
    "targetUSDTAmount",
    "modifyOrderByCloid",
    "ModifyOrderByCloid",
    "clientOrderId",
    "destinationSubAccountId",
    "subaccountId",
    "subAccountId",
)

IMPORT_RE = re.compile(
    r"(?:import\s*(?:\([^)]*?\)|[^;]*?from\s*)|export\s+[^;]*?from\s*|new\s+URL\s*\()\s*[\"']([^\"']+)[\"']",
    re.S,
)
DYNAMIC_CHUNK_RE = re.compile(r"[\"']([^\"']+\.(?:js|mjs)(?:\?[^\"']*)?)[\"']")
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")


def sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


class EntryParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.urls.append(values["src"] or "")
        if tag == "link" and values.get("href") and values.get("rel") in {"modulepreload", "preload"}:
            self.urls.append(values["href"] or "")


def fetch(url: str) -> tuple[int, bytes, dict[str, str], str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"}, method="GET")
    with urllib.request.urlopen(req, timeout=60) as response:
        body = response.read(MAX_FILE + 1)
        if len(body) > MAX_FILE:
            raise RuntimeError(f"asset exceeds per-file cap: {url}")
        return response.status, body, dict(response.headers.items()), response.url


def same_origin(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.netloc == "exchange.synthetix.io"


def normalize(base: str, raw: str) -> str | None:
    if not raw or raw.startswith(("data:", "blob:", "javascript:")):
        return None
    url = urllib.parse.urljoin(base, raw)
    parsed = urllib.parse.urlparse(url)
    clean = parsed._replace(fragment="").geturl()
    return clean if same_origin(clean) else None


def safe_name(index: int, url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    suffix = pathlib.Path(parsed.path).suffix or ".bin"
    return f"{index:04d}_{sha(url)[:16]}{suffix}"


def contexts(text: str, term: str, radius: int = 600) -> list[dict[str, Any]]:
    output = []
    start = 0
    while True:
        position = text.find(term, start)
        if position < 0:
            break
        left = max(0, position - radius)
        right = min(len(text), position + len(term) + radius)
        output.append({
            "offset": position,
            "excerpt": text[left:right],
            "excerptSha256": sha(text[left:right]),
        })
        start = position + len(term)
        if len(output) >= 100:
            break
    return output


def main() -> None:
    _, root_body, root_headers, final_root = fetch(ROOT)
    root_text = root_body.decode("utf-8", errors="replace")
    (OUT / "root.html").write_bytes(root_body)

    parser = EntryParser()
    parser.feed(root_text)
    queue: deque[str] = deque()
    queued: set[str] = set()
    for raw in parser.urls:
        url = normalize(final_root, raw)
        if url and url not in queued:
            queue.append(url)
            queued.add(url)

    records: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []
    total_bytes = len(root_body)
    index = 0

    while queue and len(records) < MAX_FILES:
        url = queue.popleft()
        try:
            status, body, headers, final_url = fetch(url)
        except Exception as exc:  # noqa: BLE001
            records.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
            continue
        total_bytes += len(body)
        if total_bytes > MAX_TOTAL:
            raise RuntimeError("total asset cap exceeded")

        filename = safe_name(index, final_url)
        index += 1
        (ASSETS / filename).write_bytes(body)
        content_type = headers.get("Content-Type", "")
        text = body.decode("utf-8", errors="replace") if any(
            token in content_type.lower() for token in ("javascript", "text", "json")
        ) or final_url.split("?", 1)[0].endswith((".js", ".mjs", ".json", ".map")) else ""

        record = {
            "url": final_url,
            "file": filename,
            "httpStatus": status,
            "contentType": content_type,
            "bytes": len(body),
            "sha256": sha(body),
        }
        records.append(record)

        if text:
            for term in TERMS:
                found = contexts(text, term)
                if found:
                    matches.append({"url": final_url, "file": filename, "term": term, "occurrences": found})

            candidates = set(IMPORT_RE.findall(text)) | set(DYNAMIC_CHUNK_RE.findall(text))
            source_map = SOURCE_MAP_RE.search(text)
            if source_map:
                candidates.add(source_map.group(1).strip())
            for raw in sorted(candidates):
                child = normalize(final_url, raw)
                if child and child not in queued:
                    queued.add(child)
                    queue.append(child)

    summary = {
        "safety": "Same-origin HTTPS GET asset collection only; no wallet, account, signature, telemetry, trade or mutation.",
        "root": ROOT,
        "rootFinalUrl": final_root,
        "rootSha256": sha(root_body),
        "rootContentType": root_headers.get("Content-Type"),
        "assetCount": len(records),
        "totalBytes": total_bytes,
        "queueRemaining": len(queue),
        "graphTruncated": bool(queue),
        "terms": list(TERMS),
        "matchCount": len(matches),
        "matchedTerms": sorted({item["term"] for item in matches}),
        "records": records,
        "matches": matches,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "assetCount": summary["assetCount"],
        "totalBytes": summary["totalBytes"],
        "graphTruncated": summary["graphTruncated"],
        "matchedTerms": summary["matchedTerms"],
        "matchCount": summary["matchCount"],
    }, indent=2))


if __name__ == "__main__":
    main()
