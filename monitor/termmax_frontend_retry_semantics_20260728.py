#!/usr/bin/env python3
"""Fetch public TermMax frontend bundles and extract MakerHelper retry/salt semantics.

Public HTTPS GET requests only. No wallet, signing, transaction, or exploit code.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
ORIGIN = "https://app.termmax.ts.finance"
PAGES = [
    "/alpha/call-put",
    "/alpha/fixed-rate",
    "/earn",
    "/markets",
    "/portfolio",
]
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/javascript,text/javascript,*/*;q=0.8",
})

PATTERNS = {
    "placeOrderForV2": re.compile(r"placeOrderForV2", re.I),
    "makerHelperEthereum": re.compile(r"513690136500dEc06553385f7a00b010455dce92", re.I),
    "delegateParams": re.compile(r"delegateParams", re.I),
    "delegateSignature": re.compile(r"delegateSignature", re.I),
    "DelegationWithSig": re.compile(r"DelegationWithSig", re.I),
    "cryptoGetRandomValues": re.compile(r"getRandomValues", re.I),
    "randomBytes": re.compile(r"randomBytes", re.I),
    "MathRandom": re.compile(r"Math\.random", re.I),
    "salt": re.compile(r"\bsalt\b", re.I),
    "retry": re.compile(r"retry|resubmit|tryAgain|try again", re.I),
    "waitForTransactionReceipt": re.compile(r"waitForTransactionReceipt", re.I),
    "simulateContract": re.compile(r"simulateContract", re.I),
    "writeContract": re.compile(r"writeContract", re.I),
    "nonce": re.compile(r"\bnonce\b", re.I),
}


def fetch(url: str, attempts: int = 5) -> requests.Response:
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            response = SESSION.get(url, timeout=90, allow_redirects=True)
            if response.status_code == 429:
                time.sleep(2 * (attempt + 1))
                continue
            response.raise_for_status()
            return response
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"GET failed {url}: {last}")


def script_urls(page_url: str, text: str) -> set[str]:
    urls: set[str] = set()
    for match in re.finditer(r"<(?:script|link)\b[^>]*(?:src|href)=[\"']([^\"']+)[\"'][^>]*>", text, re.I):
        value = html.unescape(match.group(1))
        full = urljoin(page_url, value)
        parsed = urlparse(full)
        if parsed.netloc == urlparse(ORIGIN).netloc and (
            parsed.path.endswith((".js", ".mjs")) or "/_next/static/" in parsed.path
        ):
            urls.add(full)
    for match in re.finditer(r"[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", text):
        full = urljoin(page_url, html.unescape(match.group(1)))
        if urlparse(full).netloc == urlparse(ORIGIN).netloc:
            urls.add(full)
    return urls


def clean_context(text: str, start: int, end: int, radius: int = 1200) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    context = text[left:right]
    context = context.replace("\x00", "")
    return context


def scan_text(label: str, url: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pattern_name, pattern in PATTERNS.items():
        matches = list(pattern.finditer(text))
        for index, match in enumerate(matches[:40]):
            findings.append({
                "label": label,
                "url": url,
                "pattern": pattern_name,
                "matchIndex": index,
                "offset": match.start(),
                "match": match.group(0),
                "context": clean_context(text, match.start(), match.end()),
            })
    return findings


def source_map_urls(js_url: str, text: str) -> set[str]:
    maps: set[str] = set()
    for match in re.finditer(r"sourceMappingURL=([^\s*]+)", text):
        maps.add(urljoin(js_url, match.group(1).strip()))
    if js_url.split("?", 1)[0].endswith(".js"):
        maps.add(js_url.split("?", 1)[0] + ".map")
    return maps


def main() -> int:
    pages: list[dict[str, Any]] = []
    assets: dict[str, dict[str, Any]] = {}
    all_scripts: set[str] = set()
    findings: list[dict[str, Any]] = []

    for route in PAGES:
        url = urljoin(ORIGIN, route)
        try:
            response = fetch(url)
            text = response.text
            page_path = OUT / "pages" / (route.strip("/").replace("/", "_") or "index")
            page_path.parent.mkdir(parents=True, exist_ok=True)
            page_path.with_suffix(".html").write_text(text, encoding="utf-8")
            scripts = script_urls(response.url, text)
            all_scripts.update(scripts)
            page_entry = {
                "route": route,
                "requestedUrl": url,
                "finalUrl": response.url,
                "status": response.status_code,
                "bytes": len(response.content),
                "sha256": hashlib.sha256(response.content).hexdigest(),
                "scripts": sorted(scripts),
            }
            pages.append(page_entry)
            findings.extend(scan_text("page", response.url, text))
        except Exception as exc:  # noqa: BLE001
            pages.append({"route": route, "requestedUrl": url, "error": f"{type(exc).__name__}: {exc}"})

    pending = list(sorted(all_scripts))
    seen: set[str] = set()
    map_candidates: set[str] = set()
    while pending and len(seen) < 500:
        url = pending.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            response = fetch(url)
            text = response.text
            digest = hashlib.sha256(response.content).hexdigest()
            asset_name = digest + ".js"
            destination = OUT / "assets" / asset_name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            discovered = script_urls(response.url, text)
            for child in discovered:
                if child not in seen:
                    pending.append(child)
            map_candidates.update(source_map_urls(response.url, text))
            asset_findings = scan_text("javascript", response.url, text)
            findings.extend(asset_findings)
            assets[url] = {
                "finalUrl": response.url,
                "status": response.status_code,
                "bytes": len(response.content),
                "sha256": digest,
                "savedAs": str(destination.relative_to(OUT)),
                "discoveredScripts": sorted(discovered),
                "findingCount": len(asset_findings),
            }
        except Exception as exc:  # noqa: BLE001
            assets[url] = {"error": f"{type(exc).__name__}: {exc}"}

    source_maps: dict[str, dict[str, Any]] = {}
    for url in sorted(map_candidates)[:500]:
        try:
            response = fetch(url, attempts=2)
            if len(response.content) > 100_000_000:
                source_maps[url] = {"error": "source map exceeds 100 MB"}
                continue
            text = response.text
            digest = hashlib.sha256(response.content).hexdigest()
            destination = OUT / "maps" / (digest + ".map")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            map_findings = scan_text("source-map", response.url, text)
            findings.extend(map_findings)
            source_maps[url] = {
                "finalUrl": response.url,
                "bytes": len(response.content),
                "sha256": digest,
                "savedAs": str(destination.relative_to(OUT)),
                "findingCount": len(map_findings),
            }
        except Exception as exc:  # noqa: BLE001
            source_maps[url] = {"error": f"{type(exc).__name__}: {exc}"}

    by_pattern: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        by_pattern.setdefault(finding["pattern"], []).append(finding)

    high_signal_names = [
        "placeOrderForV2", "makerHelperEthereum", "delegateParams", "delegateSignature",
        "DelegationWithSig", "cryptoGetRandomValues", "randomBytes", "MathRandom",
        "retry", "waitForTransactionReceipt", "simulateContract", "writeContract",
    ]
    high_signal = [finding for finding in findings if finding["pattern"] in high_signal_names]
    summary = {
        "schema": "termmax-public-frontend-retry-semantics/v1",
        "origin": ORIGIN,
        "pages": pages,
        "assetCount": len(assets),
        "sourceMapCount": len(source_maps),
        "patternCounts": {name: len(rows) for name, rows in sorted(by_pattern.items())},
        "highSignalFindingCount": len(high_signal),
        "highSignalFindings": high_signal,
    }
    (OUT / "ASSET_INDEX.json").write_text(json.dumps(assets, indent=2), encoding="utf-8")
    (OUT / "SOURCE_MAP_INDEX.json").write_text(json.dumps(source_maps, indent=2), encoding="utf-8")
    (OUT / "ALL_FINDINGS.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
    (OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({
        "assetCount": len(assets),
        "sourceMapCount": len(source_maps),
        "patternCounts": summary["patternCounts"],
        "highSignalFindingCount": len(high_signal),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
