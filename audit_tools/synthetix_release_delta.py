#!/usr/bin/env python3
"""Read-only delta analysis between the current Exchange release and the July-14 entry bundle.

The previously captured production entry was ``index-BjrW6h18.js``. This collector attempts
to retrieve that immutable asset, crawls both same-origin import graphs, and highlights code
and string contexts newly introduced in the current release around wallet, signing, session,
telemetry, destination, beneficiary, delegation, transaction and account-routing boundaries.

HTTPS GET only. No wallet, account, signature, API write, WebSocket, telemetry ingestion, or
state-changing request is performed.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.parse
import urllib.request
from collections import Counter, deque
from typing import Any

OUT = pathlib.Path("synthetix_release_delta")
OUT.mkdir(parents=True, exist_ok=True)
BASE = "https://exchange.synthetix.io/"
ORIGIN = "https://exchange.synthetix.io"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 20 * 1024 * 1024
MAX_ASSETS = 500
OLD_ENTRY_CANDIDATES = [
    "https://exchange.synthetix.io/assets/index-BjrW6h18.js",
    "https://exchange.synthetix.io/index-BjrW6h18.js",
]

SENSITIVE = [
    "privateKey", "sessionHandoff", "exportSession", "importedSession", "sessionSigners",
    "AddDelegatedSigner", "RemoveDelegatedSigner", "removeAllDelegatedSigners", "permissions",
    "beneficiary", "destination", "subAccountId", "subaccountId", "walletAddress",
    "eth_sendTransaction", "eth_signTypedData", "personal_sign", "signTypedData",
    "postMessage", "addEventListener(\"message", "event.origin", "event.source",
    "localStorage", "sessionStorage", "Sentry", "posthog", "segment", "telemetry",
    "withdrawCollateral", "transferCollateral", "voluntaryCollateralExchange",
    "scheduleCancel", "cancelAllOrders", "createSubaccount", "manager",
]

IMPORT_RE = re.compile(
    r"(?:from\s*|import\s*\(|import\s*)[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']"
)
SCRIPT_RE = re.compile(r"<script[^>]+type=[\"']module[\"'][^>]+src=[\"']([^\"']+)[\"']", re.I)
STRING_RE = re.compile(r"(?P<q>[\"'`])(?P<s>(?:\\.|(?!\1).){2,240})(?P=q)", re.S)


def sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=50) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
    if len(body) > MAX_BODY:
        raise RuntimeError(f"body too large: {url}")
    return status, body, headers


def same_origin_js(base_url: str, spec: str) -> str | None:
    resolved = urllib.parse.urljoin(base_url, spec)
    parsed = urllib.parse.urlparse(resolved)
    if parsed.scheme != "https" or parsed.netloc != "exchange.synthetix.io":
        return None
    if not parsed.path.endswith(".js"):
        return None
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def crawl(entry: str, label: str) -> dict[str, Any]:
    queue = deque([entry])
    seen: dict[str, dict[str, Any]] = {}
    failures = []
    while queue and len(seen) < MAX_ASSETS:
        url = queue.popleft()
        if url in seen:
            continue
        status, body, headers = fetch(url)
        if status != 200:
            failures.append({"url": url, "status": status, "bodySha256": sha(body), "bodyBytes": len(body)})
            continue
        text = body.decode("utf-8", errors="replace")
        rel = urllib.parse.urlparse(url).path.lstrip("/") or "index.js"
        safe_rel = re.sub(r"[^A-Za-z0-9._/-]", "_", rel)
        path = OUT / label / safe_rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        imports = []
        for match in IMPORT_RE.finditer(text):
            child = same_origin_js(url, match.group(1))
            if child and child not in imports:
                imports.append(child)
                if child not in seen:
                    queue.append(child)
        seen[url] = {
            "url": url,
            "path": str(path.relative_to(OUT)),
            "bytes": len(body),
            "sha256": sha(body),
            "contentType": headers.get("Content-Type") or headers.get("content-type"),
            "imports": imports,
        }
        time.sleep(0.03)
    return {"entry": entry, "assetCount": len(seen), "assets": seen, "failures": failures, "truncated": bool(queue)}


def extract_strings(graph: dict[str, Any]) -> Counter[str]:
    values: Counter[str] = Counter()
    for meta in graph.get("assets", {}).values():
        text = (OUT / meta["path"]).read_text(encoding="utf-8", errors="replace")
        for match in STRING_RE.finditer(text):
            value = match.group("s")
            if 2 <= len(value) <= 240 and not value.isspace():
                values[value] += 1
    return values


def contexts(graph: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {term: [] for term in SENSITIVE}
    for meta in graph.get("assets", {}).values():
        text = (OUT / meta["path"]).read_text(encoding="utf-8", errors="replace")
        for term in SENSITIVE:
            start = 0
            while len(result[term]) < 30:
                index = text.find(term, start)
                if index < 0:
                    break
                left = max(0, index - 350)
                right = min(len(text), index + len(term) + 500)
                excerpt = text[left:right]
                result[term].append({
                    "asset": meta["url"],
                    "offset": index,
                    "excerpt": excerpt,
                    "excerptSha256": sha(excerpt),
                })
                start = index + len(term)
    return {key: value for key, value in result.items() if value}


def main() -> None:
    status, html, _ = fetch(BASE)
    if status != 200:
        raise RuntimeError(f"current HTML returned {status}")
    html_text = html.decode("utf-8", errors="replace")
    match = SCRIPT_RE.search(html_text)
    if not match:
        raise RuntimeError("current module entry not found")
    current_entry = urllib.parse.urljoin(BASE, match.group(1))

    old_attempts = []
    old_entry = None
    for candidate in OLD_ENTRY_CANDIDATES:
        old_status, old_body, old_headers = fetch(candidate)
        old_attempts.append({
            "url": candidate,
            "status": old_status,
            "bytes": len(old_body),
            "sha256": sha(old_body),
            "contentType": old_headers.get("Content-Type") or old_headers.get("content-type"),
        })
        if old_status == 200 and b"javascript" in (old_headers.get("Content-Type", "").lower().encode() + old_body[:100].lower()):
            old_entry = candidate
            break

    current = crawl(current_entry, "current")
    current_contexts = contexts(current)
    current_strings = extract_strings(current)

    old = None
    old_contexts: dict[str, list[dict[str, Any]]] = {}
    old_strings: Counter[str] = Counter()
    if old_entry:
        old = crawl(old_entry, "old")
        old_contexts = contexts(old)
        old_strings = extract_strings(old)

    new_sensitive_terms = sorted(set(current_contexts) - set(old_contexts))
    changed_sensitive_terms = sorted(
        term for term in current_contexts
        if [item["excerptSha256"] for item in current_contexts.get(term, [])]
        != [item["excerptSha256"] for item in old_contexts.get(term, [])]
    )
    new_strings = [
        {"value": value, "count": count}
        for value, count in current_strings.items()
        if value not in old_strings and any(term.lower() in value.lower() for term in SENSITIVE)
    ]
    new_strings.sort(key=lambda item: (-item["count"], item["value"]))

    summary = {
        "safety": "HTTPS GETs to the in-scope Exchange origin only; no wallet, API write, telemetry, or state change.",
        "currentHtmlSha256": sha(html),
        "currentEntry": current_entry,
        "oldEntryAttempts": old_attempts,
        "oldEntryRecovered": old_entry,
        "currentAssetCount": current["assetCount"],
        "oldAssetCount": old["assetCount"] if old else 0,
        "currentGraphTruncated": current["truncated"],
        "oldGraphTruncated": old["truncated"] if old else None,
        "newSensitiveTerms": new_sensitive_terms,
        "changedSensitiveTerms": changed_sensitive_terms,
        "newSensitiveStrings": new_strings[:300],
        "currentContexts": current_contexts,
        "oldContexts": old_contexts,
        "verdict": "DELTA_AVAILABLE" if old else "OLD_ENTRY_UNAVAILABLE",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    (OUT / "current-graph.json").write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
    if old:
        (OUT / "old-graph.json").write_text(json.dumps(old, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "currentEntry": current_entry,
        "oldEntryRecovered": old_entry,
        "currentAssetCount": current["assetCount"],
        "oldAssetCount": old["assetCount"] if old else 0,
        "newSensitiveTerms": new_sensitive_terms,
        "changedSensitiveTermCount": len(changed_sensitive_terms),
        "verdict": summary["verdict"],
    }, indent=2))


if __name__ == "__main__":
    main()
