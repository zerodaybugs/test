#!/usr/bin/env python3
"""Read-only production asset verifier for delegated-signer visibility.

The collector fetches only same-origin assets explicitly linked or imported by
https://exchange.synthetix.io/. It performs no authentication, form submission,
API mutation, signing, or transaction. Matched assets are retained with SHA-256
hashes and narrowly scoped source excerpts for reproducibility.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

OUT = pathlib.Path("delegate_visibility_production")
ASSETS = OUT / "assets"
OUT.mkdir(parents=True, exist_ok=True)
ASSETS.mkdir(parents=True, exist_ok=True)

BASE = "https://exchange.synthetix.io/"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BYTES = 35 * 1024 * 1024
MAX_ASSETS = 300
MAX_DEPTH = 4


class LinkedAssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.urls.add(values["src"] or "")
        if tag == "link" and values.get("href"):
            rel = (values.get("rel") or "").lower()
            href = values["href"] or ""
            if any(kind in rel for kind in ("modulepreload", "preload")) or href.endswith((".js", ".mjs")):
                self.urls.add(href)


def fetch(url: str) -> tuple[bytes, dict[str, str], int]:
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError(f"asset exceeds {MAX_BYTES} bytes")
        return body, dict(response.headers.items()), response.status


def same_origin(url: str) -> bool:
    base = urllib.parse.urlsplit(BASE)
    candidate = urllib.parse.urlsplit(url)
    return (candidate.scheme, candidate.netloc) == (base.scheme, base.netloc)


def safe_name(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    base = pathlib.PurePosixPath(parsed.path).name or "index.html"
    return f"{hashlib.sha256(url.encode()).hexdigest()[:12]}__{base}"


def imports(text: str, parent: str) -> set[str]:
    found: set[str] = set()
    patterns = (
        r'(?:from\s*|import\s*)["\']([^"\']+\.m?js(?:\?[^"\']*)?)["\']',
        r'import\(["\']([^"\']+\.m?js(?:\?[^"\']*)?)["\']\)',
    )
    for pattern in patterns:
        for match in re.findall(pattern, text):
            absolute = urllib.parse.urljoin(parent, match)
            if same_origin(absolute):
                found.add(absolute)
    return found


PATTERNS: dict[str, str] = {
    "delegate_only_filter_definition": r'\b[A-Za-z_$][\w$]*=\w+=>\w+\.filter\(\w+=>\{var \w+;return\(\w+=\w+\.permissions\)==null\?void 0:\w+\.includes\("delegate"\)\}\)',
    "delegate_filter_export": r'\b[A-Za-z_$][\w$]* as e6\b',
    "delegate_filter_import": r'\be6 as [A-Za-z_$][\w$]*\b',
    "filtered_backend_signers_usage": r'[A-Za-z_$][\w$]*\([^)]*\.delegatedSigners\?\?\[\]\)',
    "filtered_map_controls": r'\.length!==0&&\w+\.set\([^;]+delegateCount:\w+\.length,delegates:\w+\.map',
    "conditional_delegate_panel": r'\w+&&\w+&&\w+\.jsx\([^,]+,\{account:\w+,onRevokeAll:',
    "revoke_all_label": r'Revoke All Delegates',
    "session_permission_creation": r'permissions:\["trading"\]',
    "session_permission_normalization_evidence": r'permissions:\["session"\]',
    "session_store": r'name:"session-storage"',
    "session_private_key_storage": r'privateKey:\w+,createdAt:Date\.now\(\),expiresAt:',
    "default_session_duration": r'DEFAULT_SESSION_DURATION:30\*24\*60\*60\*1e3',
}


def excerpts(text: str, pattern: str, radius: int = 260) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for match in re.finditer(pattern, text):
        start = max(0, match.start() - radius)
        end = min(len(text), match.end() + radius)
        results.append(
            {
                "offsetChars": match.start(),
                "match": match.group(0),
                "excerpt": text[start:end],
            }
        )
        if len(results) >= 8:
            break
    return results


def main() -> None:
    root, root_headers, root_status = fetch(BASE)
    (OUT / "index.html").write_bytes(root)
    parser = LinkedAssetParser()
    parser.feed(root.decode("utf-8", errors="replace"))

    queue: list[tuple[str, int]] = [
        (urllib.parse.urljoin(BASE, value), 0) for value in sorted(parser.urls) if value
    ]
    seen: set[str] = set()
    manifest: list[dict[str, Any]] = [
        {
            "url": BASE,
            "status": root_status,
            "bytes": len(root),
            "sha256": hashlib.sha256(root).hexdigest(),
            "contentType": root_headers.get("Content-Type", ""),
            "path": "index.html",
        }
    ]
    all_matches: dict[str, list[dict[str, Any]]] = {name: [] for name in PATTERNS}

    while queue and len(seen) < MAX_ASSETS:
        url, depth = queue.pop(0)
        if url in seen or not same_origin(url) or depth > MAX_DEPTH:
            continue
        seen.add(url)
        record: dict[str, Any] = {"url": url, "depth": depth}
        try:
            body, headers, status = fetch(url)
            name = safe_name(url)
            path = ASSETS / name
            path.write_bytes(body)
            record.update(
                status=status,
                bytes=len(body),
                sha256=hashlib.sha256(body).hexdigest(),
                contentType=headers.get("Content-Type", ""),
                path=str(path.relative_to(OUT)),
            )
            text = body.decode("utf-8", errors="ignore")
            for pattern_name, pattern in PATTERNS.items():
                for result in excerpts(text, pattern):
                    all_matches[pattern_name].append(
                        {
                            "url": url,
                            "assetPath": record["path"],
                            "assetSha256": record["sha256"],
                            **result,
                        }
                    )
            if depth < MAX_DEPTH:
                for child in sorted(imports(text, url)):
                    if child not in seen:
                        queue.append((child, depth + 1))
        except Exception as exc:  # noqa: BLE001
            record["error"] = f"{type(exc).__name__}: {exc}"
        manifest.append(record)
        time.sleep(0.04)

    counts = {name: len(values) for name, values in all_matches.items()}
    required = (
        "delegate_only_filter_definition",
        "delegate_filter_export",
        "delegate_filter_import",
        "filtered_backend_signers_usage",
        "filtered_map_controls",
        "conditional_delegate_panel",
        "revoke_all_label",
        "session_permission_creation",
        "session_store",
        "session_private_key_storage",
        "default_session_duration",
    )
    summary = {
        "safety": "Same-origin production GET asset collection only; no authentication, state change, signing or transaction.",
        "base": BASE,
        "assetCount": len(manifest) - 1,
        "erroredAssetCount": sum("error" in item for item in manifest),
        "patternCounts": counts,
        "requiredPatternsPresent": {name: counts[name] > 0 for name in required},
        "allRequiredPatternsPresent": all(counts[name] > 0 for name in required),
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (OUT / "matches.json").write_text(json.dumps(all_matches, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
