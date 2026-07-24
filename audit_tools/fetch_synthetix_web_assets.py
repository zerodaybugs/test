#!/usr/bin/env python3
"""Passively collect same-origin public web assets for static review.

No crawling beyond static assets explicitly embedded in the three in-scope
landing pages or imported by those JavaScript modules, no form submissions,
no authentication, and no state-changing requests.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser

OUT = pathlib.Path("web_assets")
TARGETS = {
    "synthetix": "https://synthetix.io/",
    "exchange": "https://exchange.synthetix.io/",
    "governance": "https://governance.synthetix.io/",
}
MAX_BYTES = 30 * 1024 * 1024
MAX_ASSETS_PER_SITE = 250
UA = "Mozilla/5.0 (compatible; passive-security-review/1.0)"
IMPORT_RE = re.compile(
    r"(?:from\s*|import\s*\()\s*['\"](?P<url>[^'\"]+)['\"]",
    re.MULTILINE,
)
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")


class AssetParser(HTMLParser):
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
            if any(kind in rel for kind in ("modulepreload", "preload", "stylesheet")) or href.endswith((".js", ".mjs")):
                self.urls.add(href)
        # Astro hydrates client islands from these explicit static module URLs.
        for attribute in ("component-url", "renderer-url", "before-hydration-url"):
            if values.get(attribute):
                self.urls.add(values[attribute] or "")


def fetch(url: str) -> tuple[bytes, dict[str, str], int]:
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(request, timeout=45) as response:
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError(f"asset exceeds {MAX_BYTES} bytes")
        return body, dict(response.headers.items()), response.status


def safe_name(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    base = pathlib.PurePosixPath(parsed.path).name or "index.html"
    digest = hashlib.sha256(url.encode()).hexdigest()[:12]
    return f"{digest}__{base}"


def same_origin(base: str, candidate: str) -> bool:
    a = urllib.parse.urlparse(base)
    b = urllib.parse.urlparse(candidate)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def add_if_static(queue: deque[str], enqueued: set[str], base: str, parent: str, value: str) -> None:
    url = urllib.parse.urljoin(parent, value.strip())
    if not same_origin(base, url) or url in enqueued:
        return
    suffix = pathlib.PurePosixPath(urllib.parse.urlparse(url).path).suffix.lower()
    if suffix not in {".js", ".mjs", ".css", ".json", ".map", ".wasm", ".woff", ".woff2"}:
        return
    enqueued.add(url)
    queue.append(url)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, object]] = []

    for label, base in TARGETS.items():
        target_dir = OUT / label
        target_dir.mkdir(parents=True, exist_ok=True)
        html, headers, status = fetch(base)
        (target_dir / "index.html").write_bytes(html)
        (target_dir / "index.headers.json").write_text(json.dumps(headers, indent=2), encoding="utf-8")
        manifest.append({"site": label, "url": base, "status": status, "bytes": len(html), "path": str(target_dir / "index.html")})

        parser = AssetParser()
        parser.feed(html.decode("utf-8", errors="replace"))
        queue: deque[str] = deque()
        enqueued: set[str] = set()
        for value in sorted(parser.urls):
            add_if_static(queue, enqueued, base, base, value)

        seen: set[str] = set()
        while queue and len(seen) < MAX_ASSETS_PER_SITE:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            path = target_dir / safe_name(url)
            record: dict[str, object] = {"site": label, "url": url, "path": str(path)}
            try:
                body, asset_headers, asset_status = fetch(url)
                path.write_bytes(body)
                record.update(status=asset_status, bytes=len(body), content_type=asset_headers.get("Content-Type", ""))

                text = body.decode("utf-8", errors="ignore")
                for match in IMPORT_RE.finditer(text):
                    add_if_static(queue, enqueued, base, url, match.group("url"))

                # Fetch only explicitly advertised source maps; do not guess paths.
                for map_ref in SOURCE_MAP_RE.findall(text[-4096:])[:1]:
                    add_if_static(queue, enqueued, base, url, map_ref.rstrip("*/"))
            except Exception as exc:  # noqa: BLE001
                record["error"] = repr(exc)
            manifest.append(record)
            time.sleep(0.05)

    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
