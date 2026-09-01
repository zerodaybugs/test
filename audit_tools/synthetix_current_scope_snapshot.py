#!/usr/bin/env python3
"""Read-only snapshot of the current public Synthetix Immunefi program pages.

Fetches only public HTML/embedded JSON and records asset URLs, impact labels, rules, timestamps, and
integrity hashes. No authentication, submission, account, or protocol interaction.
"""
from __future__ import annotations

import hashlib
import html
import json
import pathlib
import re
import urllib.request
from typing import Any

OUT = pathlib.Path("synthetix_current_scope_snapshot")
OUT.mkdir(parents=True, exist_ok=True)
URLS = {
    "information": "https://immunefi.com/bug-bounty/synthetix/information/",
    "scope": "https://immunefi.com/bug-bounty/synthetix/scope/",
}
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 15 * 1024 * 1024
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def fetch(url: str) -> tuple[int, bytes, dict[str, str], str]:
    request = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise RuntimeError("page exceeds safety cap")
        return response.status, body, dict(response.headers.items()), response.url


def strings(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from strings(child)
    elif isinstance(value, str):
        yield value


def parse_json_scripts(text: str) -> list[Any]:
    docs = []
    for match in re.finditer(r"<script[^>]*type=[\"']application/json[\"'][^>]*>(.*?)</script>", text, re.S | re.I):
        raw = html.unescape(match.group(1)).strip()
        try:
            docs.append(json.loads(raw))
        except Exception:
            pass
    for match in re.finditer(r"<script[^>]*id=[\"']__NEXT_DATA__[\"'][^>]*>(.*?)</script>", text, re.S | re.I):
        raw = html.unescape(match.group(1)).strip()
        try:
            docs.append(json.loads(raw))
        except Exception:
            pass
    return docs


def relevant_text(text: str, docs: list[Any]) -> list[str]:
    candidates = []
    plain = re.sub(r"<script.*?</script>|<style.*?</style>", " ", text, flags=re.S | re.I)
    plain = re.sub(r"<[^>]+>", " ", plain)
    plain = html.unescape(re.sub(r"\s+", " ", plain))
    for pattern in (
        r".{0,180}(?:Critical|High|Medium|Low).{0,300}",
        r".{0,180}(?:Primacy of Impact|Primacy of Rules|PoC|proof of concept).{0,300}",
        r".{0,180}(?:out of scope|prohibited|testnet|mainnet|fork).{0,300}",
    ):
        candidates.extend(m.group(0) for m in re.finditer(pattern, plain, re.I))
    for doc in docs:
        for value in strings(doc):
            if any(term.lower() in value.lower() for term in (
                "critical", "high", "private key", "direct theft", "out of scope", "proof of concept",
                "mainnet", "testnet", "fork", "primacy", "bounty", "reward",
            )):
                candidates.append(value[:1000])
    dedup = []
    seen = set()
    for item in candidates:
        clean = re.sub(r"\s+", " ", item).strip()
        if clean and clean not in seen:
            seen.add(clean)
            dedup.append(clean)
    return dedup[:500]


def main() -> None:
    result = {"pages": {}}
    all_urls = set()
    all_addresses = set()
    for label, url in URLS.items():
        status, body, headers, final_url = fetch(url)
        text = body.decode("utf-8", errors="replace")
        (OUT / f"{label}.html").write_bytes(body)
        docs = parse_json_scripts(text)
        urls = sorted(set(URL_RE.findall(text)))
        addresses = sorted(set(ADDRESS_RE.findall(text)), key=str.lower)
        for doc in docs:
            for value in strings(doc):
                urls.extend(URL_RE.findall(value))
                addresses.extend(ADDRESS_RE.findall(value))
        urls = sorted(set(urls))
        addresses = sorted(set(addresses), key=str.lower)
        all_urls.update(urls)
        all_addresses.update(addresses)
        result["pages"][label] = {
            "requestedUrl": url,
            "finalUrl": final_url,
            "httpStatus": status,
            "contentType": headers.get("Content-Type"),
            "bytes": len(body),
            "sha256": sha(body),
            "jsonDocumentCount": len(docs),
            "urls": urls,
            "addresses": addresses,
            "relevantText": relevant_text(text, docs),
        }
    result["allUrls"] = sorted(all_urls)
    result["allAddresses"] = sorted(all_addresses, key=str.lower)
    (OUT / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "pageStatuses": {k: v["httpStatus"] for k, v in result["pages"].items()},
        "uniqueUrls": len(result["allUrls"]),
        "uniqueAddresses": len(result["allAddresses"]),
        "relevantTextCounts": {k: len(v["relevantText"]) for k, v in result["pages"].items()},
    }, indent=2))


if __name__ == "__main__":
    main()
