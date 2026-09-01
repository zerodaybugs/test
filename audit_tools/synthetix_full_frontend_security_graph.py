#!/usr/bin/env python3
"""Complete read-only security inventory of the current Synthetix Exchange frontend graph.

The previous collector stopped at 400 assets while work remained in its queue. This collector raises
that deterministic cap, follows same-origin static/dynamic module references and source maps, records
security-sensitive code contexts, extracts same-origin API paths and third-party origins, and runs a
conservative credential-pattern scan. HTTPS GET only; no wallet, API write, signature, account,
telemetry submission, trade, transaction, or state mutation.
"""
from __future__ import annotations

import hashlib
import html.parser
import json
import pathlib
import re
import urllib.parse
import urllib.request
from collections import Counter, deque
from typing import Any

OUT = pathlib.Path("synthetix_full_frontend_security_graph")
ASSETS = OUT / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)

ROOT = "https://exchange.synthetix.io/"
ORIGIN = "https://exchange.synthetix.io"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_FILES = 1200
MAX_FILE = 24 * 1024 * 1024
MAX_TOTAL = 180 * 1024 * 1024

TERMS = (
    "dangerouslySetInnerHTML", ".innerHTML", "insertAdjacentHTML", "document.write", "srcdoc",
    "eval(", "new Function", "javascript:", "postMessage", "addEventListener(\"message\"",
    "addEventListener('message'", "event.origin", "event.source", "sessionHandoff", "privateKey",
    "exportSession", "importedSession", "session-storage", "localStorage", "sessionStorage",
    "window.open", "location.href", "location.assign", "location.replace", "redirect_uri",
    "WebSocket", "eth_sendTransaction", "eth_sendRawTransaction", "eth_signTypedData",
    "beneficiary", "destination", "walletAddress", "subAccountId", "delegatedSigners",
    "authorization", "access_token", "refresh_token", "client_secret", "api_key", "apiKey",
    "SENTRY_DSN", "posthog.init", "fetch(", "axios", "/api/", "papi.synthetix.io",
)

IMPORT_RE = re.compile(
    r"(?:import\s*(?:\([^)]*?\)|[^;]*?from\s*)|export\s+[^;]*?from\s*|new\s+URL\s*\()\s*[\"']([^\"']+)[\"']",
    re.S,
)
DYNAMIC_CHUNK_RE = re.compile(r"[\"']([^\"']+\.(?:js|mjs|json|map)(?:\?[^\"']*)?)[\"']")
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")
ABS_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
API_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(/api/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=${}%-]{1,260})")
HEX_SECRET_RE = re.compile(r"(?<![0-9A-Fa-f])(?:0x)?([0-9A-Fa-f]{64})(?![0-9A-Fa-f])")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)(?:client_secret|private_key|secret_key|api_secret|access_token|refresh_token)\s*[:=]\s*[\"']([^\"']{12,500})[\"']"
)


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
        if tag == "link" and values.get("href") and values.get("rel") in {
            "modulepreload", "preload", "stylesheet",
        }:
            self.urls.append(values["href"] or "")


def fetch(url: str) -> tuple[int, bytes, dict[str, str], str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"}, method="GET")
    with urllib.request.urlopen(req, timeout=75) as response:
        body = response.read(MAX_FILE + 1)
        if len(body) > MAX_FILE:
            raise RuntimeError(f"asset exceeds per-file cap: {url}")
        return response.status, body, dict(response.headers.items()), response.url


def same_origin(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.netloc == "exchange.synthetix.io"


def normalize(base: str, raw: str) -> str | None:
    raw = raw.strip().replace("\\/", "/")
    if not raw or raw.startswith(("data:", "blob:", "javascript:", "#")):
        return None
    url = urllib.parse.urljoin(base, raw)
    parsed = urllib.parse.urlparse(url)
    clean = parsed._replace(fragment="").geturl()
    return clean if same_origin(clean) else None


def safe_name(index: int, url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    suffix = pathlib.Path(parsed.path).suffix or ".bin"
    return f"{index:04d}_{sha(url)[:16]}{suffix}"


def contexts(text: str, term: str, radius: int = 450, cap: int = 35) -> list[dict[str, Any]]:
    output = []
    start = 0
    while len(output) < cap:
        position = text.find(term, start)
        if position < 0:
            break
        left = max(0, position - radius)
        right = min(len(text), position + len(term) + radius)
        excerpt = text[left:right]
        output.append({"offset": position, "excerpt": excerpt, "excerptSha256": sha(excerpt)})
        start = position + len(term)
    return output


def secret_findings(text: str, file_name: str, url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for kind, regex in (
        ("jwt", JWT_RE),
        ("pem_private_key", PEM_RE),
        ("assigned_secret", ASSIGNMENT_SECRET_RE),
    ):
        for match in list(regex.finditer(text))[:30]:
            value = match.group(1) if match.lastindex else match.group(0)
            findings.append({
                "kind": kind,
                "file": file_name,
                "url": url,
                "offset": match.start(),
                "valueSha256": sha(value),
                "length": len(value),
            })
    # 64-hex strings are mostly hashes/test constants. Store only context classification and hashes.
    for match in list(HEX_SECRET_RE.finditer(text))[:250]:
        value = match.group(1)
        around = text[max(0, match.start() - 140): min(len(text), match.end() + 140)]
        lowered = around.lower()
        label = "private-key-context" if any(k in lowered for k in (
            "privatekey", "private_key", "secretkey", "secret_key", "from_key", "wallet(", "account.from",
        )) else "generic-64hex"
        if label == "private-key-context":
            findings.append({
                "kind": label,
                "file": file_name,
                "url": url,
                "offset": match.start(),
                "valueSha256": sha(value),
                "contextSha256": sha(around),
            })
    return findings


def main() -> None:
    _, root_body, root_headers, final_root = fetch(ROOT)
    root_text = root_body.decode("utf-8", errors="replace")
    (OUT / "root.html").write_bytes(root_body)

    parser = EntryParser()
    parser.feed(root_text)
    queue: deque[str] = deque()
    discovered: set[str] = set()
    for raw in parser.urls:
        url = normalize(final_root, raw)
        if url and url not in discovered:
            queue.append(url)
            discovered.add(url)

    records: list[dict[str, Any]] = []
    term_matches: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    api_paths: Counter[str] = Counter()
    external_origins: Counter[str] = Counter()
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
        textual = any(token in content_type.lower() for token in (
            "javascript", "text", "json", "xml", "svg",
        )) or final_url.split("?", 1)[0].endswith((".js", ".mjs", ".json", ".map", ".css", ".html"))
        text = body.decode("utf-8", errors="replace") if textual else ""

        record = {
            "url": final_url,
            "file": filename,
            "httpStatus": status,
            "contentType": content_type,
            "bytes": len(body),
            "sha256": sha(body),
        }
        records.append(record)

        if not text:
            continue

        for term in TERMS:
            found = contexts(text, term)
            if found:
                term_matches.append({"url": final_url, "file": filename, "term": term, "occurrences": found})

        secrets.extend(secret_findings(text, filename, final_url))
        for match in API_PATH_RE.finditer(text):
            api_paths[match.group(1)] += 1
        for raw_url in ABS_URL_RE.findall(text):
            try:
                parsed = urllib.parse.urlparse(raw_url)
                if parsed.scheme in {"http", "https"} and parsed.netloc and parsed.netloc != "exchange.synthetix.io":
                    external_origins[f"{parsed.scheme}://{parsed.netloc}"] += 1
            except Exception:
                pass

        candidates = set(IMPORT_RE.findall(text)) | set(DYNAMIC_CHUNK_RE.findall(text))
        source_map = SOURCE_MAP_RE.search(text)
        if source_map:
            candidates.add(source_map.group(1).strip())
        for raw in sorted(candidates):
            child = normalize(final_url, raw)
            if child and child not in discovered:
                discovered.add(child)
                queue.append(child)

    summary = {
        "safety": "Same-origin HTTPS GET collection only; no wallet, account, API write, signature, telemetry, trade or mutation.",
        "root": ROOT,
        "rootFinalUrl": final_root,
        "rootSha256": sha(root_body),
        "rootContentType": root_headers.get("Content-Type"),
        "assetCount": len(records),
        "totalBytes": total_bytes,
        "discoveredUrlCount": len(discovered),
        "queueRemaining": len(queue),
        "graphTruncated": bool(queue),
        "termMatchGroups": len(term_matches),
        "matchedTerms": sorted({item["term"] for item in term_matches}),
        "secretCandidateCount": len(secrets),
        "secretCandidateKinds": dict(Counter(item["kind"] for item in secrets)),
        "apiPaths": [{"path": path, "count": count} for path, count in api_paths.most_common()],
        "externalOrigins": [{"origin": origin, "count": count} for origin, count in external_origins.most_common()],
        "records": records,
        "termMatches": term_matches,
        "secretCandidates": secrets,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "assetCount": summary["assetCount"],
        "totalBytes": summary["totalBytes"],
        "discoveredUrlCount": summary["discoveredUrlCount"],
        "graphTruncated": summary["graphTruncated"],
        "queueRemaining": summary["queueRemaining"],
        "matchedTerms": summary["matchedTerms"],
        "secretCandidateKinds": summary["secretCandidateKinds"],
        "apiPathCount": len(summary["apiPaths"]),
        "externalOriginCount": len(summary["externalOrigins"]),
    }, indent=2))


if __name__ == "__main__":
    main()
