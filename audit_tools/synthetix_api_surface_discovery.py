#!/usr/bin/env python3
"""Curated, low-noise unauthenticated surface discovery for official Synthetix API hosts.

Safety constraints:
- official production/test `*.synthetix.io` API hosts only;
- fixed path list, one GET per path per host;
- no parameters, credentials, signatures, account IDs, fuzzing, recursion, or state changes;
- responses reduced to status, headers, schema, hashes, and redacted prefixes;
- bodies capped at 2 MiB.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("api_surface_discovery")
OUT.mkdir(parents=True, exist_ok=True)
HOSTS = ("papi.synthetix.io", "api.test.synthetix.io")
PATHS = (
    "/",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/version",
    "/v1/version",
    "/v1/status",
    "/v1/exchange/status",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/api-docs/",
    "/docs",
    "/docs/",
    "/swagger",
    "/swagger/",
    "/redoc",
    "/v1/openapi.json",
    "/v1/swagger.json",
    "/v1/docs",
    "/v1/docs/",
    "/.well-known/openapi.json",
    "/metrics",
    "/config",
    "/v1/config",
    "/graphql",
)
UA = "Mozilla/5.0 (compatible; authorized-low-noise-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
SENSITIVE = {
    "secret_label": re.compile(r"(?:api[_-]?key|authorization|bearer|private[_-]?key|secret|password|token)\s*[:=]", re.I),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "internal_host": re.compile(r"(?:localhost|127\.0\.0\.1|169\.254\.169\.254|\.internal\b|\.local\b)", re.I),
    "filesystem_path": re.compile(r"(?:/var/(?:task|www)|/usr/src|/home/[^/\s]+|node_modules)", re.I),
    "stack_trace": re.compile(r"(?:traceback|stack trace|\bat\s+[\w.$<>]+\s*\()", re.I),
}


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 5:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def redact(text: str) -> str:
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"(?i)(authorization|api[_-]?key|secret|password|token)(\s*[:=]\s*)[^\s,}\]]+", r"\1\2<redacted>", text)
    return text[:2000]


def request(host: str, path: str) -> dict[str, Any]:
    url = f"https://{host}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json,text/plain,text/html,*/*;q=0.5"}, method="GET")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=35) as response:
            body = response.read(MAX_BODY + 1)
            truncated = len(body) > MAX_BODY
            body = body[:MAX_BODY]
            status = response.status
            headers = dict(response.headers.items())
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        truncated = len(body) > MAX_BODY
        body = body[:MAX_BODY]
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        final_url = exc.geturl()
    elapsed = round((time.monotonic() - started) * 1000, 2)
    text = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None
    signals = [name for name, pattern in SENSITIVE.items() if pattern.search(text)]
    final = urllib.parse.urlsplit(final_url)
    record = {
        "host": host,
        "path": path,
        "status": status,
        "elapsedMs": elapsed,
        "finalOrigin": f"{final.scheme}://{final.netloc}" if final.scheme and final.netloc else None,
        "finalPath": final.path,
        "contentType": headers.get("Content-Type"),
        "server": headers.get("Server"),
        "contentSecurityPolicy": headers.get("Content-Security-Policy"),
        "accessControlAllowOrigin": headers.get("Access-Control-Allow-Origin"),
        "accessControlAllowCredentials": headers.get("Access-Control-Allow-Credentials"),
        "bodyBytes": len(body),
        "bodySha256": digest(body),
        "truncated": truncated,
        "jsonSchema": schema(parsed) if parsed is not None else None,
        "sensitiveSignals": signals,
    }
    if status >= 400 or parsed is None or signals or "openapi" in path or "swagger" in path or path in ("/metrics", "/config", "/v1/config"):
        record["redactedTextPrefix"] = redact(text)
    return record


def main() -> None:
    records: list[dict[str, Any]] = []
    for host in HOSTS:
        for index, path in enumerate(PATHS):
            try:
                records.append(request(host, path))
            except Exception as exc:  # noqa: BLE001
                records.append({"host": host, "path": path, "errorType": type(exc).__name__, "errorSha256": digest(str(exc))})
            if index + 1 < len(PATHS):
                time.sleep(0.25)
    interesting = [
        record for record in records
        if record.get("status") not in (404, 405)
        or record.get("sensitiveSignals")
        or record.get("jsonSchema") is not None
    ]
    openapi_like = [
        {"host": record.get("host"), "path": record.get("path"), "status": record.get("status"), "bodySha256": record.get("bodySha256"), "jsonSchema": record.get("jsonSchema")}
        for record in records
        if record.get("status") == 200 and ("openapi" in record.get("path", "") or "swagger" in record.get("path", "") or "api-docs" in record.get("path", "") or record.get("path") in ("/docs", "/docs/", "/redoc"))
    ]
    summary = {
        "safety": "Fixed one-GET-per-path discovery on two official API hosts only; no auth, parameters, fuzzing, recursion or mutations.",
        "requestCount": len(records),
        "interestingCount": len(interesting),
        "openApiLike": openapi_like,
        "sensitiveSignalCases": [
            {"host": record.get("host"), "path": record.get("path"), "status": record.get("status"), "signals": record.get("sensitiveSignals"), "bodySha256": record.get("bodySha256")}
            for record in records if record.get("sensitiveSignals")
        ],
        "interesting": interesting,
        "records": records,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({"requestCount": len(records), "interestingCount": len(interesting), "openApiLike": openapi_like, "sensitiveSignalCases": summary["sensitiveSignalCases"]}, indent=2))


if __name__ == "__main__":
    main()
