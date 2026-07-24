#!/usr/bin/env python3
"""Low-noise, read-only input-boundary probe for in-scope Synthetix web APIs.

The probe makes a small fixed set of GET requests. It does not target internal
networks, metadata services, local files, authenticated endpoints, or user data.
It retains only response metadata, hashes, JSON schemas, and redacted error
signals.
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

OUT = pathlib.Path("public_api_boundary")
OUT.mkdir(parents=True, exist_ok=True)
BASE = "https://exchange.synthetix.io"
UA = "Mozilla/5.0 (compatible; authorized-low-noise-security-review/1.0)"
MAX_BODY = 3 * 1024 * 1024
ZERO = "0x0000000000000000000000000000000000000000"
SYNTHETIC = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A"

CASES: list[tuple[str, str, dict[str, str]]] = [
    ("macro_sp500_baseline", "/api/macro-price", {"symbol": "^GSPC"}),
    ("macro_gold_baseline", "/api/macro-price", {"symbol": "GC=F"}),
    ("macro_unknown_symbol", "/api/macro-price", {"symbol": "AUDIT_NOT_A_REAL_SYMBOL_20260724"}),
    ("macro_url_like_canary", "/api/macro-price", {"symbol": "https://example.com/audit-canary"}),
    ("macro_relative_path_canary", "/api/macro-price", {"symbol": "../audit-canary"}),
    ("macro_delimiter_canary", "/api/macro-price", {"symbol": "AUDIT?x=1&y=2"}),
    ("referral_teamlead_zero", "/api/referral-teamlead", {"address": ZERO}),
    ("referral_teamlead_synthetic", "/api/referral-teamlead", {"address": SYNTHETIC}),
    ("referral_teamlead_malformed", "/api/referral-teamlead", {"address": "AUDIT_'_<>_CANARY"}),
    ("referral_teamlead_url_like", "/api/referral-teamlead", {"address": "https://example.com/audit"}),
    ("referral_members_zero", "/api/referral-teammembers", {"address": ZERO}),
    ("referral_members_synthetic", "/api/referral-teammembers", {"address": SYNTHETIC}),
    ("referral_members_malformed", "/api/referral-teammembers", {"address": "AUDIT_'_<>_CANARY"}),
    ("referral_member_zero", "/api/referral-teammember", {"address": ZERO}),
    ("referral_member_synthetic", "/api/referral-teammember", {"address": SYNTHETIC}),
    ("referral_member_malformed", "/api/referral-teammember", {"address": "AUDIT_'_<>_CANARY"}),
    ("referral_teams_baseline", "/api/referral-teams", {}),
    ("leaderboard_baseline", "/api/leaderboard", {}),
    ("funding_comparison_baseline", "/api/funding-comparison", {}),
    ("fear_greed_baseline", "/api/fear-greed", {}),
    ("altcoin_season_baseline", "/api/altcoin-season", {}),
    ("dvol_baseline", "/api/dvol", {}),
    ("global_metrics_baseline", "/api/global-metrics", {}),
]

SENSITIVE_SIGNAL_PATTERNS = {
    "stack_trace": re.compile(r"(?:traceback|\bat\s+[\w.$<>]+\s*\(|stack\s*trace)", re.I),
    "internal_host": re.compile(r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254)", re.I),
    "filesystem_path": re.compile(r"(?:/var/(?:task|www)|/usr/src|node_modules|[A-Z]:\\\\)", re.I),
    "network_error": re.compile(r"(?:ECONNREFUSED|ENOTFOUND|EAI_AGAIN|socket hang up)", re.I),
    "database_error": re.compile(r"(?:postgres|postgrest|sqlstate|syntax error at or near)", re.I),
    "secret_label": re.compile(r"(?:api[_-]?key|authorization|bearer|private[_-]?key|secret)\s*[:=]", re.I),
}


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def redact(text: str) -> str:
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"(?i)(authorization|api[_-]?key|secret|token)(\s*[:=]\s*)[^\s,}\]]+", r"\1\2<redacted>", text)
    return text[:1000]


def request_case(name: str, path: str, params: dict[str, str]) -> dict[str, Any]:
    query = urllib.parse.urlencode(params)
    url = BASE + path + (("?" + query) if query else "")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "application/json,text/plain,*/*;q=0.5"},
        method="GET",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("response too large")
            status = response.status
            headers = dict(response.headers.items())
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        final_url = exc.geturl()
    elapsed_ms = round((time.monotonic() - started) * 1000, 2)

    text = body.decode("utf-8", errors="replace")
    parsed: Any = None
    try:
        parsed = json.loads(text)
    except Exception:
        pass

    signals = [label for label, pattern in SENSITIVE_SIGNAL_PATTERNS.items() if pattern.search(text)]
    record: dict[str, Any] = {
        "name": name,
        "path": path,
        "params": params,
        "status": status,
        "elapsedMs": elapsed_ms,
        "finalOrigin": urllib.parse.urlsplit(final_url).scheme + "://" + urllib.parse.urlsplit(final_url).netloc,
        "contentType": headers.get("Content-Type", ""),
        "cacheControl": headers.get("Cache-Control"),
        "accessControlAllowOrigin": headers.get("Access-Control-Allow-Origin"),
        "accessControlAllowCredentials": headers.get("Access-Control-Allow-Credentials"),
        "vary": headers.get("Vary"),
        "bodyBytes": len(body),
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "jsonSchema": schema(parsed) if parsed is not None else None,
        "sensitiveSignals": signals,
    }
    if status >= 400 or signals or parsed is None:
        record["redactedTextPrefix"] = redact(text)
    return record


def main() -> None:
    results: list[dict[str, Any]] = []
    for index, (name, path, params) in enumerate(CASES):
        try:
            results.append(request_case(name, path, params))
        except Exception as exc:  # noqa: BLE001
            results.append({"name": name, "path": path, "params": params, "error": f"{type(exc).__name__}: {exc}"})
        if index + 1 < len(CASES):
            time.sleep(0.75)

    by_name = {item["name"]: item for item in results}
    summary = {
        "safety": "Fixed low-noise GET set only; no internal hosts, metadata endpoints, local files, authentication, or state changes.",
        "requestCount": len(results),
        "unexpectedOriginRedirects": [
            item["name"] for item in results if item.get("finalOrigin") not in (None, BASE)
        ],
        "responsesWithSensitiveSignals": [
            {"name": item["name"], "signals": item.get("sensitiveSignals")}
            for item in results
            if item.get("sensitiveSignals")
        ],
        "macroUrlLikeMatchesKnownResponses": {
            "matchesUnknown": by_name.get("macro_url_like_canary", {}).get("bodySha256")
            == by_name.get("macro_unknown_symbol", {}).get("bodySha256"),
            "matchesSp500": by_name.get("macro_url_like_canary", {}).get("bodySha256")
            == by_name.get("macro_sp500_baseline", {}).get("bodySha256"),
            "matchesGold": by_name.get("macro_url_like_canary", {}).get("bodySha256")
            == by_name.get("macro_gold_baseline", {}).get("bodySha256"),
        },
        "cases": [
            {
                "name": item.get("name"),
                "status": item.get("status"),
                "contentType": item.get("contentType"),
                "bodyBytes": item.get("bodyBytes"),
                "bodySha256": item.get("bodySha256"),
                "signals": item.get("sensitiveSignals"),
                "error": item.get("error"),
            }
            for item in results
        ],
    }
    (OUT / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
