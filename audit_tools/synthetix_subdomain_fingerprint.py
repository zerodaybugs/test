#!/usr/bin/env python3
"""Low-noise read-only fingerprint audit for known Synthetix DNS-provider candidates.

The probe sends exactly one GET request to each named *.synthetix.io host and
records only status, redirect origin, headers, body hash, title, and known
provider-unclaimed fingerprints. It does not access provider control panels,
claim a domain, create a deployment, authenticate, submit forms, or mutate state.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("subdomain_fingerprint")
OUT.mkdir(parents=True, exist_ok=True)
UA = "Mozilla/5.0 (compatible; authorized-low-noise-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024

HOSTS = (
    "420.synthetix.io",
    "alpha-exchange.synthetix.io",
    "analytics.synthetix.io",
    "assets.synthetix.io",
    "base-rebates.synthetix.io",
    "blog.synthetix.io",
    "contracts.synthetix.io",
    "dev.mintr.synthetix.io",
    "dev.watcher.synthetix.io",
    "developer.synthetix.io",
    "developers.synthetix.io",
    "docs.synthetix.io",
    "erc7412.synthetix.io",
    "exchange.synthetix.io",
    "feedback.synthetix.io",
    "gov.synthetix.io",
    "governance.synthetix.io",
    "grants-perps.synthetix.io",
    "grants.synthetix.io",
    "kwenta-migration.synthetix.io",
    "l2.mintr.synthetix.io",
    "legacy-liquidity.synthetix.io",
    "legacy-staking.synthetix.io",
    "let-me-in.synthetix.io",
    "leverage.synthetix.io",
    "liquidity.grants.synthetix.io",
    "liquidity.synthetix.io",
    "loans.synthetix.io",
    "mintr.synthetix.io",
    "modular-exchange.synthetix.io",
    "nft.synthetix.io",
    "node.synthetix.io",
    "oracle-manager.synthetix.io",
    "pr.synthetix.io",
    "predeposit.synthetix.io",
    "private.synthetix.io",
    "sips.synthetix.io",
    "staging.governance.synthetix.io",
    "staging.synthetix.io",
    "staking.synthetix.io",
    "stats.synthetix.io",
    "status.synthetix.io",
    "support.synthetix.io",
    "susd.synthetix.io",
    "tlx-migration.synthetix.io",
    "tokenvest.synthetix.io",
    "tools.synthetix.io",
    "vaults.synthetix.io",
    "watcher.synthetix.io",
    "wrappers.synthetix.io",
    "www.feedback.synthetix.io",
    "www.synthetix.io",
)

FINGERPRINTS: dict[str, re.Pattern[str]] = {
    "vercel_deployment_not_found": re.compile(r"(?:DEPLOYMENT_NOT_FOUND|The deployment could not be found|404:\s*NOT_FOUND)", re.I),
    "vercel_domain_not_found": re.compile(r"(?:DOMAIN_NOT_FOUND|The specified domain does not exist)", re.I),
    "github_pages_unconfigured": re.compile(r"There isn't a GitHub Pages site here", re.I),
    "netlify_not_found": re.compile(r"Not Found - Request ID:|Site not found", re.I),
    "heroku_no_such_app": re.compile(r"No such app|herokucdn\.com/error-pages/no-such-app", re.I),
    "fastly_unknown_domain": re.compile(r"Fastly error:\s*unknown domain", re.I),
    "azure_not_found": re.compile(r"404 Web Site not found", re.I),
    "cloudfront_bad_request": re.compile(r"The request could not be satisfied", re.I),
    "readme_project_missing": re.compile(r"Project doesnt exist|Project doesn't exist", re.I),
}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def clean_title(text: str) -> str | None:
    match = TITLE_RE.search(text)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:300]


def fetch(host: str) -> dict[str, Any]:
    url = "https://" + host + "/"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.5"},
        method="GET",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
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
    fingerprints = [name for name, pattern in FINGERPRINTS.items() if pattern.search(text)]
    parsed = urllib.parse.urlsplit(final_url)
    return {
        "host": host,
        "status": status,
        "elapsedMs": elapsed_ms,
        "finalOrigin": f"{parsed.scheme}://{parsed.netloc}",
        "redirectedOffHost": (parsed.hostname or "").lower() != host.lower(),
        "contentType": headers.get("Content-Type", ""),
        "server": headers.get("Server"),
        "xVercelError": headers.get("X-Vercel-Error") or headers.get("x-vercel-error"),
        "xVercelIdPresent": bool(headers.get("X-Vercel-Id") or headers.get("x-vercel-id")),
        "cacheControl": headers.get("Cache-Control"),
        "bodyBytes": len(body),
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "title": clean_title(text),
        "unclaimedFingerprints": fingerprints,
    }


def main() -> None:
    results: list[dict[str, Any]] = []
    for index, host in enumerate(HOSTS):
        try:
            results.append(fetch(host))
        except Exception as exc:  # noqa: BLE001
            results.append(
                {
                    "host": host,
                    "errorType": type(exc).__name__,
                    "errorSha256": hashlib.sha256(str(exc).encode()).hexdigest(),
                }
            )
        if index + 1 < len(HOSTS):
            time.sleep(0.75)

    candidates = [item for item in results if item.get("unclaimedFingerprints")]
    off_host = [item for item in results if item.get("redirectedOffHost")]
    errors = [item for item in results if item.get("errorType")]
    summary = {
        "safety": "Exactly one unauthenticated GET per Synthetix host; no provider access, domain claim, deployment, form submission, or state change.",
        "hostCount": len(HOSTS),
        "candidateCount": len(candidates),
        "offHostRedirectCount": len(off_host),
        "errorCount": len(errors),
        "candidates": candidates,
        "offHostRedirects": off_host,
        "errors": errors,
        "statusCounts": {
            str(status): sum(1 for item in results if item.get("status") == status)
            for status in sorted({item.get("status") for item in results if isinstance(item.get("status"), int)})
        },
    }
    (OUT / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
