#!/usr/bin/env python3
"""Read-only Origin allowlist matching matrix for Synthetix Dynamic environments."""
from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.error
import urllib.request
from typing import Any

OUT = pathlib.Path("dynamic_origin_match")
OUT.mkdir(parents=True, exist_ok=True)

BASE = "https://app.dynamicauth.com/api/v0"
ENVIRONMENTS = (
    "d5f379e2-ec2d-4e7c-b541-8117684d3e98",
    "dca95954-81d8-4ef8-b20f-b1c3b6781cb6",
)
ORIGINS = (
    "https://exchange.synthetix.io",
    "https://exchange.synthetix.io:443",
    "http://exchange.synthetix.io",
    "https://exchange.synthetix.io.attacker.invalid",
    "https://attacker-exchange.synthetix.io",
    "https://synthetix.io",
    "https://www.synthetix.io",
    "https://governance.synthetix.io",
    "https://attacker.invalid",
    "null",
)
UA = "Mozilla/5.0 (compatible; authorized-passive-security-review/1.0)"
MAX_BODY = 1024 * 1024


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def request(url: str, origin: str, method: str, intended_method: str | None = None) -> dict[str, Any]:
    headers = {"User-Agent": UA, "Accept": "application/json", "Origin": origin}
    if intended_method:
        headers["Access-Control-Request-Method"] = intended_method
        headers["Access-Control-Request-Headers"] = "content-type"
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            raw_headers = response.headers.items()
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        raw_headers = exc.headers.items() if exc.headers else []
    if len(body) > MAX_BODY:
        raise RuntimeError("response too large")
    response_headers = {str(key).lower(): str(value) for key, value in raw_headers}
    return {
        "origin": origin,
        "method": method,
        "intendedMethod": intended_method,
        "status": status,
        "bodyBytes": len(body),
        "bodySha256": digest(body),
        "accessControlAllowOrigin": response_headers.get("access-control-allow-origin"),
        "accessControlAllowCredentials": response_headers.get("access-control-allow-credentials"),
        "accessControlAllowMethods": response_headers.get("access-control-allow-methods"),
        "accessControlAllowHeaders": response_headers.get("access-control-allow-headers"),
        "vary": response_headers.get("vary"),
    }


def main() -> None:
    results: dict[str, list[dict[str, Any]]] = {}
    for environment_id in ENVIRONMENTS:
        environment_results: list[dict[str, Any]] = []
        settings_url = f"{BASE}/sdk/{environment_id}/settings"
        init_url = f"{BASE}/sdk/{environment_id}/providers/google/initAuth"
        for origin in ORIGINS:
            environment_results.append(request(settings_url, origin, "GET"))
            environment_results.append(request(init_url, origin, "OPTIONS", "POST"))
        results[environment_id] = environment_results

    allowed = {
        environment_id: sorted(
            {
                item["origin"]
                for item in items
                if item.get("accessControlAllowOrigin") == item.get("origin")
            }
        )
        for environment_id, items in results.items()
    }
    output = {
        "safety": "Public settings GET and preflight OPTIONS only; no login, credential, user, wallet or state mutation.",
        "results": results,
        "originsExplicitlyAllowed": allowed,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"originsExplicitlyAllowed": allowed}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
