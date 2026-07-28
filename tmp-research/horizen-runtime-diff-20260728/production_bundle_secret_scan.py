#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SITE = "https://staking.horizen.io/"
MAX_ASSETS = 250
MAX_BYTES = 12_000_000

PATTERNS: dict[str, re.Pattern[str]] = {
    "pem_private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,255}\b"),
    "github_fine_grained_token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,255}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,200}\b"),
    "npm_token": re.compile(r"\bnpm_[A-Za-z0-9]{30,80}\b"),
    "cloudflare_deploy_hook": re.compile(
        r"https://api\.cloudflare\.com/client/v4/pages/webhooks/deploy_hooks/[A-Za-z0-9_-]{12,200}"
    ),
    "netlify_build_hook": re.compile(r"https://api\.netlify\.com/build_hooks/[A-Za-z0-9_-]{12,200}"),
    "vercel_deploy_hook": re.compile(r"https://api\.vercel\.com/v1/integrations/deploy/[A-Za-z0-9_/-]{12,300}"),
    "generic_bearer": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{32,}={0,2}\b"),
    "ethereum_private_key_assignment": re.compile(
        r"(?i)(?:private[_-]?key|secret[_-]?key|wallet[_-]?key)\s*[:=]\s*['\"]?0x[a-f0-9]{64}['\"]?"
    ),
    "cloudflare_api_token_assignment": re.compile(
        r"(?i)(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{30,200}['\"]?"
    ),
}

SENSITIVE_NAMES = re.compile(
    r"(?i)(?:private[_-]?key|mnemonic|seed[_-]?phrase|api[_-]?token|deploy[_-]?hook|"
    r"cloudflare[_-]?api|aws[_-]?secret|github[_-]?token|vercel[_-]?token|netlify[_-]?token)"
)


def fetch(url: str, max_bytes: int = MAX_BYTES) -> tuple[int, bytes, str, str]:
    req = urllib.request.Request(
        url,
        headers={
            "user-agent": "Mozilla/5.0 (compatible; authorized-Horizen-bundle-audit/1.0)",
            "accept": "text/html,application/javascript,text/javascript,application/json,text/css,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=45, context=ssl.create_default_context()) as response:
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise RuntimeError(f"asset exceeded {max_bytes} bytes: {url}")
        return response.status, body, response.headers.get("content-type", ""), response.geturl()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def same_origin(url: str) -> bool:
    return urllib.parse.urlparse(url).netloc == urllib.parse.urlparse(SITE).netloc


def sanitize_match(value: str) -> dict[str, Any]:
    return {
        "length": len(value),
        "sha256": hashlib.sha256(value.encode()).hexdigest(),
        "prefix": value[:4],
        "suffix": value[-4:] if len(value) >= 4 else value,
    }


def main() -> int:
    private = Path("private-evidence/production-bundle-secret-scan")
    sanitized = Path("sanitized-bundle-scan")
    private.mkdir(parents=True, exist_ok=True)
    sanitized.mkdir(parents=True, exist_ok=True)

    _, html_bytes, _, final_site = fetch(SITE)
    html = html_bytes.decode("utf-8", "ignore")
    discovered: set[str] = {final_site}
    refs = re.findall(r'''(?:src|href)=["']([^"']+)["']''', html, flags=re.I)
    for ref in refs:
        absolute = urllib.parse.urljoin(final_site, ref)
        if same_origin(absolute):
            discovered.add(absolute)

    fetched: dict[str, dict[str, Any]] = {}
    queue = list(sorted(discovered))
    source_map_urls: set[str] = set()
    errors: list[str] = []

    while queue and len(fetched) < MAX_ASSETS:
        url = queue.pop(0)
        if url in fetched:
            continue
        try:
            status, body, content_type, final_url = fetch(url)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
            continue
        text = body.decode("utf-8", "ignore")
        fetched[url] = {
            "status": status,
            "final_url": final_url,
            "content_type": content_type,
            "bytes": len(body),
            "sha256": sha(body),
            "text": text,
        }

        for ref in re.findall(r'''(?:src|href)=["']([^"']+)["']''', text, flags=re.I):
            absolute = urllib.parse.urljoin(final_url, ref)
            if same_origin(absolute) and absolute not in fetched and absolute not in queue:
                queue.append(absolute)

        for source_ref in re.findall(r"sourceMappingURL=([^\s*]+)", text):
            absolute = urllib.parse.urljoin(final_url, source_ref.strip())
            if same_origin(absolute):
                source_map_urls.add(absolute)
        if final_url.endswith((".js", ".mjs")):
            source_map_urls.add(final_url + ".map")

    for url in sorted(source_map_urls):
        if len(fetched) >= MAX_ASSETS:
            break
        if url in fetched:
            continue
        try:
            status, body, content_type, final_url = fetch(url)
            text = body.decode("utf-8", "ignore")
            fetched[url] = {
                "status": status,
                "final_url": final_url,
                "content_type": content_type,
                "bytes": len(body),
                "sha256": sha(body),
                "text": text,
            }
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    findings: list[dict[str, Any]] = []
    sensitive_name_hits: list[dict[str, Any]] = []
    source_maps: list[dict[str, Any]] = []

    for url, item in fetched.items():
        text = item["text"]
        if url.endswith(".map") or "source map" in item["content_type"].lower():
            source_maps.append({k: item[k] for k in ("status", "bytes", "sha256")} | {"url": url})
        for pattern_name, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                raw = match.group(0)
                findings.append(
                    {
                        "type": pattern_name,
                        "url": url,
                        "offset": match.start(),
                        "redacted": sanitize_match(raw),
                    }
                )
        for match in SENSITIVE_NAMES.finditer(text):
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 160)
            context = text[start:end]
            sensitive_name_hits.append(
                {
                    "url": url,
                    "name": match.group(0),
                    "offset": match.start(),
                    "context_sha256": hashlib.sha256(context.encode()).hexdigest(),
                }
            )

    high_confidence = [
        finding
        for finding in findings
        if finding["type"]
        not in {"generic_bearer"}
    ]
    result = {
        "site": SITE,
        "assets_fetched": len(fetched),
        "source_maps_fetched": len(source_maps),
        "fetch_errors": errors,
        "high_confidence_secret_candidates": len(high_confidence),
        "all_pattern_candidates": len(findings),
        "sensitive_name_occurrences": len(sensitive_name_hits),
        "findings": findings,
        "sensitive_name_hits": sensitive_name_hits,
        "source_maps": source_maps,
        "asset_manifest": [
            {k: item[k] for k in ("status", "final_url", "content_type", "bytes", "sha256")}
            | {"requested_url": url}
            for url, item in fetched.items()
        ],
        "pass": len(high_confidence) == 0,
        "security_verdict": (
            "KILL_NO_DEPLOY_CREDENTIAL_EXPOSURE"
            if not high_confidence
            else "HOLD_HIGH_CONFIDENCE_CREDENTIAL_CANDIDATE"
        ),
        "public_network_writes": 0,
    }
    (private / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    public = {
        "assets_fetched": len(fetched),
        "source_maps_fetched": len(source_maps),
        "high_confidence_secret_candidates": len(high_confidence),
        "all_pattern_candidates": len(findings),
        "sensitive_name_occurrences": len(sensitive_name_hits),
        "pass": result["pass"],
        "security_verdict": result["security_verdict"],
        "public_network_writes": 0,
    }
    (sanitized / "RESULT.json").write_text(json.dumps(public, indent=2) + "\n")
    (sanitized / "RESULT.md").write_text(
        "# Horizen production-bundle credential scan\n\n"
        f"- Assets fetched: `{len(fetched)}`\n"
        f"- Source maps fetched: `{len(source_maps)}`\n"
        f"- High-confidence credential/deploy-hook candidates: `{len(high_confidence)}`\n"
        f"- All pattern candidates: `{len(findings)}`\n"
        f"- Verdict: **{result['security_verdict']}**\n"
        "- Public-network writes: **0**\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
