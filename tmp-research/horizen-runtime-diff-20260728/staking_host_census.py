#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import json
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CRT_QUERY = "https://crt.sh/?q=%25.horizen.io&output=json"
CERTSPOTTER_QUERY = (
    "https://api.certspotter.com/v1/issuances?domain=horizen.io"
    "&include_subdomains=true&expand=dns_names"
)
KEYWORDS = ("stake", "staking", "staker", "zenstaker", "reward")
KNOWN_AND_LIKELY = {
    "staking.horizen.io",
    "staking-testnet.horizen.io",
    "stake.horizen.io",
    "staking-dev.horizen.io",
    "staking-preview.horizen.io",
    "staking-staging.horizen.io",
    "zenstaking.horizen.io",
    "zen-staking.horizen.io",
    "staker.horizen.io",
    "rewards.horizen.io",
}
TAKEOVER_FINGERPRINTS = {
    "cloudflare_pages": ["project not found", "there is nothing here yet", "unknown domain"],
    "github_pages": ["there isn't a github pages site here", "for root urls"],
    "netlify": ["not found - request id", "site not found"],
    "vercel": ["deployment_not_found", "the deployment could not be found"],
    "heroku": ["no such app"],
    "aws_s3": ["nosuchbucket"],
    "fastly": ["fastly error: unknown domain"],
}


def run(*args: str, timeout: int = 30) -> str:
    proc = subprocess.run(
        list(args), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout
    )
    return proc.stdout.strip()


def request(url: str, timeout: int = 30, attempts: int = 4) -> tuple[int | None, bytes, str | None]:
    last = b""
    for attempt in range(attempts):
        req = urllib.request.Request(
            url,
            headers={
                "user-agent": "Mozilla/5.0 (compatible; authorized-Horizen-passive-census/2.0)",
                "accept": "application/json,text/html,*/*",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as response:
                return response.status, response.read(5_000_000), response.geturl()
        except urllib.error.HTTPError as exc:
            last = exc.read(1_000_000)
            if exc.code < 500:
                return exc.code, last, exc.geturl()
        except Exception as exc:
            last = str(exc).encode()
        time.sleep(2 + attempt * 2)
    return None, last, None


def fetch_page(url: str, timeout: int = 20) -> tuple[int | None, str, str | None]:
    status, body, final = request(url, timeout=timeout, attempts=2)
    return status, body[:300_000].decode("utf-8", "ignore"), final


def valid_host(name: str) -> str | None:
    host = name.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host.endswith(".horizen.io"):
        return None
    if not re.fullmatch(r"[a-z0-9._-]+", host):
        return None
    return host


def collect_ct_names() -> tuple[set[str], dict[str, Any]]:
    names: set[str] = set()
    sources: dict[str, Any] = {}

    status, raw, _ = request(CRT_QUERY, timeout=75, attempts=5)
    sources["crt_sh_status"] = status
    sources["crt_sh_bytes"] = len(raw)
    if status == 200:
        try:
            records = json.loads(raw)
            sources["crt_sh_records"] = len(records)
            for record in records:
                for field in ("name_value", "common_name"):
                    for value in str(record.get(field) or "").splitlines():
                        host = valid_host(value)
                        if host:
                            names.add(host)
        except Exception as exc:
            sources["crt_sh_parse_error"] = str(exc)

    status, raw, _ = request(CERTSPOTTER_QUERY, timeout=60, attempts=4)
    sources["certspotter_status"] = status
    sources["certspotter_bytes"] = len(raw)
    if status == 200:
        try:
            records = json.loads(raw)
            sources["certspotter_records"] = len(records)
            for record in records:
                for value in record.get("dns_names") or []:
                    host = valid_host(value)
                    if host:
                        names.add(host)
        except Exception as exc:
            sources["certspotter_parse_error"] = str(exc)

    return names, sources


def resolve_records(host: str) -> tuple[list[str], list[str]]:
    cname = [line.rstrip(".") for line in run("dig", "+short", "CNAME", host).splitlines() if line]
    addresses: set[str] = set()
    for record_type in ("A", "AAAA"):
        for line in run("dig", "+short", record_type, host).splitlines():
            value = line.strip().rstrip(".")
            try:
                ipaddress.ip_address(value)
                addresses.add(value)
            except ValueError:
                pass
    return cname, sorted(addresses)


def main() -> int:
    private = Path("private-evidence/staking-host-census")
    sanitized = Path("sanitized-hosts")
    private.mkdir(parents=True, exist_ok=True)
    sanitized.mkdir(parents=True, exist_ok=True)

    ct_names, source_status = collect_ct_names()
    names = {host for host in ct_names if any(word in host for word in KEYWORDS)}
    names.update(KNOWN_AND_LIKELY)

    rows: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for host in sorted(names):
        cname, addresses = resolve_records(host)
        http_status, http_body, http_final = fetch_page("http://" + host)
        https_status, https_body, https_final = fetch_page("https://" + host)
        combined = (http_body + "\n" + https_body).lower()
        fingerprint_hits = [
            provider
            for provider, fingerprints in TAKEOVER_FINGERPRINTS.items()
            if any(fingerprint in combined for fingerprint in fingerprints)
        ]
        provider_cname = any(
            suffix in target
            for target in cname
            for suffix in (
                "pages.dev",
                "github.io",
                "netlify.app",
                "vercel-dns.com",
                "herokudns.com",
                "amazonaws.com",
                "fastly.net",
            )
        )
        dangling = bool(cname) and provider_cname and not addresses and bool(fingerprint_hits)
        row = {
            "host": host,
            "from_ct": host in ct_names,
            "cname": cname,
            "addresses": addresses,
            "http_status": http_status,
            "http_final": http_final,
            "https_status": https_status,
            "https_final": https_final,
            "fingerprint_hits": fingerprint_hits,
            "provider_cname": provider_cname,
            "takeover_candidate": dangling,
            "http_body_prefix": http_body[:1000],
            "https_body_prefix": https_body[:1000],
        }
        rows.append(row)
        if dangling:
            candidates.append(row)

    ct_available = source_status.get("crt_sh_status") == 200 or source_status.get("certspotter_status") == 200
    result = {
        "source_status": source_status,
        "ct_available": ct_available,
        "ct_unique_hosts": len(ct_names),
        "staking_related_hosts_checked": len(rows),
        "takeover_candidates": len(candidates),
        "hosts": rows,
        "pass": ct_available and len(candidates) == 0,
        "security_verdict": (
            "KILL_NO_DANGLING_STAKING_HOST"
            if ct_available and not candidates
            else "HOLD_TAKEOVER_CANDIDATE" if candidates else "HOLD_CT_UNAVAILABLE"
        ),
        "public_network_writes": 0,
    }
    (private / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    public = {
        "ct_available": ct_available,
        "ct_unique_hosts": len(ct_names),
        "staking_related_hosts_checked": len(rows),
        "takeover_candidates": len(candidates),
        "pass": result["pass"],
        "security_verdict": result["security_verdict"],
        "public_network_writes": 0,
    }
    (sanitized / "RESULT.json").write_text(json.dumps(public, indent=2) + "\n")
    (sanitized / "RESULT.md").write_text(
        "# Horizen staking-host takeover census\n\n"
        f"- CT data available: **{ct_available}**\n"
        f"- Unique Horizen CT hosts: `{len(ct_names)}`\n"
        f"- Staking-related hosts checked: `{len(rows)}`\n"
        f"- Takeover candidates: `{len(candidates)}`\n"
        f"- Verdict: **{result['security_verdict']}**\n"
        "- Public-network writes: **0**\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
