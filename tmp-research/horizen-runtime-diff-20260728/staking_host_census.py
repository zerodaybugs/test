#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

QUERY = "https://crt.sh/?q=%25.horizen.io&output=json"
KEYWORDS = ("stake", "staking", "staker", "zenstaker", "reward")
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


def fetch(url: str, timeout: int = 20) -> tuple[int | None, str, str | None]:
    request = urllib.request.Request(
        url,
        headers={"user-agent": "Mozilla/5.0 (compatible; authorized-Horizen-passive-census/1.0)"},
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ctx) as response:
            body = response.read(300_000).decode("utf-8", "ignore")
            return response.status, body, response.geturl()
    except urllib.error.HTTPError as exc:
        body = exc.read(300_000).decode("utf-8", "ignore")
        return exc.code, body, exc.geturl()
    except Exception as exc:
        return None, str(exc), None


def main() -> int:
    private = Path("private-evidence/staking-host-census")
    sanitized = Path("sanitized-hosts")
    private.mkdir(parents=True, exist_ok=True)
    sanitized.mkdir(parents=True, exist_ok=True)

    status, body, _ = fetch(QUERY, timeout=60)
    if status != 200:
        raise SystemExit(f"crt.sh query failed: {status}: {body[:500]}")
    records = json.loads(body)
    names: set[str] = set()
    for record in records:
        for field in ("name_value", "common_name"):
            value = record.get(field) or ""
            for name in str(value).splitlines():
                host = name.strip().lower().rstrip(".")
                if host.startswith("*."):
                    host = host[2:]
                if host.endswith(".horizen.io") and any(word in host for word in KEYWORDS):
                    names.add(host)

    rows: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for host in sorted(names):
        cname = run("dig", "+short", "CNAME", host).splitlines()
        addresses = sorted(
            set(run("dig", "+short", "A", host).splitlines() + run("dig", "+short", "AAAA", host).splitlines())
        )
        http_status, http_body, http_final = fetch("http://" + host)
        https_status, https_body, https_final = fetch("https://" + host)
        combined = (http_body + "\n" + https_body).lower()
        fingerprint_hits = []
        for provider, fingerprints in TAKEOVER_FINGERPRINTS.items():
            if any(fingerprint in combined for fingerprint in fingerprints):
                fingerprint_hits.append(provider)
        dangling = bool(cname) and not addresses and bool(fingerprint_hits)
        row = {
            "host": host,
            "cname": cname,
            "addresses": addresses,
            "http_status": http_status,
            "http_final": http_final,
            "https_status": https_status,
            "https_final": https_final,
            "fingerprint_hits": fingerprint_hits,
            "takeover_candidate": dangling,
            "http_body_prefix": http_body[:1000],
            "https_body_prefix": https_body[:1000],
        }
        rows.append(row)
        if dangling:
            candidates.append(row)

    result = {
        "crt_records": len(records),
        "staking_related_hosts": len(rows),
        "takeover_candidates": len(candidates),
        "hosts": rows,
        "pass": len(candidates) == 0,
        "security_verdict": "KILL_NO_DANGLING_STAKING_HOST" if not candidates else "HOLD_TAKEOVER_CANDIDATE",
        "public_network_writes": 0,
    }
    (private / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    public = {
        "crt_records": len(records),
        "staking_related_hosts": len(rows),
        "takeover_candidates": len(candidates),
        "pass": len(candidates) == 0,
        "security_verdict": result["security_verdict"],
        "public_network_writes": 0,
    }
    (sanitized / "RESULT.json").write_text(json.dumps(public, indent=2) + "\n")
    (sanitized / "RESULT.md").write_text(
        "# Horizen staking-host takeover census\n\n"
        f"- CT records processed: `{len(records)}`\n"
        f"- Staking-related hosts checked: `{len(rows)}`\n"
        f"- Takeover candidates: `{len(candidates)}`\n"
        f"- Verdict: **{result['security_verdict']}**\n"
        "- Public-network writes: **0**\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
