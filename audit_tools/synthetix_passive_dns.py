#!/usr/bin/env python3
"""Passive Synthetix certificate-transparency and DNS inventory.

This script queries public CT logs and Google's DNS-over-HTTPS service only.
It does not connect to discovered Synthetix hosts or send application requests.
"""

from __future__ import annotations

import json
import pathlib
import time
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("passive_dns")
OUT.mkdir(parents=True, exist_ok=True)
UA = "Mozilla/5.0 (compatible; passive-security-review/1.0)"
ROOT = "synthetix.io"
MAX_NAMES = 300

SEEDS = {
    "synthetix.io",
    "www.synthetix.io",
    "exchange.synthetix.io",
    "governance.synthetix.io",
    "docs.synthetix.io",
    "developers.synthetix.io",
    "blog.synthetix.io",
    "papi.synthetix.io",
}

TAKEOVER_SUFFIXES = (
    ".github.io",
    ".herokudns.com",
    ".netlify.app",
    ".netlify.com",
    ".vercel-dns.com",
    ".azurewebsites.net",
    ".cloudfront.net",
    ".fastly.net",
    ".readme.io",
    ".pages.dev",
    ".render.com",
    ".onrender.com",
    ".fly.dev",
    ".ghost.io",
    ".webflow.io",
    ".zendesk.com",
    ".pantheonsite.io",
    ".surge.sh",
    ".firebaseapp.com",
    ".web.app",
    ".s3-website",
)


def get_json(url: str, timeout: int = 60) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read())


def normalize_name(value: str) -> str | None:
    name = value.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if name == ROOT or name.endswith("." + ROOT):
        return name
    return None


def dns(name: str, record_type: str) -> dict[str, Any]:
    url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": name, "type": record_type})
    try:
        data = get_json(url, timeout=30)
        answers = [
            {"name": item.get("name"), "type": item.get("type"), "ttl": item.get("TTL"), "data": item.get("data")}
            for item in data.get("Answer", [])
        ]
        return {"status": data.get("Status"), "answers": answers, "comment": data.get("Comment")}
    except Exception as exc:  # noqa: BLE001
        return {"error": repr(exc), "answers": []}


def main() -> None:
    names = set(SEEDS)
    ct_url = "https://crt.sh/?q=%25.synthetix.io&output=json"
    ct_error = None
    try:
        rows = get_json(ct_url, timeout=90)
        for row in rows:
            for raw in str(row.get("name_value", "")).splitlines():
                name = normalize_name(raw)
                if name:
                    names.add(name)
    except Exception as exc:  # noqa: BLE001
        ct_error = repr(exc)

    ordered = sorted(names)[:MAX_NAMES]
    records: list[dict[str, Any]] = []
    for name in ordered:
        cname = dns(name, "CNAME")
        a = dns(name, "A")
        aaaa = dns(name, "AAAA")
        cname_values = [str(x.get("data", "")).lower().rstrip(".") for x in cname.get("answers", [])]
        takeover_provider = [
            value for value in cname_values if any(suffix in value for suffix in TAKEOVER_SUFFIXES)
        ]
        records.append(
            {
                "name": name,
                "cname": cname,
                "a": a,
                "aaaa": aaaa,
                "takeover_provider_candidates": takeover_provider,
            }
        )
        time.sleep(0.05)

    result = {
        "root": ROOT,
        "ct_url": ct_url,
        "ct_error": ct_error,
        "name_count": len(ordered),
        "records": records,
    }
    (OUT / "inventory.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (OUT / "names.txt").write_text("\n".join(ordered) + "\n", encoding="utf-8")
    candidates = [r for r in records if r["takeover_provider_candidates"]]
    (OUT / "takeover_candidates.json").write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    print(json.dumps({"name_count": len(ordered), "candidate_count": len(candidates), "ct_error": ct_error}, indent=2))


if __name__ == "__main__":
    main()
