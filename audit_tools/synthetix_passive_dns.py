#!/usr/bin/env python3
"""Passive Synthetix certificate-transparency and DNS inventory.

This script queries public CT indexes and Google's DNS-over-HTTPS service only.
It does not connect to discovered Synthetix application hosts or submit forms.
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
MAX_NAMES = 500
MAX_CERTSPOTTER_PAGES = 20

SEEDS = {
    "synthetix.io",
    "www.synthetix.io",
    "exchange.synthetix.io",
    "governance.synthetix.io",
    "docs.synthetix.io",
    "developers.synthetix.io",
    "blog.synthetix.io",
    "papi.synthetix.io",
    "sips.synthetix.io",
    "staking.synthetix.io",
    "support.synthetix.io",
    "fonts.synthetix.io",
}

TAKEOVER_MARKERS = (
    ".github.io",
    ".herokudns.com",
    ".netlify.app",
    ".netlify.com",
    "vercel-dns-",
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
    ".s3.amazonaws.com",
    ".s3-website",
)


def get_bytes(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def get_json(url: str, timeout: int = 60) -> Any:
    return json.loads(get_bytes(url, timeout=timeout))


def normalize_name(value: str) -> str | None:
    name = value.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if name == ROOT or name.endswith("." + ROOT):
        return name
    return None


def collect_crtsh(names: set[str], diagnostics: dict[str, Any]) -> None:
    url = "https://crt.sh/?q=%25.synthetix.io&output=json"
    diagnostics["crtsh_url"] = url
    try:
        rows = get_json(url, timeout=90)
        diagnostics["crtsh_rows"] = len(rows)
        for row in rows:
            for raw in str(row.get("name_value", "")).splitlines():
                name = normalize_name(raw)
                if name:
                    names.add(name)
    except Exception as exc:  # noqa: BLE001
        diagnostics["crtsh_error"] = repr(exc)


def collect_certspotter(names: set[str], diagnostics: dict[str, Any]) -> None:
    base = "https://api.certspotter.com/v1/issuances"
    after: str | None = None
    pages = 0
    issuances = 0
    try:
        while pages < MAX_CERTSPOTTER_PAGES:
            params: list[tuple[str, str]] = [
                ("domain", ROOT),
                ("include_subdomains", "true"),
                ("expand", "dns_names"),
            ]
            if after:
                params.append(("after", after))
            url = base + "?" + urllib.parse.urlencode(params)
            rows = get_json(url, timeout=90)
            if not isinstance(rows, list):
                raise ValueError(f"unexpected Cert Spotter response: {rows!r}")
            pages += 1
            issuances += len(rows)
            if not rows:
                break
            for row in rows:
                for raw in row.get("dns_names", []) or []:
                    name = normalize_name(str(raw))
                    if name:
                        names.add(name)
            after = str(rows[-1].get("id", "")) or None
            if not after:
                break
            time.sleep(0.15)
        diagnostics["certspotter_pages"] = pages
        diagnostics["certspotter_issuances"] = issuances
        diagnostics["certspotter_after"] = after
    except Exception as exc:  # noqa: BLE001
        diagnostics["certspotter_error"] = repr(exc)
        diagnostics["certspotter_pages"] = pages
        diagnostics["certspotter_issuances"] = issuances


def collect_hackertarget(names: set[str], diagnostics: dict[str, Any]) -> None:
    url = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(ROOT)
    diagnostics["hackertarget_url"] = url
    try:
        text = get_bytes(url, timeout=60).decode("utf-8", errors="replace")
        diagnostics["hackertarget_bytes"] = len(text)
        for line in text.splitlines():
            raw = line.split(",", 1)[0]
            name = normalize_name(raw)
            if name:
                names.add(name)
    except Exception as exc:  # noqa: BLE001
        diagnostics["hackertarget_error"] = repr(exc)


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
    diagnostics: dict[str, Any] = {}
    collect_crtsh(names, diagnostics)
    collect_certspotter(names, diagnostics)
    collect_hackertarget(names, diagnostics)

    ordered = sorted(names)[:MAX_NAMES]
    records: list[dict[str, Any]] = []
    for name in ordered:
        cname = dns(name, "CNAME")
        a = dns(name, "A")
        aaaa = dns(name, "AAAA")
        cname_values = [str(x.get("data", "")).lower().rstrip(".") for x in cname.get("answers", [])]
        takeover_provider = [
            value for value in cname_values if any(marker in value for marker in TAKEOVER_MARKERS)
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
        time.sleep(0.04)

    result = {
        "root": ROOT,
        "diagnostics": diagnostics,
        "name_count": len(ordered),
        "records": records,
    }
    (OUT / "inventory.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (OUT / "names.txt").write_text("\n".join(ordered) + "\n", encoding="utf-8")
    candidates = [r for r in records if r["takeover_provider_candidates"]]
    unresolved = [
        r
        for r in records
        if not r["cname"].get("answers") and not r["a"].get("answers") and not r["aaaa"].get("answers")
    ]
    (OUT / "takeover_candidates.json").write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    (OUT / "unresolved_names.json").write_text(json.dumps(unresolved, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "name_count": len(ordered),
                "candidate_count": len(candidates),
                "unresolved_count": len(unresolved),
                "diagnostics": diagnostics,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
