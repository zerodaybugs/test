#!/usr/bin/env python3
"""Passive/low-noise discovery of official-looking non-production Synthetix API environments.

Safety properties:
- one certificate-transparency query;
- DNS and TLS/HTTP metadata only for *.synthetix.io names;
- strict keyword filter and host cap;
- no authentication, signatures, credentials, account IDs or state changes;
- at most one root GET plus a small fixed health/status/info probe set per candidate;
- bodies are reduced to schema, redacted prefix and SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

OUT = pathlib.Path("cross_environment_discovery")
OUT.mkdir(parents=True, exist_ok=True)

UA = "Mozilla/5.0 (compatible; authorized-low-noise-security-review/1.0)"
MAX_BODY = 512 * 1024
MAX_HOSTS = 80
CT_URL = "https://crt.sh/?q=%25.synthetix.io&output=json"
PRODUCTION_HOSTS = {
    "synthetix.io",
    "www.synthetix.io",
    "exchange.synthetix.io",
    "papi.synthetix.io",
    "api.synthetix.io",
    "developers.synthetix.io",
    "docs.synthetix.io",
    "governance.synthetix.io",
}
SEED_HOSTS = {
    "api.test.synthetix.io",
    "papi.test.synthetix.io",
    "papi.staging.synthetix.io",
    "staging.papi.synthetix.io",
    "api.staging.synthetix.io",
    "papi.dev.synthetix.io",
    "dev.papi.synthetix.io",
    "api.dev.synthetix.io",
    "papi.alpha.synthetix.io",
    "alpha.papi.synthetix.io",
    "papi.beta.synthetix.io",
    "beta.papi.synthetix.io",
    "papi.preview.synthetix.io",
    "preview.papi.synthetix.io",
    "testnet.papi.synthetix.io",
    "papi.testnet.synthetix.io",
    "exchange.test.synthetix.io",
    "test.exchange.synthetix.io",
    "exchange.staging.synthetix.io",
    "staging.exchange.synthetix.io",
    "exchange.dev.synthetix.io",
    "dev.exchange.synthetix.io",
    "alpha-exchange.synthetix.io",
    "staging.synthetix.io",
}
ENV_KEYWORDS = re.compile(r"(?:^|[.-])(test|testnet|stage|staging|dev|development|alpha|beta|preview|sandbox|qa)(?:[.-]|$)", re.I)
SERVICE_KEYWORDS = re.compile(r"(?:^|[.-])(api|papi|exchange|trade|perps)(?:[.-]|$)", re.I)
SENSITIVE = re.compile(
    r"(?:api[_-]?key|authorization|bearer|private[_-]?key|secret|password|token)\s*[:=]\s*[^\s,}\]]+",
    re.I,
)


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(k): schema(v, depth + 1) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def redact(text: str) -> str:
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = SENSITIVE.sub(lambda m: m.group(0).split(":", 1)[0] + ":<redacted>", text)
    return text[:1200]


def read_url(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: int = 25,
) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": UA, "Accept": "application/json,text/plain,text/html,*/*;q=0.5", "Content-Type": "application/json"},
        method=method,
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                body = body[:MAX_BODY]
                truncated = True
            else:
                truncated = False
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
    elapsed_ms = round((time.monotonic() - started) * 1000, 2)
    text = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception:
        parsed = None
    split = urllib.parse.urlsplit(final_url)
    return {
        "url": url,
        "method": method,
        "status": status,
        "elapsedMs": elapsed_ms,
        "finalUrl": final_url,
        "finalOrigin": f"{split.scheme}://{split.netloc}" if split.scheme and split.netloc else None,
        "contentType": headers.get("Content-Type"),
        "server": headers.get("Server"),
        "via": headers.get("Via"),
        "xVercelError": headers.get("X-Vercel-Error"),
        "accessControlAllowOrigin": headers.get("Access-Control-Allow-Origin"),
        "accessControlAllowCredentials": headers.get("Access-Control-Allow-Credentials"),
        "bodyBytes": len(body),
        "bodySha256": digest(body),
        "truncated": truncated,
        "jsonSchema": schema(parsed) if parsed is not None else None,
        "redactedTextPrefix": redact(text) if status >= 400 or parsed is None else None,
    }


def ct_names() -> tuple[set[str], dict[str, Any]]:
    result: set[str] = set()
    diagnostic: dict[str, Any] = {"url": CT_URL}
    try:
        req = urllib.request.Request(CT_URL, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as response:
            body = response.read(20 * 1024 * 1024)
        diagnostic.update({"status": 200, "bodyBytes": len(body), "bodySha256": digest(body)})
        rows = json.loads(body)
        diagnostic["rowCount"] = len(rows) if isinstance(rows, list) else None
        for row in rows if isinstance(rows, list) else []:
            for raw in str(row.get("name_value", "")).splitlines():
                name = raw.strip().lower().rstrip(".")
                if name.startswith("*."):
                    name = name[2:]
                if name.endswith(".synthetix.io") and "*" not in name:
                    result.add(name)
    except Exception as exc:  # noqa: BLE001
        diagnostic.update({"errorType": type(exc).__name__, "errorSha256": digest(str(exc))})
    return result, diagnostic


def resolve(host: str) -> dict[str, Any]:
    record: dict[str, Any] = {"host": host}
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        record["ips"] = sorted({info[4][0] for info in infos})
    except Exception as exc:  # noqa: BLE001
        record["ips"] = []
        record["dnsErrorType"] = type(exc).__name__
        record["dnsErrorSha256"] = digest(str(exc))
    if record["ips"]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=15) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    record["tlsVersion"] = tls.version()
                    record["certificateSubject"] = cert.get("subject")
                    record["certificateIssuer"] = cert.get("issuer")
                    record["certificateNotAfter"] = cert.get("notAfter")
                    sans = cert.get("subjectAltName") or []
                    record["certificateSanCount"] = len(sans)
        except Exception as exc:  # noqa: BLE001
            record["tlsErrorType"] = type(exc).__name__
            record["tlsErrorSha256"] = digest(str(exc))
    return record


def is_candidate(host: str) -> bool:
    return (
        host.endswith(".synthetix.io")
        and host not in PRODUCTION_HOSTS
        and bool(ENV_KEYWORDS.search(host))
        and bool(SERVICE_KEYWORDS.search(host))
    )


def main() -> None:
    names, ct_diagnostic = ct_names()
    candidates = set(SEED_HOSTS)
    candidates.update(name for name in names if is_candidate(name))
    candidates = {host for host in candidates if host.endswith(".synthetix.io") and host not in PRODUCTION_HOSTS}
    ordered = sorted(candidates)[:MAX_HOSTS]

    records: list[dict[str, Any]] = []
    active_api_like: list[str] = []
    for index, host in enumerate(ordered):
        record = resolve(host)
        record["source"] = {
            "seed": host in SEED_HOSTS,
            "certificateTransparency": host in names,
        }
        if record.get("ips"):
            root = read_url(f"https://{host}/")
            record["root"] = root
            final_host = urllib.parse.urlsplit(root.get("finalUrl") or "").hostname
            redirected_to_production = final_host in PRODUCTION_HOSTS
            record["redirectedToKnownProduction"] = redirected_to_production
            server_blob = " ".join(str(root.get(k) or "") for k in ("server", "redactedTextPrefix", "contentType")).lower()
            api_like = not redirected_to_production and (
                "json" in str(root.get("contentType") or "").lower()
                or "swagger" in server_blob
                or "api" in host
                or "papi" in host
            )
            if api_like:
                probes = [
                    read_url(f"https://{host}/health"),
                    read_url(f"https://{host}/v1/status"),
                    read_url(
                        f"https://{host}/v1/info",
                        method="POST",
                        payload={"params": {"action": "getExchangeStatus"}},
                    ),
                ]
                record["apiProbes"] = probes
                if any(
                    probe.get("status") in (200, 400, 401, 403, 405)
                    and (
                        probe.get("jsonSchema") is not None
                        or "papi" in str(probe.get("redactedTextPrefix") or "").lower()
                        or "exchange" in str(probe.get("redactedTextPrefix") or "").lower()
                    )
                    for probe in probes
                ):
                    active_api_like.append(host)
        records.append(record)
        if index + 1 < len(ordered):
            time.sleep(0.35)

    summary = {
        "safety": "One CT query plus DNS/TLS and a fixed low-noise unauthenticated probe set for strict *.synthetix.io environment candidates only.",
        "certificateTransparency": ct_diagnostic,
        "ctUniqueNameCount": len(names),
        "candidateCount": len(ordered),
        "resolvedCount": sum(bool(record.get("ips")) for record in records),
        "activeApiLikeHosts": active_api_like,
        "records": records,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "ctUniqueNameCount": summary["ctUniqueNameCount"],
                "candidateCount": summary["candidateCount"],
                "resolvedCount": summary["resolvedCount"],
                "activeApiLikeHosts": active_api_like,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
