#!/usr/bin/env python3
"""Fetch a fixed public Aptos transaction sample from multiple public REST providers."""

from __future__ import annotations

import concurrent.futures
import json
import os
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

VERSIONS_PATH = Path(
    os.environ.get("VERSIONS_PATH", "research/aptos_transaction_versions_20260817.json")
)
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "evidence/aptos-raw-transactions"))
MAX_WORKERS = max(1, int(os.environ.get("MAX_WORKERS", "2")))
RETRIES_PER_PROVIDER = max(1, int(os.environ.get("RETRIES_PER_PROVIDER", "3")))
REQUEST_TIMEOUT = max(10, int(os.environ.get("REQUEST_TIMEOUT", "60")))

PROVIDERS = [
    (
        "publicnode",
        "https://aptos-rest.publicnode.com/v1/transactions/by_version/{version}",
    ),
    (
        "onfinality",
        "https://aptos.api.onfinality.io/v1/public/v1/transactions/by_version/{version}",
    ),
    (
        "aptoslabs-api",
        "https://api.mainnet.aptoslabs.com/v1/transactions/by_version/{version}",
    ),
    (
        "aptoslabs-fullnode",
        "https://fullnode.mainnet.aptoslabs.com/v1/transactions/by_version/{version}",
    ),
]


def request_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "public-aptos-transaction-archive-probe/2026-08-17",
        },
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        raw = response.read()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise TypeError(f"expected object response, got {type(value).__name__}")
    return value


def fetch_one(version: int) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    for provider, template in PROVIDERS:
        url = template.format(version=version)
        for attempt in range(1, RETRIES_PER_PROVIDER + 1):
            try:
                transaction = request_json(url)
                returned_version = str(transaction.get("version", ""))
                if returned_version != str(version):
                    raise ValueError(
                        f"version mismatch: requested={version}, returned={returned_version}"
                    )
                target = OUTPUT_DIR / "transactions" / f"{version}.json"
                target.write_text(json.dumps(transaction, indent=2) + "\n", encoding="utf-8")
                return {
                    "version": version,
                    "ok": True,
                    "provider": provider,
                    "url": url,
                    "transaction_type": transaction.get("type"),
                    "success": transaction.get("success"),
                    "sender": transaction.get("sender"),
                    "hash": transaction.get("hash"),
                    "errors": errors,
                }
            except urllib.error.HTTPError as exc:
                body = exc.read(4096).decode("utf-8", errors="replace")
                errors.append(
                    {
                        "provider": provider,
                        "attempt": attempt,
                        "kind": "HTTPError",
                        "status": exc.code,
                        "message": str(exc),
                        "body": body,
                    }
                )
                if exc.code == 404:
                    break
            except Exception as exc:  # noqa: BLE001 - preserve public endpoint errors
                errors.append(
                    {
                        "provider": provider,
                        "attempt": attempt,
                        "kind": type(exc).__name__,
                        "message": repr(exc),
                    }
                )
            time.sleep(min(8.0, 0.75 * attempt))
    return {"version": version, "ok": False, "provider": None, "errors": errors}


def main() -> None:
    versions_raw = json.loads(VERSIONS_PATH.read_text(encoding="utf-8"))
    versions = sorted({int(value) for value in versions_raw}, reverse=True)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "transactions").mkdir(exist_ok=True)
    (OUTPUT_DIR / "input_versions.json").write_text(
        json.dumps(versions, indent=2) + "\n", encoding="utf-8"
    )

    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_by_version = {
            executor.submit(fetch_one, version): version for version in versions
        }
        for future in concurrent.futures.as_completed(future_by_version):
            result = future.result()
            results.append(result)
            state = "OK" if result["ok"] else "FAIL"
            print(f"{state} version={result['version']} provider={result.get('provider')}", flush=True)

    results.sort(key=lambda row: int(row["version"]), reverse=True)
    successes = [row for row in results if row["ok"]]
    failures = [row for row in results if not row["ok"]]
    provider_counts = Counter(row["provider"] for row in successes)

    summary = {
        "requested": len(versions),
        "fetched": len(successes),
        "failed": len(failures),
        "complete": not failures,
        "provider_counts": dict(sorted(provider_counts.items())),
        "minimum_fetched_version": min((row["version"] for row in successes), default=None),
        "maximum_fetched_version": max((row["version"] for row in successes), default=None),
    }
    (OUTPUT_DIR / "results.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )
    (OUTPUT_DIR / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    marker = "FETCH_COMPLETE" if summary["complete"] else "FETCH_PARTIAL"
    (OUTPUT_DIR / marker).write_text(marker + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
