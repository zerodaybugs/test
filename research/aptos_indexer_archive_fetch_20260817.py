#!/usr/bin/env python3
"""Query public Aptos indexer metadata, then fetch matching public transactions."""

from __future__ import annotations

import json
import os
import runpy
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

GRAPHQL = os.environ.get(
    "GRAPHQL", "https://indexer.mainnet.aptoslabs.com/v1/graphql"
)
PLATFORMS = [
    value.strip().lower()
    for value in os.environ.get("PLATFORMS", "").split(",")
    if value.strip()
]
PAGE_SIZE = max(10, min(500, int(os.environ.get("PAGE_SIZE", "100"))))
MAX_ROWS_PER_PLATFORM = max(
    PAGE_SIZE, int(os.environ.get("MAX_ROWS_PER_PLATFORM", "20000"))
)
PAGE_DELAY_SECONDS = max(0.0, float(os.environ.get("PAGE_DELAY_SECONDS", "1.5")))
OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "evidence/aptos-platform-transactions"))

QUERY = """query Reports($platform: String!, $limit: Int!, $offset: Int!) {
  user_transactions(
    where: {
      entry_function_contract_address: {_eq: $platform},
      entry_function_module_name: {_eq: \"forwarder\"},
      entry_function_function_name: {_eq: \"report\"}
    },
    order_by: {version: desc},
    limit: $limit,
    offset: $offset
  ) {
    version
    sender
    timestamp
    entry_function_id_str
  }
}"""


def post_graphql(body: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(body).encode()
    last: Exception | None = None
    for attempt in range(1, 10):
        request = urllib.request.Request(
            GRAPHQL,
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "public-aptos-indexer-archive-probe/2026-08-17",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                value = json.loads(response.read())
            if not isinstance(value, dict):
                raise TypeError(f"expected object, got {type(value).__name__}")
            return value
        except urllib.error.HTTPError as exc:
            last = exc
            retry_after = exc.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                delay = min(120.0, float(retry_after))
            else:
                delay = min(120.0, 4.0 * attempt * attempt)
            print(
                f"indexer HTTP {exc.code}; attempt={attempt}; sleeping={delay}",
                flush=True,
            )
            time.sleep(delay)
        except Exception as exc:  # noqa: BLE001
            last = exc
            delay = min(60.0, 2.0 * attempt)
            print(
                f"indexer error={type(exc).__name__}; attempt={attempt}; sleeping={delay}",
                flush=True,
            )
            time.sleep(delay)
    raise RuntimeError(f"indexer request failed: {last!r}")


def query_platform(platform: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    page_dir = OUTPUT_DIR / "indexer" / platform
    page_dir.mkdir(parents=True, exist_ok=True)

    for offset in range(0, MAX_ROWS_PER_PLATFORM, PAGE_SIZE):
        value = post_graphql(
            {
                "query": QUERY,
                "variables": {
                    "platform": platform,
                    "limit": PAGE_SIZE,
                    "offset": offset,
                },
            }
        )
        (page_dir / f"page_{offset:06d}.json").write_text(
            json.dumps(value, indent=2) + "\n", encoding="utf-8"
        )
        if value.get("errors"):
            raise RuntimeError(value["errors"])
        page = value.get("data", {}).get("user_transactions", [])
        if not isinstance(page, list):
            raise TypeError("user_transactions is not a list")
        for row in page:
            row = dict(row)
            row["platform"] = platform
            rows.append(row)
        print(
            f"platform={platform} offset={offset} page={len(page)} total={len(rows)}",
            flush=True,
        )
        if len(page) < PAGE_SIZE:
            break
        time.sleep(PAGE_DELAY_SECONDS)
    return rows


def main() -> None:
    if not PLATFORMS:
        raise ValueError("PLATFORMS must contain at least one contract address")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_rows: list[dict[str, Any]] = []
    for platform in PLATFORMS:
        all_rows.extend(query_platform(platform))

    deduplicated: dict[int, dict[str, Any]] = {}
    for row in all_rows:
        deduplicated[int(row["version"])] = row
    rows = [deduplicated[key] for key in sorted(deduplicated, reverse=True)]
    versions = [int(row["version"]) for row in rows]

    (OUTPUT_DIR / "indexer_rows.json").write_text(
        json.dumps(rows, indent=2) + "\n", encoding="utf-8"
    )
    versions_path = OUTPUT_DIR / "indexer_versions.json"
    versions_path.write_text(json.dumps(versions, indent=2) + "\n", encoding="utf-8")
    (OUTPUT_DIR / "indexer_summary.json").write_text(
        json.dumps(
            {
                "platforms": PLATFORMS,
                "rows_before_deduplication": len(all_rows),
                "unique_versions": len(versions),
                "minimum_version": min(versions, default=None),
                "maximum_version": max(versions, default=None),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    os.environ["VERSIONS_PATH"] = str(versions_path)
    runpy.run_path(
        "research/aptos_raw_transaction_fetch_20260817.py", run_name="__main__"
    )


if __name__ == "__main__":
    main()
