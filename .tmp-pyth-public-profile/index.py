#!/usr/bin/env python3
"""Build a deterministic, evenly sampled index of finalized public Pyth Lazer calls.

Read-only JSON-RPC only.  The script deliberately stores only the selected sample,
not the complete signature history, to keep the artifact bounded.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import random
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PROGRAM = os.environ.get("PROGRAM_ID", "pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt")
MAX_PAGES = max(1, min(2000, int(os.environ.get("MAX_PAGES", "1000"))))
SAMPLE_PER_PAGE = max(1, min(500, int(os.environ.get("SAMPLE_PER_PAGE", "60"))))
PAGE_SIZE = 1000
OUT = Path(os.environ.get("OUT_DIR", "index"))
OUT.mkdir(parents=True, exist_ok=True)
RPCS = [
    "https://solana-rpc.publicnode.com",
    "https://api.mainnet-beta.solana.com",
    "https://solana.drpc.org",
    "https://1rpc.io/solana",
    "https://mainnet-beta.solflare.network",
    "https://solana-mainnet.rpc.extrnode.com",
]


def request(endpoint: str, method: str, params: list[Any], timeout: int = 90) -> Any:
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": random.randint(1, 2**31 - 1),
        "method": method,
        "params": params,
    }).encode()
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": "Pyth-Lazer-Public-History-Index/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = json.loads(response.read())
    if body.get("error") is not None:
        raise RuntimeError(json.dumps(body["error"], sort_keys=True))
    return body.get("result")


def rpc(method: str, params: list[Any], cursor: int, attempts: int = 18) -> tuple[Any, str, int, list[str]]:
    errors: list[str] = []
    for attempt in range(attempts):
        index = (cursor + attempt) % len(RPCS)
        endpoint = RPCS[index]
        try:
            result = request(endpoint, method, params)
            return result, endpoint, (index + 1) % len(RPCS), errors
        except Exception as exc:  # public endpoints can rate-limit transiently
            errors.append(f"{endpoint}: {type(exc).__name__}: {exc}")
            time.sleep(min(8.0, 0.2 * (2 ** min(attempt, 5))) + random.random() * 0.2)
    raise RuntimeError(" | ".join(errors[-12:]))


def deterministic_positions(count: int, wanted: int) -> list[int]:
    """Evenly spread `wanted` indexes through a page, including both edges."""
    if count <= wanted:
        return list(range(count))
    if wanted == 1:
        return [count // 2]
    positions = {round(i * (count - 1) / (wanted - 1)) for i in range(wanted)}
    return sorted(positions)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    cursor = 0
    rpc_attempts: list[dict[str, Any]] = []
    slot, endpoint, cursor, errors = rpc("getSlot", [{"commitment": "finalized"}], cursor)
    rpc_attempts.append({"method": "getSlot", "endpoint": endpoint, "ok": True, "errorsBeforeSuccess": errors, "slot": slot})
    account, endpoint, cursor, errors = rpc(
        "getAccountInfo",
        [PROGRAM, {"encoding": "base64", "commitment": "finalized"}],
        cursor,
    )
    if not account or not account.get("value") or not account["value"].get("executable"):
        raise RuntimeError("Pyth program account missing or non-executable")
    rpc_attempts.append({
        "method": "getAccountInfo",
        "endpoint": endpoint,
        "ok": True,
        "errorsBeforeSuccess": errors,
        "owner": account["value"].get("owner"),
    })

    selected: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    before: str | None = None
    total_seen = 0
    termination = "max_pages"

    for page_no in range(MAX_PAGES):
        options: dict[str, Any] = {"limit": PAGE_SIZE, "commitment": "finalized"}
        if before:
            options["before"] = before
        rows, endpoint, cursor, errors = rpc(
            "getSignaturesForAddress", [PROGRAM, options], cursor
        )
        rows = rows or []
        if not rows:
            termination = "empty_page"
            pages.append({
                "page": page_no,
                "endpoint": endpoint,
                "count": 0,
                "selected": 0,
                "errorsBeforeSuccess": errors,
            })
            break

        positions = deterministic_positions(len(rows), SAMPLE_PER_PAGE)
        for position in positions:
            row = rows[position]
            selected.append({
                "signature": row["signature"],
                "slot": row.get("slot"),
                "blockTime": row.get("blockTime"),
                "err": row.get("err"),
                "memo": row.get("memo"),
                "historyPage": page_no,
                "positionInPage": position,
                "ordinalApprox": page_no * PAGE_SIZE + position,
            })

        total_seen += len(rows)
        pages.append({
            "page": page_no,
            "endpoint": endpoint,
            "count": len(rows),
            "selected": len(positions),
            "firstSlot": rows[0].get("slot"),
            "lastSlot": rows[-1].get("slot"),
            "firstBlockTime": rows[0].get("blockTime"),
            "lastBlockTime": rows[-1].get("blockTime"),
            "firstSignature": rows[0].get("signature"),
            "lastSignature": rows[-1].get("signature"),
            "errorsBeforeSuccess": errors,
        })
        before = rows[-1]["signature"]
        if page_no % 10 == 0 or page_no + 1 == MAX_PAGES:
            print(
                f"PAGE={page_no} TOTAL_SEEN={total_seen} SELECTED={len(selected)} "
                f"LAST_SLOT={rows[-1].get('slot')}",
                flush=True,
            )
        if len(rows) < PAGE_SIZE:
            termination = "short_page"
            break
        time.sleep(0.04)

    # Preserve chronological order and remove any accidental duplicate signatures.
    dedup: dict[str, dict[str, Any]] = {}
    for row in selected:
        dedup[row["signature"]] = row
    sample = sorted(dedup.values(), key=lambda row: (row.get("slot") or 0, row["signature"]))

    sample_path = OUT / "sample.json"
    pages_path = OUT / "pages.json"
    sample_path.write_text(json.dumps(sample, separators=(",", ":")) + "\n")
    pages_path.write_text(json.dumps(pages, indent=2, sort_keys=True) + "\n")

    block_times = [row["blockTime"] for row in sample if isinstance(row.get("blockTime"), int)]
    slots = [row["slot"] for row in sample if isinstance(row.get("slot"), int)]
    summary = {
        "status": "PASS_DETERMINISTIC_PUBLIC_HISTORY_INDEX",
        "programId": PROGRAM,
        "finalizedSlotAtStart": slot,
        "maxPagesConfigured": MAX_PAGES,
        "pagesFetched": len([p for p in pages if p.get("count", 0) > 0]),
        "pageSize": PAGE_SIZE,
        "samplePerPage": SAMPLE_PER_PAGE,
        "totalSignaturesTraversed": total_seen,
        "sampleRowsBeforeDedup": len(selected),
        "sampleRows": len(sample),
        "termination": termination,
        "oldestSampleSlot": min(slots) if slots else None,
        "newestSampleSlot": max(slots) if slots else None,
        "oldestSampleBlockTime": min(block_times) if block_times else None,
        "newestSampleBlockTime": max(block_times) if block_times else None,
        "sampleTimeSpanSeconds": (max(block_times) - min(block_times)) if block_times else None,
        "sampleSha256": file_sha256(sample_path),
        "pagesSha256": file_sha256(pages_path),
        "rpcAttestation": rpc_attempts,
        "publicChainTransactionsSigned": 0,
        "publicChainTransactionsSent": 0,
        "publicChainWrites": 0,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)

    # Fail closed if the intended history depth or sample cardinality was not reached.
    history_exhausted = termination in {"short_page", "empty_page"}
    minimum_pages = max(1, math.floor(MAX_PAGES * 0.99))
    expected_rows_for_fetched_pages = summary["pagesFetched"] * SAMPLE_PER_PAGE
    minimum_rows = max(1, math.floor(expected_rows_for_fetched_pages * 0.98))
    if (
        (not history_exhausted and summary["pagesFetched"] < minimum_pages)
        or summary["sampleRows"] < minimum_rows
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
