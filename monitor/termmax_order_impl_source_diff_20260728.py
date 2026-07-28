#!/usr/bin/env python3
"""Fetch and diff the verified live TermMaxOrderV2 implementation source.

Public verified source and GitHub source only. No chain writes or exploit logic.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import requests

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
IMPLEMENTATION = "0x626DE8D4bA2627Aa0a775f8563BEf205985C476d"
PINNED_COMMIT = "e314f3f849577dfecd4614f148c4df81fdf8c72d"
PATH = "contracts/v2/TermMaxOrderV2.sol"
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"


def get_json(params: dict[str, Any]) -> dict[str, Any]:
    last: Exception | None = None
    for attempt in range(7):
        try:
            response = requests.get(
                ROUTESCAN,
                params=params,
                timeout=90,
                headers={"User-Agent": "termmax-order-source-diff/1"},
            )
            if response.status_code == 429:
                time.sleep(2 * (attempt + 1))
                continue
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"Routescan request failed: {last}")


def parse_standard_json(source_code: str) -> dict[str, Any] | None:
    text = source_code.strip()
    candidates = [text]
    if text.startswith("{{") and text.endswith("}}"):
        candidates.insert(0, text[1:-1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass
    return None


def get_text(url: str) -> str:
    response = requests.get(url, timeout=90, headers={"User-Agent": "termmax-order-source-diff/1"})
    response.raise_for_status()
    return response.text


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main() -> int:
    payload = get_json({"module": "contract", "action": "getsourcecode", "address": IMPLEMENTATION})
    rows = payload.get("result", []) if isinstance(payload, dict) else []
    if not isinstance(rows, list) or not rows:
        raise RuntimeError(f"verified source missing: {payload}")
    row = rows[0]
    standard = parse_standard_json(str(row.get("SourceCode", "")))
    if standard is None:
        raise RuntimeError("verified source is not standard JSON")
    source_entry = standard.get("sources", {}).get(PATH)
    if not isinstance(source_entry, dict) or not isinstance(source_entry.get("content"), str):
        raise RuntimeError(f"{PATH} missing from verified source")
    deployed = source_entry["content"]
    pinned = get_text(
        f"https://raw.githubusercontent.com/term-structure/termmax-contract-v2/{PINNED_COMMIT}/{PATH}"
    )
    current = get_text(f"https://raw.githubusercontent.com/term-structure/termmax-contract-v2/main/{PATH}")
    diff_pinned = "".join(
        difflib.unified_diff(
            pinned.splitlines(keepends=True),
            deployed.splitlines(keepends=True),
            fromfile=f"pinned-{PINNED_COMMIT[:8]}/{PATH}",
            tofile=f"deployed-{IMPLEMENTATION}/{PATH}",
        )
    )
    diff_main = "".join(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            deployed.splitlines(keepends=True),
            fromfile=f"github-main/{PATH}",
            tofile=f"deployed-{IMPLEMENTATION}/{PATH}",
        )
    )
    keywords = [
        "_rebalance", "issueFtByExistedGt", "gtId", "swapExactTokenToToken",
        "swapTokenToExactToken", "virtualXtReserve", "orderExpiryTimestamp",
        "maturity", "redeemAll", "borrowToken",
    ]
    changed_keyword_lines = [
        line for line in diff_pinned.splitlines()
        if line[:1] in {"+", "-"} and not line.startswith(("+++", "---"))
        and any(keyword in line for keyword in keywords)
    ]
    summary = {
        "implementation": IMPLEMENTATION,
        "contractName": row.get("ContractName"),
        "compilerVersion": row.get("CompilerVersion"),
        "optimizationUsed": row.get("OptimizationUsed"),
        "runs": row.get("Runs"),
        "evmVersion": row.get("EVMVersion"),
        "path": PATH,
        "deployedSha256": sha(deployed),
        "pinnedSha256": sha(pinned),
        "mainSha256": sha(current),
        "deployedEqualsPinned": deployed == pinned,
        "deployedEqualsMain": deployed == current,
        "diffPinnedLineCount": len(diff_pinned.splitlines()),
        "changedKeywordLines": changed_keyword_lines,
    }
    (OUT / "ROUTESCAN_SOURCE_RAW.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (OUT / "DEPLOYED_TermMaxOrderV2.sol").write_text(deployed, encoding="utf-8")
    (OUT / "PINNED_TermMaxOrderV2.sol").write_text(pinned, encoding="utf-8")
    (OUT / "MAIN_TermMaxOrderV2.sol").write_text(current, encoding="utf-8")
    (OUT / "DEPLOYED_VS_PINNED.diff").write_text(diff_pinned, encoding="utf-8")
    (OUT / "DEPLOYED_VS_MAIN.diff").write_text(diff_main, encoding="utf-8")
    (OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
