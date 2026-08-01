#!/usr/bin/env python3
"""Fast indexed-log wrapper for the read-only ERC4626 oracle-gap scanner."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

BASE_PATH = Path(__file__).with_name("termmax_erc4626_oracle_redeem_gap_20260801.py")
SPEC = importlib.util.spec_from_file_location("termmax_erc4626_oracle_gap_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base scanner: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

# web3.py v7 HexBytes.hex() omits the 0x prefix, while explorer logs include it.
# Normalize once so exact event-topic comparisons remain deterministic.
if not base.MARKET_CREATED_TOPIC.startswith("0x"):
    base.MARKET_CREATED_TOPIC = "0x" + base.MARKET_CREATED_TOPIC
if not base.PRICE_FEED_CREATED_TOPIC.startswith("0x"):
    base.PRICE_FEED_CREATED_TOPIC = "0x" + base.PRICE_FEED_CREATED_TOPIC


def indexed_first_logs(address: str, start: int, end: int) -> tuple[list[Any], list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    try:
        rows, diag = base.routescan_logs(address, start, end)
        attempts.append({"ok": True, **diag})
        return rows, attempts
    except Exception as exc:  # noqa: BLE001
        attempts.append({
            "ok": False,
            "transport": "routescan",
            "error": f"{type(exc).__name__}: {exc}",
        })
    for url in base.RPCS:
        try:
            rows, diag = base.direct_logs(url, address, start, end)
            attempts.append({"ok": True, **diag})
            return rows, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({
                "ok": False,
                "transport": "rpc",
                "url": url,
                "error": f"{type(exc).__name__}: {exc}",
            })
    raise RuntimeError(base.json.dumps(attempts))


base.all_logs = indexed_first_logs
raise SystemExit(base.main())
