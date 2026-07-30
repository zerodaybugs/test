#!/usr/bin/env python3
"""Current TermMax Router V2 ERC-20 holdings census with direct holdings API.

This wrapper preserves the original read-only RPC binding checks and replaces
historical Transfer-log token discovery with Routescan's purpose-built current
ERC-20 holdings endpoint. It contains no signer, private key, transaction
construction, simulation, or state-changing call.
"""
from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

BASE_PATH = Path(__file__).with_name("termmax_router_holdings_census_20260730.py")
SPEC = importlib.util.spec_from_file_location("termmax_router_holdings_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base scanner: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)


def first_address(value: Any) -> str | None:
    """Find an EVM address in one holdings item without assuming one schema."""
    if isinstance(value, str):
        if value.startswith("0x") and len(value) == 42:
            try:
                return Web3.to_checksum_address(value)
            except ValueError:
                return None
        return None
    if isinstance(value, dict):
        preferred = (
            "tokenAddress", "token_address", "contractAddress", "contract_address",
            "addressHash", "address_hash", "address",
        )
        for key in preferred:
            if key in value:
                found = first_address(value[key])
                if found:
                    return found
        for key in ("token", "contract", "asset", "erc20"):
            if key in value:
                found = first_address(value[key])
                if found:
                    return found
        for nested in value.values():
            found = first_address(nested)
            if found:
                return found
    if isinstance(value, list):
        for nested in value:
            found = first_address(nested)
            if found:
                return found
    return None


def current_holdings(config: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    base_url = (
        f"https://api.routescan.io/v2/network/mainnet/evm/{config['routescanId']}"
        f"/address/{Web3.to_checksum_address(config['router'])}/erc20-holdings"
    )
    tokens: set[str] = set()
    pages: list[dict[str, Any]] = []
    next_cursor: str | None = None
    for page_no in range(1, 101):
        params: dict[str, Any] = {"limit": 100}
        if next_cursor:
            params["next"] = next_cursor
        payload: Any = None
        last_error: Exception | None = None
        for attempt in range(7):
            try:
                response = requests.get(
                    base_url,
                    params=params,
                    timeout=60,
                    headers={"User-Agent": "ZeroDayBugs-TermMax-Readonly/2"},
                )
                if response.status_code == 429:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                time.sleep(1.25 * (attempt + 1))
        if payload is None:
            raise RuntimeError(f"Routescan holdings failed: {last_error}")

        items = payload.get("items", []) if isinstance(payload, dict) else []
        if not isinstance(items, list):
            raise RuntimeError(f"unexpected holdings payload: {json.dumps(payload)[:2000]}")
        parsed = 0
        for item in items:
            address = first_address(item)
            if address:
                tokens.add(address)
                parsed += 1
        next_cursor = payload.get("next") if isinstance(payload, dict) else None
        pages.append({"page": page_no, "itemCount": len(items), "parsedTokenCount": parsed, "next": next_cursor})
        if not next_cursor or not items:
            break
    return sorted(tokens), {"ok": True, "endpoint": base_url, "pages": pages, "tokenCount": len(tokens)}


def discover_tokens(w3: Web3, config: dict[str, Any], latest: int) -> tuple[list[str], dict[str, Any]]:
    diagnostics: dict[str, Any] = {}
    try:
        tokens, holding_diagnostics = current_holdings(config)
        diagnostics["currentHoldings"] = holding_diagnostics
        # A valid empty holdings response is authoritative for current balance.
        return tokens, diagnostics
    except Exception as exc:  # noqa: BLE001
        diagnostics["currentHoldings"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        tokens, fallback = base.discover_tokens(w3, config, latest)
        diagnostics["historicalFallback"] = fallback
        return tokens, diagnostics


base.discover_tokens = discover_tokens
raise SystemExit(base.main())
