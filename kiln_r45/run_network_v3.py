#!/usr/bin/env python3
"""Corrected R45 per-network entrypoint.

The v2 wrapper narrowed module.NETWORKS before calling the inherited scope parser.
That made the full-scope integrity checks see only one network and reject every
small shard. This entrypoint fetches and validates the complete current Cantina
scope independently, then returns only the selected network to the inherited
read-only runtime census.
"""
from __future__ import annotations

import hashlib
import re
import urllib.request
from collections import Counter
from typing import Any

from kiln_r45 import run_network as legacy

SCOPE_URL = "https://cantina.xyz/bounties/c9a4b51b-2e80-4713-a06f-13524c530fa6"
USER_AGENT = "Kiln-R45v3-ShardedScope/1.0"
BASELINE_SCOPE_COUNT = 101
ALL_NETWORKS = set(legacy.SAFE_NETWORKS)
_ORIGINAL_LOAD_MODULE = legacy.load_module


def _fetch_complete_scope(module: Any, selected_network: str):
    request = urllib.request.Request(SCOPE_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        html = response.read().decode(errors="replace")

    pattern = re.compile(
        r"([^|<>\n]{2,180}?)\s*\|\s*"
        r"(0x[a-fA-F0-9]{40})\s*\|\s*"
        r"([A-Z][A-Z0-9_]{1,63})\s*\|\s*"
        r"(ethereum|optimism|bnb|polygon|base|arbitrum)\s*\|\s*"
        r"([^|<>\n]{1,180})",
        re.IGNORECASE,
    )

    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for label, address, connector, network, asset_text in pattern.findall(html):
        network = network.lower()
        address = address.lower()
        connector = connector.upper()
        key = (network, address)
        if network not in ALL_NETWORKS or key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "label": re.sub(r"\s+", " ", label).strip(),
                "address": address,
                "connector": connector,
                "network": network,
                "asset_text": re.sub(r"\s+", " ", asset_text).strip(),
            }
        )

    rows.sort(key=lambda row: (row["network"], row["connector"], row["address"]))
    selected = [row for row in rows if row["network"] == selected_network]
    full_connectors = Counter(row["connector"] for row in rows)
    full_networks = Counter(row["network"] for row in rows)
    selected_connectors = Counter(row["connector"] for row in selected)

    checks = {
        "full_scope_row_count_at_least_49": len(rows) >= 49,
        "full_scope_addresses_unique": len(seen) == len(rows),
        "full_scope_all_networks_supported": all(row["network"] in ALL_NETWORKS for row in rows),
        "full_scope_all_addresses_valid": all(re.fullmatch(r"0x[a-f0-9]{40}", row["address"]) for row in rows),
        "selected_network_nonempty": bool(selected),
        "selected_network_matches": all(row["network"] == selected_network for row in selected),
        "selected_addresses_unique": len({row["address"] for row in selected}) == len(selected),
    }

    summary = {
        "row_count": len(selected),
        "baseline_row_count": BASELINE_SCOPE_COUNT,
        "scope_count_delta": len(rows) - BASELINE_SCOPE_COUNT,
        "connector_counts": dict(sorted(selected_connectors.items())),
        "network_counts": {selected_network: len(selected)},
        "full_scope_count": len(rows),
        "full_connector_counts": dict(sorted(full_connectors.items())),
        "full_network_counts": dict(sorted(full_networks.items())),
        "unknown_connectors": sorted(set(full_connectors) - set(module.KNOWN_CONNECTOR_FAMILIES)),
        "selected_network": selected_network,
        "selected_network_count": len(selected),
        "checks": checks,
    }
    return selected, summary, hashlib.sha256(html.encode()).hexdigest()


def _corrected_load_module(network: str):
    module = _ORIGINAL_LOAD_MODULE(network)

    def corrected_scope():
        return _fetch_complete_scope(module, network)

    module.fetch_scope = corrected_scope
    return module


legacy.load_module = _corrected_load_module


if __name__ == "__main__":
    raise SystemExit(legacy.main())
