#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
from pathlib import Path

import requests

URL = "https://cantina.xyz/bounties/c9a4b51b-2e80-4713-a06f-13524c530fa6"
OUT = Path("r30_scope")
OUT.mkdir(exist_ok=True)
NETWORKS = {"ethereum", "optimism", "bnb", "polygon", "base", "arbitrum"}


def main() -> int:
    response = requests.get(URL, headers={"User-Agent": "Kiln-R30-ScopeExport/1.0"}, timeout=60)
    response.raise_for_status()
    text = response.text

    # Cantina server-renders the active-vault table in pipe-separated text.
    pattern = re.compile(
        r"([^|<>\n]{2,180}?)\s*\|\s*"
        r"(0x[a-fA-F0-9]{40})\s*\|\s*"
        r"([A-Z][A-Z0-9_]{1,63})\s*\|\s*"
        r"(ethereum|optimism|bnb|polygon|base|arbitrum)\s*\|\s*"
        r"([^|<>\n]{1,180})",
        re.IGNORECASE,
    )

    rows = []
    seen = set()
    for label, address, connector, network, asset in pattern.findall(text):
        network = network.lower()
        connector = connector.upper()
        key = (network, address.lower())
        if key in seen or network not in NETWORKS:
            continue
        seen.add(key)
        rows.append({
            "label": re.sub(r"\s+", " ", label).strip(),
            "address": address,
            "connector": connector,
            "network": network,
            "asset_text": re.sub(r"\s+", " ", asset).strip(),
        })

    rows.sort(key=lambda r: (r["network"], r["connector"], r["address"].lower()))
    connectors = Counter(r["connector"] for r in rows)
    networks = Counter(r["network"] for r in rows)
    duplicate_addresses = [address for address, count in Counter(r["address"].lower() for r in rows).items() if count > 1]

    # Fail closed. The prior verified live page contained 49 AAVE vaults alone.
    checks = {
        "row_count_at_least_49": len(rows) >= 49,
        "aave_count_at_least_40": connectors.get("AAVE_V3", 0) >= 40,
        "addresses_unique": not duplicate_addresses,
        "all_networks_supported": all(r["network"] in NETWORKS for r in rows),
        "all_addresses_shape_valid": all(re.fullmatch(r"0x[a-fA-F0-9]{40}", r["address"]) for r in rows),
    }

    result = {
        "schema": "kiln-r30-live-full-scope-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_url": URL,
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "rows": rows,
        "summary": {
            "row_count": len(rows),
            "connector_counts": dict(sorted(connectors.items())),
            "network_counts": dict(sorted(networks.items())),
            "duplicate_addresses": duplicate_addresses,
            "checks": checks,
        },
    }
    evidence = OUT / "SCOPE.json"
    evidence.write_text(json.dumps(result, indent=2, sort_keys=True))
    gate = {
        "schema": "kiln-r30-scope-gate-v1",
        "decision": "PASS_CURRENT_SCOPE_EXPORTED" if all(checks.values()) else "INCONCLUSIVE_SCOPE_PARSE_FAILED_CLOSED",
        "row_count": len(rows),
        "connector_counts": dict(sorted(connectors.items())),
        "network_counts": dict(sorted(networks.items())),
        "checks": checks,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    (OUT / "SHA256SUMS.txt").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(OUT.iterdir()) if path.is_file() and path.name != "SHA256SUMS.txt"
        )
    )
    print(json.dumps(gate, sort_keys=True))
    return 0 if all(checks.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
