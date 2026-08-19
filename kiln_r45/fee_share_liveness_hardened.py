#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import fee_share_liveness as core


def hardened_source_gate() -> dict[str, Any]:
    source = core.VAULT_SOURCE.read_text()
    lines = source.splitlines()
    relevant = []
    needles = (
        "minTotalSupply",
        "collectableRewardFeesShares",
        "collectRewardFees",
        "totalSupply()",
        "_burn(",
        "_mint(",
    )
    for index, line in enumerate(lines):
        if any(needle in line for needle in needles):
            start = max(0, index - 4)
            end = min(len(lines), index + 8)
            relevant.append(
                f"===== lines {start + 1}-{end} =====\n" + "\n".join(lines[start:end])
            )
    excerpt = "\n\n".join(relevant)
    (core.OUT / "SOURCE_EXCERPTS.txt").write_text(excerpt)
    compact = re.sub(r"\s+", " ", source)
    checks = {
        "min_supply_referenced": "minTotalSupply" in source,
        "collectable_fee_shares_referenced": "collectableRewardFeesShares" in source,
        "min_supply_comparison_present": bool(
            re.search(r"minTotalSupply.{0,300}(?:<|>|==|!=)|(?:<|>|==|!=).{0,300}minTotalSupply", compact)
        ),
        "fee_collection_role_guarded": bool(
            re.search(r"collectRewardFees.{0,500}(?:FEE_COLLECTOR_ROLE|onlyRole)", compact)
            or re.search(r"(?:FEE_COLLECTOR_ROLE|onlyRole).{0,500}collectRewardFees", compact)
        ),
        "fee_shares_affect_supply": bool(
            re.search(r"collectableRewardFeesShares.{0,800}(?:_mint|_burn|totalSupply)", compact)
            or re.search(r"(?:_mint|_burn|totalSupply).{0,800}collectableRewardFeesShares", compact)
        ),
    }
    return {
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "checks": checks,
        "source_supports_hypothesis": all(checks.values()),
    }


def hardened_inspect_vault(row: dict[str, Any], quorum: dict[str, Any]) -> dict[str, Any]:
    result = core.inspect_vault(row, quorum)
    asset = result.get("asset")
    asset_decimals = None
    if asset:
        raw = core.call(
            quorum["primary"], asset, "0x" + core.selector("decimals()"), quorum["block_tag"]
        )
        raw_secondary = core.call(
            quorum["secondary"], asset, "0x" + core.selector("decimals()"), quorum["block_tag"]
        )
        left = core.decode_uint(raw)
        right = core.decode_uint(raw_secondary)
        if left == right and left is not None and 0 <= left <= 36:
            asset_decimals = left
    result["asset_decimals"] = asset_decimals
    structural = bool(result.get("structural_candidate"))
    external_assets = result.get("external_assets_estimate")
    # This is a screening floor, not a severity claim. Stablecoin-like assets require >=10k units;
    # other assets require >=10 units before a holder-level fork PoC is justified.
    text = (row.get("asset_text") or "").upper()
    stable = any(symbol in text for symbol in ("USDC", "USDT", "DAI", "USDS", "EUR", "USD"))
    units = 10_000 if stable else 10
    floor = units * (10 ** int(asset_decimals or 18))
    result["materiality_screen_units"] = units
    result["materiality_screen_raw"] = floor
    result["material_candidate"] = bool(
        structural and external_assets is not None and asset_decimals is not None and external_assets >= floor
    )
    return result


core.source_gate = hardened_source_gate
core.inspect_vault = hardened_inspect_vault

if __name__ == "__main__":
    raise SystemExit(core.main())
