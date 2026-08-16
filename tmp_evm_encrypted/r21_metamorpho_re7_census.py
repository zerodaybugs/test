#!/usr/bin/env python3
"""Kiln R21 Base MetaMorpho Re7 accounting gate. Read-only JSON-RPC only."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from web3 import Web3

OUT = Path("r21_metamorpho_re7_results")
OUT.mkdir(exist_ok=True)

RPCS = [
    "https://base-rpc.publicnode.com",
    "https://base.llamarpc.com",
    "https://mainnet.base.org",
]
VAULT = Web3.to_checksum_address("0x801ECB612d2f724dad01F22049752E9596dD3Eb1")
CALLER = Web3.to_checksum_address("0x000000000000000000000000000000000000bEEF")
ZERO = "0x" + "00" * 20

VAULT_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxRedeem","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"connectorRegistry","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorName","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]},
    {"type":"function","name":"depositFee","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"rewardFee","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"pendingDepositFee","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"pendingRewardFee","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"collectableRewardFees","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"additionalRewardsStrategy","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
REGISTRY_ABI = [
    {"type":"function","name":"get","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"address"}]},
    {"type":"function","name":"getOrRevert","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorInfo","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"address"},{"type":"uint88"},{"type":"bool"}]},
]
CONNECTOR_ABI = [
    {"type":"function","name":"metamorpho","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxDeposit","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ERC4626_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"convertToAssets","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxRedeem","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ERC20_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]


def normalize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (tuple, list)):
        return [normalize(v) for v in value]
    return value


def safe(fn, tx: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        return {"ok": True, "value": normalize(fn.call(tx or {}))}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect() -> tuple[Web3, str]:
    errors: list[str] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
            if not w3.is_connected() or w3.eth.chain_id != 8453:
                continue
            result = w3.eth.call({"to": VAULT, "data": "0x38d52e0f"})
            if len(result) < 32:
                raise RuntimeError("asset getter returned short data")
            return w3, url
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError("no Base RPC passed the exact vault getter gate | " + " | ".join(errors))


def value(result: dict[str, Any]) -> Any:
    return result.get("value") if result.get("ok") else None


def main() -> int:
    w3, rpc = connect()
    block = w3.eth.block_number
    vault = w3.eth.contract(VAULT, abi=VAULT_ABI)

    evidence: dict[str, Any] = {
        "schema": "kiln-r21-metamorpho-re7-accounting-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "chain_id": 8453,
        "network": "base",
        "rpc": rpc,
        "block": block,
        "vault": VAULT,
        "vault_code_sha256": hashlib.sha256(bytes(w3.eth.get_code(VAULT))).hexdigest(),
        "safety": {
            "read_only": True,
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "rpc_methods": ["eth_call", "eth_getCode", "eth_blockNumber"],
        },
        "outer": {},
    }

    for getter in [
        "asset", "decimals", "totalAssets", "totalSupply", "connectorRegistry", "connectorName",
        "depositFee", "rewardFee", "pendingDepositFee", "pendingRewardFee",
        "collectableRewardFees", "additionalRewardsStrategy",
    ]:
        evidence["outer"][getter] = safe(getattr(vault.functions, getter)())

    asset = value(evidence["outer"]["asset"])
    registry_address = value(evidence["outer"]["connectorRegistry"])
    connector_name = value(evidence["outer"]["connectorName"])
    if not asset or not registry_address or not connector_name:
        raise RuntimeError("outer binding unresolved")

    asset = Web3.to_checksum_address(asset)
    registry_address = Web3.to_checksum_address(registry_address)
    connector_name_bytes = bytes.fromhex(connector_name.removeprefix("0x"))
    token = w3.eth.contract(asset, abi=ERC20_ABI)
    evidence["asset"] = {
        "address": asset,
        "name": safe(token.functions.name()),
        "symbol": safe(token.functions.symbol()),
        "decimals": safe(token.functions.decimals()),
        "direct_balance_at_outer": safe(token.functions.balanceOf(VAULT)),
    }

    registry = w3.eth.contract(registry_address, abi=REGISTRY_ABI)
    evidence["registry"] = {
        "address": registry_address,
        "get": safe(registry.functions.get(connector_name_bytes)),
        "getOrRevert": safe(registry.functions.getOrRevert(connector_name_bytes)),
        "connectorInfo": safe(registry.functions.connectorInfo(connector_name_bytes)),
    }
    connector_address = value(evidence["registry"]["get"])
    if not connector_address:
        raise RuntimeError("connector unresolved")
    connector_address = Web3.to_checksum_address(connector_address)
    connector = w3.eth.contract(connector_address, abi=CONNECTOR_ABI)
    evidence["connector"] = {
        "address": connector_address,
        "code_sha256": hashlib.sha256(bytes(w3.eth.get_code(connector_address))).hexdigest(),
        "metamorpho": safe(connector.functions.metamorpho()),
        "totalAssets_as_outer": safe(connector.functions.totalAssets(asset), {"from": VAULT}),
        "maxDeposit_as_outer": safe(connector.functions.maxDeposit(asset), {"from": VAULT}),
        "maxWithdraw_as_outer": safe(connector.functions.maxWithdraw(asset), {"from": VAULT}),
    }
    target_address = value(evidence["connector"]["metamorpho"])
    if not target_address:
        raise RuntimeError("nested ERC4626 target unresolved")
    target_address = Web3.to_checksum_address(target_address)
    target = w3.eth.contract(target_address, abi=ERC4626_ABI)

    evidence["nested"] = {
        "address": target_address,
        "code_sha256": hashlib.sha256(bytes(w3.eth.get_code(target_address))).hexdigest(),
    }
    for getter in ["asset", "name", "symbol", "decimals", "totalAssets", "totalSupply"]:
        evidence["nested"][getter] = safe(getattr(target.functions, getter)())
    evidence["nested"]["outer_share_balance"] = safe(target.functions.balanceOf(VAULT))

    nested_balance = value(evidence["nested"]["outer_share_balance"])
    if nested_balance is None:
        raise RuntimeError("nested share balance unavailable")
    evidence["nested"]["previewRedeem_outer_balance"] = safe(target.functions.previewRedeem(nested_balance))
    evidence["nested"]["convertToAssets_outer_balance"] = safe(target.functions.convertToAssets(nested_balance))
    evidence["nested"]["maxWithdraw_outer"] = safe(target.functions.maxWithdraw(VAULT))
    evidence["nested"]["maxRedeem_outer"] = safe(target.functions.maxRedeem(VAULT))

    outer_decimals = value(evidence["outer"]["decimals"])
    asset_decimals = value(evidence["asset"]["decimals"])
    outer_total_assets = value(evidence["outer"]["totalAssets"])
    outer_total_supply = value(evidence["outer"]["totalSupply"])
    nested_preview = value(evidence["nested"]["previewRedeem_outer_balance"])
    connector_total_assets = value(evidence["connector"]["totalAssets_as_outer"])

    if outer_decimals is not None:
        outer_unit = 10 ** int(outer_decimals)
        evidence["outer"]["previewRedeem_one_share"] = safe(vault.functions.previewRedeem(outer_unit))
        evidence["outer"]["convertToAssets_one_share"] = safe(vault.functions.convertToAssets(outer_unit))
    if outer_total_supply is not None:
        evidence["outer"]["previewRedeem_total_supply"] = safe(vault.functions.previewRedeem(outer_total_supply))
        evidence["outer"]["convertToAssets_total_supply"] = safe(vault.functions.convertToAssets(outer_total_supply))

    calculations: dict[str, Any] = {
        "outer_asset_equals_nested_asset": value(evidence["nested"]["asset"]) is not None
            and Web3.to_checksum_address(value(evidence["nested"]["asset"])) == asset,
        "outer_totalAssets_equals_nested_preview": outer_total_assets == nested_preview,
        "outer_totalAssets_equals_connector_view": outer_total_assets == connector_total_assets,
        "outer_share_decimals": outer_decimals,
        "asset_decimals": asset_decimals,
        "decimals_offset": (int(outer_decimals) - int(asset_decimals))
            if outer_decimals is not None and asset_decimals is not None else None,
        "raw_totalAssets_to_totalSupply_ratio": (outer_total_assets / outer_total_supply)
            if outer_total_assets is not None and outer_total_supply else None,
    }
    if None not in (outer_decimals, asset_decimals, outer_total_assets, outer_total_supply) and outer_total_supply:
        calculations["normalized_asset_per_outer_share"] = (
            outer_total_assets * (10 ** int(outer_decimals))
        ) / (outer_total_supply * (10 ** int(asset_decimals)))
    evidence["calculations"] = calculations

    accounting_exact = bool(
        calculations["outer_asset_equals_nested_asset"]
        and calculations["outer_totalAssets_equals_nested_preview"]
        and calculations["outer_totalAssets_equals_connector_view"]
    )
    gate = {
        "decision": "KILL_DECIMAL_NORMALIZATION_NOT_ACCOUNTING_BUG" if accounting_exact else "HOLD_ACCOUNTING_MISMATCH_REQUIRES_FIXED_BLOCK_FORK",
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "validated_medium": 0,
        "accounting_exact": accounting_exact,
        "blocking_gates": [] if accounting_exact else [
            "fixed-block local fork",
            "attacker or victim delta",
            "third-party root-cause separation",
            "duplicate clearance",
        ],
    }

    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, sort_keys=True))
    (OUT / "MASTER_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    sums = []
    for path in sorted(OUT.glob("*.json")):
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    (OUT / "SHA256SUMS.txt").write_text("".join(sums))
    print("R21_METAMORPHO_RE7_GATE_COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
