#!/usr/bin/env python3
"""Kiln OmniVault R34 exact liveness/binding gate.

Read-only safety boundary:
- only eth_chainId, eth_blockNumber, eth_getBlockByNumber, eth_getCode,
  eth_getStorageAt, eth_getLogs and eth_call;
- no transaction signing or broadcasting;
- no public-chain state mutation.

The gate targets the five R31 error classes conservatively by inspecting all
Ethereum VENUS vaults and every Base vault in the current 101-vault scope.
A scan signal is never assigned severity. Promotion requires a two-RPC exact
state agreement and an actual holder redemption failure; a later fixed-block
fork is still mandatory.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path("r34_exact_results")
OUT.mkdir(exist_ok=True)
SCOPE_URL = (
    "https://raw.githubusercontent.com/zerodaybugs/test/"
    "agent/kiln-r30-current-scope-all-20260817/r30_scope/SCOPE.json"
)
ZERO = "0x0000000000000000000000000000000000000000"
PROBE = Web3.to_checksum_address("0x000000000000000000000000000000000000bEEF")
BEACON_SLOT = int(
    "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeeee59ff6cb3582b35133d50",
    16,
)
TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)").hex()
ZERO_TOPIC = "0x" + "00" * 32

NETWORKS: dict[str, tuple[int, list[str]]] = {
    "ethereum": (
        1,
        [
            "https://ethereum-rpc.publicnode.com",
            "https://rpc.flashbots.net",
            "https://eth.llamarpc.com",
            "https://1rpc.io/eth",
        ],
    ),
    "base": (
        8453,
        [
            "https://base-rpc.publicnode.com",
            "https://base.llamarpc.com",
            "https://mainnet.base.org",
        ],
    ),
}

VAULT_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorRegistry","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorName","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"pendingDepositFee","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"pendingRewardFee","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxRedeem","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"redeem","stateMutability":"nonpayable","inputs":[{"type":"uint256"},{"type":"address"},{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
REGISTRY_ABI = [
    {"type":"function","name":"get","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"address"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"frozen","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"pauseTimestamp","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"uint256"}]},
]
CONNECTOR_ABI = [
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxWithdraw","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"maxDeposit","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
BEACON_ABI = [
    {"type":"function","name":"implementation","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]


@dataclass(frozen=True)
class ScopeRow:
    network: str
    vault: str
    label: str
    connector: str


def normalize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    return value


def safe_call(fn: Any, block: int, tx: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        return {"ok": True, "value": normalize(fn.call(tx or {}, block_identifier=block))}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def value(result: dict[str, Any] | None) -> Any:
    return result.get("value") if isinstance(result, dict) and result.get("ok") else None


def checksum(raw: Any) -> str | None:
    try:
        return Web3.to_checksum_address(raw)
    except Exception:
        return None


def code_hash(w3: Web3, address: str | None, block: int) -> str | None:
    if not address or address.lower() == ZERO.lower():
        return None
    try:
        raw = bytes(w3.eth.get_code(Web3.to_checksum_address(address), block_identifier=block))
        return hashlib.sha256(raw).hexdigest() if raw else None
    except Exception:
        return None


def decode_name(raw: Any) -> str | None:
    try:
        if isinstance(raw, str) and raw.startswith("0x"):
            return bytes.fromhex(raw[2:]).rstrip(b"\x00").decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def load_scope() -> tuple[list[ScopeRow], dict[str, Any]]:
    response = requests.get(SCOPE_URL, headers={"User-Agent":"Kiln-R34-Liveness/2.0"}, timeout=45)
    response.raise_for_status()
    raw = response.content
    payload = response.json()
    rows = payload.get("rows", payload if isinstance(payload, list) else [])
    selected: list[ScopeRow] = []
    for row in rows:
        network = str(row.get("network", "")).lower()
        connector = str(row.get("connector", ""))
        if not ((network == "ethereum" and connector == "VENUS") or network == "base"):
            continue
        selected.append(
            ScopeRow(
                network=network,
                vault=Web3.to_checksum_address(row["address"]),
                label=str(row.get("label", "")),
                connector=connector,
            )
        )
    return selected, {
        "url": SCOPE_URL,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_row_count": len(rows),
        "selected_count": len(selected),
    }


def connect_quorum(network: str, probe_vault: str) -> tuple[list[tuple[Web3, str, int]], int, str]:
    chain_id, urls = NETWORKS[network]
    clients: list[tuple[Web3, str, int]] = []
    errors: list[str] = []
    probe = Web3.to_checksum_address(probe_vault)
    selector = Web3.keccak(text="asset()")[:4]
    for url in urls:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            if not w3.is_connected() or int(w3.eth.chain_id) != chain_id:
                raise RuntimeError("disconnected or wrong chain")
            height = int(w3.eth.block_number)
            raw = bytes(w3.eth.call({"to": probe, "data": selector}, block_identifier=height))
            if len(raw) < 32:
                raise RuntimeError("probe asset getter returned short data")
            clients.append((w3, url, height))
            if len(clients) == 2:
                break
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    if len(clients) < 2:
        raise RuntimeError("two-RPC quorum unavailable | " + " | ".join(errors))
    block = max(1, min(item[2] for item in clients) - 6)
    block_hash = clients[0][0].eth.get_block(block)["hash"].hex()
    other_hash = clients[1][0].eth.get_block(block)["hash"].hex()
    if other_hash.lower() != block_hash.lower():
        raise RuntimeError(f"RPC block-hash disagreement at {block}")
    return clients, block, block_hash


def core_state(w3: Web3, source: ScopeRow, block: int, block_hash: str) -> dict[str, Any]:
    vault_address = Web3.to_checksum_address(source.vault)
    vault = w3.eth.contract(vault_address, abi=VAULT_ABI)
    item: dict[str, Any] = {
        "network": source.network,
        "label": source.label,
        "scope_connector": source.connector,
        "vault": vault_address,
        "block": block,
        "block_hash": block_hash,
        "vault_code_sha256": code_hash(w3, vault_address, block),
    }
    for getter in [
        "asset", "connectorRegistry", "connectorName", "totalAssets", "totalSupply",
        "decimals", "pendingDepositFee", "pendingRewardFee",
    ]:
        item[getter] = safe_call(getattr(vault.functions, getter)(), block)

    asset = checksum(value(item["asset"]))
    registry_address = checksum(value(item["connectorRegistry"]))
    connector_name_raw = value(item["connectorName"])
    item["connector_name_ascii"] = decode_name(connector_name_raw)
    item["binding_complete"] = bool(asset and registry_address and isinstance(connector_name_raw, str))
    item["registry"] = None
    item["connector"] = None
    item["asset_token"] = None
    item["beacon"] = None

    if asset:
        token = w3.eth.contract(asset, abi=ERC20_ABI)
        item["asset_token"] = {
            "address": asset,
            "code_sha256": code_hash(w3, asset, block),
            "symbol": safe_call(token.functions.symbol(), block),
            "decimals": safe_call(token.functions.decimals(), block),
            "direct_balance": safe_call(token.functions.balanceOf(vault_address), block),
        }

    connector_address: str | None = None
    if registry_address and isinstance(connector_name_raw, str):
        name_bytes = bytes.fromhex(connector_name_raw.removeprefix("0x"))
        registry = w3.eth.contract(registry_address, abi=REGISTRY_ABI)
        registry_state = {
            "address": registry_address,
            "code_sha256": code_hash(w3, registry_address, block),
            "get": safe_call(registry.functions.get(name_bytes), block),
            "paused": safe_call(registry.functions.paused(name_bytes), block),
            "frozen": safe_call(registry.functions.frozen(name_bytes), block),
            "pauseTimestamp": safe_call(registry.functions.pauseTimestamp(name_bytes), block),
        }
        item["registry"] = registry_state
        connector_address = checksum(value(registry_state["get"]))

    if connector_address and connector_address.lower() != ZERO.lower():
        connector = w3.eth.contract(connector_address, abi=CONNECTOR_ABI)
        item["connector"] = {
            "address": connector_address,
            "code_sha256": code_hash(w3, connector_address, block),
            "totalAssets_as_vault": safe_call(
                connector.functions.totalAssets(asset), block, {"from": vault_address}
            ) if asset else {"ok": False, "error": "asset unresolved"},
            "maxWithdraw_as_vault": safe_call(
                connector.functions.maxWithdraw(asset), block, {"from": vault_address}
            ) if asset else {"ok": False, "error": "asset unresolved"},
            "maxDeposit_as_vault": safe_call(
                connector.functions.maxDeposit(asset), block, {"from": vault_address}
            ) if asset else {"ok": False, "error": "asset unresolved"},
        }

    try:
        raw_slot = bytes(w3.eth.get_storage_at(vault_address, BEACON_SLOT, block_identifier=block))
        beacon_address = checksum("0x" + raw_slot[-20:].hex()) if len(raw_slot) >= 20 else None
        beacon_state: dict[str, Any] = {
            "address": beacon_address,
            "code_sha256": code_hash(w3, beacon_address, block),
        }
        if beacon_address and beacon_address.lower() != ZERO.lower():
            beacon = w3.eth.contract(beacon_address, abi=BEACON_ABI)
            beacon_state["implementation"] = safe_call(beacon.functions.implementation(), block)
            implementation = checksum(value(beacon_state["implementation"]))
            beacon_state["implementation_code_sha256"] = code_hash(w3, implementation, block)
        item["beacon"] = beacon_state
    except Exception as exc:
        item["beacon"] = {"error": f"{type(exc).__name__}: {exc}"}

    supply = int(value(item["totalSupply"]) or 0)
    total_assets_ok = bool(item["totalAssets"].get("ok"))
    total_assets = int(value(item["totalAssets"]) or 0)
    connector_missing = not connector_address or connector_address.lower() == ZERO.lower()
    paused = bool(value((item.get("registry") or {}).get("paused")))
    frozen = bool(value((item.get("registry") or {}).get("frozen")))
    signals: list[str] = []
    if supply > 0 and not total_assets_ok:
        signals.append("positive_supply_totalAssets_reverts")
    if supply > 0 and total_assets_ok and total_assets == 0:
        signals.append("positive_supply_zero_totalAssets")
    if supply > 0 and connector_missing:
        signals.append("positive_supply_connector_missing")
    if supply > 0 and paused:
        signals.append("connector_paused_with_positive_supply")
    if frozen:
        signals.append("connector_frozen")
    if item.get("connector_name_ascii") != source.connector:
        signals.append("scope_connector_name_runtime_mismatch")
    if connector_address and not code_hash(w3, connector_address, block):
        signals.append("connector_has_no_runtime_code")
    item["preliminary_signals"] = sorted(set(signals))
    return item


def comparison_fingerprint(item: dict[str, Any]) -> dict[str, Any]:
    registry = item.get("registry") or {}
    connector = item.get("connector") or {}
    return {
        "asset": value(item.get("asset")),
        "connectorRegistry": value(item.get("connectorRegistry")),
        "connectorName": value(item.get("connectorName")),
        "totalSupply": value(item.get("totalSupply")),
        "totalAssets_ok": bool((item.get("totalAssets") or {}).get("ok")),
        "totalAssets": value(item.get("totalAssets")),
        "connector": value(registry.get("get")),
        "paused": value(registry.get("paused")),
        "frozen": value(registry.get("frozen")),
        "connector_totalAssets_ok": bool((connector.get("totalAssets_as_vault") or {}).get("ok")),
        "connector_totalAssets": value(connector.get("totalAssets_as_vault")),
        "vault_code_sha256": item.get("vault_code_sha256"),
    }


def find_positive_holders(
    w3: Web3,
    vault_address: str,
    block: int,
    max_positive: int = 8,
) -> dict[str, Any]:
    vault_address = Web3.to_checksum_address(vault_address)
    vault = w3.eth.contract(vault_address, abi=VAULT_ABI)
    candidates: list[str] = []
    seen: set[str] = set()
    errors: list[str] = []
    scan_budget = 1_500_000 if int(w3.eth.chain_id) == 1 else 4_000_000
    chunk = 25_000 if int(w3.eth.chain_id) == 1 else 100_000
    floor = max(0, block - scan_budget)
    end = block
    while end >= floor and len(candidates) < 80:
        start = max(floor, end - chunk + 1)
        try:
            logs = w3.eth.get_logs({
                "address": vault_address,
                "fromBlock": start,
                "toBlock": end,
                "topics": [TRANSFER_TOPIC, ZERO_TOPIC],
            })
            for log in reversed(logs):
                if len(log.get("topics", [])) < 3:
                    continue
                recipient = checksum("0x" + bytes(log["topics"][2])[-20:].hex())
                if recipient and recipient.lower() != ZERO.lower() and recipient.lower() not in seen:
                    seen.add(recipient.lower())
                    candidates.append(recipient)
        except Exception as exc:
            errors.append(f"{start}-{end}: {type(exc).__name__}: {exc}")
        end = start - 1

    positive: list[dict[str, Any]] = []
    for holder in candidates:
        balance_result = safe_call(vault.functions.balanceOf(holder), block)
        balance = int(value(balance_result) or 0)
        if balance <= 0:
            continue
        max_redeem_result = safe_call(vault.functions.maxRedeem(holder), block)
        max_redeem = int(value(max_redeem_result) or 0)
        positive.append({
            "holder": holder,
            "share_balance": balance,
            "maxRedeem": max_redeem_result,
            "maxWithdraw": safe_call(vault.functions.maxWithdraw(holder), block),
        })
        if len(positive) >= max_positive:
            break
    return {
        "scan_floor": floor,
        "scan_tip": block,
        "candidate_address_count": len(candidates),
        "positive_holders": positive,
        "log_errors": errors[-10:],
    }


def simulate_holder_redeems(w3: Web3, vault_address: str, block: int, holders: list[dict[str, Any]]) -> list[dict[str, Any]]:
    vault_address = Web3.to_checksum_address(vault_address)
    vault = w3.eth.contract(vault_address, abi=VAULT_ABI)
    rows: list[dict[str, Any]] = []
    for entry in holders[:8]:
        holder = Web3.to_checksum_address(entry["holder"])
        balance = int(entry["share_balance"])
        max_redeem = int(value(entry.get("maxRedeem")) or 0)
        samples = sorted({amount for amount in (1 if balance > 0 else 0, min(balance, max_redeem)) if amount > 0})
        attempts: list[dict[str, Any]] = []
        for shares in samples:
            preview = safe_call(vault.functions.previewRedeem(shares), block)
            redeem = safe_call(
                vault.functions.redeem(shares, holder, holder),
                block,
                {"from": holder, "gas": 30_000_000},
            )
            attempts.append({"shares": shares, "previewRedeem": preview, "redeem_eth_call": redeem})
        rows.append({**entry, "attempts": attempts})
    return rows


def any_redeem_success(rows: list[dict[str, Any]]) -> bool:
    return any(
        attempt.get("redeem_eth_call", {}).get("ok")
        for row in rows
        for attempt in row.get("attempts", [])
    )


def main() -> int:
    scope, scope_meta = load_scope()
    grouped: dict[str, list[ScopeRow]] = {}
    for row in scope:
        grouped.setdefault(row.network, []).append(row)

    evidence: dict[str, Any] = {
        "schema": "kiln-r34-exact-liveness-v2",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": scope_meta,
        "safety": {
            "read_only": True,
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "private_keys_loaded": 0,
            "rpc_methods": [
                "eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_getCode",
                "eth_getStorageAt", "eth_getLogs", "eth_call",
            ],
        },
        "chains": {},
        "rows": [],
        "errors": [],
    }

    for network, rows in sorted(grouped.items()):
        try:
            clients, block, block_hash = connect_quorum(network, rows[0].vault)
            evidence["chains"][network] = {
                "chain_id": NETWORKS[network][0],
                "rpc_urls": [entry[1] for entry in clients],
                "latest_heights": [entry[2] for entry in clients],
                "pinned_block": block,
                "pinned_block_hash": block_hash,
                "rpc_quorum_size": 2,
            }
        except Exception as exc:
            evidence["errors"].append({"network":network, "error":f"{type(exc).__name__}: {exc}"})
            continue

        primary = clients[0][0]
        secondary = clients[1][0]
        for source in rows:
            try:
                first = core_state(primary, source, block, block_hash)
                second = core_state(secondary, source, block, block_hash)
                first_fp = comparison_fingerprint(first)
                second_fp = comparison_fingerprint(second)
                agreement = first_fp == second_fp
                first["secondary_quorum"] = {
                    "rpc_url": clients[1][1],
                    "agreement": agreement,
                    "primary_fingerprint": first_fp,
                    "secondary_fingerprint": second_fp,
                }

                supply = int(value(first.get("totalSupply")) or 0)
                strong_precondition = bool(first.get("preliminary_signals")) and supply > 0
                if strong_precondition and agreement:
                    holder_census = find_positive_holders(primary, source.vault, block)
                    holder_rows = simulate_holder_redeems(
                        primary, source.vault, block, holder_census["positive_holders"]
                    )
                    holder_rows_secondary = simulate_holder_redeems(
                        secondary, source.vault, block, holder_census["positive_holders"]
                    )
                    first["holder_census"] = holder_census
                    first["holder_redeem_primary"] = holder_rows
                    first["holder_redeem_secondary"] = holder_rows_secondary
                    primary_success = any_redeem_success(holder_rows)
                    secondary_success = any_redeem_success(holder_rows_secondary)
                    first["liveness_result"] = {
                        "positive_holder_count": len(holder_census["positive_holders"]),
                        "primary_any_redeem_success": primary_success,
                        "secondary_any_redeem_success": secondary_success,
                        "two_rpc_redeem_success_agreement": primary_success == secondary_success,
                    }
                else:
                    first["holder_census"] = None
                    first["liveness_result"] = {
                        "skipped": True,
                        "reason": "no strong positive-supply precondition or RPC disagreement",
                    }

                candidate_reasons: list[str] = []
                if agreement and supply > 0 and first.get("preliminary_signals"):
                    liveness = first.get("liveness_result") or {}
                    holder_count = int(liveness.get("positive_holder_count", 0) or 0)
                    primary_success = bool(liveness.get("primary_any_redeem_success"))
                    secondary_success = bool(liveness.get("secondary_any_redeem_success"))
                    if holder_count > 0 and not primary_success and not secondary_success:
                        candidate_reasons.append("two_rpc_holder_redeem_failure_with_runtime_anomaly")
                    elif holder_count == 0:
                        candidate_reasons.append("holder_discovery_inconclusive")
                if not agreement:
                    candidate_reasons.append("killed_rpc_state_disagreement")

                first["promotion"] = {
                    "candidate": "two_rpc_holder_redeem_failure_with_runtime_anomaly" in candidate_reasons,
                    "reasons": candidate_reasons,
                    "requires_fixed_block_fork": True,
                    "severity_assigned": False,
                }
                evidence["rows"].append(first)
            except Exception as exc:
                evidence["errors"].append({
                    "network": network,
                    "vault": source.vault,
                    "label": source.label,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    candidates = [row for row in evidence["rows"] if row.get("promotion", {}).get("candidate")]
    inconclusive = [
        row for row in evidence["rows"]
        if "holder_discovery_inconclusive" in row.get("promotion", {}).get("reasons", [])
    ]
    summary = {
        "scope_count": len(scope),
        "inspected_count": len(evidence["rows"]),
        "error_count": len(evidence["errors"]),
        "preliminary_signal_rows": sum(bool(row.get("preliminary_signals")) for row in evidence["rows"]),
        "candidate_count": len(candidates),
        "inconclusive_holder_rows": len(inconclusive),
        "candidate_vaults": [row["vault"] for row in candidates],
        "candidate_reasons": sorted({
            reason for row in candidates for reason in row.get("promotion", {}).get("reasons", [])
        }),
    }
    evidence["summary"] = summary
    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, sort_keys=True))

    if candidates:
        decision = "HOLD_EXACT_FIXED_BLOCK_FORK_REQUIRED"
    elif evidence["errors"]:
        decision = "INCONCLUSIVE_TARGET_ERRORS_REMAIN"
    elif inconclusive:
        decision = "INCONCLUSIVE_HOLDER_DISCOVERY"
    else:
        decision = "KILL_NO_TWO_RPC_LIVENESS_FAILURE"
    public_gate = {
        "schema": "kiln-r34-exact-liveness-public-gate-v2",
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "scope_count": len(scope),
        "inspected_count": len(evidence["rows"]),
        "error_count": len(evidence["errors"]),
        "preliminary_signal_rows": summary["preliminary_signal_rows"],
        "candidate_count": len(candidates),
        "inconclusive_holder_rows": len(inconclusive),
        "candidate_vaults": summary["candidate_vaults"],
        "public_chain_state_changes": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(public_gate, indent=2, sort_keys=True))
    files = sorted(path for path in OUT.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
    )
    print(json.dumps(public_gate, sort_keys=True))
    return 0 if evidence["rows"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
