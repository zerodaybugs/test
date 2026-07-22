#!/usr/bin/env python3
"""Focused read-only state and event snapshot for a public rewards contract.

The script uses public Blockscout/Sourcify data and latest-state public RPC calls. It
sends no transaction, uses no private key, and writes raw plus derived evidence.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests
from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address

CHAIN_ID = 1
DISTRIBUTOR = "0xd09931d9A7A320B5D0d407D47f28A269c08Ce04D"
REGISTRY = "0x8A1396765c512811d3bD7314615B0926CA36AEFa"
TX_HASHES = [
    "0x7c8f5cc18bcba1781c6f8b9312cde1a066843b8df2653991313a20164f9d7ef3",
    "0x768a7b82a5200a839674534eb2b97b84683efe4fb64bebfb8962c3845a9d0fca",
]
BLOCKSCOUT = "https://eth.blockscout.com/api/v2"
SOURCIFY = "https://sourcify.dev/server/v2"
RPC_ENDPOINTS = [
    "https://eth.blockscout.com/api/eth-rpc",
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://1rpc.io/eth",
    "https://rpc.flashbots.net",
]

OUT = Path("rewards-state-output")
RAW = OUT / "raw"
DERIVED = OUT / "derived"
RAW.mkdir(parents=True, exist_ok=True)
DERIVED.mkdir(parents=True, exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update({"user-agent": "public-rewards-state-snapshot/2026-07-22"})
_rpc_id = 0


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def get_json(url: str, params: dict[str, Any] | None = None, timeout: int = 120) -> Any:
    response = SESSION.get(url, params=params, timeout=timeout)
    response.raise_for_status()
    return response.json()


def rpc(endpoint: str, method: str, params: list[Any], timeout: int = 90) -> Any:
    global _rpc_id
    errors: list[dict[str, str]] = []
    ordered = [endpoint] + [item for item in RPC_ENDPOINTS if item != endpoint]
    for candidate in ordered:
        _rpc_id += 1
        payload = {"jsonrpc": "2.0", "id": _rpc_id, "method": method, "params": params}
        try:
            response = SESSION.post(candidate, json=payload, timeout=timeout)
            response.raise_for_status()
            body = response.json()
            if "error" in body:
                raise RuntimeError(str(body["error"]))
            return body["result"]
        except Exception as exc:
            errors.append({"endpoint": candidate, "error": repr(exc)})
    raise RuntimeError(json.dumps({"method": method, "errors": errors}, sort_keys=True))


def choose_rpc() -> tuple[str, list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    selected: str | None = None
    for endpoint in RPC_ENDPOINTS:
        row: dict[str, Any] = {"endpoint": endpoint}
        try:
            chain_id = int(rpc(endpoint, "eth_chainId", []), 16)
            latest = int(rpc(endpoint, "eth_blockNumber", []), 16)
            code = rpc(endpoint, "eth_getCode", [DISTRIBUTOR, "latest"])
            row.update(
                {
                    "ok": chain_id == CHAIN_ID and code != "0x",
                    "chain_id": chain_id,
                    "latest_block": latest,
                    "runtime_bytes": (len(code) - 2) // 2,
                }
            )
            if row["ok"] and selected is None:
                selected = endpoint
        except Exception as exc:
            row.update({"ok": False, "error": repr(exc)})
        rows.append(row)
    if selected is None:
        raise RuntimeError(json.dumps(rows, indent=2))
    return selected, rows


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def call(endpoint: str, to: str, data: bytes) -> bytes:
    result = rpc(endpoint, "eth_call", [{"to": to, "data": "0x" + data.hex()}, "latest"])
    return bytes.fromhex(result[2:])


def call_uint(endpoint: str, to: str, signature: str, types: list[str] = [], values: list[Any] = []) -> int:
    raw = call(endpoint, to, selector(signature) + (encode(types, values) if types else b""))
    return int.from_bytes(raw[-32:], "big")


def call_bytes32(endpoint: str, to: str, signature: str, types: list[str], values: list[Any]) -> str:
    raw = call(endpoint, to, selector(signature) + encode(types, values))
    return "0x" + raw[-32:].hex()


def call_address(endpoint: str, to: str, signature: str) -> str:
    raw = call(endpoint, to, selector(signature))
    return to_checksum_address("0x" + raw[-20:].hex())


def decode_entries(decoded_input: dict[str, Any]) -> list[dict[str, Any]]:
    method = decoded_input.get("method_call", "")
    parameters = decoded_input.get("parameters", [])
    if method.startswith("claim("):
        values = {item["name"]: item["value"] for item in parameters}
        return [
            {
                "index": 0,
                "campaign_id": values["campaignId"],
                "account": to_checksum_address(values["account"]),
                "reward_token": to_checksum_address(values["rewardToken"]),
                "cumulative_amount": str(values["cumulativeAmount"]),
                "proof": values["merkleProof"],
            }
        ]
    if method.startswith("claimMultiple("):
        value = parameters[0]["value"]
        output: list[dict[str, Any]] = []
        for index, row in enumerate(value):
            if isinstance(row, dict):
                item = row
            else:
                item = {
                    "campaignId": row[0],
                    "account": row[1],
                    "rewardToken": row[2],
                    "cumulativeAmount": row[3],
                    "merkleProof": row[4],
                }
            output.append(
                {
                    "index": index,
                    "campaign_id": item["campaignId"],
                    "account": to_checksum_address(item["account"]),
                    "reward_token": to_checksum_address(item["rewardToken"]),
                    "cumulative_amount": str(item["cumulativeAmount"]),
                    "proof": item["merkleProof"],
                }
            )
        return output
    raise ValueError(method)


def paginate_address_logs(address: str) -> tuple[list[dict[str, Any]], list[str]]:
    url = f"{BLOCKSCOUT}/addresses/{address}/logs"
    params: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for _ in range(200):
        try:
            body = get_json(url, params=params)
        except Exception as exc:
            errors.append(repr(exc))
            break
        items = body.get("items", []) if isinstance(body, dict) else []
        rows.extend(items)
        next_params = body.get("next_page_params") if isinstance(body, dict) else None
        if not next_params:
            break
        params = next_params
        time.sleep(0.1)
    return rows, errors


def extract_sources(payload: dict[str, Any], label: str) -> dict[str, str]:
    sources = payload.get("sources") or {}
    output: dict[str, str] = {}
    for path, row in sources.items():
        content = row.get("content") if isinstance(row, dict) else None
        if isinstance(content, str):
            output[path] = content
            target = RAW / "sources" / label / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
    return output


def main() -> None:
    endpoint, health = choose_rpc()
    write_json(DERIVED / "rpc_health.json", {"selected": endpoint, "endpoints": health})

    contract_source = get_json(f"{SOURCIFY}/contract/{CHAIN_ID}/{DISTRIBUTOR.lower()}?fields=all")
    registry_source = get_json(f"{SOURCIFY}/contract/{CHAIN_ID}/{REGISTRY.lower()}?fields=all")
    write_json(RAW / "sourcify_distributor.json", contract_source)
    write_json(RAW / "sourcify_registry.json", registry_source)
    distributor_sources = extract_sources(contract_source, "distributor")
    registry_sources = extract_sources(registry_source, "registry")

    runtime = rpc(endpoint, "eth_getCode", [DISTRIBUTOR, "latest"])
    registry_runtime = rpc(endpoint, "eth_getCode", [REGISTRY, "latest"])
    (RAW / "distributor_runtime.hex").write_text(runtime + "\n")
    (RAW / "registry_runtime.hex").write_text(registry_runtime + "\n")

    tx_rows: list[dict[str, Any]] = []
    all_entries: list[dict[str, Any]] = []
    for tx_hash in TX_HASHES:
        tx = get_json(f"{BLOCKSCOUT}/transactions/{tx_hash}")
        logs = get_json(f"{BLOCKSCOUT}/transactions/{tx_hash}/logs")
        transfers = get_json(f"{BLOCKSCOUT}/transactions/{tx_hash}/token-transfers")
        write_json(RAW / f"tx_{tx_hash}.json", tx)
        write_json(RAW / f"tx_{tx_hash}_logs.json", logs)
        write_json(RAW / f"tx_{tx_hash}_transfers.json", transfers)
        entries = decode_entries(tx["decoded_input"])
        for entry in entries:
            entry["source_transaction"] = tx_hash
            entry["transaction_sender"] = to_checksum_address(tx["from"]["hash"])
            entry["block_number"] = tx["block_number"]
            all_entries.append(entry)
        tx_rows.append(
            {
                "tx_hash": tx_hash,
                "method": tx.get("method"),
                "status": tx.get("status"),
                "sender": tx["from"]["hash"],
                "to": tx["to"]["hash"],
                "block_number": tx["block_number"],
                "entries": entries,
                "token_transfers": tx.get("token_transfers", []),
                "logs": logs,
                "transfers_endpoint": transfers,
            }
        )

    distributor_logs, distributor_log_errors = paginate_address_logs(DISTRIBUTOR)
    registry_logs, registry_log_errors = paginate_address_logs(REGISTRY)
    write_json(RAW / "distributor_logs.json", distributor_logs)
    write_json(RAW / "registry_logs.json", registry_logs)

    campaign_count = call_uint(endpoint, REGISTRY, "getCampaignCount()")
    campaign_ids: list[str] = []
    campaigns: list[dict[str, Any]] = []
    campaign_tuple = [
        "bytes32",
        "address",
        "address",
        "address",
        "uint256",
        "uint256",
        "uint256",
        "uint256",
        "uint256",
        "uint8",
    ]
    for index in range(campaign_count):
        raw_id = call(endpoint, REGISTRY, selector("campaignIds(uint256)") + encode(["uint256"], [index]))
        campaign_id = "0x" + raw_id[-32:].hex()
        campaign_ids.append(campaign_id)
        raw_campaign = call(endpoint, REGISTRY, selector("getCampaign(bytes32)") + encode(["bytes32"], [bytes.fromhex(campaign_id[2:])]))
        decoded = decode(campaign_tuple, raw_campaign)
        root = call_bytes32(endpoint, DISTRIBUTOR, "merkleRoots(bytes32)", ["bytes32"], [bytes.fromhex(campaign_id[2:])])
        token = to_checksum_address(decoded[3])
        registry_balance = call_uint(endpoint, token, "balanceOf(address)", ["address"], [REGISTRY])
        campaigns.append(
            {
                "index": index,
                "id": "0x" + bytes(decoded[0]).hex(),
                "creator": to_checksum_address(decoded[1]),
                "c_token": to_checksum_address(decoded[2]),
                "reward_token": token,
                "total_budget": str(decoded[4]),
                "total_paid": str(decoded[5]),
                "remaining_budget": str(decoded[4] - decoded[5]),
                "start_time": decoded[6],
                "end_time": decoded[7],
                "max_apy": decoded[8],
                "status": decoded[9],
                "merkle_root": root,
                "registry_token_balance": str(registry_balance),
            }
        )

    distributor_role = "0x" + call(endpoint, REGISTRY, selector("DISTRIBUTOR_ROLE()"))[-32:].hex()
    root_role = "0x" + call(endpoint, DISTRIBUTOR, selector("ROOT_PUBLISHER_ROLE()"))[-32:].hex()
    distributor_has_role = call_uint(
        endpoint,
        REGISTRY,
        "hasRole(bytes32,address)",
        ["bytes32", "address"],
        [bytes.fromhex(distributor_role[2:]), DISTRIBUTOR],
    ) != 0

    fingerprints: list[tuple[Any, ...]] = []
    for entry in all_entries:
        fingerprints.append(
            (
                entry["campaign_id"].lower(),
                entry["account"].lower(),
                entry["reward_token"].lower(),
                entry["cumulative_amount"],
                tuple(item.lower() for item in entry["proof"]),
            )
        )
    duplicate_entry_count = sum(count - 1 for count in Counter(fingerprints).values() if count > 1)

    recipient_checks: list[dict[str, Any]] = []
    for tx in tx_rows:
        transfers = tx.get("token_transfers") or []
        for entry in tx["entries"]:
            matching = [
                item
                for item in transfers
                if (item.get("token", {}).get("address_hash", "").lower() == entry["reward_token"].lower()
                and item.get("from", {}).get("hash", "").lower() == REGISTRY.lower()
            ]
            recipient_checks.append(
                {
                    "tx_hash": tx["tx_hash"],
                    "entry_index": entry["index"],
                    "proof_account": entry["account"],
                    "matching_registry_transfers": matching,
                    "all_pay_proof_account": bool(matching)
                    and all(item.get("to", {}).get("hash", "").lower() == entry["account"].lower() for item in matching),
                }
            )

    source_checks = {
        "distributor_source_found": "src/RewardsDistributor.sol" in distributor_sources,
        "registry_source_found": "src/CampaignRegistry.sol" in registry_sources,
    }
    distributor_text = distributor_sources.get("src/RewardsDistributor.sol", "")
    registry_text = registry_sources.get("src/CampaignRegistry.sol", "")
    source_checks.update(
        {
            "leaf_binds_all_domains": "abi.encode(campaignId, account, rewardToken, cumulativeAmount)" in distributor_text,
            "claim_non_reentrant": "external\n        nonReentrant" in distributor_text,
            "claim_updates_before_payout": distributor_text.find("claimed[campaignId][account][rewardToken] = cumulativeAmount") < distributor_text.find("campaignRegistry.payoutRewards(campaignId, claimedAmount, account)"),
            "batch_updates_before_payout": distributor_text.find("claimed[c.campaignId][c.account][c.rewardToken] = c.cumulativeAmount") < distributor_text.find("campaignRegistry.payoutRewards(c.campaignId, claimedAmount, c.account)"),
            "payout_requires_distributor_role": "onlyRole(DISTRIBUTOR_ROLE)" in registry_text,
            "registry_payout_non_reentrant": "onlyRole(DISTRIBUTOR_ROLE)\n        nonReentrant" in registry_text,
            "payout_uses_proof_account": "campaignRegistry.payoutRewards(campaignId, claimedAmount, account)" in distributor_text,
            "batch_payout_uses_entry_account": "campaignRegistry.payoutRewards(c.campaignId, claimedAmount, c.account)" in distributor_text,
        }
    )

    root_updates = []
    claimed_events = []
    for item in distributor_logs:
        decoded = item.get("decoded") or {}
        method = decoded.get("method_call") or decoded.get("method") or item.get("method")
        if isinstance(method, str) and method.startswith("MerkleRootUpdated"):
            root_updates.append(item)
        if isinstance(method, str) and method.startswith("Claimed"):
            claimed_events.append(item)

    summary = {
        "chain_id": CHAIN_ID,
        "distributor": DISTRIBUTOR,
        "registry": REGISTRY,
        "selected_rpc": endpoint,
        "runtime_sha256": hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest(),
        "registry_runtime_sha256": hashlib.sha256(bytes.fromhex(registry_runtime[2:])).hexdigest(),
        "distributor_role": distributor_role,
        "root_publisher_role": root_role,
        "distributor_has_registry_role": distributor_has_role,
        "production_transactions": tx_rows,
        "production_entry_count": len(all_entries),
        "duplicate_entry_count_across_observed_transactions": duplicate_entry_count,
        "recipient_checks": recipient_checks,
        "campaign_count": campaign_count,
        "campaigns": campaigns,
        "distributor_log_count": len(distributor_logs),
        "registry_log_count": len(registry_logs),
        "root_update_events_decoded_by_blockscout": len(root_updates),
        "claimed_events_decoded_by_blockscout": len(claimed_events),
        "log_errors": distributor_log_errors + registry_log_errors,
        "source_checks": source_checks,
    }
    write_json(DERIVED / "summary.json", summary)
    write_json(DERIVED / "campaigns.json", campaigns)
    write_json(DERIVED / "production_entries.json", all_entries)

    manifest: list[str] = []
    for path in sorted(OUT.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            manifest.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(OUT).as_posix()}")
    (OUT / "SHA256SUMS.txt").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
