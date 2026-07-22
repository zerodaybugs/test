#!/usr/bin/env python3
"""Public-chain metadata and transaction snapshot utility.

The script performs read-only explorer/API/RPC requests and writes raw evidence plus a
small deterministic summary. It sends no transaction and uses no private key.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests
from eth_abi import decode, encode
from eth_utils import keccak, to_checksum_address

CHAIN_ID = 1
CONTRACT = "0xd09931d9A7A320B5D0d407D47f28A269c08Ce04D"
TX_HASHES = [
    "0x7c8f5cc18bcba1781c6f8b9312cde1a066843b8df2653991313a20164f9d7ef3",
    "0x768a7b82a5200a839674534eb2b97b84683efe4fb64bebfb8962c3845a9d0fca",
]

OUT = Path(os.environ.get("SNAPSHOT_OUT", "snapshot-output"))
RAW = OUT / "raw"
DERIVED = OUT / "derived"
RAW.mkdir(parents=True, exist_ok=True)
DERIVED.mkdir(parents=True, exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update({"user-agent": "public-evm-snapshot/2026-07-22"})

RPC_ENDPOINTS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://1rpc.io/eth",
    "https://rpc.flashbots.net",
]

BLOCKSCOUT = "https://eth.blockscout.com/api/v2"
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
SOURCIFY = "https://sourcify.dev/server/v2"


def jdump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def tput(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def get(url: str, *, timeout: int = 60) -> tuple[int | None, str, Any | None]:
    try:
        response = SESSION.get(url, timeout=timeout)
        text = response.text
        try:
            parsed = response.json()
        except Exception:
            parsed = None
        return response.status_code, text, parsed
    except Exception as exc:
        return None, repr(exc), None


def save_get(label: str, url: str) -> Any | None:
    status, text, parsed = get(url)
    tput(RAW / f"{label}.txt", text)
    jdump(RAW / f"{label}.meta.json", {"url": url, "status": status})
    if parsed is not None:
        jdump(RAW / f"{label}.json", parsed)
    return parsed


_rpc_id = 0


def rpc(endpoint: str, method: str, params: list[Any], timeout: int = 60) -> Any:
    global _rpc_id
    _rpc_id += 1
    payload = {"jsonrpc": "2.0", "id": _rpc_id, "method": method, "params": params}
    response = SESSION.post(endpoint, json=payload, timeout=timeout)
    response.raise_for_status()
    body = response.json()
    if "error" in body:
        raise RuntimeError(f"{endpoint} {method}: {body['error']}")
    return body["result"]


def select_rpc() -> tuple[str, list[dict[str, Any]]]:
    health: list[dict[str, Any]] = []
    selected: str | None = None
    for endpoint in RPC_ENDPOINTS:
        row: dict[str, Any] = {"endpoint": endpoint}
        try:
            chain_id = int(rpc(endpoint, "eth_chainId", []), 16)
            latest = int(rpc(endpoint, "eth_blockNumber", []), 16)
            code = rpc(endpoint, "eth_getCode", [CONTRACT, "latest"])
            row.update(
                {
                    "ok": chain_id == CHAIN_ID and isinstance(code, str) and code != "0x",
                    "chain_id": chain_id,
                    "latest_block": latest,
                    "runtime_bytes": (len(code) - 2) // 2,
                }
            )
            if row["ok"] and selected is None:
                selected = endpoint
        except Exception as exc:
            row.update({"ok": False, "error": repr(exc)})
        health.append(row)
    if selected is None:
        raise RuntimeError(f"No usable RPC endpoint: {health}")
    return selected, health


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def word_address(value: bytes | str) -> str:
    raw = bytes.fromhex(value[2:]) if isinstance(value, str) else value
    return to_checksum_address("0x" + raw[-20:].hex())


def eth_call(endpoint: str, to: str, data: bytes, block: int | str) -> bytes:
    tag = hex(block) if isinstance(block, int) else block
    result = rpc(endpoint, "eth_call", [{"to": to, "data": "0x" + data.hex()}, tag])
    return bytes.fromhex(result[2:])


def decode_claim(raw_input: str) -> list[dict[str, Any]]:
    data = bytes.fromhex(raw_input[2:])
    sig = data[:4]
    body = data[4:]
    claim_sig = selector("claim(bytes32,address,address,uint256,bytes32[])")
    multiple_sig = selector("claimMultiple((bytes32,address,address,uint256,bytes32[])[])")
    if sig == claim_sig:
        campaign, account, token, cumulative, proof = decode(
            ["bytes32", "address", "address", "uint256", "bytes32[]"], body
        )
        rows = [(campaign, account, token, cumulative, proof)]
        method = "claim"
    elif sig == multiple_sig:
        (rows,) = decode(["(bytes32,address,address,uint256,bytes32[])[]"], body)
        method = "claimMultiple"
    else:
        raise ValueError(f"Unknown selector 0x{sig.hex()}")
    output: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        campaign, account, token, cumulative, proof = row
        output.append(
            {
                "method": method,
                "index": index,
                "campaign_id": "0x" + bytes(campaign).hex(),
                "account": to_checksum_address(account),
                "reward_token": to_checksum_address(token),
                "cumulative_amount": str(cumulative),
                "proof": ["0x" + bytes(item).hex() for item in proof],
            }
        )
    return output


def encode_claim_args(entry: dict[str, Any]) -> bytes:
    return encode(
        ["bytes32", "address", "address", "uint256", "bytes32[]"],
        [
            bytes.fromhex(entry["campaign_id"][2:]),
            entry["account"],
            entry["reward_token"],
            int(entry["cumulative_amount"]),
            [bytes.fromhex(item[2:]) for item in entry["proof"]],
        ],
    )


def read_claim_state(endpoint: str, entry: dict[str, Any], block: int) -> dict[str, Any]:
    campaign = bytes.fromhex(entry["campaign_id"][2:])
    account = entry["account"]
    token = entry["reward_token"]
    cumulative = int(entry["cumulative_amount"])
    proof = [bytes.fromhex(item[2:]) for item in entry["proof"]]

    verify_data = selector("verifyProof(bytes32,address,address,uint256,bytes32[])") + encode(
        ["bytes32", "address", "address", "uint256", "bytes32[]"],
        [campaign, account, token, cumulative, proof],
    )
    claimed_data = selector("claimed(bytes32,address,address)") + encode(
        ["bytes32", "address", "address"], [campaign, account, token]
    )
    root_data = selector("merkleRoots(bytes32)") + encode(["bytes32"], [campaign])
    claimable_data = selector("getClaimable(bytes32,address,address,uint256,bytes32[])") + encode(
        ["bytes32", "address", "address", "uint256", "bytes32[]"],
        [campaign, account, token, cumulative, proof],
    )
    balance_data = selector("balanceOf(address)") + encode(["address"], [CONTRACT])

    verify = int.from_bytes(eth_call(endpoint, CONTRACT, verify_data, block), "big") != 0
    claimed = int.from_bytes(eth_call(endpoint, CONTRACT, claimed_data, block), "big")
    root = eth_call(endpoint, CONTRACT, root_data, block)
    claimable = int.from_bytes(eth_call(endpoint, CONTRACT, claimable_data, block), "big")
    balance = int.from_bytes(eth_call(endpoint, token, balance_data, block), "big")
    return {
        "block": block,
        "proof_valid": verify,
        "claimed": str(claimed),
        "merkle_root": "0x" + root[-32:].hex(),
        "get_claimable": str(claimable),
        "distributor_token_balance": str(balance),
        "entitlement_delta": str(cumulative - claimed),
    }


def parse_transfer_logs(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    transfer_topic = "0x" + keccak(text="Transfer(address,address,uint256)").hex()
    rows: list[dict[str, Any]] = []
    for log in receipt.get("logs", []):
        topics = [topic.lower() for topic in log.get("topics", [])]
        if len(topics) != 3 or topics[0] != transfer_topic.lower():
            continue
        rows.append(
            {
                "token": to_checksum_address(log["address"]),
                "from": word_address(topics[1]),
                "to": word_address(topics[2]),
                "amount": str(int(log.get("data", "0x0"), 16)),
                "log_index": int(log.get("logIndex", "0x0"), 16),
            }
        )
    return rows


def parse_claimed_logs(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    topic0 = "0x" + keccak(text="Claimed(bytes32,address,address,uint256)").hex()
    rows: list[dict[str, Any]] = []
    for log in receipt.get("logs", []):
        topics = [topic.lower() for topic in log.get("topics", [])]
        if len(topics) != 4 or topics[0] != topic0.lower():
            continue
        rows.append(
            {
                "campaign_id": topics[1],
                "account": word_address(topics[2]),
                "reward_token": word_address(topics[3]),
                "amount": str(int(log.get("data", "0x0"), 16)),
                "log_index": int(log.get("logIndex", "0x0"), 16),
            }
        )
    return rows


def chunked_logs(endpoint: str, address: str, from_block: int, to_block: int) -> list[dict[str, Any]]:
    all_logs: list[dict[str, Any]] = []
    step = 5_000
    start = from_block
    while start <= to_block:
        end = min(start + step - 1, to_block)
        try:
            rows = rpc(
                endpoint,
                "eth_getLogs",
                [{"address": address, "fromBlock": hex(start), "toBlock": hex(end)}],
                timeout=120,
            )
            all_logs.extend(rows)
        except Exception as exc:
            # Retry with smaller ranges before recording an error sentinel.
            if step > 500:
                step = 500
                continue
            all_logs.append(
                {
                    "_error": repr(exc),
                    "from_block": start,
                    "to_block": end,
                }
            )
        start = end + 1
    return all_logs


def main() -> None:
    # Explorer and verification records.
    save_get("blockscout_contract", f"{BLOCKSCOUT}/smart-contracts/{CONTRACT}")
    address_info = save_get("blockscout_address", f"{BLOCKSCOUT}/addresses/{CONTRACT}")
    save_get("sourcify_contract", f"{SOURCIFY}/contract/{CHAIN_ID}/{CONTRACT.lower()}?fields=all")
    save_get(
        "routescan_source",
        ROUTESCAN + "?" + urlencode({"module": "contract", "action": "getsourcecode", "address": CONTRACT}),
    )
    save_get(
        "routescan_abi",
        ROUTESCAN + "?" + urlencode({"module": "contract", "action": "getabi", "address": CONTRACT}),
    )

    endpoint, health = select_rpc()
    jdump(DERIVED / "rpc_health.json", {"selected": endpoint, "endpoints": health})
    latest = int(rpc(endpoint, "eth_blockNumber", []), 16)
    runtime = rpc(endpoint, "eth_getCode", [CONTRACT, "latest"])
    tput(RAW / "runtime.hex", runtime + "\n")

    campaign_registry_raw = eth_call(endpoint, CONTRACT, selector("campaignRegistry()"), "latest")
    campaign_registry = word_address(campaign_registry_raw)
    root_role_raw = eth_call(endpoint, CONTRACT, selector("ROOT_PUBLISHER_ROLE()"), "latest")
    root_role = "0x" + root_role_raw[-32:].hex()

    # Companion contract metadata.
    save_get("blockscout_registry_contract", f"{BLOCKSCOUT}/smart-contracts/{campaign_registry}")
    save_get("blockscout_registry_address", f"{BLOCKSCOUT}/addresses/{campaign_registry}")
    save_get(
        "sourcify_registry",
        f"{SOURCIFY}/contract/{CHAIN_ID}/{campaign_registry.lower()}?fields=all",
    )
    save_get(
        "routescan_registry_source",
        ROUTESCAN + "?" + urlencode({"module": "contract", "action": "getsourcecode", "address": campaign_registry}),
    )

    tx_derived: list[dict[str, Any]] = []
    all_entries: list[dict[str, Any]] = []
    creation_block: int | None = None

    if isinstance(address_info, dict):
        creation_tx = address_info.get("creation_tx_hash") or address_info.get("creation_transaction_hash")
        if creation_tx:
            try:
                creation_obj = rpc(endpoint, "eth_getTransactionByHash", [creation_tx])
                if creation_obj and creation_obj.get("blockNumber"):
                    creation_block = int(creation_obj["blockNumber"], 16)
                jdump(RAW / "creation_transaction.json", creation_obj)
            except Exception as exc:
                tput(RAW / "creation_transaction.error.txt", repr(exc))

    for tx_hash in TX_HASHES:
        label = tx_hash[2:12]
        save_get(f"blockscout_tx_{label}", f"{BLOCKSCOUT}/transactions/{tx_hash}")
        save_get(f"blockscout_tx_logs_{label}", f"{BLOCKSCOUT}/transactions/{tx_hash}/logs")
        save_get(f"blockscout_tx_transfers_{label}", f"{BLOCKSCOUT}/transactions/{tx_hash}/token-transfers")
        save_get(
            f"routescan_tx_{label}",
            ROUTESCAN + "?" + urlencode({"module": "proxy", "action": "eth_getTransactionByHash", "txhash": tx_hash}),
        )
        save_get(
            f"routescan_receipt_{label}",
            ROUTESCAN + "?" + urlencode({"module": "proxy", "action": "eth_getTransactionReceipt", "txhash": tx_hash}),
        )

        tx = rpc(endpoint, "eth_getTransactionByHash", [tx_hash])
        receipt = rpc(endpoint, "eth_getTransactionReceipt", [tx_hash])
        jdump(RAW / f"rpc_tx_{label}.json", tx)
        jdump(RAW / f"rpc_receipt_{label}.json", receipt)
        block_number = int(tx["blockNumber"], 16)
        pre_block = block_number - 1
        entries = decode_claim(tx["input"])
        for entry in entries:
            entry["source_transaction"] = tx_hash
            entry["transaction_sender"] = to_checksum_address(tx["from"])
            entry["claim_block"] = block_number
            entry["pre_claim_state"] = read_claim_state(endpoint, entry, pre_block)
            entry["post_claim_state"] = read_claim_state(endpoint, entry, block_number)
            all_entries.append(entry)

        transfers = parse_transfer_logs(receipt)
        claimed_events = parse_claimed_logs(receipt)
        tx_derived.append(
            {
                "tx_hash": tx_hash,
                "block_number": block_number,
                "sender": to_checksum_address(tx["from"]),
                "to": to_checksum_address(tx["to"]),
                "status": int(receipt["status"], 16),
                "entries": entries,
                "transfer_events": transfers,
                "claimed_events": claimed_events,
            }
        )

    # Determine a conservative log-scan start.
    if creation_block is None:
        earliest_claim = min(item["block_number"] for item in tx_derived)
        creation_block = max(0, earliest_claim - 500_000)

    logs = chunked_logs(endpoint, CONTRACT, creation_block, latest)
    jdump(RAW / "contract_logs.json", logs)

    root_topic = "0x" + keccak(text="MerkleRootUpdated(bytes32,bytes32,bytes32)").hex()
    claimed_topic = "0x" + keccak(text="Claimed(bytes32,address,address,uint256)").hex()
    role_granted_topic = "0x" + keccak(text="RoleGranted(bytes32,address,address)").hex()
    role_revoked_topic = "0x" + keccak(text="RoleRevoked(bytes32,address,address)").hex()

    root_updates: list[dict[str, Any]] = []
    claimed_logs: list[dict[str, Any]] = []
    role_logs: list[dict[str, Any]] = []
    for log in logs:
        if "_error" in log:
            continue
        topics = [item.lower() for item in log.get("topics", [])]
        if not topics:
            continue
        block_number = int(log["blockNumber"], 16)
        tx_hash = log["transactionHash"]
        data = bytes.fromhex(log.get("data", "0x")[2:])
        if topics[0] == root_topic.lower() and len(topics) >= 2 and len(data) >= 64:
            root_updates.append(
                {
                    "campaign_id": topics[1],
                    "old_root": "0x" + data[:32].hex(),
                    "new_root": "0x" + data[32:64].hex(),
                    "block_number": block_number,
                    "tx_hash": tx_hash,
                    "log_index": int(log["logIndex"], 16),
                }
            )
        elif topics[0] == claimed_topic.lower() and len(topics) >= 4:
            claimed_logs.append(
                {
                    "campaign_id": topics[1],
                    "account": word_address(topics[2]),
                    "reward_token": word_address(topics[3]),
                    "amount": str(int.from_bytes(data[-32:], "big")),
                    "block_number": block_number,
                    "tx_hash": tx_hash,
                    "log_index": int(log["logIndex"], 16),
                }
            )
        elif topics[0] in {role_granted_topic.lower(), role_revoked_topic.lower()} and len(topics) >= 4:
            role_logs.append(
                {
                    "kind": "granted" if topics[0] == role_granted_topic.lower() else "revoked",
                    "role": topics[1],
                    "account": word_address(topics[2]),
                    "sender": word_address(topics[3]),
                    "block_number": block_number,
                    "tx_hash": tx_hash,
                    "log_index": int(log["logIndex"], 16),
                }
            )

    root_updates.sort(key=lambda x: (x["block_number"], x["log_index"]))
    roots_by_campaign: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in root_updates:
        roots_by_campaign[row["campaign_id"]].append(row)

    rollbacks: list[dict[str, Any]] = []
    for campaign, rows in roots_by_campaign.items():
        seen: dict[str, int] = {}
        for row in rows:
            new_root = row["new_root"]
            if new_root in seen:
                rollbacks.append(
                    {
                        "campaign_id": campaign,
                        "root": new_root,
                        "first_index": seen[new_root],
                        "repeat_block": row["block_number"],
                        "repeat_tx": row["tx_hash"],
                    }
                )
            seen[new_root] = row["block_number"]

    duplicate_batches: list[dict[str, Any]] = []
    for tx_row in tx_derived:
        fingerprints = [
            (
                entry["campaign_id"].lower(),
                entry["account"].lower(),
                entry["reward_token"].lower(),
                entry["cumulative_amount"],
                tuple(item.lower() for item in entry["proof"]),
            )
            for entry in tx_row["entries"]
        ]
        counts = Counter(fingerprints)
        dup_count = sum(count - 1 for count in counts.values() if count > 1)
        if dup_count:
            duplicate_batches.append({"tx_hash": tx_row["tx_hash"], "duplicate_entry_count": dup_count})

    recipient_checks: list[dict[str, Any]] = []
    for tx_row in tx_derived:
        transfers = tx_row["transfer_events"]
        for entry in tx_row["entries"]:
            matches = [
                row
                for row in transfers
                if row["token"].lower() == entry["reward_token"].lower()
                and row["from"].lower() == CONTRACT.lower()
            ]
            recipient_checks.append(
                {
                    "tx_hash": tx_row["tx_hash"],
                    "entry_index": entry["index"],
                    "proof_account": entry["account"],
                    "transaction_sender": entry["transaction_sender"],
                    "matching_distributor_transfers": matches,
                    "all_matching_transfers_pay_proof_account": bool(matches)
                    and all(row["to"].lower() == entry["account"].lower() for row in matches),
                }
            )

    tokens = sorted({entry["reward_token"] for entry in all_entries}, key=str.lower)
    current_balances: dict[str, str] = {}
    balance_selector = selector("balanceOf(address)")
    for token in tokens:
        raw = eth_call(endpoint, token, balance_selector + encode(["address"], [CONTRACT]), "latest")
        current_balances[token] = str(int.from_bytes(raw, "big"))

    summary = {
        "chain_id": CHAIN_ID,
        "contract": CONTRACT,
        "runtime_sha256": hashlib.sha256(bytes.fromhex(runtime[2:])).hexdigest(),
        "runtime_bytes": (len(runtime) - 2) // 2,
        "campaign_registry": campaign_registry,
        "root_publisher_role": root_role,
        "selected_rpc": endpoint,
        "latest_block": latest,
        "scan_start_block": creation_block,
        "production_transactions": tx_derived,
        "production_entry_count": len(all_entries),
        "duplicate_batches": duplicate_batches,
        "recipient_checks": recipient_checks,
        "root_update_count": len(root_updates),
        "campaign_count": len(roots_by_campaign),
        "root_update_counts_by_campaign": {key: len(value) for key, value in roots_by_campaign.items()},
        "repeated_roots_or_rollbacks": rollbacks,
        "claimed_event_count": len(claimed_logs),
        "role_event_count": len(role_logs),
        "current_reward_token_balances": current_balances,
        "raw_log_errors": [row for row in logs if "_error" in row],
    }
    jdump(DERIVED / "summary.json", summary)
    jdump(DERIVED / "decoded_claim_entries.json", all_entries)
    jdump(DERIVED / "root_updates.json", root_updates)
    jdump(DERIVED / "claimed_logs.json", claimed_logs)
    jdump(DERIVED / "role_logs.json", role_logs)

    # Portable integrity manifest.
    manifest: list[str] = []
    for path in sorted(OUT.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest.append(f"{digest}  {path.relative_to(OUT).as_posix()}")
    tput(OUT / "SHA256SUMS.txt", "\n".join(manifest) + "\n")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
