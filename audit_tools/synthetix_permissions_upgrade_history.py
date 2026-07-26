#!/usr/bin/env python3
"""Collect and compare the complete PermissionsRegistry implementation history.

Read-only operations only:
- public Ethereum JSON-RPC logs, storage, code and calls;
- public Sourcify verified-source metadata;
- no signature, credential, transaction, state mutation or account data.

The output records implementation/code/source hashes, storage layouts, upgrade events,
proxy owner/admin state and deterministic compatibility checks between every version.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

from eth_utils import keccak, to_checksum_address

OUT = pathlib.Path("permissions_upgrade_history")
OUT.mkdir(parents=True, exist_ok=True)

CHAIN_ID = 1
PROXY = "0x45F91031b33Da2585932c8f1cdFF0faa6cD329ae"
START_BLOCK = 24_000_000
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=all"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 40 * 1024 * 1024

UPGRADED_TOPIC = "0x" + keccak(text="Upgraded(address)").hex()
IMPLEMENTATION_SLOT = int.from_bytes(keccak(text="eip1967.proxy.implementation"), "big") - 1
ADMIN_SLOT = int.from_bytes(keccak(text="eip1967.proxy.admin"), "big") - 1
OWNER_SELECTOR = "0x8da5cb5b"
PAUSED_SELECTOR = "0x5c975abb"
PROXIABLE_UUID_SELECTOR = "0x52d1902d"


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise RuntimeError("response too large")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1)


def get_url(url: str, timeout: int = 60) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise RuntimeError("response too large")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1)


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                error = parsed.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                errors.append(f"status={status},code={code}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def get_logs(start: int, end: int) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [
                {
                    "address": PROXY,
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [UPGRADED_TOPIC],
                }
            ],
        )
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return get_logs(start, middle) + get_logs(middle + 1, end)


def storage_address(slot: int, block: str = "latest") -> str:
    raw = rpc("eth_getStorageAt", [PROXY, hex(slot), block])
    return to_checksum_address("0x" + raw[-40:])


def code_record(address: str, block: str = "latest") -> dict[str, Any]:
    code = rpc("eth_getCode", [address, block])
    code_bytes = bytes.fromhex(code.removeprefix("0x"))
    delegation = None
    if len(code_bytes) == 23 and code_bytes[:3] == bytes.fromhex("ef0100"):
        delegation = to_checksum_address("0x" + code_bytes[3:].hex())
    return {
        "address": to_checksum_address(address),
        "codeBytes": len(code_bytes),
        "codeSha256": digest(code_bytes),
        "eip7702DelegationTarget": delegation,
    }


def eth_call(to: str, data: str, block: str = "latest") -> str:
    return rpc("eth_call", [{"to": to, "data": data}, block])


def decode_address_word(raw: str) -> str | None:
    value = raw.removeprefix("0x")
    if len(value) < 64 or int(value, 16) == 0:
        return None
    return to_checksum_address("0x" + value[-40:])


def sourcify(address: str) -> tuple[int, Any, bytes]:
    status, body = get_url(SOURCIFY.format(chain=CHAIN_ID, address=to_checksum_address(address)))
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    return status, parsed, body


def compact_storage(layout: Any) -> dict[str, Any]:
    if not isinstance(layout, dict):
        return {"storage": [], "types": {}}
    storage = []
    for item in layout.get("storage", []) or []:
        if not isinstance(item, dict):
            continue
        storage.append(
            {
                "astId": item.get("astId"),
                "contract": item.get("contract"),
                "label": item.get("label"),
                "offset": int(item.get("offset", 0)),
                "slot": str(item.get("slot")),
                "type": item.get("type"),
            }
        )
    return {"storage": storage, "types": layout.get("types", {}) or {}}


def canonical_type(type_id: str, types: dict[str, Any], seen: set[str] | None = None) -> Any:
    seen = set() if seen is None else set(seen)
    if type_id in seen:
        return {"cycle": type_id}
    seen.add(type_id)
    item = types.get(type_id)
    if not isinstance(item, dict):
        return {"missing": type_id}
    result: dict[str, Any] = {
        "encoding": item.get("encoding"),
        "label": item.get("label"),
        "numberOfBytes": str(item.get("numberOfBytes")),
    }
    for key in ("key", "value", "base"):
        child = item.get(key)
        if isinstance(child, str):
            result[key] = canonical_type(child, types, seen)
    members = item.get("members")
    if isinstance(members, list):
        result["members"] = [
            {
                "label": member.get("label"),
                "offset": int(member.get("offset", 0)),
                "slot": str(member.get("slot")),
                "type": canonical_type(str(member.get("type")), types, seen),
            }
            for member in members
            if isinstance(member, dict)
        ]
    return result


def compare_layout(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    prev_storage = previous.get("storage", [])
    curr_storage = current.get("storage", [])
    prev_types = previous.get("types", {})
    curr_types = current.get("types", {})
    curr_by_position = {(str(item["slot"]), int(item["offset"])): item for item in curr_storage}
    mismatches: list[dict[str, Any]] = []
    for old in prev_storage:
        pos = (str(old["slot"]), int(old["offset"]))
        new = curr_by_position.get(pos)
        if new is None:
            mismatches.append({"kind": "removed_or_moved", "previous": old})
            continue
        old_shape = canonical_type(str(old.get("type")), prev_types)
        new_shape = canonical_type(str(new.get("type")), curr_types)
        if old.get("label") != new.get("label") or old_shape != new_shape:
            mismatches.append(
                {
                    "kind": "changed",
                    "position": {"slot": pos[0], "offset": pos[1]},
                    "previous": old,
                    "current": new,
                    "previousTypeShape": old_shape,
                    "currentTypeShape": new_shape,
                }
            )
    prev_positions = {(str(item["slot"]), int(item["offset"])) for item in prev_storage}
    additions = [item for item in curr_storage if (str(item["slot"]), int(item["offset"])) not in prev_positions]
    max_prev_slot = max((int(item["slot"]) for item in prev_storage), default=-1)
    non_append_additions = [item for item in additions if int(item["slot"]) < max_prev_slot]
    return {
        "compatible": not mismatches and not non_append_additions,
        "previousStorageEntryCount": len(prev_storage),
        "currentStorageEntryCount": len(curr_storage),
        "mismatchCount": len(mismatches),
        "mismatches": mismatches,
        "additionCount": len(additions),
        "additions": additions,
        "nonAppendAdditionCount": len(non_append_additions),
        "nonAppendAdditions": non_append_additions,
    }


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    logs = get_logs(START_BLOCK, latest)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))

    events: list[dict[str, Any]] = []
    implementations: list[str] = []
    for log in logs:
        topics = log.get("topics", [])
        if len(topics) < 2:
            continue
        implementation = to_checksum_address("0x" + str(topics[1])[-40:])
        block_number = int(log["blockNumber"], 16)
        tx_hash = str(log["transactionHash"])
        transaction = rpc("eth_getTransactionByHash", [tx_hash])
        events.append(
            {
                "blockNumber": block_number,
                "logIndex": int(log["logIndex"], 16),
                "implementation": implementation,
                "transactionHashSha256": digest(tx_hash),
                "transactionFromSha256": digest(str(transaction.get("from", "")).lower())
                if isinstance(transaction, dict)
                else None,
                "transactionToSha256": digest(str(transaction.get("to", "")).lower())
                if isinstance(transaction, dict) and transaction.get("to")
                else None,
            }
        )
        if implementation not in implementations:
            implementations.append(implementation)

    live_implementation = storage_address(IMPLEMENTATION_SLOT)
    if live_implementation not in implementations:
        implementations.append(live_implementation)

    records: list[dict[str, Any]] = []
    layouts: list[dict[str, Any]] = []
    for index, implementation in enumerate(implementations):
        status, parsed, raw = sourcify(implementation)
        folder = OUT / f"implementation_{index}_{implementation.lower()}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "sourcify_response.json").write_bytes(raw)
        record: dict[str, Any] = {
            "index": index,
            "address": implementation,
            "code": code_record(implementation),
            "sourcifyStatus": status,
            "sourcifyBodySha256": digest(raw),
            "verified": isinstance(parsed, dict) and status == 200,
        }
        if isinstance(parsed, dict):
            compilation = parsed.get("compilation") if isinstance(parsed.get("compilation"), dict) else {}
            deployment = parsed.get("deployment") if isinstance(parsed.get("deployment"), dict) else {}
            layout = compact_storage(parsed.get("storageLayout"))
            layouts.append(layout)
            (folder / "storage_layout.json").write_text(json.dumps(layout, indent=2), encoding="utf-8")
            record.update(
                {
                    "match": parsed.get("match"),
                    "runtimeMatch": parsed.get("runtimeMatch"),
                    "creationMatch": parsed.get("creationMatch"),
                    "contractName": compilation.get("name"),
                    "fullyQualifiedName": compilation.get("fullyQualifiedName"),
                    "compiler": compilation.get("compiler"),
                    "compilerVersion": compilation.get("compilerVersion"),
                    "deploymentBlock": deployment.get("blockNumber"),
                    "storageEntryCount": len(layout["storage"]),
                    "sourceCount": len(parsed.get("sources", {}) or {}),
                }
            )
            sources = parsed.get("sources", {}) or {}
            for logical_path, source in sources.items():
                if not isinstance(source, dict) or not isinstance(source.get("content"), str):
                    continue
                output_path = folder / "sources" / logical_path
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(source["content"], encoding="utf-8")
        else:
            layouts.append({"storage": [], "types": {}})
        try:
            uuid = eth_call(implementation, PROXIABLE_UUID_SELECTOR)
        except Exception as exc:  # noqa: BLE001
            uuid = f"error:{type(exc).__name__}"
        record["proxiableUUID"] = uuid
        records.append(record)
        time.sleep(0.15)

    comparisons = []
    for index in range(1, len(records)):
        comparison = compare_layout(layouts[index - 1], layouts[index])
        comparison.update(
            {
                "from": records[index - 1]["address"],
                "to": records[index]["address"],
            }
        )
        comparisons.append(comparison)

    owner_raw = eth_call(PROXY, OWNER_SELECTOR)
    paused_raw = eth_call(PROXY, PAUSED_SELECTOR)
    owner = decode_address_word(owner_raw)
    owner_code = code_record(owner) if owner else None
    admin = storage_address(ADMIN_SLOT)
    admin_is_zero = int(admin, 16) == 0

    output = {
        "safety": "Public Ethereum reads and public Sourcify metadata only; no mutation.",
        "proxy": PROXY,
        "startBlock": START_BLOCK,
        "latestBlock": latest,
        "upgradedTopic": UPGRADED_TOPIC,
        "implementationSlot": hex(IMPLEMENTATION_SLOT),
        "adminSlot": hex(ADMIN_SLOT),
        "upgradeEventCount": len(events),
        "upgradeEvents": events,
        "implementationCount": len(records),
        "liveImplementation": live_implementation,
        "implementations": records,
        "layoutComparisons": comparisons,
        "allVerified": all(item["verified"] for item in records),
        "allLayoutTransitionsCompatible": all(item["compatible"] for item in comparisons),
        "proxyOwner": owner,
        "proxyOwnerCode": owner_code,
        "paused": int(paused_raw, 16) != 0,
        "eip1967Admin": admin,
        "eip1967AdminIsZero": admin_is_zero,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "upgradeEventCount": output["upgradeEventCount"],
                "implementationCount": output["implementationCount"],
                "liveImplementation": output["liveImplementation"],
                "allVerified": output["allVerified"],
                "allLayoutTransitionsCompatible": output["allLayoutTransitionsCompatible"],
                "layoutMismatchCounts": [item["mismatchCount"] for item in comparisons],
                "proxyOwner": output["proxyOwner"],
                "proxyOwnerCodeBytes": owner_code["codeBytes"] if owner_code else None,
                "paused": output["paused"],
                "eip1967AdminIsZero": output["eip1967AdminIsZero"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
