#!/usr/bin/env python3
"""Read-only control-plane audit for the Safe holding Synthetix OWNER/MANAGER roles.

The collector uses only public Ethereum JSON-RPC and Safe Transaction Service GET
requests. It does not create, sign, propose, or execute transactions.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from eth_utils import keccak, to_checksum_address

OUT = pathlib.Path("safe_control_plane")
OUT.mkdir(parents=True, exist_ok=True)

SAFE = to_checksum_address("0xeb3107117fead7de89cd14d463d340a2e6917769")
DEPOSIT_PROXY = to_checksum_address("0xd62595c3c23b690baee0935e107a209cb1dbd37b")
SAFE_API = "https://api.safe.global/tx-service/eth/api/v1"
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 20 * 1024 * 1024
SENTINEL = "0x0000000000000000000000000000000000000001"


def http_json(url: str, payload: dict[str, Any] | None = None, timeout: int = 60) -> Any:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": UA, "Accept": "application/json", "Content-Type": "application/json"},
        method="GET" if payload is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError(f"response exceeds {MAX_BODY} bytes")
        return json.loads(body)


def rpc(method: str, params: list[Any]) -> Any:
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            result = http_json(url, payload, timeout=45)
            if "error" in result:
                errors.append(f"{url}: {result['error']}")
                continue
            return result["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def selector(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


def word(value: int | str) -> str:
    if isinstance(value, int):
        return hex(value)[2:].rjust(64, "0")
    raw = value.lower().removeprefix("0x")
    return raw.rjust(64, "0")


def call(data: str) -> str:
    return rpc("eth_call", [{"to": SAFE, "data": data}, "latest"])


def decode_uint(raw: str) -> int:
    return int(raw, 16)


def decode_address_word(raw: str) -> str:
    return to_checksum_address("0x" + raw[-40:])


def decode_dynamic_address_array(raw: str) -> list[str]:
    body = raw.removeprefix("0x")
    if len(body) < 128:
        return []
    offset = int(body[:64], 16) * 2
    if offset + 64 > len(body):
        return []
    length = int(body[offset : offset + 64], 16)
    out: list[str] = []
    cursor = offset + 64
    for _ in range(length):
        if cursor + 64 > len(body):
            break
        out.append(decode_address_word(body[cursor : cursor + 64]))
        cursor += 64
    return out


def decode_modules_page(raw: str) -> tuple[list[str], str | None]:
    body = raw.removeprefix("0x")
    if len(body) < 128:
        return [], None
    array_offset = int(body[:64], 16) * 2
    next_module = decode_address_word(body[64:128])
    if array_offset + 64 > len(body):
        return [], next_module
    length = int(body[array_offset : array_offset + 64], 16)
    modules: list[str] = []
    cursor = array_offset + 64
    for _ in range(length):
        if cursor + 64 > len(body):
            break
        modules.append(decode_address_word(body[cursor : cursor + 64]))
        cursor += 64
    return modules, next_module


def decode_string(raw: str) -> str | None:
    body = raw.removeprefix("0x")
    if len(body) < 128:
        return None
    offset = int(body[:64], 16) * 2
    if offset + 64 > len(body):
        return None
    length = int(body[offset : offset + 64], 16)
    start = offset + 64
    end = start + length * 2
    try:
        return bytes.fromhex(body[start:end]).decode("utf-8", errors="replace")
    except Exception:
        return None


def storage_address(slot_hex: str) -> str:
    raw = rpc("eth_getStorageAt", [SAFE, slot_hex, "latest"])
    return decode_address_word(raw)


def code_info(address: str) -> dict[str, Any]:
    code = rpc("eth_getCode", [address, "latest"])
    body = code.removeprefix("0x")
    return {
        "address": to_checksum_address(address),
        "codeBytes": len(body) // 2,
        "codeSha256": hashlib.sha256(bytes.fromhex(body)).hexdigest() if body else None,
        "codePrefix": "0x" + body[:160],
    }


def get_logs_split(start: int, end: int, topics: list[Any]) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [{"address": SAFE, "fromBlock": hex(start), "toBlock": hex(end), "topics": topics}],
        )
    except Exception:
        if start >= end:
            raise
        midpoint = (start + end) // 2
        return get_logs_split(start, midpoint, topics) + get_logs_split(midpoint + 1, end, topics)


def event_topic(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


def decode_config_event(log: dict[str, Any], topic_to_name: dict[str, str]) -> dict[str, Any]:
    topics = log.get("topics", [])
    name = topic_to_name.get(str(topics[0]).lower(), "unknown") if topics else "unknown"
    record: dict[str, Any] = {
        "event": name,
        "blockNumber": int(log["blockNumber"], 16),
        "transactionHash": log["transactionHash"],
        "logIndex": int(log["logIndex"], 16),
    }
    if len(topics) > 1:
        record["indexedAddress"] = decode_address_word(topics[1])
    data = str(log.get("data", "0x"))
    if data not in ("0x", ""):
        record["dataUint"] = int(data, 16)
        if len(data.removeprefix("0x")) >= 64:
            try:
                record["dataAddress"] = decode_address_word(data)
            except Exception:
                pass
    return record


def safe_api_get(path: str) -> Any:
    return http_json(SAFE_API + path)


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    api_info = safe_api_get(f"/safes/{SAFE}/")
    creation = safe_api_get(f"/safes/{SAFE}/creation/")
    module_transactions = safe_api_get(f"/safes/{SAFE}/module-transactions/?limit=100")

    creation_block = int(creation.get("blockNumber") or 0)
    if creation_block <= 0:
        tx_hash = creation.get("transactionHash")
        if tx_hash:
            receipt = rpc("eth_getTransactionReceipt", [tx_hash])
            creation_block = int(receipt["blockNumber"], 16)
    if creation_block <= 0:
        creation_block = 0

    owners_raw = call(selector("getOwners()"))
    owners_onchain = decode_dynamic_address_array(owners_raw)
    threshold = decode_uint(call(selector("getThreshold()")))
    nonce = decode_uint(call(selector("nonce()")))
    version = decode_string(call(selector("VERSION()")))
    modules_raw = call(selector("getModulesPaginated(address,uint256)") + word(SENTINEL) + word(100))
    modules_onchain, modules_next = decode_modules_page(modules_raw)

    singleton = storage_address("0x" + "00" * 32)
    fallback_slot = "0x" + keccak(text="fallback_manager.handler.address").hex()
    guard_slot = "0x" + keccak(text="guard_manager.guard.address").hex()
    module_guard_slot = "0x" + keccak(text="module_manager.module_guard.address").hex()
    fallback_handler = storage_address(fallback_slot)
    guard = storage_address(guard_slot)
    module_guard = storage_address(module_guard_slot)

    event_signatures = (
        "AddedOwner(address)",
        "RemovedOwner(address)",
        "ChangedThreshold(uint256)",
        "EnabledModule(address)",
        "DisabledModule(address)",
        "ChangedGuard(address)",
        "ChangedModuleGuard(address)",
        "ChangedFallbackHandler(address)",
        "ChangedMasterCopy(address)",
        "ExecutionFromModuleSuccess(address)",
        "ExecutionFromModuleFailure(address)",
    )
    topic_to_name = {event_topic(sig).lower(): sig.split("(", 1)[0] for sig in event_signatures}
    logs = get_logs_split(creation_block, latest, [list(topic_to_name.keys())]) if creation_block else []
    config_events = sorted(
        (decode_config_event(log, topic_to_name) for log in logs),
        key=lambda item: (item["blockNumber"], item["logIndex"]),
    )

    related: set[str] = {SAFE, singleton, fallback_handler, guard, module_guard, *owners_onchain, *modules_onchain}
    related.discard("0x0000000000000000000000000000000000000000")
    for value in api_info.get("owners", []) or []:
        related.add(to_checksum_address(value))
    for key in ("masterCopy", "fallbackHandler", "guard"):
        value = api_info.get(key)
        if value:
            related.add(to_checksum_address(value))
    for value in api_info.get("modules", []) or []:
        related.add(to_checksum_address(value))

    code_inventory = [code_info(address) for address in sorted(related, key=str.lower)]

    result = {
        "safety": "Public GET and Ethereum read-only RPC calls only; no proposal, signature or transaction was created.",
        "latestBlock": latest,
        "safe": SAFE,
        "depositProxyControlled": DEPOSIT_PROXY,
        "safeApi": api_info,
        "creation": creation,
        "onchain": {
            "version": version,
            "singleton": singleton,
            "owners": owners_onchain,
            "threshold": threshold,
            "nonce": nonce,
            "modules": modules_onchain,
            "modulesNext": modules_next,
            "fallbackHandler": fallback_handler,
            "guard": guard,
            "moduleGuard": module_guard,
            "storageSlots": {
                "fallbackHandler": fallback_slot,
                "guard": guard_slot,
                "moduleGuard": module_guard_slot,
            },
        },
        "configurationEvents": config_events,
        "moduleTransactions": module_transactions,
        "relatedCode": code_inventory,
    }
    (OUT / "safe_control_plane.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    summary = {
        "version": version,
        "owners": owners_onchain,
        "threshold": threshold,
        "modules": modules_onchain,
        "fallbackHandler": fallback_handler,
        "guard": guard,
        "moduleGuard": module_guard,
        "configurationEventCount": len(config_events),
        "moduleTransactionCount": len(module_transactions.get("results", [])) if isinstance(module_transactions, dict) else None,
        "relatedCode": code_inventory,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
