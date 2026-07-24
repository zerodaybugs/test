#!/usr/bin/env python3
"""Read-only control-plane audit for the Safe holding Synthetix OWNER/MANAGER roles.

Only public Ethereum JSON-RPC and Safe Transaction Service GET requests are
used. No transaction, proposal, signature, or state-changing request is made.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import traceback
import urllib.request
from typing import Any, Callable

from eth_utils import keccak, to_checksum_address

OUT = pathlib.Path("safe_control_plane")
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "collector_started.json").write_text(json.dumps({"started": True}, indent=2), encoding="utf-8")

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
ZERO = "0x0000000000000000000000000000000000000000"


def http_json(url: str, payload: dict[str, Any] | None = None, timeout: int = 60) -> Any:
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": UA, "Accept": "application/json", "Content-Type": "application/json"},
        method="GET" if payload is None else "POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError(f"response exceeds {MAX_BODY} bytes")
        return json.loads(body)


def rpc(method: str, params: list[Any]) -> Any:
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            data = http_json(url, payload, timeout=45)
            if "error" in data:
                errors.append(f"{url}: {data['error']}")
                continue
            return data["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def attempt(name: str, fn: Callable[[], Any], errors: dict[str, str]) -> Any:
    try:
        value = fn()
        (OUT / f"stage_{name}.json").write_text(json.dumps({"ok": True}, indent=2), encoding="utf-8")
        return value
    except Exception as exc:  # noqa: BLE001
        errors[name] = f"{type(exc).__name__}: {exc}"
        (OUT / f"stage_{name}.json").write_text(
            json.dumps({"ok": False, "error": errors[name]}, indent=2), encoding="utf-8"
        )
        return None


def selector(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


def word(value: int | str) -> str:
    if isinstance(value, int):
        return hex(value)[2:].rjust(64, "0")
    return value.lower().removeprefix("0x").rjust(64, "0")


def call(data: str) -> str:
    return rpc("eth_call", [{"to": SAFE, "data": data}, "latest"])


def decode_address_word(raw: str) -> str:
    body = raw.removeprefix("0x")
    if len(body) < 40:
        raise ValueError("ABI word too short for address")
    return to_checksum_address("0x" + body[-40:])


def decode_uint(raw: str) -> int:
    return int(raw, 16)


def decode_dynamic_address_array(raw: str) -> list[str]:
    body = raw.removeprefix("0x")
    if len(body) < 128:
        return []
    offset = int(body[:64], 16) * 2
    if offset + 64 > len(body):
        return []
    length = int(body[offset : offset + 64], 16)
    cursor = offset + 64
    out: list[str] = []
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
    offset = int(body[:64], 16) * 2
    next_module = decode_address_word(body[64:128])
    if offset + 64 > len(body):
        return [], next_module
    length = int(body[offset : offset + 64], 16)
    cursor = offset + 64
    modules: list[str] = []
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
    return bytes.fromhex(body[start : start + length * 2]).decode("utf-8", errors="replace")


def storage_address(slot: str) -> str:
    return decode_address_word(rpc("eth_getStorageAt", [SAFE, slot, "latest"]))


def code_info(address: str) -> dict[str, Any]:
    address = to_checksum_address(address)
    code = rpc("eth_getCode", [address, "latest"])
    body = code.removeprefix("0x")
    return {
        "address": address,
        "codeBytes": len(body) // 2,
        "codeSha256": hashlib.sha256(bytes.fromhex(body)).hexdigest() if body else None,
        "codePrefix": "0x" + body[:240],
    }


def main() -> None:
    errors: dict[str, str] = {}
    result: dict[str, Any] = {
        "safety": "Public GET and Ethereum read-only RPC calls only; no proposal, signature or transaction was created.",
        "safe": SAFE,
        "depositProxyControlled": DEPOSIT_PROXY,
        "errors": errors,
    }

    result["latestBlock"] = attempt("latest_block", lambda: int(rpc("eth_blockNumber", []), 16), errors)
    api_info = attempt("safe_api_info", lambda: http_json(f"{SAFE_API}/safes/{SAFE}/"), errors)
    creation = attempt("safe_api_creation", lambda: http_json(f"{SAFE_API}/safes/{SAFE}/creation/"), errors)
    module_txs = attempt(
        "safe_api_module_transactions",
        lambda: http_json(f"{SAFE_API}/safes/{SAFE}/module-transactions/?limit=100"),
        errors,
    )
    result["safeApi"] = api_info
    result["creation"] = creation
    result["moduleTransactions"] = module_txs

    owners = attempt("owners", lambda: decode_dynamic_address_array(call(selector("getOwners()"))), errors)
    threshold = attempt("threshold", lambda: decode_uint(call(selector("getThreshold()"))), errors)
    nonce = attempt("nonce", lambda: decode_uint(call(selector("nonce()"))), errors)
    version = attempt("version", lambda: decode_string(call(selector("VERSION()"))), errors)

    def modules_call() -> dict[str, Any]:
        raw = call(selector("getModulesPaginated(address,uint256)") + word(SENTINEL) + word(100))
        modules, next_module = decode_modules_page(raw)
        return {"modules": modules, "next": next_module}

    modules_page = attempt("modules", modules_call, errors)

    singleton = attempt("singleton", lambda: storage_address("0x" + "00" * 32), errors)
    fallback_slot = "0x" + keccak(text="fallback_manager.handler.address").hex()
    guard_slot = "0x" + keccak(text="guard_manager.guard.address").hex()
    module_guard_slot = "0x" + keccak(text="module_manager.module_guard.address").hex()
    fallback_handler = attempt("fallback_handler", lambda: storage_address(fallback_slot), errors)
    guard = attempt("guard", lambda: storage_address(guard_slot), errors)
    module_guard = attempt("module_guard", lambda: storage_address(module_guard_slot), errors)

    result["onchain"] = {
        "version": version,
        "singleton": singleton,
        "owners": owners,
        "threshold": threshold,
        "nonce": nonce,
        "modules": modules_page,
        "fallbackHandler": fallback_handler,
        "guard": guard,
        "moduleGuard": module_guard,
        "storageSlots": {
            "fallbackHandler": fallback_slot,
            "guard": guard_slot,
            "moduleGuard": module_guard_slot,
        },
    }

    related: set[str] = {SAFE}
    for value in (singleton, fallback_handler, guard, module_guard):
        if isinstance(value, str) and value != ZERO:
            related.add(value)
    for value in owners or []:
        related.add(value)
    if isinstance(modules_page, dict):
        for value in modules_page.get("modules", []) or []:
            related.add(value)
    if isinstance(api_info, dict):
        for value in api_info.get("owners", []) or []:
            related.add(to_checksum_address(value))
        for key in ("masterCopy", "fallbackHandler", "guard"):
            value = api_info.get(key)
            if value:
                related.add(to_checksum_address(value))
        for value in api_info.get("modules", []) or []:
            related.add(to_checksum_address(value))

    inventory: list[dict[str, Any]] = []
    for address in sorted(related, key=str.lower):
        info = attempt("code_" + address.lower().removeprefix("0x"), lambda a=address: code_info(a), errors)
        if info:
            inventory.append(info)
    result["relatedCode"] = inventory

    (OUT / "safe_control_plane.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    summary = {
        "version": version,
        "owners": owners,
        "threshold": threshold,
        "modules": modules_page,
        "fallbackHandler": fallback_handler,
        "guard": guard,
        "moduleGuard": module_guard,
        "apiInfo": api_info,
        "moduleTransactionCount": len(module_txs.get("results", [])) if isinstance(module_txs, dict) else None,
        "relatedCode": inventory,
        "errors": errors,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:  # noqa: BLE001
        failure = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
        }
        (OUT / "collector_failure.json").write_text(json.dumps(failure, indent=2), encoding="utf-8")
        print(failure["traceback"])
        raise
