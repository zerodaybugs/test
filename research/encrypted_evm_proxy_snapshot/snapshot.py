#!/usr/bin/env python3
"""Read-only EVM deployment health snapshot. No transaction is signed or broadcast."""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from Crypto.Hash import keccak

COMMON = "0xACeA761c27A909d4D3895128EBe6370FDE2dF481"
TARGETS = [
    {"name": "Arbitrum One", "explorer": "arbiscan.io", "address": COMMON, "fallback": ["https://arb1.arbitrum.io/rpc"]},
    {"name": "Base", "explorer": "basescan.org", "address": COMMON, "fallback": ["https://mainnet.base.org", "https://base-mainnet.public.blastapi.io"]},
    {"name": "Berachain", "explorer": "berascan.com", "address": COMMON, "fallback": ["https://rpc.berachain.com"]},
    {"name": "BNB Smart Chain", "explorer": "bscscan.com", "address": COMMON, "fallback": ["https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com"]},
    {"name": "Cronos", "explorer": "explorer.cronos.org", "address": COMMON, "fallback": ["https://evm.cronos.org"]},
    {"name": "Ethereal", "explorer": "explorer.ethereal.trade", "address": COMMON, "fallback": []},
    {"name": "Fluent", "explorer": "fluentscan.xyz", "address": COMMON, "fallback": []},
    {"name": "Injective", "explorer": "blockscout.injective.network", "address": COMMON, "fallback": ["https://sentry.evm-rpc.injective.network"]},
    {"name": "MegaETH", "explorer": "megaexplorer.xyz", "address": COMMON, "fallback": []},
    {"name": "Mezo", "explorer": "explorer.mezo.org", "address": "0x00Aa49132AF596DE135C840E85E4bF6871dB4Eb8", "fallback": []},
    {"name": "Monad", "explorer": "monadvision.com", "address": COMMON, "fallback": []},
    {"name": "Polygon", "explorer": "polygonscan.com", "address": COMMON, "fallback": ["https://polygon-rpc.com", "https://polygon-bor-rpc.publicnode.com"]},
    {"name": "Robinhood Chain", "explorer": "robinhoodchain.blockscout.com", "address": COMMON, "fallback": []},
    {"name": "Soneium", "explorer": "soneium.blockscout.com", "address": COMMON, "fallback": ["https://rpc.soneium.org"]},
    {"name": "Sonic", "explorer": "sonicscan.org", "address": COMMON, "fallback": ["https://rpc.soniclabs.com"]},
    {"name": "Tempo", "explorer": "explore.tempo.xyz", "address": COMMON, "fallback": []},
]

CHAINLIST_URL = "https://chainid.network/chains.json"
OUT = Path(os.environ.get("PRIVATE_OUT", "private_out"))
RANDOM_CALLER = "0x00000000000000000000000000000000A11CE001"
RANDOM_ADDRESS = "0x00000000000000000000000000000000B0B00001"
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


def selector(signature: str) -> str:
    h = keccak.new(digest_bits=256)
    h.update(signature.encode())
    return "0x" + h.hexdigest()[:8]


def word_address(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64, "0")


def word_uint(value: int) -> str:
    return hex(value)[2:].rjust(64, "0")


def abi_initialize(address: str) -> str:
    return selector("initialize(address)") + word_address(address)


def abi_update_signer(address: str, expires: int) -> str:
    return selector("updateTrustedSigner(address,uint256)") + word_address(address) + word_uint(expires)


def abi_upgrade(address: str) -> str:
    # upgradeToAndCall(address,bytes): address, dynamic offset=64, empty bytes length=0
    return (
        selector("upgradeToAndCall(address,bytes)")
        + word_address(address)
        + word_uint(64)
        + word_uint(0)
    )


def load_chainlist() -> list[dict[str, Any]]:
    req = urllib.request.Request(
        CHAINLIST_URL,
        headers={"accept": "application/json", "user-agent": "read-only-evm-deployment-snapshot/1.0"},
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.loads(response.read())


def chain_for_target(chains: list[dict[str, Any]], target: dict[str, Any]) -> dict[str, Any] | None:
    match = target["explorer"].lower()
    candidates = []
    for chain in chains:
        explorers = chain.get("explorers") or []
        urls = [str(item.get("url", "")).lower() for item in explorers if isinstance(item, dict)]
        if any(match in url for url in urls):
            candidates.append(chain)
    # Prefer a mainnet-looking entry, then the lowest chain id for deterministic output.
    candidates.sort(
        key=lambda c: (
            any(x in str(c.get("name", "")).lower() for x in ("test", "sepolia", "devnet")),
            int(c.get("chainId", 2**63 - 1)),
        )
    )
    return candidates[0] if candidates else None


def usable_rpc(url: str) -> bool:
    text = url.strip()
    return (
        text.startswith("https://")
        and "${" not in text
        and "<" not in text
        and "}" not in text
        and "API_KEY" not in text.upper()
        and "INFURA" not in text.upper()
    )


def rpc_request(url: str, method: str, params: list[Any], request_id: int) -> dict[str, Any]:
    payload = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
    errors = []
    for attempt in range(4):
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "read-only-evm-deployment-snapshot/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read()
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                raise ValueError(f"non-object JSON-RPC response: {type(obj).__name__}")
            return obj
        except urllib.error.HTTPError as exc:
            body = exc.read()[:2000].decode("utf-8", "replace")
            errors.append({"attempt": attempt + 1, "http": exc.code, "body": body})
        except Exception as exc:
            errors.append({"attempt": attempt + 1, "error": repr(exc)})
        if attempt < 3:
            time.sleep(1.0 + attempt)
    return {"transport_errors": errors}


def result_or_error(obj: dict[str, Any]) -> dict[str, Any]:
    if "result" in obj:
        return {"status": "RESULT", "result": obj.get("result")}
    if "error" in obj:
        return {"status": "ERROR", "error": obj.get("error")}
    return {"status": "TRANSPORT_ERROR", "details": obj}


def decode_address(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    raw = value[2:]
    if len(raw) < 40:
        return None
    return "0x" + raw[-40:]


def decode_uint(value: Any) -> int | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def decode_string(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        raw = bytes.fromhex(value[2:])
        if len(raw) < 64:
            return None
        offset = int.from_bytes(raw[:32], "big")
        if offset + 32 > len(raw):
            return None
        length = int.from_bytes(raw[offset : offset + 32], "big")
        body = raw[offset + 32 : offset + 32 + length]
        return body.decode("utf-8", "replace")
    except Exception:
        return None


def call(url: str, to: str, data: str, request_id: int, *, from_address: str | None = None) -> dict[str, Any]:
    tx: dict[str, Any] = {"to": to, "data": data}
    if from_address:
        tx["from"] = from_address
    return result_or_error(rpc_request(url, "eth_call", [tx, "latest"], request_id))


def scan_target(chains: list[dict[str, Any]], target: dict[str, Any], id_base: int) -> dict[str, Any]:
    chain = chain_for_target(chains, target)
    rpcs: list[str] = []
    for url in target.get("fallback", []):
        if usable_rpc(url) and url not in rpcs:
            rpcs.append(url)
    if chain:
        for url in chain.get("rpc") or []:
            if usable_rpc(str(url)) and str(url) not in rpcs:
                rpcs.append(str(url))
    rpcs = rpcs[:10]

    attempts = []
    chosen = None
    request_id = id_base
    for url in rpcs:
        chain_id_obj = rpc_request(url, "eth_chainId", [], request_id)
        request_id += 1
        code_obj = rpc_request(url, "eth_getCode", [target["address"], "latest"], request_id)
        request_id += 1
        chain_id = result_or_error(chain_id_obj)
        code = result_or_error(code_obj)
        item = {"rpc": url, "chain_id": chain_id, "code_probe": code}
        attempts.append(item)
        code_value = code.get("result")
        if chain_id.get("status") == "RESULT" and isinstance(code_value, str) and code_value not in ("0x", "0x0", ""):
            chosen = url
            break

    result: dict[str, Any] = {
        "target": target,
        "chainlist_entry": chain,
        "rpc_attempts": attempts,
        "chosen_rpc": chosen,
    }
    if not chosen:
        result["status"] = "NO_WORKING_DEPLOYMENT_RPC"
        return result

    address = target["address"]
    block = result_or_error(rpc_request(chosen, "eth_getBlockByNumber", ["latest", False], request_id))
    request_id += 1
    code = result_or_error(rpc_request(chosen, "eth_getCode", [address, "latest"], request_id))
    request_id += 1
    impl_slot = result_or_error(rpc_request(chosen, "eth_getStorageAt", [address, IMPLEMENTATION_SLOT, "latest"], request_id))
    request_id += 1
    admin_slot = result_or_error(rpc_request(chosen, "eth_getStorageAt", [address, ADMIN_SLOT, "latest"], request_id))
    request_id += 1
    owner_call = call(chosen, address, selector("owner()"), request_id)
    request_id += 1
    version_call = call(chosen, address, selector("version()"), request_id)
    request_id += 1
    fee_call = call(chosen, address, selector("verification_fee()"), request_id)
    request_id += 1
    signers_call = call(chosen, address, selector("getTrustedSigners()"), request_id)
    request_id += 1
    initialize_call = call(chosen, address, abi_initialize(RANDOM_ADDRESS), request_id, from_address=RANDOM_CALLER)
    request_id += 1
    update_call = call(
        chosen,
        address,
        abi_update_signer(RANDOM_ADDRESS, 2**256 - 1),
        request_id,
        from_address=RANDOM_CALLER,
    )
    request_id += 1
    upgrade_call = call(chosen, address, abi_upgrade(RANDOM_ADDRESS), request_id, from_address=RANDOM_CALLER)
    request_id += 1

    code_value = code.get("result") if code.get("status") == "RESULT" else None
    impl_address = decode_address(impl_slot.get("result")) if impl_slot.get("status") == "RESULT" else None
    impl_code = None
    if impl_address and impl_address.lower() != "0x" + "00" * 20:
        impl_code = result_or_error(rpc_request(chosen, "eth_getCode", [impl_address, "latest"], request_id))
        request_id += 1

    owner = decode_address(owner_call.get("result")) if owner_call.get("status") == "RESULT" else None
    version = decode_string(version_call.get("result")) if version_call.get("status") == "RESULT" else None
    fee = decode_uint(fee_call.get("result")) if fee_call.get("status") == "RESULT" else None
    block_obj = block.get("result") if block.get("status") == "RESULT" and isinstance(block.get("result"), dict) else {}
    chain_id_hex = attempts[-1]["chain_id"].get("result") if attempts else None
    expected_chain_id = int(chain.get("chainId")) if chain and chain.get("chainId") is not None else None
    observed_chain_id = int(chain_id_hex, 16) if isinstance(chain_id_hex, str) else None

    checks = {
        "code_present": isinstance(code_value, str) and code_value not in ("0x", "0x0", ""),
        "chain_id_matches_chainlist": expected_chain_id is None or observed_chain_id == expected_chain_id,
        "implementation_slot_nonzero": bool(impl_address and impl_address.lower() != "0x" + "00" * 20),
        "implementation_code_present": bool(
            impl_code and impl_code.get("status") == "RESULT" and impl_code.get("result") not in ("0x", "0x0", "")
        ),
        "owner_nonzero": bool(owner and owner.lower() != "0x" + "00" * 20),
        "initialize_reverted": initialize_call.get("status") == "ERROR",
        "unauthorized_update_reverted": update_call.get("status") == "ERROR",
        "unauthorized_upgrade_reverted": upgrade_call.get("status") == "ERROR",
    }

    result.update(
        {
            "status": "SCANNED",
            "observed_chain_id": observed_chain_id,
            "latest_block": {
                "number": int(block_obj.get("number", "0x0"), 16) if isinstance(block_obj.get("number"), str) else None,
                "hash": block_obj.get("hash"),
                "timestamp": int(block_obj.get("timestamp", "0x0"), 16) if isinstance(block_obj.get("timestamp"), str) else None,
            },
            "code": {
                "length_bytes": (len(code_value) - 2) // 2 if isinstance(code_value, str) and code_value.startswith("0x") else None,
                "sha256": hashlib.sha256(bytes.fromhex(code_value[2:])).hexdigest() if isinstance(code_value, str) and code_value.startswith("0x") else None,
            },
            "implementation_slot": impl_slot,
            "implementation_address": impl_address,
            "implementation_code": impl_code,
            "admin_slot": admin_slot,
            "owner_call": owner_call,
            "owner": owner,
            "version_call": version_call,
            "version": version,
            "verification_fee_call": fee_call,
            "verification_fee": fee,
            "trusted_signers_call": signers_call,
            "initialize_simulation": initialize_call,
            "unauthorized_update_simulation": update_call,
            "unauthorized_upgrade_simulation": upgrade_call,
            "checks": checks,
        }
    )
    return result


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    chains = load_chainlist()
    (OUT / "CHAINLIST_SOURCE.json").write_text(json.dumps(chains, separators=(",", ":")) + "\n")
    results = []
    for index, target in enumerate(TARGETS):
        result = scan_target(chains, target, 1000 + index * 100)
        results.append(result)
        print(
            json.dumps(
                {
                    "name": target["name"],
                    "status": result.get("status"),
                    "rpc_found": bool(result.get("chosen_rpc")),
                    "scanned": result.get("status") == "SCANNED",
                },
                sort_keys=True,
            )
        )

    scanned = [item for item in results if item.get("status") == "SCANNED"]
    init_success = [item["target"]["name"] for item in scanned if item["initialize_simulation"].get("status") == "RESULT"]
    unauthorized_update_success = [
        item["target"]["name"] for item in scanned if item["unauthorized_update_simulation"].get("status") == "RESULT"
    ]
    unauthorized_upgrade_success = [
        item["target"]["name"] for item in scanned if item["unauthorized_upgrade_simulation"].get("status") == "RESULT"
    ]
    zero_owner = [item["target"]["name"] for item in scanned if not item["checks"].get("owner_nonzero")]
    summary = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "mode": "PUBLIC_CHAIN_READ_ONLY_ETH_CALL",
        "no_transaction_signed_or_broadcast": True,
        "target_count": len(TARGETS),
        "scanned_count": len(scanned),
        "uninitialized_simulation_success": init_success,
        "unauthorized_update_simulation_success": unauthorized_update_success,
        "unauthorized_upgrade_simulation_success": unauthorized_upgrade_success,
        "zero_or_unreadable_owner": zero_owner,
        "results": results,
    }
    (OUT / "RESULTS.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    markers = [
        "PUBLIC_CHAIN_MODE=READ_ONLY_ETH_CALL",
        "SIGNED_OR_BROADCAST_TRANSACTIONS=0",
        f"TARGET_COUNT={len(TARGETS)}",
        f"SCANNED_COUNT={len(scanned)}",
        f"INITIALIZE_SIMULATION_SUCCESS_COUNT={len(init_success)}",
        f"UNAUTHORIZED_UPDATE_SUCCESS_COUNT={len(unauthorized_update_success)}",
        f"UNAUTHORIZED_UPGRADE_SUCCESS_COUNT={len(unauthorized_upgrade_success)}",
        f"ZERO_OR_UNREADABLE_OWNER_COUNT={len(zero_owner)}",
    ]
    (OUT / "SUMMARY_MARKERS.txt").write_text("\n".join(markers) + "\n")


if __name__ == "__main__":
    main()
