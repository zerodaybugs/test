#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any

HORIZEN_RPC = "https://horizen.calderachain.xyz/http"
BASE_RPC = "https://mainnet.base.org"
SAFE = "0x1Afb144aaD0aE02f3Bb04C1eae4AC6020a727A21"
FALLBACK_SLOT = "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5"
GUARD_SLOT = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
SINGLETON_SLOT = "0x" + "00" * 32


def rpc(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json", "user-agent": "Horizen-Safe-attestation/1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        obj = json.loads(response.read())
    if "error" in obj:
        raise RuntimeError(f"{method}: {obj['error']}")
    return obj.get("result")


def address_from_word(word: str) -> str:
    raw = word[2:] if word.startswith("0x") else word
    return "0x" + raw[-40:].lower()


def code(url: str, address: str) -> bytes:
    raw = rpc(url, "eth_getCode", [address, "latest"])
    return bytes.fromhex(raw[2:]) if raw and raw != "0x" else b""


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def calldata(signature_selector: str) -> str:
    return signature_selector


def decode_uint(raw: str) -> int:
    return int(raw, 16) if raw and raw != "0x" else 0


def decode_string(raw: str) -> str:
    data = bytes.fromhex(raw[2:])
    if len(data) < 64:
        return ""
    offset = int.from_bytes(data[:32], "big")
    length = int.from_bytes(data[offset : offset + 32], "big")
    return data[offset + 32 : offset + 32 + length].decode("utf-8", "replace")


def decode_address_array(raw: str, tuple_index: int = 0) -> list[str]:
    data = bytes.fromhex(raw[2:])
    if len(data) < 64:
        return []
    offset = int.from_bytes(data[tuple_index * 32 : tuple_index * 32 + 32], "big")
    length = int.from_bytes(data[offset : offset + 32], "big")
    out = []
    for i in range(length):
        word = data[offset + 32 + i * 32 : offset + 64 + i * 32]
        out.append("0x" + word[-20:].hex())
    return out


def eth_call(to: str, data: str) -> str:
    return rpc(HORIZEN_RPC, "eth_call", [{"to": to, "data": data}, "latest"])


def main() -> int:
    out = Path("private-evidence/safe-control-plane")
    out.mkdir(parents=True, exist_ok=True)

    singleton = address_from_word(rpc(HORIZEN_RPC, "eth_getStorageAt", [SAFE, SINGLETON_SLOT, "latest"]))
    fallback = address_from_word(rpc(HORIZEN_RPC, "eth_getStorageAt", [SAFE, FALLBACK_SLOT, "latest"]))
    guard = address_from_word(rpc(HORIZEN_RPC, "eth_getStorageAt", [SAFE, GUARD_SLOT, "latest"]))

    safe_code = code(HORIZEN_RPC, SAFE)
    singleton_h = code(HORIZEN_RPC, singleton)
    singleton_b = code(BASE_RPC, singleton)
    fallback_h = code(HORIZEN_RPC, fallback) if int(fallback, 16) else b""
    fallback_b = code(BASE_RPC, fallback) if int(fallback, 16) else b""
    guard_h = code(HORIZEN_RPC, guard) if int(guard, 16) else b""
    guard_b = code(BASE_RPC, guard) if int(guard, 16) else b""

    # VERSION(), getThreshold(), getOwners(), getModulesPaginated(sentinel,100)
    version = decode_string(eth_call(SAFE, "0xffa1ad74"))
    threshold = decode_uint(eth_call(SAFE, "0xe75235b8"))
    owners = decode_address_array(eth_call(SAFE, "0xa0e67e2b"))
    modules_data = "0xcc2f8452" + (1).to_bytes(32, "big").hex() + (100).to_bytes(32, "big").hex()
    modules = decode_address_array(eth_call(SAFE, modules_data), 0)

    singleton_canonical = bool(singleton_h) and singleton_h == singleton_b
    fallback_canonical = int(fallback, 16) == 0 or (bool(fallback_h) and fallback_h == fallback_b)
    guard_zero = int(guard, 16) == 0
    passed = all(
        [
            len(safe_code) == 171,
            version == "1.4.1",
            threshold == 4,
            len(owners) == 7,
            len(modules) == 0,
            singleton_canonical,
            fallback_canonical,
            guard_zero,
        ]
    )

    result = {
        "safe": SAFE.lower(),
        "safe_code_bytes": len(safe_code),
        "safe_code_sha256": sha(safe_code),
        "version": version,
        "threshold": threshold,
        "owner_count": len(owners),
        "owners": owners,
        "module_count": len(modules),
        "modules": modules,
        "singleton": singleton,
        "singleton_horizen_code_bytes": len(singleton_h),
        "singleton_horizen_sha256": sha(singleton_h) if singleton_h else None,
        "singleton_base_code_bytes": len(singleton_b),
        "singleton_base_sha256": sha(singleton_b) if singleton_b else None,
        "singleton_canonical_base_match": singleton_canonical,
        "fallback_handler": fallback,
        "fallback_horizen_code_bytes": len(fallback_h),
        "fallback_horizen_sha256": sha(fallback_h) if fallback_h else None,
        "fallback_base_code_bytes": len(fallback_b),
        "fallback_base_sha256": sha(fallback_b) if fallback_b else None,
        "fallback_canonical_base_match": fallback_canonical,
        "guard": guard,
        "guard_horizen_code_bytes": len(guard_h),
        "guard_horizen_sha256": sha(guard_h) if guard_h else None,
        "guard_base_code_bytes": len(guard_b),
        "guard_base_sha256": sha(guard_b) if guard_b else None,
        "guard_is_zero": guard_zero,
        "pass": passed,
        "security_verdict": "KILL_CANONICAL_SAFE" if passed else "HOLD_SAFE_EXTENSION_OR_RUNTIME_DELTA",
        "public_network_writes": 0,
    }
    (out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / "singleton-horizen.hex").write_text("0x" + singleton_h.hex() + "\n")
    (out / "singleton-base.hex").write_text("0x" + singleton_b.hex() + "\n")
    (out / "fallback-horizen.hex").write_text("0x" + fallback_h.hex() + "\n")
    (out / "fallback-base.hex").write_text("0x" + fallback_b.hex() + "\n")
    (out / "guard-horizen.hex").write_text("0x" + guard_h.hex() + "\n")
    (out / "guard-base.hex").write_text("0x" + guard_b.hex() + "\n")

    sanitized = Path("sanitized-safe")
    sanitized.mkdir(exist_ok=True)
    public = {
        "safe_version": version,
        "threshold": threshold,
        "owner_count": len(owners),
        "module_count": len(modules),
        "singleton_canonical_base_match": singleton_canonical,
        "fallback_handler_present": int(fallback, 16) != 0,
        "fallback_canonical_base_match": fallback_canonical,
        "guard_present": not guard_zero,
        "pass": passed,
        "security_verdict": result["security_verdict"],
        "public_network_writes": 0,
    }
    (sanitized / "RESULT.json").write_text(json.dumps(public, indent=2) + "\n")
    lines = [
        "# Horizen Safe control-plane attestation",
        "",
        f"- Verdict: **{result['security_verdict']}**",
        f"- Safe version: `{version}`",
        f"- Threshold / owners: `{threshold}/{len(owners)}`",
        f"- Enabled modules: `{len(modules)}`",
        f"- Singleton canonical Base match: **{singleton_canonical}**",
        f"- Fallback handler present: **{int(fallback, 16) != 0}**",
        f"- Fallback canonical Base match: **{fallback_canonical}**",
        f"- Guard present: **{not guard_zero}**",
        "- Public-network writes: **0**",
    ]
    (sanitized / "RESULT.md").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
