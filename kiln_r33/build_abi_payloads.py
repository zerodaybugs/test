#!/usr/bin/env python3
"""Build deterministic admin/control payloads from Forge ABI JSON files."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from web3 import Web3

CONTROL_NAME = re.compile(
    r"^(initialize|reinitialize|upgrade|grant|revoke|renounce|transferOwnership|acceptOwnership|"
    r"set|update|add|remove|pause|unpause|freeze|unfreeze|change|configure|register|unregister|"
    r"collect|sweep|rescue|recover|create|deploy)",
    re.IGNORECASE,
)


def canonical(item: dict[str, Any]) -> str:
    type_name = str(item["type"])
    if type_name.startswith("tuple"):
        suffix = type_name[len("tuple"):]
        return "(" + ",".join(canonical(part) for part in item.get("components", [])) + ")" + suffix
    return type_name


def fill(item: dict[str, Any], attacker: str) -> Any:
    type_name = str(item["type"])
    # Arrays, including tuple arrays.
    array_match = re.match(r"^(.*)\[(.*?)\]$", type_name)
    if array_match:
        base, length_text = array_match.groups()
        if length_text == "":
            return []
        length = int(length_text)
        child = dict(item)
        child["type"] = base
        return [fill(child, attacker) for _ in range(length)]
    if type_name == "tuple":
        return tuple(fill(part, attacker) for part in item.get("components", []))
    if type_name == "address":
        return attacker
    if type_name == "bool":
        return True
    if type_name == "string":
        return ""
    if type_name == "bytes":
        return b""
    if type_name.startswith("bytes"):
        size = int(type_name[5:])
        if size == 32:
            return bytes(Web3.keccak(text="R33_ABI_CONTROL_TEST"))
        return b"\x00" * size
    if type_name.startswith("uint") or type_name.startswith("int"):
        return 1
    if type_name == "function":
        return b"\x00" * 24
    raise ValueError(f"unsupported ABI type: {type_name}")


def load_abi(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text())
    if isinstance(payload, dict):
        payload = payload.get("abi", payload.get("result", []))
    if isinstance(payload, str):
        payload = json.loads(payload)
    if not isinstance(payload, list):
        raise ValueError(f"ABI is not a list: {path}")
    return [item for item in payload if isinstance(item, dict)]


def main() -> int:
    abi_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "r33_abis")
    output = Path(sys.argv[2] if len(sys.argv) > 2 else "r33_payload_corpus.json")
    attacker = Web3.to_checksum_address(sys.argv[3] if len(sys.argv) > 3 else "0x1000000000000000000000000000000000000001")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    errors: list[dict[str, str]] = []
    w3 = Web3()

    for path in sorted(abi_dir.glob("*.json")):
        contract = path.stem
        try:
            abi = load_abi(path)
        except Exception as exc:
            errors.append({"contract":contract, "error":f"load: {type(exc).__name__}: {exc}"})
            continue
        for item in abi:
            if item.get("type") != "function":
                continue
            if item.get("stateMutability") in {"view", "pure"}:
                continue
            name = str(item.get("name", ""))
            if not CONTROL_NAME.match(name):
                continue
            inputs = item.get("inputs", [])
            try:
                types = [canonical(part) for part in inputs]
                values = [fill(part, attacker) for part in inputs]
                signature = f"{name}({','.join(types)})"
                data = bytes(Web3.keccak(text=signature)[:4]) + bytes(w3.codec.encode(types, values))
                data_hex = "0x" + data.hex()
                if data_hex in seen:
                    continue
                seen.add(data_hex)
                entries.append({
                    "label":f"abi:{contract}:{signature}",
                    "contract":contract,
                    "signature":signature,
                    "data_hex":data_hex,
                })
            except Exception as exc:
                errors.append({
                    "contract":contract,
                    "function":name,
                    "error":f"encode: {type(exc).__name__}: {exc}",
                })

    payload = {
        "schema":"kiln-r33-abi-payload-corpus-v1",
        "attacker_template":attacker,
        "abi_file_count":len(list(abi_dir.glob('*.json'))),
        "payload_count":len(entries),
        "error_count":len(errors),
        "entries":entries,
        "errors":errors,
    }
    output.write_text(json.dumps(payload,indent=2,sort_keys=True))
    print(json.dumps({k:payload[k] for k in ["abi_file_count","payload_count","error_count"]},sort_keys=True))
    return 0 if entries else 2


if __name__ == "__main__":
    raise SystemExit(main())
