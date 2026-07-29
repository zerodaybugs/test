#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("evidence")
RAW = OUT / "raw"
RPCS = {
    "official": "https://mainnet.evm.nodes.onflow.org",
    "thirdweb": "https://747.rpc.thirdweb.com",
}
LAZER = "0xACeA761c27A909d4D3895128EBe6370FDE2dF481"
EXECUTOR = "0x26DD80569a8B23768A1d80869Ed7339e07595E85"
WORMHOLE = "0xb27e5ca259702f209a29225d0eDdC131039C9933"
RANDOM = "0x1111111111111111111111111111111111111111"
EXPECTED_OWNER_EMITTER = (
    "0x5635979a221c34931e32620b9293a463065555ea71fe97cd6237ade875b12e9e"
)
IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"


def selector(signature: str) -> str:
    proc = subprocess.run(
        ["openssl", "dgst", "-keccak-256"],
        input=signature.encode(),
        stdout=subprocess.PIPE,
        check=True,
    )
    digest = proc.stdout.decode().strip().split("=")[-1].strip()
    return "0x" + digest[:8]


def keccak_hex(hex_data: str) -> str | None:
    if not hex_data or hex_data == "0x":
        return None
    raw = bytes.fromhex(hex_data.removeprefix("0x"))
    proc = subprocess.run(
        ["openssl", "dgst", "-keccak-256"],
        input=raw,
        stdout=subprocess.PIPE,
        check=True,
    )
    return "0x" + proc.stdout.decode().strip().split("=")[-1].strip()


def encode_uint(value: int) -> str:
    return f"{value:064x}"


def encode_address(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64, "0")


def rpc(url: str, method: str, params: list[Any]) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"content-type": "application/json", "user-agent": "read-only-census/1"},
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.loads(response.read())


def eth_call(
    url: str,
    address: str,
    signature: str,
    args: str = "",
    *,
    sender: str | None = None,
) -> dict[str, Any]:
    tx: dict[str, Any] = {"to": address, "data": selector(signature) + args}
    if sender:
        tx["from"] = sender
    return rpc(url, "eth_call", [tx, "latest"])


def result(obj: dict[str, Any]) -> str | None:
    value = obj.get("result")
    return value if isinstance(value, str) else None


def word(raw: str | None, index: int = 0) -> int:
    if not raw or raw == "0x":
        return 0
    body = raw.removeprefix("0x")
    return int(body[index * 64 : (index + 1) * 64], 16)


def address_word(raw: str | None, index: int = 0) -> str:
    if not raw or raw == "0x":
        return "0x" + "00" * 20
    body = raw.removeprefix("0x")
    return "0x" + body[index * 64 + 24 : (index + 1) * 64]


def decode_string(raw: str | None) -> str | None:
    if not raw or raw == "0x":
        return None
    body = raw.removeprefix("0x")
    offset = int(body[:64], 16) * 2
    length = int(body[offset : offset + 64], 16)
    return bytes.fromhex(body[offset + 64 : offset + 64 + length * 2]).decode(
        errors="replace"
    )


def decode_signers(raw: str | None) -> list[dict[str, Any]]:
    if not raw or raw == "0x":
        return []
    body = raw.removeprefix("0x")
    offset = int(body[:64], 16) * 2
    count = int(body[offset : offset + 64], 16)
    base = offset + 64
    values: list[dict[str, Any]] = []
    for index in range(count):
        start = base + index * 128
        values.append(
            {
                "address": "0x" + body[start + 24 : start + 64],
                "expires_at": int(body[start + 64 : start + 128], 16),
            }
        )
    return values


def decode_guardian_set(raw: str | None) -> dict[str, Any]:
    if not raw or raw == "0x":
        return {"keys": [], "expiration_time": None}
    body = raw.removeprefix("0x")
    offset = int(body[:64], 16) * 2
    expiration = int(body[64:128], 16)
    count = int(body[offset : offset + 64], 16)
    base = offset + 64
    keys = [
        "0x" + body[base + i * 64 : base + (i + 1) * 64][-40:]
        for i in range(count)
    ]
    return {"keys": keys, "expiration_time": expiration}


def decode_executor_slot(raw: str | None) -> dict[str, Any]:
    value = int(raw or "0x0", 16)
    return {
        "wormhole": f"0x{value & ((1 << 160) - 1):040x}",
        "last_executed_sequence": (value >> 160) & ((1 << 64) - 1),
        "receiver_chain_id": (value >> 224) & 0xFFFF,
        "owner_emitter_chain_id": (value >> 240) & 0xFFFF,
    }


def storage(url: str, address: str, slot: str) -> dict[str, Any]:
    return rpc(url, "eth_getStorageAt", [address, slot, "latest"])


def inspect_provider(label: str, url: str) -> dict[str, Any]:
    raw: dict[str, Any] = {"label": label, "rpc": url, "calls": {}}
    chain = rpc(url, "eth_chainId", [])
    block_number_obj = rpc(url, "eth_blockNumber", [])
    block_number = int(result(block_number_obj) or "0x0", 16)
    block = rpc(url, "eth_getBlockByNumber", [hex(block_number), False])
    timestamp = int((block.get("result") or {}).get("timestamp", "0x0"), 16)
    raw.update(
        {
            "chain_id_raw": chain,
            "block_number_raw": block_number_obj,
            "block_raw": block,
            "block_number": block_number,
            "timestamp": timestamp,
        }
    )

    for name, address in (
        ("lazer", LAZER),
        ("executor", EXECUTOR),
        ("wormhole", WORMHOLE),
    ):
        code_obj = rpc(url, "eth_getCode", [address, "latest"])
        code = result(code_obj) or "0x"
        raw[f"{name}_code"] = code_obj
        raw[f"{name}_code_length"] = max(0, (len(code) - 2) // 2)
        raw[f"{name}_code_keccak"] = keccak_hex(code)
        raw[f"{name}_implementation_slot"] = storage(
            url, address, IMPLEMENTATION_SLOT
        )
        raw[f"{name}_admin_slot"] = storage(url, address, ADMIN_SLOT)

    calls = raw["calls"]
    for key, signature in {
        "lazer_owner": "owner()",
        "lazer_version": "version()",
        "lazer_fee": "verification_fee()",
        "lazer_signers": "getTrustedSigners()",
        "lazer_uuid": "proxiableUUID()",
        "executor_owner": "owner()",
        "executor_version": "version()",
        "executor_uuid": "proxiableUUID()",
        "executor_owner_chain": "getOwnerChainId()",
        "executor_owner_emitter": "getOwnerEmitterAddress()",
        "executor_last_sequence": "getLastExecutedSequence()",
        "wormhole_guardian_index": "getCurrentGuardianSetIndex()",
        "wormhole_guardian_expiry": "getGuardianSetExpiry()",
        "wormhole_chain_id": "chainId()",
        "wormhole_governance_chain": "governanceChainId()",
        "wormhole_governance_contract": "governanceContract()",
    }.items():
        address = (
            LAZER
            if key.startswith("lazer_")
            else EXECUTOR
            if key.startswith("executor_")
            else WORMHOLE
        )
        calls[key] = eth_call(url, address, signature)

    signers = decode_signers(result(calls["lazer_signers"]))
    signer_checks: list[dict[str, Any]] = []
    for signer in signers:
        expiry_obj = eth_call(
            url,
            LAZER,
            "getTrustedSignerExpiry(address)",
            encode_address(signer["address"]),
        )
        valid_obj = eth_call(
            url,
            LAZER,
            "isValidSigner(address)",
            encode_address(signer["address"]),
        )
        signer_checks.append(
            {
                **signer,
                "mapping_expiry": word(result(expiry_obj)),
                "is_valid": bool(word(result(valid_obj))),
            }
        )

    calls["lazer_initialize"] = rpc(
        url,
        "eth_call",
        [
            {
                "from": RANDOM,
                "to": LAZER,
                "data": selector("initialize(address)") + encode_address(RANDOM),
            },
            "latest",
        ],
    )
    calls["lazer_unauthorized_update"] = rpc(
        url,
        "eth_call",
        [
            {
                "from": RANDOM,
                "to": LAZER,
                "data": selector("updateTrustedSigner(address,uint256)")
                + encode_address(RANDOM)
                + encode_uint(timestamp + 86_400),
            },
            "latest",
        ],
    )
    calls["executor_initialize"] = rpc(
        url,
        "eth_call",
        [
            {
                "from": RANDOM,
                "to": EXECUTOR,
                "data": selector(
                    "initialize(address,uint64,uint16,uint16,bytes32)"
                )
                + encode_address(WORMHOLE)
                + encode_uint(0)
                + encode_uint(60_062)
                + encode_uint(1)
                + EXPECTED_OWNER_EMITTER.removeprefix("0x"),
            },
            "latest",
        ],
    )

    guardian_index = word(result(calls["wormhole_guardian_index"]))
    calls["wormhole_guardian_set"] = eth_call(
        url, WORMHOLE, "getGuardianSet(uint32)", encode_uint(guardian_index)
    )
    executor_slot0_raw = storage(url, EXECUTOR, "0x0")
    executor_slot1_raw = storage(url, EXECUTOR, "0x1")

    raw["decoded"] = {
        "chain_id": int(result(chain) or "0x0", 16),
        "lazer_owner": address_word(result(calls["lazer_owner"])),
        "lazer_version": decode_string(result(calls["lazer_version"])),
        "lazer_fee": word(result(calls["lazer_fee"])),
        "lazer_implementation": address_word(
            result(raw["lazer_implementation_slot"])
        ),
        "lazer_admin": address_word(result(raw["lazer_admin_slot"])),
        "trusted_signers": signer_checks,
        "lazer_initialize_rejected": "error" in calls["lazer_initialize"],
        "lazer_unauthorized_update_rejected": "error"
        in calls["lazer_unauthorized_update"],
        "executor_owner": address_word(result(calls["executor_owner"])),
        "executor_version": decode_string(result(calls["executor_version"])),
        "executor_implementation": address_word(
            result(raw["executor_implementation_slot"])
        ),
        "executor_admin": address_word(result(raw["executor_admin_slot"])),
        "executor_owner_chain": word(result(calls["executor_owner_chain"])),
        "executor_owner_emitter": result(calls["executor_owner_emitter"]),
        "executor_last_sequence": word(result(calls["executor_last_sequence"])),
        "executor_initialize_rejected": "error" in calls["executor_initialize"],
        "executor_slot0": decode_executor_slot(result(executor_slot0_raw)),
        "executor_slot1": result(executor_slot1_raw),
        "wormhole_implementation": address_word(
            result(raw["wormhole_implementation_slot"])
        ),
        "wormhole_admin": address_word(result(raw["wormhole_admin_slot"])),
        "wormhole_guardian_index": guardian_index,
        "wormhole_guardian_expiry": word(result(calls["wormhole_guardian_expiry"])),
        "wormhole_chain_id": word(result(calls["wormhole_chain_id"])),
        "wormhole_governance_chain": word(
            result(calls["wormhole_governance_chain"])
        ),
        "wormhole_governance_contract": result(
            calls["wormhole_governance_contract"]
        ),
        "wormhole_guardian_set": decode_guardian_set(
            result(calls["wormhole_guardian_set"])
        ),
    }
    return raw


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    RAW.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for label, url in RPCS.items():
        try:
            inspected = inspect_provider(label, url)
            results.append(inspected)
            (RAW / f"{label}.json").write_text(
                json.dumps(inspected, indent=2), encoding="utf-8"
            )
        except Exception as error:  # evidence must retain provider failures
            failures.append({"label": label, "rpc": url, "error": repr(error)})

    comparable = [
        {
            "lazer_code_keccak": item["lazer_code_keccak"],
            "executor_code_keccak": item["executor_code_keccak"],
            "wormhole_code_keccak": item["wormhole_code_keccak"],
            "decoded": item["decoded"],
        }
        for item in results
    ]
    exact_agreement = len(comparable) >= 2 and all(
        value == comparable[0] for value in comparable[1:]
    )

    checks: dict[str, bool] = {}
    if results:
        item = results[0]
        decoded = item["decoded"]
        executor_storage = decoded["executor_slot0"]
        signers = decoded["trusted_signers"]
        checks = {
            "two_rpc_exact_agreement": exact_agreement,
            "flow_chain_id": decoded["chain_id"] == 747,
            "all_contracts_have_code": all(
                item[f"{name}_code_length"] > 0
                for name in ("lazer", "executor", "wormhole")
            ),
            "lazer_owner_is_executor": decoded["lazer_owner"].lower()
            == EXECUTOR.lower(),
            "executor_self_owned": decoded["executor_owner"].lower()
            == EXECUTOR.lower(),
            "lazer_initialized": decoded["lazer_initialize_rejected"],
            "executor_initialized": decoded["executor_initialize_rejected"],
            "unauthorized_signer_update_rejected": decoded[
                "lazer_unauthorized_update_rejected"
            ],
            "lazer_version": decoded["lazer_version"] == "0.2.0",
            "executor_version": decoded["executor_version"] == "0.1.1",
            "verification_fee": decoded["lazer_fee"] == 1,
            "lazer_admin_zero": int(
                result(item["lazer_admin_slot"]) or "0x0", 16
            )
            == 0,
            "executor_admin_zero": int(
                result(item["executor_admin_slot"]) or "0x0", 16
            )
            == 0,
            "executor_wormhole": executor_storage["wormhole"].lower()
            == WORMHOLE.lower(),
            "executor_receiver_chain": executor_storage["receiver_chain_id"]
            == 60_062,
            "executor_owner_chain": executor_storage["owner_emitter_chain_id"]
            == 1,
            "executor_owner_emitter": (decoded["executor_slot1"] or "").lower()
            == EXPECTED_OWNER_EMITTER.lower(),
            "executor_views_match_storage": decoded["executor_owner_chain"]
            == executor_storage["owner_emitter_chain_id"]
            and (decoded["executor_owner_emitter"] or "").lower()
            == (decoded["executor_slot1"] or "").lower()
            and decoded["executor_last_sequence"]
            == executor_storage["last_executed_sequence"],
            "trusted_signers_exist": len(signers) > 0,
            "signer_array_mapping_consistent": all(
                signer["expires_at"] == signer["mapping_expiry"]
                for signer in signers
            ),
            "currently_valid_signer_exists": any(
                signer["is_valid"] and signer["expires_at"] > item["timestamp"]
                for signer in signers
            ),
            "wormhole_receiver_chain": decoded["wormhole_chain_id"] == 60_062,
            "wormhole_governance_chain": decoded["wormhole_governance_chain"] == 1,
            "wormhole_guardian_set_nonempty": len(
                decoded["wormhole_guardian_set"]["keys"]
            )
            > 0,
        }

    failed_checks = sorted(key for key, passed in checks.items() if not passed)
    verdict = (
        "PASS_CONFIGURATION_BASELINE"
        if checks and not failed_checks
        else "INVESTIGATE_CONFIGURATION_DIVERGENCE"
    )
    evidence = {
        "schema": "pyth-flow-deployment-census/v1",
        "generated_at_unix": int(time.time()),
        "results": results,
        "provider_failures": failures,
        "checks": checks,
        "failed_checks": failed_checks,
        "verdict": verdict,
    }
    (OUT / "census.json").write_text(
        json.dumps(evidence, indent=2), encoding="utf-8"
    )

    lines = [
        f"VERDICT={verdict}",
        f"SUCCESSFUL_RPC_COUNT={len(results)}",
        f"TWO_RPC_EXACT_AGREEMENT={str(exact_agreement).lower()}",
        f"FAILED_CHECK_COUNT={len(failed_checks)}",
    ]
    if results:
        item = results[0]
        decoded = item["decoded"]
        slot = decoded["executor_slot0"]
        lines.extend(
            [
                f"BLOCK={item['block_number']}",
                f"LAZER_OWNER={decoded['lazer_owner']}",
                f"LAZER_IMPLEMENTATION={decoded['lazer_implementation']}",
                f"EXECUTOR_OWNER={decoded['executor_owner']}",
                f"EXECUTOR_IMPLEMENTATION={decoded['executor_implementation']}",
                f"EXECUTOR_WORMHOLE={slot['wormhole']}",
                f"EXECUTOR_RECEIVER_CHAIN_ID={slot['receiver_chain_id']}",
                f"EXECUTOR_OWNER_EMITTER_CHAIN={slot['owner_emitter_chain_id']}",
                f"EXECUTOR_LAST_SEQUENCE={slot['last_executed_sequence']}",
                f"TRUSTED_SIGNER_COUNT={len(decoded['trusted_signers'])}",
                f"WORMHOLE_GUARDIAN_SET_INDEX={decoded['wormhole_guardian_index']}",
                f"WORMHOLE_GUARDIAN_COUNT={len(decoded['wormhole_guardian_set']['keys'])}",
            ]
        )
    lines.extend(f"FAILED_CHECK={key}" for key in failed_checks)
    summary = "\n".join(lines) + "\n"
    (OUT / "summary.txt").write_text(summary, encoding="utf-8")
    print(summary, end="")
    return 0 if len(results) >= 2 else 2


if __name__ == "__main__":
    raise SystemExit(main())
