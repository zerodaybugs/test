#!/usr/bin/env python3
"""Read-only census for Pyth Solana receiver config PDAs.

No transaction is constructed, signed, simulated, or broadcast.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import urllib.request
from pathlib import Path
from typing import Any

from solders.pubkey import Pubkey

RPCS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
]
PROGRAMS = {
    "standard": "rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ",
    "pro_compatible": "rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp",
}
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
ZERO_PUBKEY = str(Pubkey.default())
OUT = Path("evidence")
OUT.mkdir(parents=True, exist_ok=True)


def request_json(url: str, payload: dict[str, Any], timeout: int = 35) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            "user-agent": "Pyth-authorized-read-only-solana-census/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except Exception as exc:
        return {"transport_error": type(exc).__name__, "message": str(exc)}


def rpc(url: str, method: str, params: list[Any]) -> dict[str, Any]:
    return request_json(
        url, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    )


def result(obj: dict[str, Any]) -> Any:
    return obj.get("result") if isinstance(obj, dict) else None


def choose_rpc() -> tuple[str | None, list[dict[str, Any]]]:
    probes = []
    for url in RPCS:
        version = rpc(url, "getVersion", [])
        slot = rpc(url, "getSlot", [{"commitment": "finalized"}])
        ok = isinstance(result(version), dict) and isinstance(result(slot), int)
        probes.append({"url": url, "version": version, "slot": slot, "ok": ok})
    return next((probe["url"] for probe in probes if probe["ok"]), None), probes


def account_info(url: str, address: str) -> dict[str, Any]:
    return rpc(
        url,
        "getAccountInfo",
        [address, {"encoding": "base64", "commitment": "finalized"}],
    )


def account_value(raw: dict[str, Any]) -> dict[str, Any] | None:
    value = result(raw)
    if not isinstance(value, dict):
        return None
    account = value.get("value")
    return account if isinstance(account, dict) else None


def account_data(account: dict[str, Any] | None) -> bytes:
    if not account:
        return b""
    data = account.get("data")
    if not isinstance(data, list) or len(data) < 2 or data[1] != "base64":
        return b""
    return base64.b64decode(data[0])


def anchor_discriminator(name: str) -> bytes:
    return hashlib.sha256(f"account:{name}".encode()).digest()[:8]


def take_pubkey(data: bytes, offset: int) -> tuple[str, int]:
    if len(data) < offset + 32:
        raise ValueError("truncated pubkey")
    return str(Pubkey.from_bytes(data[offset : offset + 32])), offset + 32


def decode_config(data: bytes) -> dict[str, Any]:
    expected_discriminator = anchor_discriminator("Config")
    if len(data) < 8:
        raise ValueError("config data shorter than discriminator")
    offset = 8
    governance, offset = take_pubkey(data, offset)
    if len(data) <= offset:
        raise ValueError("truncated target authority option")
    target_flag = data[offset]
    offset += 1
    target = None
    if target_flag == 1:
        target, offset = take_pubkey(data, offset)
    elif target_flag != 0:
        raise ValueError(f"invalid option flag {target_flag}")
    wormhole, offset = take_pubkey(data, offset)
    if len(data) < offset + 4:
        raise ValueError("truncated data source vector length")
    data_source_count = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    data_sources = []
    for _ in range(data_source_count):
        if len(data) < offset + 2:
            raise ValueError("truncated data source chain")
        chain = struct.unpack_from("<H", data, offset)[0]
        offset += 2
        emitter, offset = take_pubkey(data, offset)
        data_sources.append({"chain": chain, "emitter": emitter})
    if len(data) < offset + 9:
        raise ValueError("truncated fee/minimum signature fields")
    fee = struct.unpack_from("<Q", data, offset)[0]
    offset += 8
    minimum_signatures = data[offset]
    offset += 1
    return {
        "discriminator": data[:8].hex(),
        "expected_discriminator": expected_discriminator.hex(),
        "discriminator_matches": data[:8] == expected_discriminator,
        "governance_authority": governance,
        "target_governance_authority": target,
        "wormhole": wormhole,
        "data_source_count": data_source_count,
        "data_sources": data_sources,
        "single_update_fee_in_lamports": fee,
        "minimum_signatures": minimum_signatures,
        "decoded_length": offset,
        "account_data_length": len(data),
    }


def decode_program_account(data: bytes) -> dict[str, Any]:
    # Solana bincode UpgradeableLoaderState::Program is enum tag 2 + ProgramData pubkey.
    if len(data) < 36:
        return {"decoded": False, "data_length": len(data)}
    tag = struct.unpack_from("<I", data, 0)[0]
    programdata = str(Pubkey.from_bytes(data[4:36])) if tag == 2 else None
    return {"decoded": tag == 2, "tag": tag, "programdata": programdata, "data_length": len(data)}


def decode_programdata_account(data: bytes) -> dict[str, Any]:
    # UpgradeableLoaderState::ProgramData: enum tag 3, slot u64, Option<Pubkey>.
    if len(data) < 13:
        return {"decoded": False, "data_length": len(data)}
    tag = struct.unpack_from("<I", data, 0)[0]
    slot = struct.unpack_from("<Q", data, 4)[0] if tag == 3 else None
    option_flag = data[12] if tag == 3 else None
    authority = None
    if tag == 3 and option_flag == 1 and len(data) >= 45:
        authority = str(Pubkey.from_bytes(data[13:45]))
    return {
        "decoded": tag == 3 and option_flag in (0, 1),
        "tag": tag,
        "slot": slot,
        "upgrade_authority": authority,
        "immutable": tag == 3 and option_flag == 0,
        "data_length": len(data),
    }


def main() -> None:
    url, probes = choose_rpc()
    evidence: dict[str, Any] = {"selected_rpc": url, "rpc_probes": probes, "programs": {}}
    if not url:
        evidence["fatal"] = "no working Solana mainnet RPC"
        (OUT / "solana_receiver_census.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True)
        )
        raise SystemExit(2)

    current_slot = rpc(url, "getSlot", [{"commitment": "finalized"}])
    evidence["current_slot"] = result(current_slot)

    for label, program_id_text in PROGRAMS.items():
        program_id = Pubkey.from_string(program_id_text)
        config_pda, config_bump = Pubkey.find_program_address([b"config"], program_id)
        program_raw = account_info(url, program_id_text)
        config_raw = account_info(url, str(config_pda))
        program_account = account_value(program_raw)
        config_account = account_value(config_raw)
        program_data = account_data(program_account)
        config_data = account_data(config_account)

        row: dict[str, Any] = {
            "program_id": program_id_text,
            "config_pda": str(config_pda),
            "config_bump": config_bump,
            "raw": {"program": program_raw, "config": config_raw},
        }
        row["program"] = {
            "exists": program_account is not None,
            "owner": program_account.get("owner") if program_account else None,
            "executable": program_account.get("executable") if program_account else None,
            "lamports": program_account.get("lamports") if program_account else None,
            "data_length": len(program_data),
        }
        row["config"] = {
            "exists": config_account is not None,
            "owner": config_account.get("owner") if config_account else None,
            "executable": config_account.get("executable") if config_account else None,
            "lamports": config_account.get("lamports") if config_account else None,
            "data_length": len(config_data),
        }

        program_decoded = decode_program_account(program_data)
        row["program_decoded"] = program_decoded
        programdata_address = program_decoded.get("programdata")
        if programdata_address:
            programdata_raw = account_info(url, programdata_address)
            programdata_account = account_value(programdata_raw)
            programdata_data = account_data(programdata_account)
            row["raw"]["programdata"] = programdata_raw
            row["programdata"] = {
                "address": programdata_address,
                "exists": programdata_account is not None,
                "owner": programdata_account.get("owner") if programdata_account else None,
                "executable": programdata_account.get("executable") if programdata_account else None,
                "data_length": len(programdata_data),
                "decoded": decode_programdata_account(programdata_data),
            }

        try:
            row["config_decoded"] = decode_config(config_data) if config_data else None
            row["config_decode_error"] = None
        except Exception as exc:
            row["config_decoded"] = None
            row["config_decode_error"] = f"{type(exc).__name__}: {exc}"

        decoded = row.get("config_decoded") or {}
        wormhole = decoded.get("wormhole")
        if wormhole and wormhole != ZERO_PUBKEY:
            wormhole_raw = account_info(url, wormhole)
            wormhole_account = account_value(wormhole_raw)
            row["raw"]["wormhole"] = wormhole_raw
            row["wormhole_account"] = {
                "exists": wormhole_account is not None,
                "owner": wormhole_account.get("owner") if wormhole_account else None,
                "executable": wormhole_account.get("executable") if wormhole_account else None,
                "data_length": len(account_data(wormhole_account)),
            }

        row["gates"] = {
            "program_exists": row["program"]["exists"],
            "program_executable": row["program"]["executable"] is True,
            "program_loader_is_upgradeable": row["program"]["owner"] == UPGRADEABLE_LOADER,
            "config_exists": row["config"]["exists"],
            "config_owned_by_program": row["config"]["owner"] == program_id_text,
            "config_decodes": row.get("config_decoded") is not None,
            "config_discriminator_matches": decoded.get("discriminator_matches") is True,
            "governance_nonzero": decoded.get("governance_authority") not in (None, ZERO_PUBKEY),
            "wormhole_nonzero": wormhole not in (None, ZERO_PUBKEY),
            "wormhole_account_exists": (row.get("wormhole_account") or {}).get("exists") is True,
            "wormhole_executable": (row.get("wormhole_account") or {}).get("executable") is True,
            "data_sources_positive": isinstance(decoded.get("data_source_count"), int)
            and decoded["data_source_count"] > 0,
            "minimum_signatures_positive": isinstance(decoded.get("minimum_signatures"), int)
            and decoded["minimum_signatures"] > 0,
        }
        evidence["programs"][label] = row

    failures = []
    for label, row in evidence["programs"].items():
        for gate, passed in row.get("gates", {}).items():
            if passed is False:
                failures.append({"program": label, "gate": gate})
    evidence["gate_failures"] = failures
    (OUT / "solana_receiver_census.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True)
    )
    (OUT / "gate_failures.json").write_text(
        json.dumps(failures, indent=2, sort_keys=True)
    )
    print(f"programs={len(PROGRAMS)} failures={len(failures)}")
    for failure in failures:
        print(failure["program"], failure["gate"])


if __name__ == "__main__":
    main()
