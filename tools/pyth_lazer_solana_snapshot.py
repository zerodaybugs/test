#!/usr/bin/env python3
"""Read-only, dual-provider snapshot of the public Pyth Lazer Solana deployment."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROGRAM_ID = "pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt"
STORAGE_ID = "3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL"
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
EXPECTED_STORAGE_LEN = 381
EXPECTED_DISCRIMINATOR = hashlib.sha256(b"account:Storage").digest()[:8]
MAX_TRUSTED = 2
OUT = Path(os.environ.get("OUT_DIR", "out"))

PROVIDERS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
    "https://rpc.ankr.com/solana",
    "https://solana-mainnet.g.alchemy.com/v2/demo",
]

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    zeros = len(raw) - len(raw.lstrip(b"\0"))
    value = int.from_bytes(raw, "big")
    encoded = bytearray()
    while value:
        value, rem = divmod(value, 58)
        encoded.append(ALPHABET[rem])
    encoded.reverse()
    return (ALPHABET[:1] * zeros + encoded).decode() or "1"


def rpc(url: str, method: str, params: list[Any], request_id: int) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()
    errors: list[str] = []
    for attempt in range(5):
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "user-agent": "pyth-lazer-solana-read-only-binding/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=35) as response:
                body = response.read()
            obj = json.loads(body)
            if "error" in obj:
                raise RuntimeError(f"RPC error: {obj['error']}")
            return obj
        except (urllib.error.URLError, TimeoutError, RuntimeError, json.JSONDecodeError) as exc:
            errors.append(f"attempt={attempt + 1}: {exc!r}")
            if attempt < 4:
                time.sleep(1.0 + attempt * 1.5)
    raise RuntimeError("; ".join(errors))


def account_bytes(response: dict[str, Any]) -> tuple[bytes, dict[str, Any], int]:
    result = response.get("result")
    if not isinstance(result, dict) or result.get("value") is None:
        raise ValueError("account absent")
    value = result["value"]
    data = value.get("data")
    if not isinstance(data, list) or len(data) < 1:
        raise ValueError("unexpected account data encoding")
    return base64.b64decode(data[0], validate=True), value, int(result["context"]["slot"])


def decode_storage(data: bytes) -> dict[str, Any]:
    if len(data) != EXPECTED_STORAGE_LEN:
        raise ValueError(f"storage length {len(data)} != {EXPECTED_STORAGE_LEN}")
    discriminator = data[:8]
    pos = 8

    def take(count: int) -> bytes:
        nonlocal pos
        chunk = data[pos : pos + count]
        if len(chunk) != count:
            raise ValueError("short storage data")
        pos += count
        return chunk

    top_authority = b58encode(take(32))
    treasury = b58encode(take(32))
    fee = struct.unpack("<Q", take(8))[0]
    num_ed25519 = take(1)[0]
    ed25519 = []
    for index in range(5):
        pubkey = b58encode(take(32))
        expires_at = struct.unpack("<q", take(8))[0]
        ed25519.append({"index": index, "pubkey": pubkey, "expires_at": expires_at})
    num_ecdsa = take(1)[0]
    ecdsa = []
    for index in range(2):
        address = "0x" + take(20).hex()
        expires_at = struct.unpack("<q", take(8))[0]
        ecdsa.append({"index": index, "address": address, "expires_at": expires_at})
    extra = take(43)
    if pos != len(data):
        raise ValueError(f"unconsumed storage bytes: {len(data) - pos}")

    now = int(time.time())
    active_ed25519 = [x for x in ed25519[:num_ed25519] if x["expires_at"] > now]
    active_ecdsa = [x for x in ecdsa[:num_ecdsa] if x["expires_at"] > now]
    return {
        "discriminator_hex": discriminator.hex(),
        "discriminator_matches": discriminator == EXPECTED_DISCRIMINATOR,
        "top_authority": top_authority,
        "treasury": treasury,
        "single_update_fee_in_lamports": fee,
        "num_trusted_signers": num_ed25519,
        "trusted_signers": ed25519,
        "active_trusted_signers": active_ed25519,
        "num_trusted_ecdsa_signers": num_ecdsa,
        "trusted_ecdsa_signers": ecdsa,
        "active_trusted_ecdsa_signers": active_ecdsa,
        "extra_space_all_zero": extra == bytes(len(extra)),
    }


def decode_program(data: bytes) -> dict[str, Any]:
    if len(data) < 36:
        raise ValueError(f"short upgradeable program account: {len(data)}")
    variant = struct.unpack("<I", data[:4])[0]
    return {
        "variant": variant,
        "programdata_address": b58encode(data[4:36]),
        "trailing_hex": data[36:].hex(),
    }


def decode_programdata(data: bytes) -> dict[str, Any]:
    if len(data) < 13:
        raise ValueError(f"short programdata account: {len(data)}")
    variant = struct.unpack("<I", data[:4])[0]
    slot = struct.unpack("<Q", data[4:12])[0]
    tag = data[12]
    pos = 13
    authority = None
    if tag == 1:
        if len(data) < pos + 32:
            raise ValueError("short programdata authority")
        authority = b58encode(data[pos : pos + 32])
        pos += 32
    elif tag != 0:
        raise ValueError(f"invalid authority option tag {tag}")
    return {
        "variant": variant,
        "last_deploy_slot": slot,
        "upgrade_authority": authority,
        "metadata_length": pos,
        "program_elf_length": len(data) - pos,
        "program_elf_sha256": hashlib.sha256(data[pos:]).hexdigest(),
    }


def account_summary(raw: bytes, value: dict[str, Any], slot: int) -> dict[str, Any]:
    return {
        "slot": slot,
        "lamports": int(value["lamports"]),
        "owner": value["owner"],
        "executable": bool(value["executable"]),
        "rent_epoch": value.get("rentEpoch"),
        "data_length": len(raw),
        "data_sha256": hashlib.sha256(raw).hexdigest(),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    provider_results: dict[str, Any] = {}
    successes: list[str] = []
    request_id = 1

    # First pass obtains program and storage accounts independently.
    for provider in PROVIDERS:
        safe = hashlib.sha256(provider.encode()).hexdigest()[:12]
        try:
            program_resp = rpc(
                provider,
                "getAccountInfo",
                [PROGRAM_ID, {"encoding": "base64", "commitment": "finalized"}],
                request_id,
            )
            request_id += 1
            storage_resp = rpc(
                provider,
                "getAccountInfo",
                [STORAGE_ID, {"encoding": "base64", "commitment": "finalized"}],
                request_id,
            )
            request_id += 1
            (OUT / f"{safe}-program.json").write_text(json.dumps(program_resp, indent=2) + "\n")
            (OUT / f"{safe}-storage.json").write_text(json.dumps(storage_resp, indent=2) + "\n")
            program_raw, program_value, program_slot = account_bytes(program_resp)
            storage_raw, storage_value, storage_slot = account_bytes(storage_resp)
            program_decoded = decode_program(program_raw)
            storage_decoded = decode_storage(storage_raw)
            provider_results[provider] = {
                "status": "PASS",
                "program": account_summary(program_raw, program_value, program_slot),
                "program_decoded": program_decoded,
                "storage": account_summary(storage_raw, storage_value, storage_slot),
                "storage_decoded": storage_decoded,
            }
            successes.append(provider)
        except Exception as exc:  # preserve partial provider failures
            provider_results[provider] = {"status": "ERROR", "error": repr(exc)}

    if len(successes) < 2:
        (OUT / "PROVIDER_RESULTS.json").write_text(json.dumps(provider_results, indent=2) + "\n")
        raise SystemExit(f"fewer than two providers succeeded: {successes}")

    reference = provider_results[successes[0]]
    programdata_address = reference["program_decoded"]["programdata_address"]

    # Second pass binds the upgradeable ProgramData account and authority.
    for provider in successes:
        safe = hashlib.sha256(provider.encode()).hexdigest()[:12]
        try:
            response = rpc(
                provider,
                "getAccountInfo",
                [programdata_address, {"encoding": "base64", "commitment": "finalized"}],
                request_id,
            )
            request_id += 1
            (OUT / f"{safe}-programdata.json").write_text(json.dumps(response, indent=2) + "\n")
            raw, value, slot = account_bytes(response)
            provider_results[provider]["programdata"] = account_summary(raw, value, slot)
            provider_results[provider]["programdata_decoded"] = decode_programdata(raw)
        except Exception as exc:
            provider_results[provider]["programdata_error"] = repr(exc)

    # Read authority and treasury metadata from one provider. These are not trusted
    # for equality gates, but are useful operational context.
    for label, address in {
        "top_authority_account": reference["storage_decoded"]["top_authority"],
        "treasury_account": reference["storage_decoded"]["treasury"],
    }.items():
        try:
            response = rpc(
                successes[0],
                "getAccountInfo",
                [address, {"encoding": "base64", "commitment": "finalized"}],
                request_id,
            )
            request_id += 1
            raw, value, slot = account_bytes(response)
            reference[label] = account_summary(raw, value, slot)
        except Exception as exc:
            reference[label] = {"status": "ERROR", "error": repr(exc)}

    def all_equal(path: tuple[str, ...]) -> bool:
        values = []
        for provider in successes:
            node: Any = provider_results[provider]
            for key in path:
                if not isinstance(node, dict) or key not in node:
                    return False
                node = node[key]
            values.append(node)
        return len(set(values)) == 1

    storage = reference["storage_decoded"]
    checks = {
        "at_least_two_providers": len(successes) >= 2,
        "program_bytes_identical": all_equal(("program", "data_sha256")),
        "storage_bytes_identical": all_equal(("storage", "data_sha256")),
        "programdata_bytes_identical": all_equal(("programdata", "data_sha256")),
        "program_is_executable": reference["program"]["executable"],
        "program_owner_is_upgradeable_loader": reference["program"]["owner"] == UPGRADEABLE_LOADER,
        "program_variant_is_program": reference["program_decoded"]["variant"] == 2,
        "programdata_variant_is_programdata": reference["programdata_decoded"]["variant"] == 3,
        "programdata_owner_is_upgradeable_loader": reference["programdata"]["owner"] == UPGRADEABLE_LOADER,
        "storage_owner_is_program": reference["storage"]["owner"] == PROGRAM_ID,
        "storage_not_executable": not reference["storage"]["executable"],
        "storage_length_matches_source": reference["storage"]["data_length"] == EXPECTED_STORAGE_LEN,
        "storage_discriminator_matches": storage["discriminator_matches"],
        "ed25519_count_within_source_max": storage["num_trusted_signers"] <= MAX_TRUSTED,
        "ecdsa_count_within_source_max": storage["num_trusted_ecdsa_signers"] <= MAX_TRUSTED,
        "at_least_one_active_signer": bool(storage["active_trusted_signers"] or storage["active_trusted_ecdsa_signers"]),
        "top_authority_non_default": storage["top_authority"] != "11111111111111111111111111111111",
        "treasury_non_default": storage["treasury"] != "11111111111111111111111111111111",
    }

    summary = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "mode": "PUBLIC_MAINNET_READ_ONLY",
        "program_id": PROGRAM_ID,
        "storage_id": STORAGE_ID,
        "programdata_address": programdata_address,
        "successful_providers": successes,
        "provider_results": provider_results,
        "checks": checks,
    }
    (OUT / "SNAPSHOT.json").write_text(json.dumps(summary, indent=2) + "\n")
    (OUT / "PROVIDER_RESULTS.json").write_text(json.dumps(provider_results, indent=2) + "\n")
    markers = [
        "PYTH_LAZER_SOLANA_LIVE_SNAPSHOT_PASS",
        f"SUCCESSFUL_PROVIDER_COUNT={len(successes)}",
        f"PROGRAM_ID={PROGRAM_ID}",
        f"STORAGE_ID={STORAGE_ID}",
        f"PROGRAMDATA_ADDRESS={programdata_address}",
        f"TOP_AUTHORITY={storage['top_authority']}",
        f"TREASURY={storage['treasury']}",
        f"UPDATE_FEE_LAMPORTS={storage['single_update_fee_in_lamports']}",
        f"ED25519_SIGNER_COUNT={storage['num_trusted_signers']}",
        f"ACTIVE_ED25519_SIGNER_COUNT={len(storage['active_trusted_signers'])}",
        f"ECDSA_SIGNER_COUNT={storage['num_trusted_ecdsa_signers']}",
        f"ACTIVE_ECDSA_SIGNER_COUNT={len(storage['active_trusted_ecdsa_signers'])}",
        f"UPGRADE_AUTHORITY={reference['programdata_decoded']['upgrade_authority']}",
    ]
    for name, passed in checks.items():
        markers.append(f"{name.upper()}={str(bool(passed)).lower()}")
    (OUT / "PASS_MARKERS.txt").write_text("\n".join(markers) + "\n")
    print(json.dumps(summary, indent=2))
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise SystemExit(f"mandatory checks failed: {failed}")


if __name__ == "__main__":
    main()
