#!/usr/bin/env python3
"""Read-only Pyth Lazer Solana mainnet deployment census.

Checks the canonical program, Storage PDA, authority state, trusted signers and
upgrade authority through finalized public JSON-RPC reads only. The surrounding
workflow encrypts all output before upload. No transaction is constructed,
signed or broadcast.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("evidence/solana_mainnet")
PROGRAM_ID = "pytd2yyk641x7ak7mkaasSJVXh6YYZnC7wTmtgAyxPt"
STORAGE_ID = "3rdJbqfnagQ4yx9HXJViD4zc4xpiSqmFsKpPuSCQVyQL"
UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
SYSTEM_PROGRAM = "11111111111111111111111111111111"
RPCS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
    "https://rpc.ankr.com/solana",
]

# Public fixture identities used only for exact deployment checks.
KNOWN_ED25519 = {
    "staging_fixture": "74313a6525edf99936aa1477e94c72bc5cc617b21745f5f03296f3154461f214",
    "production_fixture": "80efc1f480c5615af3fb673d42287e993da9fbc3506b6e41dfa32950820c2e6c",
}
KNOWN_ECDSA = {
    "staging_fixture": "b8d50f0bae75bf6e03c104903d7c3afc4a6596da",
    "production_fixture": "26fb61a864c758ae9fba027a96010480658385b9",
}

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHABET_INDEX = {char: index for index, char in enumerate(ALPHABET)}


def b58encode(raw: bytes) -> str:
    zeros = len(raw) - len(raw.lstrip(b"\x00"))
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = ALPHABET[remainder] + encoded
    return "1" * zeros + (encoded or ("" if zeros else "1"))


def b58decode(value: str) -> bytes:
    number = 0
    for char in value:
        number = number * 58 + ALPHABET_INDEX[char]
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeros + raw


def rpc(url: str, method: str, params: list[Any], timeout: int = 35) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    last: Exception | None = None
    for attempt in range(4):
        request = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "content-type": "application/json",
                "user-agent": "Pyth-authorized-read-only-solana-census/2026-07-30",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                item = json.loads(response.read())
            if not isinstance(item, dict):
                raise ValueError("non-object JSON-RPC response")
            return item
        except Exception as error:
            last = error
            time.sleep(0.7 * (attempt + 1))
    return {"error": {"message": type(last).__name__ if last else "RPC failure"}}


def result(item: Any) -> Any:
    return item.get("result") if isinstance(item, dict) else None


def choose_rpc() -> tuple[str, list[dict[str, Any]]]:
    attempts = []
    for url in RPCS:
        response = rpc(url, "getGenesisHash", [])
        genesis = result(response)
        attempts.append(
            {
                "rpc": url,
                "genesis_hash": genesis,
                "error": response.get("error") if isinstance(response, dict) else None,
            }
        )
        # Solana mainnet-beta canonical genesis hash.
        if genesis == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2h9S":
            return url, attempts
    raise RuntimeError("No RPC confirmed the Solana mainnet genesis hash")


def account_info(url: str, address: str) -> dict[str, Any] | None:
    response = rpc(
        url,
        "getAccountInfo",
        [address, {"encoding": "base64", "commitment": "finalized"}],
    )
    value = result(response)
    if not isinstance(value, dict):
        return None
    return value.get("value")


def multiple_accounts(url: str, addresses: list[str]) -> list[dict[str, Any] | None]:
    response = rpc(
        url,
        "getMultipleAccounts",
        [addresses, {"encoding": "base64", "commitment": "finalized"}],
    )
    value = result(response)
    if not isinstance(value, dict) or not isinstance(value.get("value"), list):
        return [None] * len(addresses)
    return value["value"]


def account_data(account: dict[str, Any] | None) -> bytes | None:
    if not account:
        return None
    data = account.get("data")
    if not isinstance(data, list) or not data or not isinstance(data[0], str):
        return None
    try:
        return base64.b64decode(data[0], validate=True)
    except Exception:
        return None


def account_summary(address: str, account: dict[str, Any] | None) -> dict[str, Any]:
    raw = account_data(account)
    return {
        "address": address,
        "exists": account is not None,
        "lamports": account.get("lamports") if account else None,
        "owner": account.get("owner") if account else None,
        "executable": account.get("executable") if account else None,
        "rent_epoch": account.get("rentEpoch") if account else None,
        "data_length": len(raw) if raw is not None else None,
        "data_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
    }


def decode_storage(raw: bytes) -> dict[str, Any]:
    expected_discriminator = hashlib.sha256(b"account:Storage").digest()[:8]
    output: dict[str, Any] = {
        "raw_length": len(raw),
        "expected_length": 381,
        "discriminator": raw[:8].hex() if len(raw) >= 8 else None,
        "expected_discriminator": expected_discriminator.hex(),
        "discriminator_matches": len(raw) >= 8 and raw[:8] == expected_discriminator,
        "decode_errors": [],
    }
    if len(raw) < 381:
        output["decode_errors"].append("storage_account_too_short")
        return output

    offset = 8
    top_authority_raw = raw[offset : offset + 32]
    offset += 32
    treasury_raw = raw[offset : offset + 32]
    offset += 32
    fee = int.from_bytes(raw[offset : offset + 8], "little")
    offset += 8
    num_ed25519 = raw[offset]
    offset += 1

    ed25519_entries = []
    for index in range(5):
        key = raw[offset : offset + 32]
        expiry = int.from_bytes(raw[offset + 32 : offset + 40], "little", signed=True)
        offset += 40
        ed25519_entries.append(
            {
                "index": index,
                "public_key_hex": key.hex(),
                "public_key_base58": b58encode(key),
                "expires_at": expiry,
                "is_zero": key == b"\x00" * 32 and expiry == 0,
                "fixture_labels": [
                    label
                    for label, value in KNOWN_ED25519.items()
                    if key.hex() == value.lower()
                ],
            }
        )

    num_ecdsa = raw[offset]
    offset += 1
    ecdsa_entries = []
    for index in range(2):
        address = raw[offset : offset + 20]
        expiry = int.from_bytes(raw[offset + 20 : offset + 28], "little", signed=True)
        offset += 28
        address_hex = address.hex()
        ecdsa_entries.append(
            {
                "index": index,
                "address": "0x" + address_hex,
                "expires_at": expiry,
                "is_zero": address == b"\x00" * 20 and expiry == 0,
                "fixture_labels": [
                    label
                    for label, value in KNOWN_ECDSA.items()
                    if address_hex == value.lower()
                ],
            }
        )

    extra = raw[offset : offset + 43]
    offset += 43
    output.update(
        {
            "top_authority": b58encode(top_authority_raw),
            "top_authority_hex": top_authority_raw.hex(),
            "treasury": b58encode(treasury_raw),
            "treasury_hex": treasury_raw.hex(),
            "single_update_fee_in_lamports": fee,
            "num_trusted_signers": num_ed25519,
            "trusted_signer_capacity": 5,
            "max_num_trusted_signers": 2,
            "ed25519_entries": ed25519_entries,
            "initialized_ed25519_entries": ed25519_entries[:num_ed25519]
            if num_ed25519 <= 5
            else [],
            "num_trusted_ecdsa_signers": num_ecdsa,
            "trusted_ecdsa_capacity": 2,
            "max_num_trusted_ecdsa_signers": 2,
            "ecdsa_entries": ecdsa_entries,
            "initialized_ecdsa_entries": ecdsa_entries[:num_ecdsa]
            if num_ecdsa <= 2
            else [],
            "extra_space_hex": extra.hex(),
            "decoded_end_offset": offset,
            "trailing_hex": raw[offset:].hex(),
        }
    )
    if num_ed25519 > 5:
        output["decode_errors"].append("ed25519_count_exceeds_storage_capacity")
    if num_ed25519 > 2:
        output["decode_errors"].append("ed25519_count_exceeds_contract_maximum")
    if num_ecdsa > 2:
        output["decode_errors"].append("ecdsa_count_exceeds_contract_maximum")
    for entry in ed25519_entries[num_ed25519:] if num_ed25519 <= 5 else []:
        if not entry["is_zero"]:
            output["decode_errors"].append(
                f"nonzero_ed25519_entry_beyond_count_{entry['index']}"
            )
    for entry in ecdsa_entries[num_ecdsa:] if num_ecdsa <= 2 else []:
        if not entry["is_zero"]:
            output["decode_errors"].append(
                f"nonzero_ecdsa_entry_beyond_count_{entry['index']}"
            )
    return output


def decode_program_account(raw: bytes) -> dict[str, Any]:
    output: dict[str, Any] = {"raw_length": len(raw), "decode_errors": []}
    if len(raw) < 36:
        output["decode_errors"].append("program_account_too_short")
        return output
    state_tag = int.from_bytes(raw[:4], "little")
    programdata_raw = raw[4:36]
    output.update(
        {
            "state_tag": state_tag,
            "expected_state_tag": 2,
            "programdata_address": b58encode(programdata_raw),
            "programdata_hex": programdata_raw.hex(),
            "trailing_hex": raw[36:].hex(),
        }
    )
    if state_tag != 2:
        output["decode_errors"].append("not_upgradeable_loader_program_state")
    return output


def decode_programdata(raw: bytes) -> dict[str, Any]:
    output: dict[str, Any] = {"raw_length": len(raw), "decode_errors": []}
    if len(raw) < 13:
        output["decode_errors"].append("programdata_account_too_short")
        return output
    state_tag = int.from_bytes(raw[:4], "little")
    slot = int.from_bytes(raw[4:12], "little")
    option_tag = raw[12]
    offset = 13
    authority = None
    authority_hex = None
    if option_tag == 1:
        if len(raw) < 45:
            output["decode_errors"].append("programdata_authority_truncated")
            return output
        authority_raw = raw[offset : offset + 32]
        authority = b58encode(authority_raw)
        authority_hex = authority_raw.hex()
        offset += 32
    elif option_tag != 0:
        output["decode_errors"].append("invalid_upgrade_authority_option_tag")
    bytecode = raw[offset:]
    output.update(
        {
            "state_tag": state_tag,
            "expected_state_tag": 3,
            "deployment_slot": slot,
            "upgrade_authority_option": option_tag,
            "upgrade_authority": authority,
            "upgrade_authority_hex": authority_hex,
            "metadata_length": offset,
            "bytecode_length": len(bytecode),
            "bytecode_sha256": hashlib.sha256(bytecode).hexdigest(),
            "bytecode_prefix_hex": bytecode[:32].hex(),
        }
    )
    if state_tag != 3:
        output["decode_errors"].append("not_programdata_state")
    if not bytecode:
        output["decode_errors"].append("program_bytecode_empty")
    return output


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rpc_url, rpc_attempts = choose_rpc()
    initial_accounts = multiple_accounts(rpc_url, [PROGRAM_ID, STORAGE_ID])
    program_account, storage_account = initial_accounts
    program_raw = account_data(program_account)
    storage_raw = account_data(storage_account)

    program_decoded = decode_program_account(program_raw or b"")
    storage_decoded = decode_storage(storage_raw or b"")
    programdata_address = program_decoded.get("programdata_address")
    top_authority = storage_decoded.get("top_authority")
    treasury = storage_decoded.get("treasury")

    second_addresses = [
        address
        for address in [programdata_address, top_authority, treasury]
        if isinstance(address, str)
    ]
    second_values = multiple_accounts(rpc_url, second_addresses)
    second_by_address = dict(zip(second_addresses, second_values))
    programdata_account = second_by_address.get(programdata_address)
    programdata_raw = account_data(programdata_account)
    programdata_decoded = decode_programdata(programdata_raw or b"")
    upgrade_authority = programdata_decoded.get("upgrade_authority")

    if isinstance(upgrade_authority, str) and upgrade_authority not in second_by_address:
        authority_account = account_info(rpc_url, upgrade_authority)
        second_by_address[upgrade_authority] = authority_account

    slot_response = rpc(rpc_url, "getSlot", [{"commitment": "finalized"}])
    finalized_slot = result(slot_response)
    block_time_response = (
        rpc(rpc_url, "getBlockTime", [finalized_slot])
        if isinstance(finalized_slot, int)
        else {"error": {"message": "slot unavailable"}}
    )
    finalized_time = result(block_time_response)

    live_ed25519 = [
        entry
        for entry in storage_decoded.get("initialized_ed25519_entries", [])
        if isinstance(finalized_time, int) and entry["expires_at"] > finalized_time
    ]
    live_ecdsa = [
        entry
        for entry in storage_decoded.get("initialized_ecdsa_entries", [])
        if isinstance(finalized_time, int) and entry["expires_at"] > finalized_time
    ]

    account_summaries = {
        PROGRAM_ID: account_summary(PROGRAM_ID, program_account),
        STORAGE_ID: account_summary(STORAGE_ID, storage_account),
    }
    for address, account in second_by_address.items():
        account_summaries[address] = account_summary(address, account)

    checks: dict[str, bool] = {
        "program_exists": program_account is not None,
        "program_executable": bool(program_account and program_account.get("executable")),
        "program_owned_by_upgradeable_loader": bool(
            program_account and program_account.get("owner") == UPGRADEABLE_LOADER
        ),
        "program_account_state_valid": not program_decoded.get("decode_errors"),
        "storage_exists": storage_account is not None,
        "storage_owned_by_program": bool(
            storage_account and storage_account.get("owner") == PROGRAM_ID
        ),
        "storage_not_executable": bool(
            storage_account and not storage_account.get("executable")
        ),
        "storage_length_expected": storage_decoded.get("raw_length") == 381,
        "storage_discriminator_matches": bool(
            storage_decoded.get("discriminator_matches")
        ),
        "storage_decode_clean": not storage_decoded.get("decode_errors"),
        "top_authority_nonzero": storage_decoded.get("top_authority_hex")
        not in (None, "00" * 32),
        "treasury_nonzero": storage_decoded.get("treasury_hex")
        not in (None, "00" * 32),
        "fee_expected": storage_decoded.get("single_update_fee_in_lamports") == 1,
        "ed25519_count_within_contract_max": isinstance(
            storage_decoded.get("num_trusted_signers"), int
        )
        and storage_decoded["num_trusted_signers"] <= 2,
        "ecdsa_count_within_contract_max": isinstance(
            storage_decoded.get("num_trusted_ecdsa_signers"), int
        )
        and storage_decoded["num_trusted_ecdsa_signers"] <= 2,
        "has_live_ed25519_signer": len(live_ed25519) > 0,
        "has_live_ecdsa_signer": len(live_ecdsa) > 0,
        "programdata_exists": programdata_account is not None,
        "programdata_owned_by_upgradeable_loader": bool(
            programdata_account
            and programdata_account.get("owner") == UPGRADEABLE_LOADER
        ),
        "programdata_state_valid": not programdata_decoded.get("decode_errors"),
        "program_bytecode_nonempty": programdata_decoded.get("bytecode_length", 0) > 0,
    }

    anomalies = [name for name, passed in checks.items() if not passed]
    critical_signals = []
    for entry in live_ed25519:
        if "staging_fixture" in entry["fixture_labels"]:
            critical_signals.append(
                {"type": "live_staging_ed25519_signer", "entry": entry}
            )
    for entry in live_ecdsa:
        if "staging_fixture" in entry["fixture_labels"]:
            critical_signals.append(
                {"type": "live_staging_ecdsa_signer", "entry": entry}
            )

    report = {
        "generated_at_unix": int(time.time()),
        "read_only": True,
        "transactions_constructed": 0,
        "transactions_signed": 0,
        "transactions_broadcast": 0,
        "rpc": rpc_url,
        "rpc_attempts": rpc_attempts,
        "finalized_slot": finalized_slot,
        "finalized_block_time": finalized_time,
        "program": account_summaries.get(PROGRAM_ID),
        "program_decoded": program_decoded,
        "storage": account_summaries.get(STORAGE_ID),
        "storage_decoded": storage_decoded,
        "programdata": account_summaries.get(programdata_address),
        "programdata_decoded": programdata_decoded,
        "top_authority_account": account_summaries.get(top_authority),
        "treasury_account": account_summaries.get(treasury),
        "upgrade_authority_account": account_summaries.get(upgrade_authority),
        "live_ed25519_signers": live_ed25519,
        "live_ecdsa_signers": live_ecdsa,
        "checks": checks,
        "anomalies": anomalies,
        "critical_signals": critical_signals,
        "raw_rpc": {
            "slot": slot_response,
            "block_time": block_time_response,
        },
    }
    OUT.joinpath("results.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    OUT.joinpath("critical_signals.json").write_text(
        json.dumps(critical_signals, indent=2, sort_keys=True)
    )
    OUT.joinpath("account_summaries.json").write_text(
        json.dumps(account_summaries, indent=2, sort_keys=True)
    )

    summary = [
        "# Pyth Lazer Solana mainnet read-only census",
        "",
        f"RPC: {rpc_url}",
        f"Finalized slot: {finalized_slot}",
        f"Finalized block time: {finalized_time}",
        f"Program: {PROGRAM_ID}",
        f"Storage PDA: {STORAGE_ID}",
        f"Top authority: {top_authority}",
        f"Upgrade authority: {upgrade_authority or 'immutable / none'}",
        f"Live Ed25519 signers: {len(live_ed25519)}",
        f"Live ECDSA signers: {len(live_ecdsa)}",
        f"Failed gates: {len(anomalies)}",
        f"Takeover-class signals: {len(critical_signals)}",
        "Public-chain transactions broadcast: 0",
        "",
        "## Failed gates",
        "",
        *(f"- {name}" for name in anomalies),
        "",
        "## Live Ed25519 signers",
        "",
        *(f"- `{entry['public_key_hex']}` expires `{entry['expires_at']}` labels={entry['fixture_labels']}" for entry in live_ed25519),
        "",
        "## Live ECDSA signers",
        "",
        *(f"- `{entry['address']}` expires `{entry['expires_at']}` labels={entry['fixture_labels']}" for entry in live_ecdsa),
    ]
    OUT.joinpath("SUMMARY.md").write_text("\n".join(summary) + "\n")
    print("SOLANA_CENSUS_COMPLETE")


if __name__ == "__main__":
    main()
