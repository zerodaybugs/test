#!/usr/bin/env python3
"""Cross-check Pyth EVM Lazer signer array, expiry mapping and validity view.

The mapping was introduced after the original array-based implementation. This
read-only follow-up checks for missing backfill and stale live mapping entries.
It never signs or broadcasts a transaction.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

INPUT = Path("evidence/legacy_storage/results.json")
OUT = Path("evidence/mapping_consistency")
IS_VALID_SELECTOR = "0xd5f50582"  # isValidSigner(address)
GET_EXPIRY_SELECTOR = "0xe656a69d"  # getTrustedSignerExpiry(address)
MAPPING_BASE_SLOT = 201
ZERO = "0x0000000000000000000000000000000000000000"

# Publicly documented fixture identities. These are audit probes only; no key is
# embedded. The staging identity has a golden signed update in the upstream test
# corpus, while the production identity appears in current live fixtures.
FIXTURE_ADDRESSES = {
    "staging_fixture": "0xb8d50f0bae75bf6e03c104903d7c3afc4a6596da",
    "production_fixture": "0x26fb61a864c758ae9fba027a96010480658385b9",
}


def enc_address(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64, "0")


def mapping_slot(address: str) -> str:
    preimage = bytes.fromhex(enc_address(address) + f"{MAPPING_BASE_SLOT:064x}")
    digest = subprocess.check_output(
        ["openssl", "dgst", "-keccak-256", "-binary"], input=preimage
    )
    return "0x" + digest.hex()


def rpc(url: str, method: str, params: list[Any], timeout: int = 25) -> dict[str, Any]:
    encoded = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        separators=(",", ":"),
    ).encode()
    last: Exception | None = None
    for attempt in range(3):
        request = urllib.request.Request(
            url,
            data=encoded,
            method="POST",
            headers={
                "content-type": "application/json",
                "user-agent": "Pyth-authorized-read-only-mapping-census/2026-07-30",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                item = json.loads(response.read())
            if isinstance(item, dict):
                return item
            raise ValueError("non-object response")
        except Exception as error:
            last = error
            time.sleep(0.5 * (attempt + 1))
    return {"error": {"message": type(last).__name__ if last else "RPC failure"}}


def rpc_batch(url: str, calls: list[tuple[str, str, list[Any]]]) -> dict[str, dict[str, Any]]:
    if not calls:
        return {}
    payload = [
        {"jsonrpc": "2.0", "id": index + 1, "method": method, "params": params}
        for index, (_, method, params) in enumerate(calls)
    ]
    encoded = json.dumps(payload, separators=(",", ":")).encode()
    try:
        request = urllib.request.Request(
            url,
            data=encoded,
            method="POST",
            headers={
                "content-type": "application/json",
                "user-agent": "Pyth-authorized-read-only-mapping-census/2026-07-30",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read())
        if not isinstance(data, list):
            raise ValueError("batch unsupported")
        indexed = {
            int(item["id"]): item
            for item in data
            if isinstance(item, dict) and item.get("id") is not None
        }
        if set(indexed) != set(range(1, len(calls) + 1)):
            raise ValueError("incomplete batch")
        return {
            name: indexed[index + 1]
            for index, (name, _, _) in enumerate(calls)
        }
    except Exception:
        return {
            name: rpc(url, method, params)
            for name, method, params in calls
        }


def result(item: Any) -> Any:
    return item.get("result") if isinstance(item, dict) else None


def uint(value: str | None) -> int | None:
    if not value or value == "0x":
        return None
    return int(value, 16)


def boolean(value: str | None) -> bool | None:
    parsed = uint(value)
    return None if parsed is None else bool(parsed)


def inspect(record: dict[str, Any], candidates: list[str]) -> dict[str, Any]:
    chain = record["chain"]
    address = record["address"]
    url = record.get("selected_rpc")
    timestamp = record.get("latest_timestamp")
    array_entries = {
        item["address"].lower(): int(item["expires_at"])
        for item in record.get("storage_signers", [])
    }
    output: dict[str, Any] = {
        "chain": chain,
        "address": address,
        "rpc": url,
        "timestamp": timestamp,
        "version": record.get("version"),
        "rows": [],
        "anomalies": [],
        "critical_signals": [],
    }
    if not url:
        output["anomalies"].append("no_confirmed_rpc")
        return output

    calls: list[tuple[str, str, list[Any]]] = []
    for index, signer in enumerate(candidates):
        encoded = enc_address(signer)
        calls.extend(
            [
                (
                    f"valid_{index}",
                    "eth_call",
                    [{"to": address, "data": IS_VALID_SELECTOR + encoded}, "latest"],
                ),
                (
                    f"mapping_{index}",
                    "eth_getStorageAt",
                    [address, mapping_slot(signer), "latest"],
                ),
                (
                    f"getter_{index}",
                    "eth_call",
                    [{"to": address, "data": GET_EXPIRY_SELECTOR + encoded}, "latest"],
                ),
            ]
        )
    responses = rpc_batch(url, calls)

    for index, signer in enumerate(candidates):
        signer = signer.lower()
        array_expiry = array_entries.get(signer)
        mapping_expiry = uint(result(responses[f"mapping_{index}"]))
        validity = boolean(result(responses[f"valid_{index}"]))
        getter_expiry = uint(result(responses[f"getter_{index}"]))
        getter_supported = result(responses[f"getter_{index}"]) is not None
        expected_valid = (
            mapping_expiry is not None
            and timestamp is not None
            and mapping_expiry > timestamp
        )
        row = {
            "signer": signer,
            "labels": [
                label for label, value in FIXTURE_ADDRESSES.items()
                if value.lower() == signer
            ],
            "in_array": array_expiry is not None,
            "array_expiry": array_expiry,
            "mapping_expiry": mapping_expiry,
            "getter_supported": getter_supported,
            "getter_expiry": getter_expiry,
            "is_valid": validity,
            "expected_valid_from_mapping": expected_valid,
            "mapping_slot": mapping_slot(signer),
            "raw": {
                "valid": responses[f"valid_{index}"],
                "mapping": responses[f"mapping_{index}"],
                "getter": responses[f"getter_{index}"],
            },
            "anomalies": [],
        }
        if mapping_expiry is None or validity is None:
            row["anomalies"].append("mapping_or_validity_read_failed")
        else:
            if validity != expected_valid:
                row["anomalies"].append("is_valid_mapping_disagreement")
            if array_expiry is not None and array_expiry != mapping_expiry:
                row["anomalies"].append("array_mapping_expiry_mismatch")
            if array_expiry is None and mapping_expiry > 0:
                row["anomalies"].append("mapping_entry_not_present_in_array")
            if getter_supported and getter_expiry != mapping_expiry:
                row["anomalies"].append("getter_mapping_expiry_mismatch")
            if array_expiry is not None and timestamp is not None:
                array_live = array_expiry > timestamp
                if array_live and not validity:
                    row["anomalies"].append("live_array_signer_rejected_by_mapping")
                if not array_live and validity:
                    row["anomalies"].append("expired_array_signer_accepted")
            if (
                array_expiry is None
                and validity is True
                and timestamp is not None
                and mapping_expiry > timestamp
            ):
                row["anomalies"].append("stale_live_mapping_signer")
                output["critical_signals"].append(
                    {"type": "stale_live_mapping_signer", "signer": signer}
                )
        output["rows"].append(row)
        if row["anomalies"]:
            output["anomalies"].append(
                {"signer": signer, "issues": row["anomalies"]}
            )
    return output


def main() -> None:
    records = json.loads(INPUT.read_text())
    unique = {value.lower() for value in FIXTURE_ADDRESSES.values()}
    for record in records:
        for item in record.get("storage_signers", []):
            unique.add(item["address"].lower())
        for item in record.get("getter_signers") or []:
            unique.add(item["address"].lower())
    candidates = sorted(unique)

    OUT.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(inspect, record, candidates) for record in records]
        results = []
        for future, record in zip(futures, records):
            try:
                results.append(future.result())
            except Exception as error:
                results.append(
                    {
                        "chain": record["chain"],
                        "address": record["address"],
                        "anomalies": ["inspection_exception"],
                        "critical_signals": [],
                        "exception_type": type(error).__name__,
                    }
                )
    results.sort(key=lambda item: item["chain"])
    anomalies = [item for item in results if item.get("anomalies")]
    critical = [item for item in results if item.get("critical_signals")]
    OUT.joinpath("results.json").write_text(json.dumps(results, indent=2, sort_keys=True))
    OUT.joinpath("anomalies.json").write_text(json.dumps(anomalies, indent=2, sort_keys=True))
    OUT.joinpath("critical_signals.json").write_text(json.dumps(critical, indent=2, sort_keys=True))
    OUT.joinpath("candidates.json").write_text(json.dumps(candidates, indent=2))

    lines = [
        "# Pyth EVM signer mapping consistency",
        "",
        f"Chains: {len(results)}",
        f"Candidate signer identities: {len(candidates)}",
        f"Chains with inconsistencies: {len(anomalies)}",
        f"Chains with stale-live mapping signals: {len(critical)}",
        "Public-chain transactions broadcast: 0",
        "",
        "| Chain | Version | Inconsistency rows | Critical signals |",
        "|---|---|---:|---:|",
    ]
    for item in results:
        lines.append(
            f"| {item['chain']} | {item.get('version') or 'N/A'} | "
            f"{len(item.get('anomalies', []))} | {len(item.get('critical_signals', []))} |"
        )
    OUT.joinpath("SUMMARY.md").write_text("\n".join(lines) + "\n")
    print("MAPPING_CONSISTENCY_COMPLETE")


if __name__ == "__main__":
    main()
