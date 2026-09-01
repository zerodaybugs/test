#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("evidence-cardano-assets")
OUT.mkdir(parents=True, exist_ok=True)
BASE = "https://api.koios.rest/api/v1"
ASSETS = {
    "pyth_state": (
        "c935c937d0deda8975142c7b77aeef8f8cd48791e89a8ca7a0edc154",
        "50797468205374617465",
    ),
    "pyth_ops": (
        "c935c937d0deda8975142c7b77aeef8f8cd48791e89a8ca7a0edc154",
        "50797468204f7073",
    ),
    "wormhole_state": (
        "59853d703e416898c4c36f2ea8310a2b6f764f9dcc02ae5f58dc93e5",
        "5079746820576f726d686f6c65",
    ),
    "wormhole_ops": (
        "59853d703e416898c4c36f2ea8310a2b6f764f9dcc02ae5f58dc93e5",
        "5079746820576f726d686f6c65204f7073",
    ),
}
BECH32_MAP = {c: i for i, c in enumerate("qpzry9x8gf2tvdw0s3jn54khce6mua7l")}


def get_json(url: str, body: dict[str, Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": "pyth-cardano-all-assets-census/1",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def convert_bits(data: list[int], from_bits: int, to_bits: int) -> bytes:
    acc = 0
    bits = 0
    out = bytearray()
    maxv = (1 << to_bits) - 1
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & maxv)
    return bytes(out)


def classify_address(address: str | None) -> dict[str, Any]:
    if not address or "1" not in address:
        return {"address_type": None, "payment_credential_type": None}
    _, encoded = address.rsplit("1", 1)
    try:
        values = [BECH32_MAP[c] for c in encoded[:-6]]
        raw = convert_bits(values, 5, 8)
        header = raw[0]
        kind = header >> 4
    except Exception:
        return {"address_type": "decode_error", "payment_credential_type": None}
    names = {
        0: ("base_key_key", "key"),
        1: ("base_script_key", "script"),
        2: ("base_key_script", "key"),
        3: ("base_script_script", "script"),
        4: ("pointer_key", "key"),
        5: ("pointer_script", "script"),
        6: ("enterprise_key", "key"),
        7: ("enterprise_script", "script"),
        8: ("byron", "byron"),
        14: ("reward_key", "key"),
        15: ("reward_script", "script"),
    }
    name, payment = names.get(kind, (f"unknown_{kind}", "unknown"))
    return {
        "address_header": header,
        "address_type": name,
        "payment_credential_type": payment,
    }


def normalized_row(item: dict[str, Any]) -> dict[str, Any]:
    row = {
        "tx_hash": item.get("tx_hash"),
        "tx_index": item.get("tx_index"),
        "address": item.get("address"),
        "payment_cred": item.get("payment_cred"),
        "stake_address": item.get("stake_address"),
        "datum_hash": item.get("datum_hash"),
        "inline_datum": item.get("inline_datum"),
        "reference_script": item.get("reference_script"),
        "asset_list": item.get("asset_list"),
        "is_spent": item.get("is_spent"),
        "block_height": item.get("block_height"),
        "block_time": item.get("block_time"),
    }
    row.update(classify_address(row["address"]))
    return row


def main() -> int:
    result: dict[str, Any] = {
        "schema": "pyth-cardano-all-assets-census/v1",
        "generated_at_unix": int(time.time()),
        "assets": {},
    }
    errors: list[dict[str, str]] = []
    for name, (policy, asset_name) in ASSETS.items():
        try:
            payload = get_json(
                f"{BASE}/asset_utxos",
                {"_asset_list": [[policy, asset_name]], "_extended": True},
            )
            rows = [normalized_row(item) for item in payload if isinstance(item, dict)]
            result["assets"][name] = {
                "policy_id": policy,
                "asset_name_hex": asset_name,
                "utxo_count": len(rows),
                "rows": rows,
            }
        except Exception as error:
            errors.append({"asset": name, "error": repr(error)})
            result["assets"][name] = {
                "policy_id": policy,
                "asset_name_hex": asset_name,
                "utxo_count": 0,
                "rows": [],
            }
    result["errors"] = errors
    (OUT / "census.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    lines: list[str] = []
    for name, value in result["assets"].items():
        lines.append(f"{name.upper()}_UTXO_COUNT={value['utxo_count']}")
        for index, row in enumerate(value["rows"]):
            prefix = f"{name.upper()}_{index}"
            lines.extend(
                [
                    f"{prefix}_OUTREF={row['tx_hash']}#{row['tx_index']}",
                    f"{prefix}_ADDRESS={row['address']}",
                    f"{prefix}_ADDRESS_TYPE={row['address_type']}",
                    f"{prefix}_PAYMENT_CREDENTIAL_TYPE={row['payment_credential_type']}",
                    f"{prefix}_PAYMENT_CRED={row['payment_cred']}",
                    f"{prefix}_INLINE_DATUM={row['inline_datum'] is not None}",
                    f"{prefix}_REFERENCE_SCRIPT={row['reference_script'] is not None}",
                    f"{prefix}_IS_SPENT={row['is_spent']}",
                ]
            )
    lines.append(f"ERROR_COUNT={len(errors)}")
    text = "\n".join(lines) + "\n"
    (OUT / "summary.txt").write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
