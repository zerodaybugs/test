#!/usr/bin/env python3
from __future__ import annotations

import json
import traceback
import urllib.request
from pathlib import Path

RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://1rpc.io/eth",
]

DEPLOYER = "0x00000000000004533Fe15556B1E086BB1A72cEae"
MULTICALL = "0x00000000000000CF9E3c5A26621af382fA17f24f"
FACTORY = "0x00000000000000304861c3aDfb80dd5ebeC96325"
TELLER = "0xeE98730AAAdA5e6e092cA69F1AC1B9B554c059dF"
MESSAGE_SENT_TOPIC = "0xe0ec62d39b054dc2fd626dbc271483735df6e6fa1ef8389754bf8ab27a75eab2"
REFERENCE_BLOCK = 25_180_132

OUT = Path("snapshot-output")
OUT.mkdir(exist_ok=True)
_request_id = 0


def rpc(method: str, params: list):
    global _request_id
    _request_id += 1
    body = json.dumps({"jsonrpc": "2.0", "id": _request_id, "method": method, "params": params}).encode()
    errors = []
    for url in RPCS:
        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={"content-type": "application/json", "user-agent": "public-evm-snapshot/2.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as response:
                payload = json.load(response)
            if "error" in payload:
                raise RuntimeError(payload["error"])
            return payload["result"], url
        except Exception as exc:
            errors.append(f"{url}: {exc!r}")
    raise RuntimeError(f"{method} failed: {errors}")


def eth_call(to: str, data: str, tag: str = "latest") -> str:
    result, _ = rpc("eth_call", [{"to": to, "data": data}, tag])
    return result


def address_result(raw: str) -> str | None:
    if not raw or raw == "0x":
        return None
    value = "0x" + raw[-40:]
    return None if int(value, 16) == 0 else value


def encode_u256(value: int) -> str:
    return hex(value)[2:].rjust(64, "0")


def safe(label: str, fn):
    try:
        return {"ok": True, "value": fn()}
    except Exception as exc:
        return {"ok": False, "error": repr(exc), "traceback": traceback.format_exc()}


def get_balance(address: str, tag: str = "latest") -> int:
    raw, _ = rpc("eth_getBalance", [address, tag])
    return int(raw, 16)


def get_code(address: str, tag: str = "latest") -> str:
    raw, _ = rpc("eth_getCode", [address, tag])
    return raw


def resolve(selector: str, token_id: int) -> str | None:
    return address_result(eth_call(DEPLOYER, selector + encode_u256(token_id)))


snapshot: dict = {"reference_block": REFERENCE_BLOCK, "addresses": {}, "diagnostics": {}}
chain = safe("chain", lambda: rpc("eth_chainId", []))
latest = safe("latest", lambda: rpc("eth_blockNumber", []))
snapshot["diagnostics"]["chain"] = chain
snapshot["diagnostics"]["latest"] = latest
if not chain["ok"] or not latest["ok"]:
    (OUT / "snapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n")
    raise SystemExit(0)

snapshot["chain_id"] = int(chain["value"][0], 16)
snapshot["provider"] = chain["value"][1]
snapshot["latest_block"] = int(latest["value"][0], 16)

resolved = {
    "previous_bridge": safe("previous_bridge", lambda: resolve("0xe2603dc2", 5)),
    "current_bridge": safe("current_bridge", lambda: resolve("0x6352211e", 5)),
    "multicall": {"ok": True, "value": MULTICALL},
    "cross_chain_factory": {"ok": True, "value": FACTORY},
    "nucleus_teller": {"ok": True, "value": TELLER},
}
snapshot["diagnostics"]["resolved"] = resolved

for label, result in resolved.items():
    address = result.get("value") if result.get("ok") else None
    if not address:
        snapshot["addresses"][label] = result
        continue
    row = {"address": address}
    for tag_name, tag in [
        ("latest", "latest"),
        ("reference", hex(REFERENCE_BLOCK)),
        ("reference_previous", hex(REFERENCE_BLOCK - 1)),
    ]:
        row[f"balance_{tag_name}"] = safe(label, lambda address=address, tag=tag: get_balance(address, tag))
    row["code_latest"] = safe(label, lambda address=address: get_code(address))
    snapshot["addresses"][label] = row

# Optional, fail-soft event scan around the known integration era and recent blocks.
log_ranges = [
    (25_170_000, min(snapshot["latest_block"], 25_200_000)),
    (max(0, snapshot["latest_block"] - 100_000), snapshot["latest_block"]),
]
log_rows = []
for start, end in log_ranges:
    if start > end:
        continue
    current = start
    while current <= end:
        stop = min(end, current + 1_999)
        result = safe(
            "logs",
            lambda current=current, stop=stop: rpc(
                "eth_getLogs",
                [{
                    "fromBlock": hex(current),
                    "toBlock": hex(stop),
                    "address": TELLER,
                    "topics": [MESSAGE_SENT_TOPIC],
                }],
            ),
        )
        if not result["ok"]:
            snapshot["diagnostics"].setdefault("log_errors", []).append({
                "from": current,
                "to": stop,
                "error": result["error"],
            })
            break
        logs = result["value"][0]
        log_rows.extend(logs)
        current = stop + 1

snapshot["nucleus_message_sent"] = log_rows
snapshot["nucleus_message_sent_count"] = len(log_rows)
(OUT / "snapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n")
print(json.dumps({
    "chain_id": snapshot.get("chain_id"),
    "provider": snapshot.get("provider"),
    "latest_block": snapshot.get("latest_block"),
    "addresses": {
        label: row.get("address") if isinstance(row, dict) else None
        for label, row in snapshot["addresses"].items()
    },
    "nucleus_message_sent_count": len(log_rows),
    "log_error_count": len(snapshot["diagnostics"].get("log_errors", [])),
}, indent=2))
