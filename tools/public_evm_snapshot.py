#!/usr/bin/env python3
from __future__ import annotations

import json
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
START_BLOCK = 25_000_000

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
            req = urllib.request.Request(url, data=body, headers={"content-type": "application/json", "user-agent": "public-evm-snapshot/1.0"})
            with urllib.request.urlopen(req, timeout=90) as response:
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

def owner_call(selector: str, token_id: int) -> str | None:
    return address_result(eth_call(DEPLOYER, selector + encode_u256(token_id)))

def get_balance(address: str, tag: str = "latest") -> int:
    raw, _ = rpc("eth_getBalance", [address, tag])
    return int(raw, 16)

def get_code(address: str, tag: str = "latest") -> str:
    raw, _ = rpc("eth_getCode", [address, tag])
    return raw

def chunked_logs(address: str, topic0: str, start: int, end: int, chunk: int = 4_000):
    rows = []
    current = start
    while current <= end:
        stop = min(end, current + chunk - 1)
        result, _ = rpc("eth_getLogs", [{
            "fromBlock": hex(current),
            "toBlock": hex(stop),
            "address": address,
            "topics": [topic0],
        }])
        rows.extend(result)
        current = stop + 1
    return rows

chain_id_raw, provider = rpc("eth_chainId", [])
latest_raw, _ = rpc("eth_blockNumber", [])
latest = int(latest_raw, 16)

addresses = {
    "previous_bridge": owner_call("0xe2603dc2", 5),
    "current_bridge": owner_call("0x6352211e", 5),
    "multicall": MULTICALL,
    "cross_chain_factory": FACTORY,
    "nucleus_teller": TELLER,
}

snapshot = {
    "provider": provider,
    "chain_id": int(chain_id_raw, 16),
    "latest_block": latest,
    "addresses": {},
}
for label, address in addresses.items():
    if address is None:
        snapshot["addresses"][label] = None
        continue
    snapshot["addresses"][label] = {
        "address": address,
        "native_balance_wei": get_balance(address),
        "code": get_code(address),
    }

logs = chunked_logs(TELLER, MESSAGE_SENT_TOPIC, START_BLOCK, latest)
log_rows = []
for log in logs:
    block_number = int(log["blockNumber"], 16)
    tx_hash = log["transactionHash"]
    tx, _ = rpc("eth_getTransactionByHash", [tx_hash])
    receipt, _ = rpc("eth_getTransactionReceipt", [tx_hash])
    row = {
        "block_number": block_number,
        "transaction_hash": tx_hash,
        "transaction_from": tx.get("from") if tx else None,
        "transaction_to": tx.get("to") if tx else None,
        "transaction_value_wei": int(tx.get("value", "0x0"), 16) if tx else None,
        "status": int(receipt.get("status", "0x0"), 16) if receipt else None,
        "log_index": int(log["logIndex"], 16),
        "data": log["data"],
        "topics": log["topics"],
    }
    for label in ("previous_bridge", "current_bridge"):
        address = addresses[label]
        if address:
            try:
                row[f"{label}_balance_at_block_wei"] = get_balance(address, hex(block_number))
                row[f"{label}_balance_previous_block_wei"] = get_balance(address, hex(block_number - 1))
            except Exception as exc:
                row[f"{label}_balance_error"] = repr(exc)
    log_rows.append(row)

snapshot["nucleus_message_sent_count"] = len(log_rows)
snapshot["nucleus_message_sent"] = log_rows

(OUT / "snapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n")
print(json.dumps({
    "provider": provider,
    "latest_block": latest,
    "addresses": {
        label: None if row is None else {
            "address": row["address"],
            "native_balance_wei": row["native_balance_wei"],
            "code_bytes": (len(row["code"]) - 2) // 2,
        }
        for label, row in snapshot["addresses"].items()
    },
    "nucleus_message_sent_count": len(log_rows),
}, indent=2))
