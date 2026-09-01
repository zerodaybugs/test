#!/usr/bin/env python3
"""Read-only eth_call simulation of Prime Yield's live dealBadDebt bucket.

No transaction is signed or broadcast. The script simulates the state-changing call
against a pinned latest block and includes an insufficient-share negative control.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path("termmax-prime-dealbaddebt-simulation")
RPCS = [
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
    "https://ethereum-rpc.publicnode.com",
]
VAULT = "0x17337c22cf8b7c1b6fc86f0ef7fcf05a7fa93f48"
COLLATERAL = "0xa3ca88cfb7bbe9cfbd47df053ffa2130c7e6f770"
BAD_DEBT = 939_875
RECIPIENT = "0x1111111111111111111111111111111111111111"
EMPTY_EOA = "0x2222222222222222222222222222222222222222"
CANDIDATE_HOLDERS = [
    "0xd22ce4fc867dcce46bbd74be535f41e2444395c1",
    "0x20b20eae302c821b53018037b0f3c1ec90c0af5b",
    "0x40e0e194bcf8cb5f876b92827503eee84727a3a3",
    "0xaf96b0a1f6c294cffad0a6be13735f7601d12c82",
    "0x9a85709e9d9badc12d1703401edc5e0c706081e9",
    "0x3b368bfe0c2825b0d89adb76fb29d7f54db2cc1b",
]
S = {
    "previewWithdraw": "0x0a28a477",
    "previewMint": "0xb3d7f6b9",
    "balanceOf": "0x70a08231",
    "dealBadDebt": "0x7207fbb4",
    "badDebtMapping": "0x618f9694",
    "totalAssets": "0x01e1d114",
    "totalSupply": "0x18160ddd",
    "maxDeposit": "0x402d267d",
    "paused": "0x5c975abb",
}


def rpc_one(url: str, method: str, params: list[Any]) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json", "user-agent": "termmax-prime-dealbaddebt-readonly/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        body = json.load(response)
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body.get("result")


def rpc(method: str, params: list[Any]) -> tuple[Any, str]:
    errors: list[str] = []
    for url in RPCS:
        try:
            return rpc_one(url, method, params), url
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(" | ".join(errors))


def word(data: str, index: int = 0) -> str:
    raw = (data or "0x").removeprefix("0x")
    return raw[index * 64 : (index + 1) * 64].ljust(64, "0")


def uint(data: str, index: int = 0) -> int:
    return int(word(data, index) or "0", 16)


def arg_uint(value: int) -> str:
    return f"{value:064x}"


def arg_address(address: str) -> str:
    return address.removeprefix("0x").lower().rjust(64, "0")


def call(to: str, data: str, block: int, from_address: str | None = None) -> dict[str, Any]:
    tx: dict[str, Any] = {"to": to, "data": data}
    if from_address:
        tx["from"] = from_address
    try:
        raw, url = rpc("eth_call", [tx, hex(block)])
        return {"ok": True, "raw": raw, "rpc": url, "blockTag": hex(block)}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "blockTag": hex(block)}


def block_meta(number: int) -> dict[str, Any]:
    block, url = rpc("eth_getBlockByNumber", [hex(number), False])
    timestamp = int(block["timestamp"], 16)
    return {
        "number": number,
        "hash": block.get("hash"),
        "timestamp": timestamp,
        "timestampUtc": dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat(),
        "rpc": url,
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    latest_hex, _ = rpc("eth_blockNumber", [])
    block = int(latest_hex, 16)
    meta = block_meta(block)

    preview = call(VAULT, S["previewWithdraw"] + arg_uint(BAD_DEBT), block)
    if not preview.get("ok"):
        raise RuntimeError(f"previewWithdraw failed: {preview}")
    shares_required = uint(preview["raw"])

    preview_mint = call(VAULT, S["previewMint"] + arg_uint(shares_required), block)
    if not preview_mint.get("ok"):
        raise RuntimeError(f"previewMint failed: {preview_mint}")
    assets_required = uint(preview_mint["raw"])

    holders: list[dict[str, Any]] = []
    selected: str | None = None
    for holder in CANDIDATE_HOLDERS:
        response = call(VAULT, S["balanceOf"] + arg_address(holder), block)
        balance = uint(response["raw"]) if response.get("ok") else None
        holders.append({"holder": holder, "balanceResponse": response, "balance": balance})
        if selected is None and balance is not None and balance >= shares_required:
            selected = holder
    if selected is None:
        raise RuntimeError("no current holder has enough shares for the simulation")

    current_bad = call(VAULT, S["badDebtMapping"] + arg_address(COLLATERAL), block)
    total_assets = call(VAULT, S["totalAssets"], block)
    total_supply = call(VAULT, S["totalSupply"], block)
    max_deposit = call(VAULT, S["maxDeposit"] + arg_address(EMPTY_EOA), block)
    paused = call(VAULT, S["paused"], block)

    calldata = (
        S["dealBadDebt"]
        + arg_address(COLLATERAL)
        + arg_uint(BAD_DEBT)
        + arg_address(RECIPIENT)
        + arg_address(selected)
    )
    positive = call(VAULT, calldata, block, selected)
    if positive.get("ok"):
        positive["decoded"] = {
            "sharesBurned": uint(positive["raw"], 0),
            "collateralOut": uint(positive["raw"], 1),
        }

    control_calldata = (
        S["dealBadDebt"]
        + arg_address(COLLATERAL)
        + arg_uint(BAD_DEBT)
        + arg_address(RECIPIENT)
        + arg_address(EMPTY_EOA)
    )
    negative = call(VAULT, control_calldata, block, EMPTY_EOA)

    result = {
        "schema": "termmax-prime-dealbaddebt-simulation/v1",
        "generatedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "safety": {
            "signedTransactions": 0,
            "broadcastTransactions": 0,
            "method": "eth_call",
        },
        "block": meta,
        "addresses": {
            "vault": VAULT,
            "collateral": COLLATERAL,
            "selectedHolder": selected,
            "recipient": RECIPIENT,
            "negativeControlEOA": EMPTY_EOA,
        },
        "preState": {
            "badDebtRaw": uint(current_bad["raw"]) if current_bad.get("ok") else None,
            "totalAssetsRaw": uint(total_assets["raw"]) if total_assets.get("ok") else None,
            "totalSupplyRaw": uint(total_supply["raw"]) if total_supply.get("ok") else None,
            "maxDepositRaw": uint(max_deposit["raw"]) if max_deposit.get("ok") else None,
            "paused": bool(uint(paused["raw"])) if paused.get("ok") else None,
            "holders": holders,
        },
        "economics": {
            "badDebtRaw": BAD_DEBT,
            "sharesRequired": shares_required,
            "freshEntrantAssetsRequiredRaw": assets_required,
        },
        "positiveSimulation": positive,
        "negativeControl": negative,
    }
    result["assertions"] = {
        "bucketPresent": result["preState"]["badDebtRaw"] == BAD_DEBT,
        "depositOpen": (result["preState"]["maxDepositRaw"] or 0) > 0 and result["preState"]["paused"] is False,
        "ordinaryHolderReachable": positive.get("ok") is True,
        "burnMatchesPreview": positive.get("decoded", {}).get("sharesBurned") == shares_required,
        "allCollateralOut": positive.get("decoded", {}).get("collateralOut") == 9_267,
        "emptyHolderRejected": negative.get("ok") is False,
    }
    result["status"] = "PASS" if all(result["assertions"].values()) else "FAIL"
    (OUT / "SUMMARY.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    concise = {
        "status": result["status"],
        "block": meta,
        "selectedHolder": selected,
        "economics": result["economics"],
        "positive": positive,
        "negativeControl": negative,
        "assertions": result["assertions"],
    }
    (OUT / "CONCISE.json").write_text(json.dumps(concise, indent=2), encoding="utf-8")
    print(json.dumps(concise, indent=2))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
