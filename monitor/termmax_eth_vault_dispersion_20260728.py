#!/usr/bin/env python3
"""Public read-only recovery-dispersion census for known Ethereum TermMax V2 vaults.

The monitor inventories current vault balances and mature order recoveries using
only public ``eth_call`` and indexed HTTPS GET requests. It contains no exploit
execution, signing code, private key, or transaction-broadcast capability.
"""
from __future__ import annotations

import importlib.util
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hexbytes import HexBytes
from web3 import Web3

BASE_PATH = Path(__file__).with_name("termmax_state_20260728.py")
SPEC = importlib.util.spec_from_file_location("termmax_census_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load base monitor")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

# Factory snapshot captured at Ethereum block 25,577,000. New factory events are
# scanned separately from that block forward.
KNOWN_VAULTS = [
    ("0xD7977c2A74005CA3af5b201546369F0c7c177842", 23446046, "TMX-USDC-Test"),
    ("0xF488ccdf04079cC03183cDB6A147d12Cf97F9317", 23490022, "TermMax USDC Vault V2"),
    ("0x95fB87609f80c47e3102B976455023D2B9BE9b8F", 23490023, "TermMax WETH Vault V2"),
    ("0xfd2ddb1f5989491967c7598da1d3D65324522339", 23516442, "InfiniFi USDC Vault"),
    ("0x17337c22CF8b7C1B6fC86F0ef7Fcf05a7fA93f48", 23516443, "Prime Yield"),
    ("0xd7114698d3d6DE7389a6cB94dc6f3F9C2eA08D03", 23519461, "MEV Capital USDC v2"),
    ("0x0093e24Af6Ff1E6aC61CE756bD1F772be6187E89", 23519462, "amphrETH"),
    ("0xB3C2C8c6670bB1DbE20CD37193d7e1334730e333", 23524960, "TermMax WBTC V2"),
    ("0x18d91B5e3218AB16Ef86fB7Cb054CB48bA1e8b8e", 23524961, "USDU Core"),
    ("0xBbf747e83f2f1650F7B303F6166Fc3fE8a5B0cE5", 23540487, "Edge Capital UltraYield"),
    ("0xad58811276A0b9fB842E860774793a9663094879", 23567600, "TermMax USDC Reactor"),
    ("0x7FF1f331af4a90f6b14F57cB24977f74be3FF31d", 23567605, "Keyrock USDC"),
    ("0x5b98E87312487A9e09365E63dAc4BdBBf9569C2F", 23574673, "InfiniFi USDC Vault 2"),
    ("0x92e5280AEDF6B5128f81f7a1e0EC78Fc00F2d490", 23719017, "TermMax x RockawayX USDC"),
    ("0xadB077b53628AC11648CB3C76EFd9Af15b76e965", 23868543, "TermMax x custom USDC"),
    ("0x30233aCB313ed324Fd0cEa782C0687c2eaebdCB7", 23868576, "TermMax x USDC"),
    ("0x97263E74912e19176A34AB32871A873a395487D9", 23883788, "TermMax x Mezen Capital Vault V2"),
    ("0x7F5B94f35381BE3C064088941B53c1A3BFdbB576", 23930221, "USDC Boost Yield Vault v2"),
    ("0x394ec054e8275C40c45F116683f250a3E40Ea34d", 24036283, "TermMax x MezenCap Ext"),
    ("0xa231215C8a78E18205Ec5Ba2B52e98d99Bf43236", 24194935, "USDU Yield"),
    ("0xe0C139B915A637A519cB71c9F80cdD1F123b192E", 24202502, "USDU RWA"),
    ("0x7A84fCB839BEb377861001c6339a986B9e6d6D68", 24338283, "Coinshift rlUSD vault"),
    ("0xE3662545B96032858c72D89a124Bf62c6D3a5f5c", 24374956, "Limit Order Enabler USDC"),
    ("0x391b9161d6AEA25c17C398DBffe5bB431F03EB98", 24374961, "Limit Order Enabler WETH"),
    ("0x9E3e8F1eb9384efF8dc857b5138dc864CB752eA9", 24374963, "Limit Order Enabler WBTC"),
    ("0x86Da188246A063274fb4A914AF21d6Fd3655B706", 24419138, "Pharos Pre-Deposit USDC Vault"),
    ("0x6D155090A1d8b92b6785372b1A80Ffc9Fd02EF8C", 24783334, "TermMax reUSD Vault"),
    ("0x88699fB68A541269C67A5564cac3929391e61291", 24790380, "TermMax XAUt Vault"),
    ("0xE3e545abfA18019bcd74abA2C13dC569d6D018A8", 24832165, "Ellen Capital USDC Prime"),
    ("0x7fB02AeA6f04d44a61E413FA220CaF18DCD626Fb", 24832207, "XAUE XAUt Vault"),
    ("0x93EF43914B2F6f885F2C0a230481782405f639B7", 24832244, "MEXC XAUt Vault"),
    ("0x34f5C0AaE579F61B6E64F702A4Dbd70FE7aDdA59", 24926774, "TermMax USDT Vault"),
]

FACTORIES = [
    Web3.to_checksum_address("0x5b8B26a6734B5eABDBe6C5A19580Ab2D0424f027"),
    Web3.to_checksum_address("0xF2BDa87CA467eB90A1b68f824cB136baA68a8177"),
]
FACTORY_SCAN_FROM = 25_577_001

VAULT_CREATED_ABI = {
    "anonymous": False,
    "type": "event",
    "name": "VaultCreated",
    "inputs": [
        {"indexed": True, "name": "vault", "type": "address"},
        {"indexed": True, "name": "creator", "type": "address"},
        {
            "indexed": False,
            "name": "initialParams",
            "type": "tuple",
            "components": [
                {"name": "admin", "type": "address"},
                {"name": "curator", "type": "address"},
                {"name": "guardian", "type": "address"},
                {"name": "timelock", "type": "uint256"},
                {"name": "asset", "type": "address"},
                {"name": "pool", "type": "address"},
                {"name": "maxCapacity", "type": "uint256"},
                {"name": "name", "type": "string"},
                {"name": "symbol", "type": "string"},
                {"name": "performanceFeeRate", "type": "uint64"},
                {"name": "minApy", "type": "uint64"},
            ],
        },
    ],
}


def default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, HexBytes)):
        return "0x" + bytes(value).hex()
    return str(value)


def val(result: dict[str, Any], fallback: Any = None) -> Any:
    return result.get("value", fallback) if result.get("ok") else fallback


def parse_num(value: Any) -> int:
    if value is None or str(value).strip().lower() in {"", "0x"}:
        return 0
    if isinstance(value, int):
        return value
    text = str(value)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def topic(abi: dict[str, Any]) -> str:
    def canonical(item: dict[str, Any]) -> str:
        if item["type"] != "tuple":
            return item["type"]
        return "(" + ",".join(canonical(component) for component in item["components"]) + ")"

    signature = f"{abi['name']}({','.join(canonical(item) for item in abi['inputs'])})"
    return "0x" + bytes(Web3.keccak(text=signature)).hex()


def indexed_event_rows(address: str, abi: dict[str, Any], start: int, end: int) -> list[dict[str, Any]]:
    page = 1
    output: list[dict[str, Any]] = []
    while True:
        payload = base.get_json(
            "etherscan/api",
            {
                "module": "logs",
                "action": "getLogs",
                "address": address,
                "fromBlock": start,
                "toBlock": end,
                "topic0": topic(abi),
                "page": page,
                "offset": 1000,
            },
        )
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            if "No" in rows:
                break
            raise RuntimeError(f"log query failed: {payload}")
        if not rows:
            break
        output.extend(rows)
        if len(rows) < 1000:
            break
        page += 1
    return output


def decode_rows(w3: Web3, abi: dict[str, Any], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        log = {
            "address": Web3.to_checksum_address(row["address"]),
            "topics": [HexBytes(item) for item in row.get("topics", [])],
            "data": HexBytes(row.get("data") or "0x"),
            "blockNumber": parse_num(row.get("blockNumber")),
            "transactionHash": HexBytes(row["transactionHash"]),
            "transactionIndex": parse_num(row.get("transactionIndex")),
            "blockHash": HexBytes(row["blockHash"]),
            "logIndex": parse_num(row.get("logIndex")),
            "removed": False,
        }
        decoded = base.get_event_data(w3.codec, abi, log)
        output.append(
            {
                "blockNumber": log["blockNumber"],
                "blockHash": "0x" + bytes(log["blockHash"]).hex(),
                "transactionHash": "0x" + bytes(log["transactionHash"]).hex(),
                "logIndex": log["logIndex"],
                "args": dict(decoded["args"]),
            }
        )
    return output


def discover_new_vaults(w3: Web3, latest: int) -> list[tuple[str, int, str]]:
    discovered = []
    for factory in FACTORIES:
        try:
            rows = indexed_event_rows(factory, VAULT_CREATED_ABI, FACTORY_SCAN_FROM, latest)
            for event in decode_rows(w3, VAULT_CREATED_ABI, rows):
                params = event["args"]["initialParams"]
                name = params[7] if len(params) > 7 else "new vault"
                discovered.append((Web3.to_checksum_address(event["args"]["vault"]), event["blockNumber"], str(name)))
        except Exception as exc:
            (OUT / "factory_discovery_errors.log").open("a", encoding="utf-8").write(
                f"{factory}: {type(exc).__name__}: {exc}\n"
            )
    return discovered


def new_order_abi() -> dict[str, Any]:
    return base.EVENTS["NewOrderCreated"]


def order_addresses(w3: Web3, vault: str, created_block: int, latest: int) -> list[str]:
    rows = indexed_event_rows(vault, new_order_abi(), created_block, latest)
    decoded = decode_rows(w3, new_order_abi(), rows)
    return list(dict.fromkeys(Web3.to_checksum_address(event["args"]["order"]) for event in decoded))


def token_meta(w3: Web3, address: str, block: int) -> dict[str, Any]:
    return base.token(w3, address, block)


def debt_price_from_orders(orders: list[dict[str, Any]]) -> tuple[int | None, int | None]:
    for row in orders:
        result = row.get("debtPrice")
        price = val(result) if isinstance(result, dict) else None
        if price and int(price[0]) > 0:
            return int(price[0]), int(price[1])
    return None, None


def holders_for(vault: str) -> dict[str, Any]:
    try:
        payload = base.get_json(f"erc20/{vault}/holders", {"limit": 100, "count": "true"})
        rows = []
        for item in payload.get("items", []):
            address = item.get("address") or item.get("holder") or item.get("id")
            balance = item.get("balance") or item.get("value") or 0
            if address:
                rows.append(
                    {
                        "address": Web3.to_checksum_address(address),
                        "balance": parse_num(balance),
                        "percentage": item.get("percentage"),
                    }
                )
        return {"ok": True, "count": payload.get("count"), "items": rows}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def inspect_vault(w3: Web3, address: str, created_block: int, label: str, latest: int, timestamp: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    vault = w3.eth.contract(address=address, abi=base.VAULT_ABI)
    state = {
        name: base.safe(getattr(vault.functions, name)().call, block_identifier=latest)
        for name in ["name", "symbol", "asset", "pool", "totalFt", "totalAssets", "totalSupply", "paused"]
    }
    total_assets = int(val(state["totalAssets"], 0) or 0)
    total_supply = int(val(state["totalSupply"], 0) or 0)
    asset = val(state["asset"])
    result: dict[str, Any] = {
        "vault": address,
        "createdBlock": created_block,
        "snapshotLabel": label,
        "state": state,
        "assetMeta": token_meta(w3, asset, latest) if asset else None,
        "orders": [],
    }
    if total_assets == 0 or total_supply == 0:
        result["economics"] = {"status": "empty"}
        return result

    try:
        addresses = order_addresses(w3, address, created_block, latest)
    except Exception as exc:
        result["orderDiscoveryError"] = f"{type(exc).__name__}: {exc}"
        result["economics"] = {"status": "order-discovery-failed"}
        return result

    orders = [base.inspect_order(w3, vault, order, latest, timestamp) for order in addresses]
    result["orders"] = orders
    active = [row for row in orders if int(val(row.get("orderMaturity", {}), 0) or 0) > 0]
    mature = [
        row
        for row in active
        if row.get("matured") and row.get("economics", {}).get("recovery") is not None
    ]
    impaired = [row for row in mature if int(row["economics"].get("loss") or 0) > 0]
    near_par = [
        row
        for row in mature
        if int(row["economics"].get("quality1e18") or 0) >= 999_900_000_000_000_000
    ]
    loss_raw = sum(int(row["economics"]["loss"]) for row in impaired)
    good_raw = sum(int(row["economics"]["nominal"]) for row in near_par)
    transfer_raw = good_raw * loss_raw // total_assets if total_assets else 0
    decimals = int(val((result["assetMeta"] or {}).get("decimals", {}), 18) or 18)
    price, price_decimals = debt_price_from_orders(mature)
    transfer_usd = None
    total_assets_usd = None
    if price is not None and price_decimals is not None:
        transfer_usd = transfer_raw * price / (10**decimals * 10**price_decimals)
        total_assets_usd = total_assets * price / (10**decimals * 10**price_decimals)

    shares_needed = int(vault.functions.previewWithdraw(good_raw).call(block_identifier=latest)) if good_raw else 0
    economics = {
        "status": "scanned",
        "createdOrderCount": len(addresses),
        "activeOrderCount": len(active),
        "matureResolvedOrderCount": len(mature),
        "impairedOrderCount": len(impaired),
        "nearParOrderCount": len(near_par),
        "knownLatentLossRaw": loss_raw,
        "knownGoodCapacityRaw": good_raw,
        "maximumFairProRataTransferRaw": transfer_raw,
        "assetDecimals": decimals,
        "assetPrice": price,
        "assetPriceDecimals": price_decimals,
        "maximumFairProRataTransferUsd": transfer_usd,
        "totalAssetsUsd": total_assets_usd,
        "sharesNeededForGoodCapacity": shares_needed,
        "worstOrder": max(impaired, key=lambda row: int(row["economics"]["loss"]), default=None),
        "bestOrder": max(near_par, key=lambda row: int(row["economics"]["quality1e18"]), default=None),
    }

    if transfer_usd is not None and transfer_usd >= 1_000 and shares_needed > 0:
        holder_state = holders_for(address)
        capable = [item for item in holder_state.get("items", []) if item["balance"] >= shares_needed]
        economics["holders"] = holder_state
        economics["capableHoldersTop100"] = capable
        best = economics["bestOrder"]
        if best and capable:
            one_unit = min(10**decimals, int(best["economics"]["nominal"]))
            economics["readOnlyPositiveSimulation"] = base.simulate(
                w3, vault, best["order"], one_unit, capable[0]["address"], latest
            )
            economics["readOnlyNegativeControl"] = base.simulate(
                w3,
                vault,
                best["order"],
                one_unit,
                "0x2222222222222222222222222222222222222222",
                latest,
            )
    result["economics"] = economics
    return result


def main() -> int:
    w3, rpc, attempts = base.connect()
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    timestamp = int(block.timestamp)

    known = [(Web3.to_checksum_address(v), b, n) for v, b, n in KNOWN_VAULTS]
    newly_discovered = discover_new_vaults(w3, latest)
    combined: dict[str, tuple[str, int, str]] = {address.lower(): (address, block_no, label) for address, block_no, label in known}
    for address, block_no, label in newly_discovered:
        combined.setdefault(address.lower(), (address, block_no, label))

    vaults = []
    for index, (address, created_block, label) in enumerate(combined.values(), start=1):
        try:
            vaults.append(inspect_vault(w3, address, created_block, label, latest, timestamp))
        except Exception as exc:
            vaults.append(
                {
                    "vault": address,
                    "createdBlock": created_block,
                    "snapshotLabel": label,
                    "fatalError": f"{type(exc).__name__}: {exc}",
                }
            )
        print(f"[{index}/{len(combined)}] {address}", flush=True)
        time.sleep(0.15)

    ranking = sorted(
        [
            {
                "vault": row["vault"],
                "name": val(row.get("state", {}).get("name", {}), row.get("snapshotLabel")),
                **row.get("economics", {}),
            }
            for row in vaults
            if row.get("economics", {}).get("status") == "scanned"
        ],
        key=lambda row: float(row.get("maximumFairProRataTransferUsd") or 0),
        reverse=True,
    )

    result = {
        "schema": "termmax-ethereum-vault-dispersion/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {
            "number": latest,
            "hash": "0x" + bytes(block.hash).hex(),
            "timestamp": timestamp,
            "timestampUtc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        },
        "knownVaultCount": len(known),
        "newlyDiscoveredVaults": newly_discovered,
        "totalVaultCount": len(combined),
        "ranking": ranking,
        "vaults": vaults,
    }
    compact = {
        "generatedAtUtc": result["generatedAtUtc"],
        "block": result["block"],
        "knownVaultCount": len(known),
        "newlyDiscoveredVaults": newly_discovered,
        "ranking": ranking,
    }
    (OUT / "ETH_VAULT_CENSUS_FULL.json").write_text(json.dumps(result, indent=2, default=default), encoding="utf-8")
    (OUT / "ETH_VAULT_CENSUS_COMPACT.json").write_text(json.dumps(compact, indent=2, default=default), encoding="utf-8")
    print(json.dumps(compact, indent=2, default=default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
