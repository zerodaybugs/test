#!/usr/bin/env python3
"""Read-only current ERC-20 holdings census for official TermMax Router V2 deployments.

The program discovers token contracts from public Transfer logs whose recipient
is an official Router V2 address, then reads current balances, proxy
implementation, pause state, and ownership. It performs no signing, transaction
construction, simulation, or state mutation.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from hexbytes import HexBytes
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)").hex()
IMPLEMENTATION_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)

CHAINS: list[dict[str, Any]] = [
    {
        "name": "ethereum", "chainId": 1, "routescanId": 1,
        "router": "0x324596C1682a5675008f6e58F9C4E0A894b079c7", "startBlock": 24_883_366,
        "rpcs": ["https://ethereum-rpc.publicnode.com", "https://rpc.mevblocker.io", "https://eth.drpc.org"],
        "poa": False,
    },
    {
        "name": "arbitrum", "chainId": 42161, "routescanId": 42161,
        "router": "0xCAa5689bfe6E1B9c79D7C44D9E4410f6BFb6c4b5", "startBlock": 452_661_450,
        "rpcs": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.drpc.org"],
        "poa": False,
    },
    {
        "name": "bnb", "chainId": 56, "routescanId": 56,
        "router": "0xFB0c46985d937C755265f697BC10AD3387Ae801a", "startBlock": 92_629_573,
        "rpcs": ["https://bsc-dataseed.binance.org", "https://bsc-rpc.publicnode.com", "https://bsc.drpc.org"],
        "poa": True,
    },
    {
        "name": "base", "chainId": 8453, "routescanId": 8453,
        "router": "0x830fBad7Cd1c3Cc5B693Dc64b985f2901B253C5B", "startBlock": 44_722_441,
        "rpcs": ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"],
        "poa": False,
    },
    {
        "name": "b2", "chainId": 223, "routescanId": 223,
        "router": "0x830fBad7Cd1c3Cc5B693Dc64b985f2901B253C5B", "startBlock": 31_535_305,
        "rpcs": ["https://rpc.bsquared.network", "https://b2-mainnet.alt.technology"],
        "poa": False,
    },
    {
        "name": "berachain", "chainId": 80094, "routescanId": 80094,
        "router": "0x0B30251FA697A39Fd41813b267b50F03414E82da", "startBlock": 19_609_794,
        "rpcs": ["https://rpc.berachain.com", "https://berachain-rpc.publicnode.com"],
        "poa": False,
    },
    {
        "name": "xlayer", "chainId": 196, "routescanId": 196,
        "router": "0xa50929A67daF9Ff3567e2Bb3411204A134f72546", "startBlock": 57_465_452,
        "rpcs": ["https://rpc.xlayer.tech", "https://xlayerrpc.okx.com"],
        "poa": False,
    },
    {
        "name": "pharos", "chainId": 688688, "routescanId": 688688,
        "router": "0xc56cF74254C5aDd64fa1198476233BEC1878145B", "startBlock": 5_278_169,
        "rpcs": ["https://rpc.pharosnetwork.xyz", "https://api.pharosnetwork.xyz"],
        "poa": False,
    },
]

ROUTER_ABI = [
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"owner","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"getVersion","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]


def checksum(address: str) -> str:
    return Web3.to_checksum_address(address)


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    text = str(value or "0")
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address.lower().replace("0x", "")


def safe_call(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        if isinstance(value, HexBytes):
            value = value.hex()
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def value(result: dict[str, Any], default: Any = None) -> Any:
    return result.get("value", default) if result.get("ok") else default


def connect(config: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    env_name = f"{config['name'].upper()}_RPC_URL"
    urls = [os.environ.get(env_name, "").strip(), *config["rpcs"]]
    for url in [x for x in urls if x]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            if config.get("poa"):
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            latest = w3.eth.block_number
            block = w3.eth.get_block(latest)
            if chain_id != config["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": latest, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def routescan_logs(config: dict[str, Any], latest: int) -> list[dict[str, Any]]:
    url = f"https://api.routescan.io/v2/network/mainnet/evm/{config['routescanId']}/etherscan/api"
    page = 1
    rows_all: list[dict[str, Any]] = []
    while True:
        params = {
            "module": "logs", "action": "getLogs",
            "fromBlock": config["startBlock"], "toBlock": latest,
            "topic0": TRANSFER_TOPIC, "topic2": topic_address(config["router"]),
            "topic0_2_opr": "and", "page": page, "offset": 1000,
        }
        payload = None
        last_error: Exception | None = None
        for attempt in range(6):
            try:
                response = requests.get(url, params=params, timeout=60, headers={"User-Agent":"ZeroDayBugs-TermMax-Readonly/1"})
                if response.status_code == 429:
                    time.sleep(1.5 * (attempt + 1)); continue
                response.raise_for_status()
                payload = response.json(); break
            except Exception as exc:  # noqa: BLE001
                last_error = exc; time.sleep(1.25 * (attempt + 1))
        if payload is None:
            raise RuntimeError(f"Routescan failed: {last_error}")
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            if "No" in rows or "not found" in rows.lower():
                break
            raise RuntimeError(f"unexpected Routescan result: {payload}")
        if not rows:
            break
        rows_all.extend(rows)
        if len(rows) < 1000:
            break
        page += 1
        time.sleep(0.25)
    return rows_all


def rpc_logs(w3: Web3, config: dict[str, Any], latest: int) -> list[Any]:
    output: list[Any] = []
    cursor = config["startBlock"]
    sizes = [100_000, 20_000, 5_000, 1_000]
    size_index = 0
    topics = [TRANSFER_TOPIC, None, topic_address(config["router"])]
    while cursor <= latest:
        end = min(latest, cursor + sizes[size_index] - 1)
        try:
            output.extend(w3.eth.get_logs({"fromBlock":cursor,"toBlock":end,"topics":topics}))
            cursor = end + 1
            size_index = 0
        except Exception:
            if size_index + 1 < len(sizes):
                size_index += 1
            else:
                raise
    return output


def discover_tokens(w3: Web3, config: dict[str, Any], latest: int) -> tuple[list[str], dict[str, Any]]:
    diagnostics: dict[str, Any] = {}
    token_addresses: set[str] = set()
    try:
        rows = routescan_logs(config, latest)
        diagnostics["routescan"] = {"ok": True, "rowCount": len(rows)}
        for row in rows:
            try:
                token_addresses.add(checksum(row["address"]))
            except Exception:
                continue
    except Exception as exc:  # noqa: BLE001
        diagnostics["routescan"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        try:
            rows = rpc_logs(w3, config, latest)
            diagnostics["rpcLogs"] = {"ok": True, "rowCount": len(rows)}
            for row in rows:
                token_addresses.add(checksum(row["address"]))
        except Exception as rpc_exc:  # noqa: BLE001
            diagnostics["rpcLogs"] = {"ok": False, "error": f"{type(rpc_exc).__name__}: {rpc_exc}"}
    return sorted(token_addresses), diagnostics


def inspect_token(w3: Web3, token_address: str, router: str, block: int) -> dict[str, Any]:
    token = w3.eth.contract(address=checksum(token_address), abi=ERC20_ABI)
    balance_r = safe_call(token.functions.balanceOf(router).call, block_identifier=block)
    decimals_r = safe_call(token.functions.decimals().call, block_identifier=block)
    raw = int(value(balance_r, 0) or 0)
    decimals = value(decimals_r)
    human = None
    if decimals is not None:
        try:
            human = raw / (10 ** int(decimals))
        except Exception:
            pass
    return {
        "token": checksum(token_address),
        "codeBytes": len(w3.eth.get_code(checksum(token_address), block_identifier=block)),
        "balanceRaw": balance_r,
        "symbol": safe_call(token.functions.symbol().call, block_identifier=block),
        "name": safe_call(token.functions.name().call, block_identifier=block),
        "decimals": decimals_r,
        "balanceHuman": human,
        "nonzero": raw > 0,
    }


def inspect_chain(config: dict[str, Any]) -> dict[str, Any]:
    w3, rpc, attempts = connect(config)
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    router_address = checksum(config["router"])
    router = w3.eth.contract(address=router_address, abi=ROUTER_ABI)
    token_addresses, discovery = discover_tokens(w3, config, latest)
    tokens = [inspect_token(w3, token, router_address, latest) for token in token_addresses]
    nonzero = [row for row in tokens if row["nonzero"]]
    implementation_raw = w3.eth.get_storage_at(router_address, IMPLEMENTATION_SLOT, block_identifier=latest)
    implementation = checksum("0x" + implementation_raw.hex()[-40:]) if int.from_bytes(implementation_raw, "big") else None
    return {
        "chain": config["name"], "chainId": config["chainId"], "rpc": rpc, "rpcAttempts": attempts,
        "block": {"number":latest,"hash":block.hash.hex(),"timestamp":int(block.timestamp),"timestampUtc":datetime.fromtimestamp(block.timestamp,tz=timezone.utc).isoformat()},
        "router": router_address,
        "routerCodeBytes": len(w3.eth.get_code(router_address, block_identifier=latest)),
        "implementation": implementation,
        "implementationCodeBytes": len(w3.eth.get_code(implementation, block_identifier=latest)) if implementation else 0,
        "paused": safe_call(router.functions.paused().call, block_identifier=latest),
        "owner": safe_call(router.functions.owner().call, block_identifier=latest),
        "version": safe_call(router.functions.getVersion().call, block_identifier=latest),
        "nativeBalanceWei": w3.eth.get_balance(router_address, block_identifier=latest),
        "tokenDiscovery": discovery,
        "discoveredTokenCount": len(token_addresses),
        "nonzeroTokenCount": len(nonzero),
        "tokens": tokens,
        "nonzeroTokens": nonzero,
    }


def main() -> int:
    requested = os.environ.get("CHAIN", "all").strip().lower()
    selected = CHAINS if requested == "all" else [row for row in CHAINS if row["name"] == requested]
    if not selected:
        raise RuntimeError(f"unknown CHAIN={requested}")
    results: list[dict[str, Any]] = []
    for config in selected:
        try:
            results.append(inspect_chain(config))
        except Exception as exc:  # noqa: BLE001
            results.append({"chain":config["name"],"chainId":config["chainId"],"router":config["router"],"fatalError":f"{type(exc).__name__}: {exc}"})
    result = {
        "schema":"termmax-router-current-holdings/v1",
        "generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "results":results,
    }
    compact = {
        "generatedAtUtc":result["generatedAtUtc"],
        "chains":[{
            "chain":row["chain"],"chainId":row["chainId"],"router":row["router"],
            "block":row.get("block"),"implementation":row.get("implementation"),"paused":row.get("paused"),
            "discoveredTokenCount":row.get("discoveredTokenCount"),"nonzeroTokenCount":row.get("nonzeroTokenCount"),
            "nonzeroTokens":row.get("nonzeroTokens",[]),"fatalError":row.get("fatalError")
        } for row in results]
    }
    (OUT / "ROUTER_HOLDINGS_FULL.json").write_text(json.dumps(result,indent=2,default=str),encoding="utf-8")
    (OUT / "ROUTER_HOLDINGS_COMPACT.json").write_text(json.dumps(compact,indent=2,default=str),encoding="utf-8")
    print(json.dumps(compact,indent=2,default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
