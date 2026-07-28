#!/usr/bin/env python3
"""Targeted read-only WQ-1/TM-V1B census for the largest non-Ethereum vaults.

Only public JSON-RPC eth_call/block reads and indexed explorer GET requests are
used. No signer, private key, transaction construction, or state mutation is
present.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

from hexbytes import HexBytes
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

BASE_PATH = Path(__file__).with_name("termmax_crosschain_vault_census_20260728.py")
SPEC = importlib.util.spec_from_file_location("termmax_targeted_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base census: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

base.CHAINS = [
    {
        "name": "base-targeted",
        "chainId": 8453,
        "routescanId": 8453,
        "rpcs": [
            "https://mainnet.base.org",
            "https://base-rpc.publicnode.com",
            "https://base.drpc.org",
        ],
        "poa": False,
        "staticVaults": [
            ("0xd42c1bf2aca1dd771795453277cc14f6c3b2c388", 43_289_755),
        ],
    },
    {
        "name": "bnb-targeted",
        "chainId": 56,
        "routescanId": 56,
        "rpcs": [
            "https://bsc-rpc.publicnode.com",
            "https://bsc-dataseed.binance.org",
            "https://bsc.drpc.org",
        ],
        "poa": True,
        "staticVaults": [
            ("0xb5a2224bc5a4f42f319242ac089cdce97ff8a004", 63_100_000),
            ("0xcf2b43172521118156bd20dcc75729a7953e4d21", 63_100_000),
            ("0xe0188f026c90f7b6d410149d21046d33f144de26", 63_100_000),
            ("0x2fb88c622a408699781f140616ca0ea806d0fd96", 63_100_000),
        ],
    },
    {
        "name": "arbitrum-targeted",
        "chainId": 42161,
        "routescanId": 42161,
        "rpcs": [
            "https://arb1.arbitrum.io/rpc",
            "https://arbitrum-one-rpc.publicnode.com",
            "https://arbitrum.drpc.org",
        ],
        "poa": False,
        "staticVaults": [
            ("0xCb94ABCffbF5CC76a55f9c1496632A26D19f9947", 385_228_046),
            ("0xb6692aCb982c2dA0775c947Cb329B04EBFB4e0ac", 385_228_046),
        ],
    },
]


def connect(config: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts = []
    for url in config["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 45}))
            if config.get("poa"):
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            latest = w3.eth.block_number
            block = w3.eth.get_block(latest)
            if chain_id != config["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            config["_w3"] = w3
            attempts.append({"url":url,"ok":True,"block":latest,"hash":"0x"+bytes(block.hash).hex()})
            return w3, url, attempts
        except Exception as exc:
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def discover_vaults(config: dict[str, Any], latest: int) -> list[tuple[str, int]]:
    del latest
    return [
        (Web3.to_checksum_address(address), int(start))
        for address, start in config["staticVaults"]
    ]


def rpc_order_logs(w3: Web3, vault: str, start: int, latest: int) -> list[dict[str, Any]]:
    output = []
    cursor = int(start)
    preferred = 250_000
    while cursor <= latest:
        step = preferred
        rows = None
        while rows is None:
            end = min(latest, cursor + step - 1)
            try:
                rows = w3.eth.get_logs({
                    "address": Web3.to_checksum_address(vault),
                    "topics": [base.NEW_ORDER_TOPIC],
                    "fromBlock": cursor,
                    "toBlock": end,
                })
            except Exception:
                if step <= 1_000:
                    raise
                step = max(1_000, step // 2)
        for row in rows:
            output.append({
                "topics": ["0x" + bytes(HexBytes(item)).hex() for item in row["topics"]],
                "blockNumber": int(row["blockNumber"]),
                "transactionHash": "0x" + bytes(row["transactionHash"]).hex(),
                "retrieval": "public-rpc-eth_getLogs",
            })
        cursor = min(latest, cursor + step - 1) + 1
    return output


def discover_orders(config: dict[str, Any], vault: str, start: int, latest: int) -> list[str]:
    notes = []
    rows = []
    try:
        rows = base.routescan_logs(config["routescanId"], vault, int(start), latest, base.NEW_ORDER_TOPIC)
        notes.append(f"routescan_rows={len(rows)}")
    except Exception as exc:
        notes.append(f"routescan_error={type(exc).__name__}: {exc}")
    if not rows:
        try:
            rows = rpc_order_logs(config["_w3"], vault, int(start), latest)
            notes.append(f"rpc_rows={len(rows)}")
        except Exception as exc:
            notes.append(f"rpc_error={type(exc).__name__}: {exc}")
    orders = []
    for row in rows:
        topics = row.get("topics", [])
        if len(topics) >= 4:
            orders.append(base.topic_address(topics[3]))
    with (base.OUT / "TARGETED_ORDER_DISCOVERY.log").open("a", encoding="utf-8") as handle:
        handle.write(f"{config['name']} {vault} start={start} {'; '.join(notes)} orders={len(orders)}\n")
    return list(dict.fromkeys(orders))


base.connect = connect
base.discover_vaults = discover_vaults
base.discover_orders = discover_orders
raise SystemExit(base.main())
