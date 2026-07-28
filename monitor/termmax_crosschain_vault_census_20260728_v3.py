#!/usr/bin/env python3
"""TermMax V2 cross-chain recovery-dispersion census, revision 3.

Public and read-only only:
- public JSON-RPC calls (eth_call, eth_getLogs, block/code reads);
- indexed explorer GET requests;
- public DefiLlama yield-pool metadata.

The program contains no private key, signer, state-changing RPC method, or
transaction-broadcast path.
"""
from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from hexbytes import HexBytes
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

BASE_PATH = Path(__file__).with_name("termmax_crosschain_vault_census_20260728.py")
SPEC = importlib.util.spec_from_file_location("termmax_crosschain_base_v3", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base census: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

# Current V2 factories are taken from the public DefiLlama TermMax adapter.
# BNB vaults below are public app/DefiLlama-linked vaults and provide a hard
# fallback if an explorer or factory event index is incomplete.
base.CHAINS = [
    {
        "name": "base",
        "defiLlamaChain": "Base",
        "chainId": 8453,
        "routescanId": 8453,
        "factories": [
            ("0xDA4aAF85Bb924B53DCc2DFFa9e1A9C2Ef97aCFDF", 43_289_755),
            # Earlier official V2 deployment factory retained as a fallback.
            ("0x28e47A7d7E710d796DBAFd8081c052444deEcF10", 44_722_441),
        ],
        "rpcs": [
            "https://mainnet.base.org",
            "https://base-rpc.publicnode.com",
            "https://base.drpc.org",
        ],
        "staticVaults": [],
        "poa": False,
    },
    {
        "name": "bnb",
        "defiLlamaChain": "BSC",
        "chainId": 56,
        "routescanId": 56,
        "factories": [
            ("0x1401049368eD6AD8194f8bb7E41732c4620F170b", 63_100_000),
            ("0xdffE6De6de1dB8e1B5Ce77D3222eba401C2573b5", 63_100_000),
        ],
        "rpcs": [
            "https://bsc-rpc.publicnode.com",
            "https://bsc-dataseed.binance.org",
            "https://bsc.drpc.org",
        ],
        "staticVaults": [
            ("0xe0188f026c90f7b6d410149d21046d33f144de26", 63_100_000),
            ("0xcf2b43172521118156bd20dcc75729a7953e4d21", 63_100_000),
            ("0xb5a2224bc5a4f42f319242ac089cdce97ff8a004", 63_100_000),
        ],
        "poa": True,
    },
    {
        "name": "arbitrum",
        "defiLlamaChain": "Arbitrum",
        "chainId": 42161,
        "routescanId": 42161,
        "factories": [
            ("0xa7c93162962D050098f4BB44E88661517484C5EB", 385_228_046),
            ("0x18b8A9433dBefcd15370F10a75e28149bcc2e301", 385_228_046),
        ],
        "rpcs": [
            "https://arb1.arbitrum.io/rpc",
            "https://arbitrum-one-rpc.publicnode.com",
            "https://arbitrum.drpc.org",
        ],
        "staticVaults": [
            ("0xCb94ABCffbF5CC76a55f9c1496632A26D19f9947", 385_285_536),
            ("0xb6692aCb982c2dA0775c947Cb329B04EBFB4e0ac", 385_285_536),
        ],
        "poa": False,
    },
]

_DEFILLAMA_POOLS: list[dict[str, Any]] | None = None


def defi_llama_pools() -> list[dict[str, Any]]:
    global _DEFILLAMA_POOLS
    if _DEFILLAMA_POOLS is not None:
        return _DEFILLAMA_POOLS
    response = requests.get(
        "https://yields.llama.fi/pools",
        timeout=90,
        headers={"User-Agent": "termmax-public-census/3"},
    )
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("data", []) if isinstance(payload, dict) else []
    _DEFILLAMA_POOLS = [
        row for row in rows if str(row.get("project", "")).lower() == "termmax"
    ]
    (base.OUT / "defillama_termmax_pools.json").write_text(
        json.dumps(_DEFILLAMA_POOLS, indent=2, default=base.default),
        encoding="utf-8",
    )
    return _DEFILLAMA_POOLS


def extract_address(row: dict[str, Any]) -> str | None:
    candidates: list[str] = []
    pool_value = str(row.get("pool", ""))
    if pool_value:
        candidates.append(pool_value.split("-", 1)[0])

    url_value = str(row.get("url", ""))
    if url_value:
        try:
            candidates.extend(part for part in urlparse(url_value).path.split("/") if part)
        except Exception:
            pass

    for candidate in candidates:
        candidate = candidate.split("?", 1)[0].strip()
        if candidate.startswith("0x") and len(candidate) == 42:
            try:
                return Web3.to_checksum_address(candidate)
            except ValueError:
                continue
    return None


def connect(config: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in config["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 45}))
            if config.get("poa"):
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            block_number = w3.eth.block_number
            block = w3.eth.get_block(block_number)
            if chain_id != config["chainId"]:
                raise RuntimeError(f"unexpected chainId={chain_id}")
            config["_w3"] = w3
            attempts.append(
                {
                    "url": url,
                    "ok": True,
                    "block": block_number,
                    "blockHash": "0x" + bytes(block.hash).hex(),
                    "poaMiddleware": bool(config.get("poa")),
                }
            )
            return w3, url, attempts
        except Exception as exc:
            attempts.append(
                {
                    "url": url,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "poaMiddleware": bool(config.get("poa")),
                }
            )
    raise RuntimeError(json.dumps(attempts))


def rpc_logs(
    w3: Web3,
    address: str,
    start: int,
    end: int,
    topic0: str,
    preferred_step: int = 2_000_000,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    cursor = int(start)
    while cursor <= end:
        step = preferred_step
        rows = None
        while rows is None:
            window_end = min(end, cursor + step - 1)
            try:
                rows = w3.eth.get_logs(
                    {
                        "address": Web3.to_checksum_address(address),
                        "topics": [topic0],
                        "fromBlock": cursor,
                        "toBlock": window_end,
                    }
                )
            except Exception:
                if step <= 1_000:
                    raise
                step = max(1_000, step // 2)
        for row in rows:
            output.append(
                {
                    "address": Web3.to_checksum_address(row["address"]),
                    "topics": ["0x" + bytes(HexBytes(item)).hex() for item in row["topics"]],
                    "data": "0x" + bytes(HexBytes(row["data"])).hex(),
                    "blockNumber": int(row["blockNumber"]),
                    "transactionHash": "0x" + bytes(HexBytes(row["transactionHash"])).hex(),
                    "transactionIndex": int(row["transactionIndex"]),
                    "blockHash": "0x" + bytes(HexBytes(row["blockHash"])).hex(),
                    "logIndex": int(row["logIndex"]),
                    "retrieval": "public-rpc-eth_getLogs",
                }
            )
        cursor = min(end, cursor + step - 1) + 1
    return output


def defillama_vaults(config: dict[str, Any]) -> list[tuple[str, int]]:
    output: list[tuple[str, int]] = []
    minimum_start = min(int(block) for _, block in config.get("factories", []))
    wanted_chain = str(config["defiLlamaChain"]).lower()
    for row in defi_llama_pools():
        if str(row.get("chain", "")).lower() != wanted_chain:
            continue
        address = extract_address(row)
        if address:
            output.append((address, minimum_start))
    return output


def discover_vaults(config: dict[str, Any], latest: int) -> list[tuple[str, int]]:
    output = [
        (Web3.to_checksum_address(address), int(block_number))
        for address, block_number in config.get("staticVaults", [])
    ]
    notes: list[str] = []
    w3: Web3 = config["_w3"]

    for factory_address, start_block in config.get("factories", []):
        factory = Web3.to_checksum_address(factory_address)
        rows: list[dict[str, Any]] = []
        try:
            rows = base.routescan_logs(
                config["routescanId"], factory, int(start_block), latest, base.VAULT_CREATED_TOPIC
            )
            notes.append(f"{factory}: routescan_rows={len(rows)}")
        except Exception as exc:
            notes.append(f"{factory}: routescan_error={type(exc).__name__}: {exc}")

        if not rows:
            try:
                rows = rpc_logs(w3, factory, int(start_block), latest, base.VAULT_CREATED_TOPIC)
                notes.append(f"{factory}: rpc_rows={len(rows)}")
            except Exception as exc:
                notes.append(f"{factory}: rpc_error={type(exc).__name__}: {exc}")

        for row in rows:
            topics = row.get("topics", [])
            if len(topics) >= 2:
                output.append(
                    (base.topic_address(topics[1]), base.parse_num(row.get("blockNumber")))
                )

    try:
        llama_rows = defillama_vaults(config)
        output.extend(llama_rows)
        notes.append(f"defillama_rows={len(llama_rows)}")
    except Exception as exc:
        notes.append(f"defillama_error={type(exc).__name__}: {exc}")

    (base.OUT / f"{config['name']}_vault_discovery.log").write_text(
        "\n".join(notes) + "\n", encoding="utf-8"
    )

    unique: dict[str, tuple[str, int]] = {}
    for address, block_number in output:
        key = address.lower()
        if key not in unique or int(block_number) < unique[key][1]:
            unique[key] = (address, int(block_number))
    return list(unique.values())


def discover_orders(config: dict[str, Any], vault: str, start: int, latest: int) -> list[str]:
    notes: list[str] = []
    rows: list[dict[str, Any]] = []
    try:
        rows = base.routescan_logs(
            config["routescanId"], vault, int(start), latest, base.NEW_ORDER_TOPIC
        )
        notes.append(f"routescan_rows={len(rows)}")
    except Exception as exc:
        notes.append(f"routescan_error={type(exc).__name__}: {exc}")

    if not rows:
        try:
            rows = rpc_logs(
                config["_w3"], vault, int(start), latest, base.NEW_ORDER_TOPIC
            )
            notes.append(f"rpc_rows={len(rows)}")
        except Exception as exc:
            notes.append(f"rpc_error={type(exc).__name__}: {exc}")

    output: list[str] = []
    for row in rows:
        topics = row.get("topics", [])
        if len(topics) >= 4:
            output.append(base.topic_address(topics[3]))

    with (base.OUT / f"{config['name']}_order_discovery.log").open(
        "a", encoding="utf-8"
    ) as handle:
        handle.write(f"{vault} start={start} {'; '.join(notes)} orders={len(output)}\n")
    return list(dict.fromkeys(output))


base.connect = connect
base.discover_vaults = discover_vaults
base.discover_orders = discover_orders
raise SystemExit(base.main())
