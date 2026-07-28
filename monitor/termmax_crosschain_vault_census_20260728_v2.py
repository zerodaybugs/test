#!/usr/bin/env python3
"""Corrected public read-only TermMax V2 cross-chain vault census.

This wrapper replaces stale factory addresses with the current factory set used
by the public DefiLlama TermMax adapter, adds BNB Chain PoA middleware, and
supplements factory discovery with the public DefiLlama yield-pool index. It
uses only public JSON-RPC calls and indexed HTTPS GET requests. It has no
private key, signer, or transaction-broadcast capability.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import requests
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

BASE_PATH = Path(__file__).with_name("termmax_crosschain_vault_census_20260728.py")
SPEC = importlib.util.spec_from_file_location("termmax_crosschain_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load base census: {BASE_PATH}")
base = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(base)

# Current public V2 factories and deployment start blocks from the public
# DefiLlama TermMax yield adapter.
base.CHAINS = [
    {
        "name": "base",
        "defiLlamaChain": "Base",
        "defiLlamaPoolSuffix": "base",
        "chainId": 8453,
        "routescanId": 8453,
        "factories": [
            ("0xDA4aAF85Bb924B53DCc2DFFa9e1A9C2Ef97aCFDF", 43_289_755),
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
        "defiLlamaPoolSuffix": "bsc",
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
        "staticVaults": [],
        "poa": True,
    },
    {
        "name": "arbitrum",
        "defiLlamaChain": "Arbitrum",
        "defiLlamaPoolSuffix": "arbitrum",
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
        timeout=60,
        headers={"User-Agent": "termmax-public-census/2"},
    )
    response.raise_for_status()
    payload = response.json()
    rows = payload.get("data", []) if isinstance(payload, dict) else []
    _DEFILLAMA_POOLS = [
        row for row in rows if str(row.get("project", "")).lower() == "termmax"
    ]
    return _DEFILLAMA_POOLS


def corrected_connect(config: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in config["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 40}))
            if config.get("poa"):
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            block_number = w3.eth.block_number
            # Force block decoding here so PoA/header middleware failures are
            # caught before the census starts.
            block = w3.eth.get_block(block_number)
            if chain_id != config["chainId"]:
                raise RuntimeError(f"chainId={chain_id}")
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


def defillama_vaults(config: dict[str, Any]) -> list[tuple[str, int]]:
    output: list[tuple[str, int]] = []
    minimum_start = min(int(block) for _, block in config.get("factories", []))
    wanted_chain = str(config["defiLlamaChain"]).lower()
    wanted_suffix = str(config["defiLlamaPoolSuffix"]).lower()
    for row in defi_llama_pools():
        if str(row.get("chain", "")).lower() != wanted_chain:
            continue
        pool_id = str(row.get("pool", ""))
        address = pool_id.split("-", 1)[0]
        if not address.startswith("0x") or len(address) != 42:
            continue
        # The public TermMax adapter formats pool IDs as address-chain.
        if "-" in pool_id and not pool_id.lower().endswith("-" + wanted_suffix):
            continue
        try:
            output.append((Web3.to_checksum_address(address), minimum_start))
        except ValueError:
            continue
    return output


def corrected_discover_vaults(config: dict[str, Any], latest: int) -> list[tuple[str, int]]:
    output = [
        (Web3.to_checksum_address(address), int(block_number))
        for address, block_number in config.get("staticVaults", [])
    ]
    discovery_notes: list[str] = []

    for factory_address, start_block in config.get("factories", []):
        factory = Web3.to_checksum_address(factory_address)
        try:
            rows = base.routescan_logs(
                config["routescanId"],
                factory,
                int(start_block),
                latest,
                base.VAULT_CREATED_TOPIC,
            )
            discovery_notes.append(f"{factory}: routescan_rows={len(rows)}")
            for row in rows:
                topics = row.get("topics", [])
                if len(topics) >= 2:
                    output.append(
                        (
                            base.topic_address(topics[1]),
                            base.parse_num(row.get("blockNumber")),
                        )
                    )
        except Exception as exc:
            discovery_notes.append(
                f"{factory}: routescan_error={type(exc).__name__}: {exc}"
            )

    try:
        llama_rows = defillama_vaults(config)
        output.extend(llama_rows)
        discovery_notes.append(f"defillama_rows={len(llama_rows)}")
    except Exception as exc:
        discovery_notes.append(
            f"defillama_error={type(exc).__name__}: {exc}"
        )

    path = base.OUT / f"{config['name']}_vault_discovery.log"
    path.write_text("\n".join(discovery_notes) + "\n", encoding="utf-8")

    unique: dict[str, tuple[str, int]] = {}
    for address, block_number in output:
        key = address.lower()
        if key not in unique or block_number < unique[key][1]:
            unique[key] = (address, block_number)
    return list(unique.values())


base.connect = corrected_connect
base.discover_vaults = corrected_discover_vaults
raise SystemExit(base.main())
