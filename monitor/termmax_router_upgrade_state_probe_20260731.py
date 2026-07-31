#!/usr/bin/env python3
"""Read-only upgrade-state and adapter-binding census for Router V2 deployments.

No signer, private key, transaction construction, broadcast, or state mutation.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3

INITIALIZABLE_SLOT = int("f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00", 16)
REENTRANCY_SLOT = int("9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00", 16)
IMPLEMENTATION_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
PROBE_SELECTOR = Web3.keccak(text="initializeV2()")[:4]
PROBE_SENDER = Web3.to_checksum_address("0x1000000000000000000000000000000000000001")

ADAPTERS: dict[str, list[tuple[str, str]]] = {
    "ethereum": [
        ("termMaxSwapAdapter", "0xd8a90e69aFa072B9ff33BbFdFf56767BE2028Dc9"),
        ("erc4626VaultAdapterV2", "0xf03f14d1c1672D9740E0B23c8Fe88dc25Ae4d463"),
        ("lifiSwapAdapter", "0x4eBA5ebC7E96922229FfA5cC8d959357497666d2"),
        ("odosV2AdapterV2", "0x7a9d038285aBf4B35906508821E5C3bB41493cf5"),
        ("okxSwapAdapter", "0x8fE56ef6fD4f64dd2A0eB21FB634391890455f63"),
        ("ondoSwapAdapter", "0xfaa4cBa1aaa206FfB774A252224fFd54f7f2F082"),
        ("oneInchSwapAdapter", "0x06035214e843C0f115eE02a74a38B95bF978a3B8"),
        ("pancakeSmartAdapter", "0x043516D022bF814ccfAF6e9eB2eAc6E97341D14b"),
        ("pendleSwapV3AdapterV2", "0xfaF7D0EE1300631f465fF8cA6ea332F9c5a27bbe"),
    ],
    "arbitrum": [
        ("termMaxSwapAdapter", "0x6Aa7148411001217f31d5AE96053E17A7f8ecE6A"),
        ("erc4626VaultAdapterV2", "0x4961bC8E4B0b2be8c6dBE99d2d4647C27F62E4Cd"),
        ("lifiSwapAdapter", "0xbaC506e0EAE9F05Ce9cEEEa7B0C9660C279b8B05"),
        ("odosV2AdapterV2", "0x242CB48c78591058bB278008d96f6c1dd0f7a8c6"),
        ("okxSwapAdapter", "0x9BB1A564A6d01aEB9268f7162b537bDf958126d6"),
        ("oneInchSwapAdapter", "0xe9AD9a916b3555C310e206a4fA116e174da97Dd8"),
        ("pendleSwapV3AdapterV2", "0xC7cdaD93bDcAFCC7b8f30c20B23b13E17147300D"),
    ],
    "bnb": [
        ("termMaxSwapAdapter", "0x9a3fAdF7a1F7e897BA33BD48802cDDa446c4508E"),
        ("erc4626VaultAdapterV2", "0x6ece47d0606428b46b0CfED2E33Fab806Cc888dc"),
        ("lifiSwapAdapter", "0x89ed60510b1E98F80F977B2c33C0601ec955695c"),
        ("odosV2AdapterV2", "0x8DA157f56E279acc6d2CA897E8B1d7FFA8Cc2270"),
        ("okxSwapAdapter", "0x9BfAd67747e4430945a223D991bC01e0ABD26F5e"),
        ("ondoSwapAdapter", "0xeD2Af062189Fc331805B186634Aae58b61D77be4"),
        ("oneInchSwapAdapter", "0x286427fB95948374B755b716CFEE94935956491E"),
        ("pancakeSmartAdapter", "0x32aCd5ba1235841c320BbE95994781945dE55170"),
        ("pendleSwapV3AdapterV2", "0x5cd23AEF6850af95b039e17baA8C13788DC6FE88"),
    ],
    "base": [
        ("termMaxSwapAdapter", "0x8b2ae4e2070b3E9bf9625FC61290700a2E24A808"),
        ("erc4626VaultAdapterV2", "0xbb35188CD8Ba0A85ED8C8406187cA6443203423d"),
        ("lifiSwapAdapter", "0x6Ac37B549660F2c9F1a77597Ee1ACA5F742C7093"),
        ("odosV2AdapterV2", "0xFa8BE638a78fa426C4228Df1002fD54fA48A6CAF"),
        ("okxSwapAdapter", "0x6Fa11E0e1e0eE768DEB0E728a08a4407d15EE466"),
        ("oneInchSwapAdapter", "0xAD4b718378A9B4144b1A549915D794D4d67523dB"),
        ("pendleSwapV3AdapterV2", "0x2F5a0E23833C55C3B60b3c0a9926d37b49f2b152"),
    ],
    "b2": [
        ("termMaxSwapAdapter", "0x4dF00b86ceB111dD727c14942b5Fdab8A695cCD3"),
        ("erc4626VaultAdapterV2", "0x4C6b0fA7f63383466fBa3466B7AF3ca91Ec815Ea"),
        ("uniswapV3AdapterV2", "0xBd795F755dbB5A5358D6c60AED53ceB486Fa8517"),
    ],
    "berachain": [
        ("termMaxSwapAdapter", "0xFfa110A6b661f6a434DeD132168f6fa9f394B7cF"),
        ("erc4626VaultAdapterV2", "0x8Cf5139144b3B472d5A914E2aCe5Ae5c06dB11eE"),
        ("kodiakSwapAdapter", "0x5036017067A141726AEE407dbD07949Bc8BeBD2B"),
        ("pendleSwapV3AdapterV2", "0x93002b4E4894eDDB2fDdE5545f4C792624251b6E"),
    ],
    "xlayer": [
        ("termMaxSwapAdapter", "0x48bCd27e208dC973C3F56812F762077A90E88Cea"),
        ("erc4626VaultAdapterV2", "0xC7dE1A55758bDBa5CC6b6f7535006eE1349A6d37"),
        ("okxSwapAdapter", "0xA0E0702b701cCaC329732Bb409681612f43E41AD"),
    ],
    "pharos": [
        ("termMaxSwapAdapter", "0xdE91aA25C3555be729a751eFcC836dd7F3446EFc"),
        ("erc4626VaultAdapterV2", "0x5B5788881d5f291c1c6b48C5231f4AA64635e5Bd"),
    ],
}

ROUTER_ABI = [
    {"type":"function","name":"whitelistManager","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"defaultWhitelistModule","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"adapterWhitelist","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"bool"}]},
]
WHITELIST_ABI = [
    {"type":"function","name":"isWhitelisted","stateMutability":"view","inputs":[{"type":"address"},{"type":"uint8"}],"outputs":[{"type":"bool"}]},
]


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def run(base: Any) -> None:
    requested = os.environ.get("CHAIN", "all").strip().lower()
    configs = base.CHAINS if requested == "all" else [row for row in base.CHAINS if row["name"] == requested]
    rows: list[dict[str, Any]] = []
    for config in configs:
        try:
            w3, rpc, attempts = base.connect(config)
            latest = w3.eth.block_number
            block = w3.eth.get_block(latest)
            router_address = Web3.to_checksum_address(config["router"])
            router = w3.eth.contract(address=router_address, abi=ROUTER_ABI)
            init_raw = w3.eth.get_storage_at(router_address, INITIALIZABLE_SLOT, block_identifier=latest)
            guard_raw = w3.eth.get_storage_at(router_address, REENTRANCY_SLOT, block_identifier=latest)
            impl_raw = w3.eth.get_storage_at(router_address, IMPLEMENTATION_SLOT, block_identifier=latest)
            initialized = int.from_bytes(init_raw[-8:], "big")
            initializing = bool(init_raw[-9])
            guard_status = int.from_bytes(guard_raw, "big")
            implementation = Web3.to_checksum_address("0x" + impl_raw[-20:].hex())
            implementation_code = w3.eth.get_code(implementation, block_identifier=latest)
            manager_r = safe(router.functions.whitelistManager().call, block_identifier=latest)
            default_module_r = safe(router.functions.defaultWhitelistModule().call, block_identifier=latest)
            manager_address = manager_r.get("value") if manager_r.get("ok") else None
            manager = (
                w3.eth.contract(address=Web3.to_checksum_address(manager_address), abi=WHITELIST_ABI)
                if manager_address else None
            )
            adapter_rows: list[dict[str, Any]] = []
            for name, raw_address in ADAPTERS.get(config["name"], []):
                address = Web3.to_checksum_address(raw_address)
                adapter_rows.append({
                    "name": name,
                    "address": address,
                    "codeBytes": len(w3.eth.get_code(address, block_identifier=latest)),
                    "moduleAdapterWhitelisted": (
                        safe(manager.functions.isWhitelisted(address, 0).call, block_identifier=latest)
                        if manager else {"ok": False, "error": "whitelist manager unavailable"}
                    ),
                    "legacyAdapterWhitelist": safe(
                        router.functions.adapterWhitelist(address).call, block_identifier=latest
                    ),
                })
            probe_call: dict[str, Any]
            try:
                result = w3.eth.call(
                    {"from": PROBE_SENDER, "to": router_address, "data": PROBE_SELECTOR},
                    block_identifier=latest,
                )
                probe_call = {"ok": True, "returnData": Web3.to_hex(result)}
            except Exception as exc:  # noqa: BLE001
                probe_call = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            rows.append({
                "chain": config["name"],
                "chainId": config["chainId"],
                "rpc": rpc,
                "rpcAttempts": attempts,
                "block": {
                    "number": latest,
                    "hash": block.hash.hex(),
                    "timestamp": int(block.timestamp),
                    "timestampUtc": datetime.fromtimestamp(block.timestamp, tz=timezone.utc).isoformat(),
                },
                "router": router_address,
                "implementation": implementation,
                "implementationCodeBytes": len(implementation_code),
                "probeSelectorPresentInImplementation": bytes(PROBE_SELECTOR) in bytes(implementation_code),
                "initializableStorageRaw": Web3.to_hex(init_raw),
                "initializedVersion": initialized,
                "initializing": initializing,
                "reentrancyStorageRaw": Web3.to_hex(guard_raw),
                "reentrancyStatus": guard_status,
                "whitelistManager": manager_r,
                "defaultWhitelistModule": default_module_r,
                "arbitrarySenderUpgradeStateProbe": probe_call,
                "adapters": adapter_rows,
                "verdict": {
                    "initializedVersionIsOne": initialized == 1,
                    "guardIdleStatusIsOne": guard_status == 1,
                    "probeCallSucceeds": bool(probe_call.get("ok")),
                    "hasLiveModuleWhitelistedAdapter": any(
                        row["codeBytes"] > 0
                        and row["moduleAdapterWhitelisted"].get("ok")
                        and row["moduleAdapterWhitelisted"].get("value") is True
                        for row in adapter_rows
                    ),
                    "hasLiveModuleWhitelistedCallbackAdapter": any(
                        row["name"] in {"okxSwapAdapter", "lifiSwapAdapter", "odosV2AdapterV2", "oneInchSwapAdapter", "pancakeSmartAdapter", "kodiakSwapAdapter"}
                        and row["codeBytes"] > 0
                        and row["moduleAdapterWhitelisted"].get("ok")
                        and row["moduleAdapterWhitelisted"].get("value") is True
                        for row in adapter_rows
                    ),
                },
            })
        except Exception as exc:  # noqa: BLE001
            rows.append({
                "chain": config["name"],
                "chainId": config["chainId"],
                "router": config["router"],
                "fatalError": f"{type(exc).__name__}: {exc}",
            })
    result = {
        "schema": "termmax-router-upgrade-state-census/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rows": rows,
    }
    out = Path(os.environ.get("OUT_DIR", "evidence"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "ROUTER_UPGRADE_STATE_CENSUS.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "ROUTER_UPGRADE_STATE_VERDICT.json").write_text(
        json.dumps({row.get("chain"): row.get("verdict", {"fatalError": row.get("fatalError")}) for row in rows}, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2))
