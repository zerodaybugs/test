#!/usr/bin/env python3
"""Read-only cross-chain initialization and ownership census for TermMax core proxies.

Safety boundary: this script only performs public JSON-RPC reads and eth_call
simulations at the latest block. It has no private key, signer, transaction
construction, broadcast, impersonation, or state-changing capability.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eth_abi import encode
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
REPO = Path(os.environ.get("TERMMAX_REPO", "/tmp/termmax-contract-v2"))
ATTACKER = Web3.to_checksum_address("0x1000000000000000000000000000000000000001")
ZERO = "0x0000000000000000000000000000000000000000"

IMPLEMENTATION_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
ADMIN_SLOT = int("b53127684a568b3173ae13b9f8a6016e0194a0f7915d6e331c9b6a557b5d6103", 16)
BEACON_SLOT = int("a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", 16)
INITIALIZABLE_SLOT = int("f0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00", 16)
DEFAULT_ADMIN_ROLE = b"\x00" * 32

CHAINS: list[dict[str, Any]] = [
    {
        "name": "ethereum", "chainId": 1, "deploymentDir": "eth-mainnet", "poa": False,
        "rpcs": ["https://ethereum-rpc.publicnode.com", "https://rpc.mevblocker.io", "https://eth.drpc.org"],
    },
    {
        "name": "arbitrum", "chainId": 42161, "deploymentDir": "arb-mainnet", "poa": False,
        "rpcs": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.drpc.org"],
    },
    {
        "name": "bnb", "chainId": 56, "deploymentDir": "bnb-mainnet", "poa": True,
        "rpcs": ["https://bsc-dataseed.binance.org", "https://bsc-rpc.publicnode.com", "https://bsc.drpc.org"],
    },
    {
        "name": "base", "chainId": 8453, "deploymentDir": "base-mainnet", "poa": False,
        "rpcs": ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"],
    },
    {
        "name": "b2", "chainId": 223, "deploymentDir": "b2-mainnet", "poa": False,
        "rpcs": ["https://rpc.bsquared.network", "https://b2-mainnet.alt.technology"],
    },
    {
        "name": "berachain", "chainId": 80094, "deploymentDir": "bera-mainnet", "poa": False,
        "rpcs": ["https://rpc.berachain.com", "https://berachain-rpc.publicnode.com"],
    },
    {
        "name": "xlayer", "chainId": 196, "deploymentDir": "xlayer-mainnet", "poa": True,
        "rpcs": ["https://rpc.xlayer.tech", "https://xlayerrpc.okx.com"],
    },
    {
        "name": "pharos", "chainId": 688688, "deploymentDir": "pharos-mainnet", "poa": False,
        "rpcs": ["https://rpc.pharosnetwork.xyz", "https://api.pharosnetwork.xyz"],
    },
    {
        "name": "hyperevm", "chainId": 999, "deploymentDir": "hyperevm-mainnet", "poa": False,
        "rpcs": ["https://rpc.hyperliquid.xyz/evm"],
    },
]

OWNABLE_ABI = [
    {"type":"function","name":"owner","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"pendingOwner","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"getVersion","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]
ACCESS_ABI = [
    {"type":"function","name":"hasRole","stateMutability":"view","inputs":[{"type":"bytes32"},{"type":"address"}],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"getRoleAdmin","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bytes32"}]},
    {"type":"function","name":"getVersion","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
]


def checksum(value: str) -> str:
    return Web3.to_checksum_address(value)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        if isinstance(value, bytes):
            value = "0x" + value.hex()
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect(config: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    env_name = f"{config['name'].upper()}_RPC_URL"
    urls = [os.environ.get(env_name, "").strip(), *config["rpcs"]]
    for url in [x for x in urls if x]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            if config.get("poa"):
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = int(w3.eth.chain_id)
            block = w3.eth.get_block("latest")
            if chain_id != config["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def load_deployment(config: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    deployment_dir = REPO / "deployments" / config["deploymentDir"]
    core_files = sorted(deployment_dir.glob("*-core-v2.json"))
    access_files = sorted(deployment_dir.glob("*-access-manager.json"))
    if not core_files:
        raise FileNotFoundError(f"no core-v2 deployment in {deployment_dir}")
    core = json.loads(core_files[-1].read_text(encoding="utf-8"))
    access = json.loads(access_files[-1].read_text(encoding="utf-8")) if access_files else {}
    return core, access


def address_from_slot(raw: bytes) -> str:
    if not raw or int.from_bytes(raw, "big") == 0:
        return ZERO
    return checksum("0x" + raw[-20:].hex())


def decode_initializable(raw: bytes) -> tuple[int, bool]:
    initialized = int.from_bytes(raw[-8:], "big")
    initializing = bool(raw[-9])
    return initialized, initializing


def eth_call_data(w3: Web3, target: str, signature: str, args: list[Any], arg_types: list[str], block: int) -> dict[str, Any]:
    selector = Web3.keccak(text=signature)[:4]
    payload = selector + (encode(arg_types, args) if arg_types else b"")
    return safe(
        w3.eth.call,
        {"from": ATTACKER, "to": target, "data": payload},
        block_identifier=block,
    )


def inspect_proxy(
    w3: Web3,
    block: int,
    chain: str,
    kind: str,
    address: str,
    expected_owner: str | None,
    expected_admin: str | None,
) -> dict[str, Any]:
    address = checksum(address)
    code = w3.eth.get_code(address, block_identifier=block)
    impl_raw = w3.eth.get_storage_at(address, IMPLEMENTATION_SLOT, block_identifier=block)
    admin_raw = w3.eth.get_storage_at(address, ADMIN_SLOT, block_identifier=block)
    beacon_raw = w3.eth.get_storage_at(address, BEACON_SLOT, block_identifier=block)
    init_raw = w3.eth.get_storage_at(address, INITIALIZABLE_SLOT, block_identifier=block)
    implementation = address_from_slot(impl_raw)
    proxy_admin = address_from_slot(admin_raw)
    beacon = address_from_slot(beacon_raw)
    initialized, initializing = decode_initializable(init_raw)

    contract = w3.eth.contract(address=address, abi=ACCESS_ABI if kind == "accessManager" else OWNABLE_ABI)
    calls: dict[str, Any] = {}
    if kind == "accessManager":
        if expected_admin:
            calls["expectedAdminHasDefaultAdminRole"] = safe(
                contract.functions.hasRole(DEFAULT_ADMIN_ROLE, checksum(expected_admin)).call,
                block_identifier=block,
            )
        calls["attackerHasDefaultAdminRole"] = safe(
            contract.functions.hasRole(DEFAULT_ADMIN_ROLE, ATTACKER).call,
            block_identifier=block,
        )
        calls["defaultAdminRoleAdmin"] = safe(
            contract.functions.getRoleAdmin(DEFAULT_ADMIN_ROLE).call,
            block_identifier=block,
        )
        calls["getVersion"] = safe(contract.functions.getVersion().call, block_identifier=block)
    else:
        calls["owner"] = safe(contract.functions.owner().call, block_identifier=block)
        calls["pendingOwner"] = safe(contract.functions.pendingOwner().call, block_identifier=block)
        calls["paused"] = safe(contract.functions.paused().call, block_identifier=block)
        calls["getVersion"] = safe(contract.functions.getVersion().call, block_identifier=block)

    init_probe = eth_call_data(w3, address, "initialize(address)", [ATTACKER], ["address"], block)
    reinit_probe = (
        eth_call_data(w3, address, "initializeV2()", [], [], block)
        if kind == "routerV2"
        else None
    )

    implementation_row: dict[str, Any] = {
        "address": implementation,
        "codeBytes": 0,
        "initializableStorageRaw": None,
        "initializedVersion": None,
        "arbitrarySenderInitializeEthCall": None,
    }
    if implementation != ZERO:
        impl_code = w3.eth.get_code(implementation, block_identifier=block)
        impl_init_raw = w3.eth.get_storage_at(implementation, INITIALIZABLE_SLOT, block_identifier=block)
        impl_initialized, impl_initializing = decode_initializable(impl_init_raw)
        implementation_row.update({
            "codeBytes": len(impl_code),
            "initializableStorageRaw": "0x" + impl_init_raw.hex(),
            "initializedVersion": impl_initialized,
            "initializing": impl_initializing,
            "arbitrarySenderInitializeEthCall": eth_call_data(
                w3, implementation, "initialize(address)", [ATTACKER], ["address"], block
            ),
            "nativeBalanceWei": int(w3.eth.get_balance(implementation, block_identifier=block)),
        })

    owner_value = calls.get("owner", {}).get("value") if kind != "accessManager" else None
    expected_owner_match = (
        isinstance(owner_value, str)
        and expected_owner is not None
        and owner_value.lower() == expected_owner.lower()
    )
    proxy_takeover_open = bool(init_probe.get("ok")) or initialized == 0
    proxy_shape_valid = implementation != ZERO and len(code) > 0 and implementation_row["codeBytes"] > 0
    ownership_valid = True
    if kind == "accessManager":
        ownership_valid = bool(calls.get("expectedAdminHasDefaultAdminRole", {}).get("value")) and not bool(
            calls.get("attackerHasDefaultAdminRole", {}).get("value")
        )
    elif expected_owner is not None:
        ownership_valid = expected_owner_match

    return {
        "chain": chain,
        "kind": kind,
        "address": address,
        "codeBytes": len(code),
        "expectedOwner": expected_owner,
        "expectedAdmin": expected_admin,
        "implementationSlotRaw": "0x" + impl_raw.hex(),
        "implementation": implementation,
        "adminSlot": proxy_admin,
        "beaconSlot": beacon,
        "initializableStorageRaw": "0x" + init_raw.hex(),
        "initializedVersion": initialized,
        "initializing": initializing,
        "calls": calls,
        "arbitrarySenderInitializeEthCall": init_probe,
        "arbitrarySenderInitializeV2EthCall": reinit_probe,
        "implementationState": implementation_row,
        "verdict": {
            "proxyShapeValid": proxy_shape_valid,
            "proxyTakeoverOpen": proxy_takeover_open,
            "ownershipOrAdminValid": ownership_valid,
            "expectedOwnerMatches": expected_owner_match if kind != "accessManager" else None,
            "implementationInitializerUnlocked": bool(
                implementation_row.get("arbitrarySenderInitializeEthCall", {}).get("ok")
            ),
            "implementationHasNativeBalance": bool(implementation_row.get("nativeBalanceWei", 0)),
            "criticalCandidate": proxy_shape_valid and (proxy_takeover_open or not ownership_valid),
        },
    }


def run_chain(config: dict[str, Any]) -> dict[str, Any]:
    core, access_deployment = load_deployment(config)
    w3, rpc, attempts = connect(config)
    block_obj = w3.eth.get_block("latest")
    block = int(block_obj.number)
    contracts = core.get("contracts", {})
    admin = checksum(access_deployment.get("admin") or core.get("admin"))
    access_manager = access_deployment.get("contracts", {}).get("accessManager")
    access_manager = checksum(access_manager) if access_manager and access_manager != ZERO else None

    targets: list[tuple[str, str, str | None, str | None]] = []
    if access_manager:
        targets.append(("accessManager", access_manager, None, admin))
    for kind, key in [
        ("whitelistManager", "whitelistManager"),
        ("routerV2", "routerV2"),
        ("termMaxViewer", "termMaxViewer"),
        ("makerHelper", "makerHelper"),
    ]:
        address = contracts.get(key)
        if address and address != ZERO:
            targets.append((kind, checksum(address), access_manager, None))

    rows = [
        inspect_proxy(w3, block, config["name"], kind, address, owner, expected_admin)
        for kind, address, owner, expected_admin in targets
    ]
    return {
        "chain": config["name"],
        "chainId": config["chainId"],
        "deploymentDir": config["deploymentDir"],
        "deploymentCommit": core.get("gitCommitHash"),
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {
            "number": block,
            "hash": block_obj.hash.hex(),
            "timestamp": int(block_obj.timestamp),
            "timestampUtc": datetime.fromtimestamp(block_obj.timestamp, tz=timezone.utc).isoformat(),
        },
        "admin": admin,
        "accessManager": access_manager,
        "rows": rows,
        "criticalCandidates": [row for row in rows if row["verdict"]["criticalCandidate"]],
    }


def main() -> int:
    requested = os.environ.get("CHAIN", "all").strip().lower()
    configs = CHAINS if requested == "all" else [row for row in CHAINS if row["name"] == requested]
    chains: list[dict[str, Any]] = []
    for config in configs:
        try:
            chains.append(run_chain(config))
        except Exception as exc:  # noqa: BLE001
            chains.append({
                "chain": config["name"],
                "chainId": config["chainId"],
                "deploymentDir": config["deploymentDir"],
                "fatalError": f"{type(exc).__name__}: {exc}",
            })

    all_rows = [row for chain in chains for row in chain.get("rows", [])]
    critical = [row for row in all_rows if row.get("verdict", {}).get("criticalCandidate")]
    unlocked_implementations = [
        row for row in all_rows if row.get("verdict", {}).get("implementationInitializerUnlocked")
    ]
    verdict = {
        "chainCount": len(chains),
        "successfulChainCount": sum(1 for chain in chains if not chain.get("fatalError")),
        "targetCount": len(all_rows),
        "criticalCandidateCount": len(critical),
        "unlockedImplementationInitializerCount": len(unlocked_implementations),
        "nextStep": "PINNED_FORK_TAKEOVER_POC" if critical else "KILL_NO_UNINITIALIZED_OR_MISOWNED_CORE_PROXY",
    }
    result = {
        "schema": "termmax-core-proxy-init-census/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {
            "privateKeys": 0,
            "signers": 0,
            "signedTransactions": 0,
            "broadcastTransactions": 0,
            "stateChanges": 0,
        },
        "source": {
            "repository": "term-structure/termmax-contract-v2",
            "commit": "e314f3f849577dfecd4614f148c4df81fdf8c72d",
        },
        "verdict": verdict,
        "chains": chains,
        "criticalCandidates": critical,
        "unlockedImplementationInitializers": unlocked_implementations,
    }
    (OUT / "CORE_PROXY_INIT_CENSUS.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (OUT / "VERDICT.json").write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    print(json.dumps(verdict, indent=2))
    return 0 if all(not chain.get("fatalError") for chain in chains) else 2


if __name__ == "__main__":
    raise SystemExit(main())
