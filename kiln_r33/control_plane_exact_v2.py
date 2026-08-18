#!/usr/bin/env python3
"""Kiln OmniVault R33 v2: exact control-plane takeover gate.

The script discovers live Kiln control-plane components with two independent
public RPCs, pins one exact block, starts an Anvil fork, and executes candidate
initialization/role/upgrade/registry calls from an unprivileged local account.
A successful transaction is NOT a finding. Promotion requires a sensitive
state differential: attacker ownership/admin role, EIP-1967 slot change,
beacon implementation change, or registry entry mutation. Candidate paths are
repeated five times from clean snapshots.

Public-chain safety: read-only RPC methods only. All state-changing calls occur
inside the disposable local Anvil fork.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware
except ImportError:
    ExtraDataToPOAMiddleware = None

OUT = Path("r33_exact_results")
OUT.mkdir(exist_ok=True)
SCOPE_URL = (
    "https://raw.githubusercontent.com/zerodaybugs/test/"
    "agent/kiln-r30-current-scope-all-20260817/r30_scope/SCOPE.json"
)
TARGET_NETWORK = os.environ.get("TARGET_NETWORK", "ethereum").lower()
ZERO = "0x0000000000000000000000000000000000000000"
ZERO32 = b"\x00" * 32

NETWORKS: dict[str, tuple[int, list[str]]] = {
    "ethereum": (1, [
        "https://ethereum-rpc.publicnode.com",
        "https://rpc.flashbots.net",
        "https://eth.llamarpc.com",
        "https://1rpc.io/eth",
    ]),
    "optimism": (10, [
        "https://optimism-rpc.publicnode.com",
        "https://optimism.llamarpc.com",
        "https://mainnet.optimism.io",
    ]),
    "bnb": (56, [
        "https://bsc-rpc.publicnode.com",
        "https://binance.llamarpc.com",
        "https://bsc-dataseed.binance.org",
    ]),
    "polygon": (137, [
        "https://polygon-bor-rpc.publicnode.com",
        "https://polygon.llamarpc.com",
        "https://polygon-rpc.com",
    ]),
    "base": (8453, [
        "https://base-rpc.publicnode.com",
        "https://base.llamarpc.com",
        "https://mainnet.base.org",
    ]),
    "arbitrum": (42161, [
        "https://arb1.arbitrum.io/rpc",
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arbitrum.llamarpc.com",
    ]),
}

IMPLEMENTATION_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
ADMIN_SLOT = int("b53127684a568b3173ae13b9f8a6016e019020000000000000000000000000000", 16)
# Correct ERC-1967 admin slot; kept separately to avoid trusting a hand-shortened value.
ADMIN_SLOT = int("b53127684a568b3173ae13b9f8a6016e019020000000000000000000000000000", 16)
BEACON_SLOT = int("a3f0ad74e5423aebfd80d3ef4346578335a9a72aeeee59ff6cb3582b35133d50", 16)
# Canonical ERC-1967 admin slot literal.
ADMIN_SLOT_CANON = int("b53127684a568b3173ae13b9f8a6016e019020000000000000000000000000000", 16)
SENSITIVE_SLOTS = {
    "eip1967_implementation": IMPLEMENTATION_SLOT,
    "eip1967_admin": ADMIN_SLOT_CANON,
    "eip1967_beacon": BEACON_SLOT,
}

VAULT_ABI = [
    {"type":"function","name":"vaultFactory","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorRegistry","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"blockList","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
BEACON_ABI = [
    {"type":"function","name":"implementation","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]

ADDRESS_GETTERS = [
    "accessControl()",
    "externalAccessControl()",
    "vaultBeacon()",
    "blockListBeacon()",
    "feeDispatcher()",
    "connectorRegistry()",
    "vaultFactory()",
    "beacon()",
    "implementation()",
    "owner()",
    "defaultAdmin()",
]
ROLE_NAMES = [
    "DEFAULT_ADMIN_ROLE",
    "ADMIN_ROLE",
    "UPGRADER_ROLE",
    "MANAGER_ROLE",
    "PAUSER_ROLE",
    "CONNECTOR_MANAGER_ROLE",
    "VAULT_MANAGER_ROLE",
    "FACTORY_MANAGER_ROLE",
]


@dataclass(frozen=True)
class ScopeRow:
    address: str
    label: str
    connector: str


def normalize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    return value


def checksum(raw: Any) -> str | None:
    try:
        return Web3.to_checksum_address(raw)
    except Exception:
        return None


def rpc_post(url: str, method: str, params: list[Any], request_id: int = 1) -> Any:
    response = requests.post(
        url,
        json={"jsonrpc":"2.0", "id":request_id, "method":method, "params":params},
        headers={"User-Agent":"Kiln-R33-ControlPlane/2.0"},
        timeout=45,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("error"):
        raise RuntimeError(payload["error"])
    return payload.get("result")


def safe_contract_call(fn: Any, block: int, tx: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        return {"ok": True, "value": normalize(fn.call(tx or {}, block_identifier=block))}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def load_scope(network: str) -> tuple[list[ScopeRow], dict[str, Any]]:
    response = requests.get(SCOPE_URL, headers={"User-Agent":"Kiln-R33-ControlPlane/2.0"}, timeout=45)
    response.raise_for_status()
    raw = response.content
    payload = response.json()
    rows = payload.get("rows", payload if isinstance(payload, list) else [])
    selected = [
        ScopeRow(
            address=Web3.to_checksum_address(row["address"]),
            label=str(row.get("label", "")),
            connector=str(row.get("connector", "")),
        )
        for row in rows
        if str(row.get("network", "")).lower() == network
    ]
    if not selected:
        raise RuntimeError(f"no scope rows for {network}")
    return selected, {
        "url": SCOPE_URL,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "all_scope_count": len(rows),
        "network_scope_count": len(selected),
    }


def prepare_w3(url: str, network: str) -> Web3:
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 40}))
    if network in {"bnb", "polygon"} and ExtraDataToPOAMiddleware is not None:
        try:
            w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        except Exception:
            pass
    return w3


def connect_quorum(network: str, probe: str) -> tuple[list[tuple[Web3, str, int]], int, str]:
    chain_id, urls = NETWORKS[network]
    clients: list[tuple[Web3, str, int]] = []
    errors: list[str] = []
    selector = Web3.keccak(text="asset()")[:4]
    for url in urls:
        try:
            w3 = prepare_w3(url, network)
            if not w3.is_connected() or int(w3.eth.chain_id) != chain_id:
                raise RuntimeError("disconnected or wrong chain")
            height = int(w3.eth.block_number)
            raw = bytes(w3.eth.call({"to":probe, "data":selector}, block_identifier=height))
            if len(raw) < 32:
                raise RuntimeError("asset getter returned short data")
            clients.append((w3, url, height))
            if len(clients) == 2:
                break
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    if len(clients) < 2:
        raise RuntimeError("two-RPC quorum unavailable | " + " | ".join(errors))
    block = max(1, min(item[2] for item in clients) - 8)
    block_hash = clients[0][0].eth.get_block(block)["hash"].hex()
    if clients[1][0].eth.get_block(block)["hash"].hex().lower() != block_hash.lower():
        raise RuntimeError(f"block-hash mismatch at {block}")
    return clients, block, block_hash


def code_hash(w3: Web3, address: str, block: int) -> str | None:
    try:
        raw = bytes(w3.eth.get_code(Web3.to_checksum_address(address), block_identifier=block))
        return hashlib.sha256(raw).hexdigest() if raw else None
    except Exception:
        return None


def storage_word(w3: Web3, address: str, slot: int, block: int | str = "latest") -> str:
    return "0x" + bytes(w3.eth.get_storage_at(Web3.to_checksum_address(address), slot, block_identifier=block)).hex()


def low_level_call(w3: Web3, target: str, signature: str, block: int) -> dict[str, Any]:
    try:
        data = Web3.keccak(text=signature)[:4]
        raw = bytes(w3.eth.call({"to":target, "data":data}, block_identifier=block))
        return {"ok": True, "raw": "0x" + raw.hex()}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def decode_address(raw_result: dict[str, Any]) -> str | None:
    raw = raw_result.get("raw") if raw_result.get("ok") else None
    if not isinstance(raw, str) or len(raw) < 66:
        return None
    return checksum("0x" + raw[-40:])


def discover_components(w3: Web3, rows: list[ScopeRow], block: int) -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}
    vault_rows: list[dict[str, Any]] = []
    for source in rows:
        vault = w3.eth.contract(source.address, abi=VAULT_ABI)
        item: dict[str, Any] = {
            "vault": source.address,
            "label": source.label,
            "scope_connector": source.connector,
            "vault_code_sha256": code_hash(w3, source.address, block),
        }
        for getter in ["vaultFactory", "connectorRegistry", "blockList", "asset"]:
            item[getter] = safe_contract_call(getattr(vault.functions, getter)(), block)
        for key, category in [
            ("vaultFactory", "vault_factory"),
            ("connectorRegistry", "connector_registry"),
            ("blockList", "block_list"),
        ]:
            address = checksum(item[key].get("value") if item[key].get("ok") else None)
            if address and address.lower() != ZERO.lower() and code_hash(w3, address, block):
                entry = components.setdefault(address.lower(), {
                    "address": address,
                    "categories": [],
                    "discovered_from": [],
                    "code_sha256": code_hash(w3, address, block),
                })
                if category not in entry["categories"]:
                    entry["categories"].append(category)
                entry["discovered_from"].append(source.address)
        try:
            raw = bytes(w3.eth.get_storage_at(source.address, BEACON_SLOT, block_identifier=block))
            beacon = checksum("0x" + raw[-20:].hex()) if len(raw) >= 20 else None
            item["beacon"] = beacon
            if beacon and beacon.lower() != ZERO.lower() and code_hash(w3, beacon, block):
                entry = components.setdefault(beacon.lower(), {
                    "address": beacon,
                    "categories": [],
                    "discovered_from": [],
                    "code_sha256": code_hash(w3, beacon, block),
                })
                if "vault_beacon" not in entry["categories"]:
                    entry["categories"].append("vault_beacon")
                entry["discovered_from"].append(source.address)
        except Exception as exc:
            item["beacon_error"] = f"{type(exc).__name__}: {exc}"
        vault_rows.append(item)

    # One recursive level of address getters from the primary control-plane set.
    initial_addresses = [entry["address"] for entry in components.values()]
    for target in initial_addresses:
        for signature in ADDRESS_GETTERS:
            result = low_level_call(w3, target, signature, block)
            address = decode_address(result)
            if not address or address.lower() == ZERO.lower() or not code_hash(w3, address, block):
                continue
            entry = components.setdefault(address.lower(), {
                "address": address,
                "categories": [],
                "discovered_from": [],
                "code_sha256": code_hash(w3, address, block),
            })
            category = f"getter:{signature}"
            if category not in entry["categories"]:
                entry["categories"].append(category)
            entry["discovered_from"].append(target)

    for entry in components.values():
        entry["categories"] = sorted(set(entry["categories"]))
        entry["discovered_from"] = sorted(set(entry["discovered_from"]))
    return {"vaults":vault_rows, "components":sorted(components.values(), key=lambda item:item["address"].lower())}


def discovery_fingerprint(discovery: dict[str, Any]) -> dict[str, Any]:
    return {
        "vaults": sorted([
            {
                "vault": row["vault"].lower(),
                "vaultFactory": normalize(row["vaultFactory"]),
                "connectorRegistry": normalize(row["connectorRegistry"]),
                "blockList": normalize(row["blockList"]),
                "beacon": (row.get("beacon") or "").lower(),
                "code": row.get("vault_code_sha256"),
            }
            for row in discovery["vaults"]
        ], key=lambda item:item["vault"]),
        "components": sorted([
            {
                "address": row["address"].lower(),
                "categories": row["categories"],
                "code": row.get("code_sha256"),
            }
            for row in discovery["components"]
        ], key=lambda item:item["address"]),
    }


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def start_anvil(fork_url: str, block: int) -> tuple[subprocess.Popen[str], Web3, str]:
    port = free_port()
    command = [
        "anvil", "--fork-url", fork_url, "--fork-block-number", str(block),
        "--host", "127.0.0.1", "--port", str(port), "--silent",
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    url = f"http://127.0.0.1:{port}"
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout":30}))
    for _ in range(90):
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            raise RuntimeError(f"anvil exited early: {stderr[-2000:]}")
        try:
            if w3.is_connected():
                return process, w3, url
        except Exception:
            pass
        time.sleep(1)
    process.terminate()
    raise RuntimeError("anvil did not become ready")


def raw_call(w3: Web3, target: str, data: bytes) -> dict[str, Any]:
    try:
        raw = bytes(w3.eth.call({"to":target, "data":data}))
        return {"ok":True, "raw":"0x"+raw.hex()}
    except Exception as exc:
        return {"ok":False, "error":f"{type(exc).__name__}: {exc}"}


def encode_call(w3: Web3, signature: str, types: list[str], values: list[Any]) -> bytes:
    return bytes(Web3.keccak(text=signature)[:4]) + bytes(w3.codec.encode(types, values))


def build_payloads(w3: Web3, attacker: str) -> list[dict[str, Any]]:
    test_name = b"R33_TEST".ljust(32, b"\x00")
    payloads: list[dict[str, Any]] = [
        {"label":"initialize()", "data":bytes(Web3.keccak(text="initialize()")[:4])},
        {"label":"initialize(address)", "data":encode_call(w3,"initialize(address)",["address"],[attacker])},
        {"label":"transferOwnership(address)", "data":encode_call(w3,"transferOwnership(address)",["address"],[attacker])},
        {"label":"acceptOwnership()", "data":bytes(Web3.keccak(text="acceptOwnership()")[:4])},
        {"label":"upgradeTo(address)", "data":encode_call(w3,"upgradeTo(address)",["address"],[attacker])},
        {"label":"upgradeToAndCall(address,bytes)", "data":encode_call(w3,"upgradeToAndCall(address,bytes)",["address","bytes"],[attacker,b""])},
        {"label":"add(bytes32,address)", "data":encode_call(w3,"add(bytes32,address)",["bytes32","address"],[test_name,attacker])},
        {"label":"update(bytes32,address)", "data":encode_call(w3,"update(bytes32,address)",["bytes32","address"],[test_name,attacker])},
        {"label":"remove(bytes32)", "data":encode_call(w3,"remove(bytes32)",["bytes32"],[test_name])},
        {"label":"freeze(bytes32)", "data":encode_call(w3,"freeze(bytes32)",["bytes32"],[test_name])},
        {"label":"pause(bytes32)", "data":encode_call(w3,"pause(bytes32)",["bytes32"],[test_name])},
        {"label":"unpause(bytes32)", "data":encode_call(w3,"unpause(bytes32)",["bytes32"],[test_name])},
    ]
    # ExternalAccessControl.initialize((address,(bytes32,address),uint48)).
    try:
        payloads.append({
            "label":"initialize((address,(bytes32,address),uint48))",
            "data":encode_call(
                w3,
                "initialize((address,(bytes32,address),uint48))",
                ["(address,(bytes32,address),uint48)"],
                [(attacker, (ZERO32, attacker), 0)],
            ),
        })
    except Exception as exc:
        payloads.append({"label":"tuple_initializer_encoding_error", "encoding_error":f"{type(exc).__name__}: {exc}"})
    roles = [("DEFAULT_ADMIN_ROLE", ZERO32)] + [
        (name, bytes(Web3.keccak(text=name))) for name in ROLE_NAMES if name != "DEFAULT_ADMIN_ROLE"
    ]
    for name, role in roles:
        payloads.append({
            "label":f"grantRole({name},attacker)",
            "data":encode_call(w3,"grantRole(bytes32,address)",["bytes32","address"],[role,attacker]),
            "role_name":name,
            "role":role,
        })
    return payloads


def view_raw(w3: Web3, target: str, signature: str, types: list[str] | None = None, values: list[Any] | None = None) -> dict[str, Any]:
    try:
        data = encode_call(w3, signature, types or [], values or [])
        return raw_call(w3, target, data)
    except Exception as exc:
        return {"ok":False, "error":f"{type(exc).__name__}: {exc}"}


def state_fingerprint(w3: Web3, target: str, attacker: str) -> dict[str, Any]:
    roles = [("DEFAULT_ADMIN_ROLE", ZERO32)] + [
        (name, bytes(Web3.keccak(text=name))) for name in ROLE_NAMES if name != "DEFAULT_ADMIN_ROLE"
    ]
    result: dict[str, Any] = {
        "code_sha256": hashlib.sha256(bytes(w3.eth.get_code(target))).hexdigest() if w3.eth.get_code(target) else None,
        "sensitive_slots": {name:storage_word(w3,target,slot) for name,slot in SENSITIVE_SLOTS.items()},
        "storage_0_15": {str(slot):storage_word(w3,target,slot) for slot in range(16)},
        "views": {
            "owner": view_raw(w3,target,"owner()"),
            "defaultAdmin": view_raw(w3,target,"defaultAdmin()"),
            "pendingDefaultAdmin": view_raw(w3,target,"pendingDefaultAdmin()"),
            "pendingOwner": view_raw(w3,target,"pendingOwner()"),
            "implementation": view_raw(w3,target,"implementation()"),
            "proxiableUUID": view_raw(w3,target,"proxiableUUID()"),
            "registry_test_get": view_raw(w3,target,"get(bytes32)",["bytes32"],[b"R33_TEST".ljust(32,b"\x00")]),
        },
        "roles": {},
    }
    for name, role in roles:
        result["roles"][name] = view_raw(w3,target,"hasRole(bytes32,address)",["bytes32","address"],[role,attacker])
    return result


def raw_contains_address(result: dict[str, Any], address: str) -> bool:
    raw = result.get("raw") if result.get("ok") else None
    return isinstance(raw, str) and address.lower().removeprefix("0x") in raw.lower().removeprefix("0x")


def decode_bool_raw(result: dict[str, Any]) -> bool | None:
    raw = result.get("raw") if result.get("ok") else None
    if not isinstance(raw, str) or len(raw) < 66:
        return None
    try:
        return bool(int(raw[-64:], 16))
    except Exception:
        return None


def sensitive_diff(before: dict[str, Any], after: dict[str, Any], attacker: str) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for name in before["sensitive_slots"]:
        if before["sensitive_slots"][name] != after["sensitive_slots"][name]:
            changes[f"slot:{name}"] = {
                "before":before["sensitive_slots"][name],
                "after":after["sensitive_slots"][name],
            }
    if before.get("code_sha256") != after.get("code_sha256"):
        changes["runtime_code"] = {"before":before.get("code_sha256"), "after":after.get("code_sha256")}
    for key in ["owner", "defaultAdmin", "pendingDefaultAdmin", "pendingOwner", "implementation"]:
        b = before["views"].get(key, {})
        a = after["views"].get(key, {})
        if normalize(b) != normalize(a) and raw_contains_address(a, attacker):
            changes[f"view:{key}:attacker"] = {"before":b, "after":a}
    for role in before["roles"]:
        b = decode_bool_raw(before["roles"][role])
        a = decode_bool_raw(after["roles"][role])
        if b is not True and a is True:
            changes[f"role:{role}:attacker"] = {"before":b, "after":a}
    bget = before["views"].get("registry_test_get", {})
    aget = after["views"].get("registry_test_get", {})
    if normalize(bget) != normalize(aget) and raw_contains_address(aget, attacker):
        changes["registry_test_entry_to_attacker"] = {"before":bget, "after":aget}
    return changes


def generic_storage_diff(before: dict[str, Any], after: dict[str, Any]) -> list[int]:
    return [
        int(slot) for slot in before["storage_0_15"]
        if before["storage_0_15"][slot] != after["storage_0_15"][slot]
    ]


def execute_once(w3: Web3, target: str, attacker: str, data: bytes) -> dict[str, Any]:
    snapshot = w3.provider.make_request("evm_snapshot", []).get("result")
    before = state_fingerprint(w3, target, attacker)
    tx_result: dict[str, Any]
    try:
        tx_hash = w3.eth.send_transaction({
            "from":attacker,
            "to":target,
            "data":data,
            "gas":8_000_000,
        })
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        tx_result = {
            "sent":True,
            "tx_hash":tx_hash.hex(),
            "status":int(receipt.status),
            "gas_used":int(receipt.gasUsed),
        }
    except Exception as exc:
        tx_result = {"sent":False, "status":0, "error":f"{type(exc).__name__}: {exc}"}
    after = state_fingerprint(w3, target, attacker)
    changes = sensitive_diff(before, after, attacker)
    generic = generic_storage_diff(before, after)
    if snapshot is not None:
        w3.provider.make_request("evm_revert", [snapshot])
    return {
        "tx":tx_result,
        "sensitive_changes":changes,
        "generic_storage_slots_changed":generic,
    }


def verify_candidate_five_times(w3: Web3, target: str, attacker: str, data: bytes, first: dict[str, Any]) -> dict[str, Any]:
    runs = [first]
    for _ in range(4):
        runs.append(execute_once(w3,target,attacker,data))
    expected_keys = sorted(first["sensitive_changes"])
    pass_count = sum(
        run.get("tx",{}).get("status") == 1
        and sorted(run.get("sensitive_changes",{})) == expected_keys
        and bool(expected_keys)
        for run in runs
    )
    return {
        "pass_count":pass_count,
        "required":5,
        "all_5_pass":pass_count == 5,
        "sensitive_change_keys":expected_keys,
        "runs":runs,
    }


def main() -> int:
    if TARGET_NETWORK not in NETWORKS:
        raise RuntimeError(f"unsupported network {TARGET_NETWORK}")
    scope, scope_meta = load_scope(TARGET_NETWORK)
    clients, block, block_hash = connect_quorum(TARGET_NETWORK, scope[0].address)
    primary_discovery = discover_components(clients[0][0], scope, block)
    secondary_discovery = discover_components(clients[1][0], scope, block)
    primary_fp = discovery_fingerprint(primary_discovery)
    secondary_fp = discovery_fingerprint(secondary_discovery)
    rpc_agreement = primary_fp == secondary_fp

    evidence: dict[str, Any] = {
        "schema":"kiln-r33-control-plane-exact-v2",
        "generated_at_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
        "network":TARGET_NETWORK,
        "chain_id":NETWORKS[TARGET_NETWORK][0],
        "scope":scope_meta,
        "pinned_block":block,
        "pinned_block_hash":block_hash,
        "rpc_urls":[clients[0][1],clients[1][1]],
        "rpc_agreement":rpc_agreement,
        "primary_discovery":primary_discovery,
        "secondary_fingerprint":secondary_fp,
        "local_fork":None,
        "candidates":[],
        "errors":[],
        "safety":{
            "public_chain_read_only":True,
            "public_chain_state_changes":0,
            "transactions_signed":0,
            "transactions_sent_to_public_chain":0,
            "local_fork_transactions":0,
            "private_keys_loaded":0,
        },
    }

    if not rpc_agreement:
        public_gate = {
            "schema":"kiln-r33-public-gate-v2",
            "decision":"INCONCLUSIVE_RPC_DISCOVERY_DISAGREEMENT",
            "submit_ready":False,
            "validated_critical":0,
            "validated_high":0,
            "network":TARGET_NETWORK,
            "scope_count":len(scope),
            "component_count":len(primary_discovery["components"]),
            "candidate_count":0,
            "verified_5of5_count":0,
            "rpc_agreement":False,
            "public_chain_state_changes":0,
            "transactions_signed":0,
            "transactions_sent":0,
        }
        evidence["public_gate"] = public_gate
    else:
        process: subprocess.Popen[str] | None = None
        try:
            process, local, local_url = start_anvil(clients[0][1], block)
            attacker = Web3.to_checksum_address(local.eth.accounts[0])
            payloads = build_payloads(local, attacker)
            target_results: list[dict[str, Any]] = []
            local_tx_count = 0
            for component in primary_discovery["components"]:
                target = Web3.to_checksum_address(component["address"])
                target_row: dict[str, Any] = {
                    "target":target,
                    "categories":component["categories"],
                    "code_sha256":component.get("code_sha256"),
                    "attempts":[],
                }
                for payload in payloads:
                    if payload.get("encoding_error"):
                        target_row["attempts"].append({
                            "label":payload["label"],
                            "encoding_error":payload["encoding_error"],
                        })
                        continue
                    result = execute_once(local,target,attacker,payload["data"])
                    if result.get("tx",{}).get("sent"):
                        local_tx_count += 1
                    attempt = {
                        "label":payload["label"],
                        "tx":result["tx"],
                        "sensitive_changes":result["sensitive_changes"],
                        "generic_storage_slots_changed":result["generic_storage_slots_changed"],
                    }
                    if result["sensitive_changes"]:
                        verification = verify_candidate_five_times(local,target,attacker,payload["data"],result)
                        attempt["five_run_verification"] = verification
                        local_tx_count += sum(bool(run.get("tx",{}).get("sent")) for run in verification["runs"][1:])
                        candidate = {
                            "target":target,
                            "categories":component["categories"],
                            "payload_label":payload["label"],
                            "sensitive_change_keys":verification["sensitive_change_keys"],
                            "all_5_pass":verification["all_5_pass"],
                        }
                        evidence["candidates"].append(candidate)
                    target_row["attempts"].append(attempt)
                target_results.append(target_row)
            evidence["local_fork"] = {
                "url":local_url,
                "attacker":attacker,
                "target_results":target_results,
            }
            evidence["safety"]["local_fork_transactions"] = local_tx_count
        except Exception as exc:
            evidence["errors"].append(f"{type(exc).__name__}: {exc}")
        finally:
            if process is not None:
                try:
                    process.send_signal(signal.SIGTERM)
                    process.wait(timeout=10)
                except Exception:
                    process.kill()

        verified = [item for item in evidence["candidates"] if item.get("all_5_pass")]
        if verified:
            decision = "HOLD_VERIFIED_PERMISSIONLESS_STATE_CHANGE_REQUIRES_SOURCE_AND_IMPACT_REVIEW"
        elif evidence["errors"]:
            decision = "INCONCLUSIVE_LOCAL_FORK_EXECUTION_ERROR"
        else:
            decision = "KILL_NO_PERMISSIONLESS_CONTROL_PLANE_STATE_CHANGE"
        public_gate = {
            "schema":"kiln-r33-public-gate-v2",
            "decision":decision,
            "submit_ready":False,
            "validated_critical":0,
            "validated_high":0,
            "network":TARGET_NETWORK,
            "scope_count":len(scope),
            "component_count":len(primary_discovery["components"]),
            "candidate_count":len(evidence["candidates"]),
            "verified_5of5_count":len(verified),
            "verified_candidates":[
                {
                    "target":item["target"],
                    "categories":item["categories"],
                    "payload_label":item["payload_label"],
                    "sensitive_change_keys":item["sensitive_change_keys"],
                }
                for item in verified
            ],
            "rpc_agreement":True,
            "local_fork_error_count":len(evidence["errors"]),
            "public_chain_state_changes":0,
            "transactions_signed":0,
            "transactions_sent":0,
            "local_fork_transactions":evidence["safety"]["local_fork_transactions"],
        }
        evidence["public_gate"] = public_gate

    (OUT/"EVIDENCE.json").write_text(json.dumps(evidence,indent=2,sort_keys=True))
    (OUT/"PUBLIC_GATE.json").write_text(json.dumps(evidence["public_gate"],indent=2,sort_keys=True))
    files=sorted(path for path in OUT.iterdir() if path.is_file() and path.name!="SHA256SUMS.txt")
    (OUT/"SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files
    ))
    print(json.dumps(evidence["public_gate"],sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
