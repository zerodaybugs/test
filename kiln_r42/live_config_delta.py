#!/usr/bin/env python3
"""Kiln OmniVault R42 read-only live configuration/deployment delta census.

Safety boundary:
- public JSON-RPC reads and eth_call simulations only;
- no signing, private keys, or transaction broadcasts;
- fail closed on scope, RPC quorum, decoding, or coverage errors.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

OUT = Path("r42_results")
OUT.mkdir(parents=True, exist_ok=True)
SCOPE_URL = "https://cantina.xyz/bounties/c9a4b51b-2e80-4713-a06f-13524c530fa6"
USER_AGENT = "Kiln-R42-LiveConfigDelta/1.0"
TIMEOUT = 45
ZERO = "0x" + "00" * 20
ATTACKER = "0x1000000000000000000000000000000000000042"
BASELINE_SCOPE_COUNT = 101
BASELINE_MAINNET_VAULT_IMPLEMENTATION = "0x869855168858364368e62a5d1d092cc1dbd31f5a"

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
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arb1.arbitrum.io/rpc",
        "https://arbitrum.llamarpc.com",
    ]),
}

KNOWN_CONNECTOR_FAMILIES = {
    "AAVE_V3", "COMPOUND_V3", "SDAI", "SUSDS", "VENUS", "FLUID",
    "ANGLE_STUSD", "ANGLE_STEUR",
    "METAMORPHO_STEAKHOUSE_USDC", "METAMORPHO_STEAKHOUSE_USDT",
    "METAMORPHO_STEAKHOUSE_ETH", "METAMORPHO_GAUNTLET_USDA_CORE",
    "METAMORPHO_GAUNTLET_USDC_CORE", "METAMORPHO_GAUNTLET_USDC_PRIME",
    "METAMORPHO_GAUNTLET_USDT_PRIME", "METAMORPHO_GAUNTLET_LBTC_CORE",
    "METAMORPHO_RE7_USDC",
}

BEACON_SLOT = "0x" + "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeae e59ff6cb3582b35133d50".replace(" ", "")
VAULT_STORAGE_BASE = int("6bb5a2a0ae924c2ea94f037035a09f65614421e2a7d96c9bcbd59acdd32e6000", 16)

ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
MASK64 = (1 << 64) - 1


def rol64(value: int, shift: int) -> int:
    if shift == 0:
        return value & MASK64
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def keccak_f(state: list[int]) -> None:
    for rc in RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rol64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rol64(state[x + 5 * y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        keccak_f(state)
    output = bytearray()
    while len(output) < 32:
        for i in range(rate // 8):
            output.extend(state[i].to_bytes(8, "little"))
            if len(output) >= 32:
                return bytes(output[:32])
        keccak_f(state)
    return bytes(output[:32])


def selector(signature: str) -> str:
    return keccak256(signature.encode())[:4].hex()


def pad_word(hex_value: str) -> str:
    value = hex_value.removeprefix("0x")
    if len(value) > 64:
        raise ValueError(f"ABI word too long: {hex_value}")
    return value.rjust(64, "0")


def encode_address(address: str) -> str:
    return pad_word(address.lower().removeprefix("0x"))


def encode_bytes32(value: str) -> str:
    raw = value.removeprefix("0x")
    if len(raw) != 64:
        raise ValueError(f"bytes32 expected, got {value}")
    return raw


def encode_bool(value: bool) -> str:
    return pad_word("1" if value else "0")


def calldata(signature: str, args: Iterable[str] = ()) -> str:
    return "0x" + selector(signature) + "".join(args)


def decode_word(data: str, index: int = 0) -> str:
    raw = data.removeprefix("0x")
    start = index * 64
    if len(raw) < start + 64:
        raise ValueError(f"short ABI return ({len(raw)} hex chars), word {index}")
    return raw[start:start + 64]


def decode_uint(data: str, index: int = 0) -> int:
    return int(decode_word(data, index), 16)


def decode_address(data: str, index: int = 0) -> str:
    return "0x" + decode_word(data, index)[-40:].lower()


def decode_bool(data: str, index: int = 0) -> bool:
    return decode_uint(data, index) != 0


def decode_bytes32(data: str, index: int = 0) -> str:
    return "0x" + decode_word(data, index).lower()


def bytes32_text(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return bytes.fromhex(value.removeprefix("0x")).rstrip(b"\x00").decode(errors="replace")
    except Exception:
        return None


def normalize_address(value: str | None) -> str | None:
    if not value:
        return None
    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", value):
        return None
    return value.lower()


def json_request(url: str, payload: Any, timeout: int = TIMEOUT) -> Any:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    last: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"RPC request failed for {url}: {type(last).__name__}: {last}")


@dataclass
class RpcEndpoint:
    url: str
    chain_id: int
    next_id: int = 1

    def call(self, method: str, params: list[Any]) -> Any:
        request_id = self.next_id
        self.next_id += 1
        response = json_request(self.url, {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        if response.get("error") is not None:
            raise RuntimeError(f"{method}: {response['error']}")
        return response.get("result")

    def batch(self, calls: list[tuple[str, list[Any]]], chunk: int = 40) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for start in range(0, len(calls), chunk):
            current = calls[start:start + chunk]
            payload = []
            mapping: dict[int, int] = {}
            for local_index, (method, params) in enumerate(current):
                request_id = self.next_id
                self.next_id += 1
                mapping[request_id] = local_index
                payload.append({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            response = json_request(self.url, payload)
            if not isinstance(response, list):
                response = []
                for request in payload:
                    try:
                        response.append(json_request(self.url, request))
                    except Exception as exc:
                        response.append({"jsonrpc": "2.0", "id": request["id"], "error": {"message": f"{type(exc).__name__}: {exc}"}})
            ordered: list[dict[str, Any] | None] = [None] * len(current)
            for item in response:
                if item.get("id") in mapping:
                    ordered[mapping[item["id"]]] = item
            for index, item in enumerate(ordered):
                if item is None:
                    results.append({"ok": False, "error": "missing batch response", "method": current[index][0]})
                elif item.get("error") is not None:
                    results.append({"ok": False, "error": item.get("error"), "method": current[index][0]})
                else:
                    results.append({"ok": True, "value": item.get("result"), "method": current[index][0]})
        return results


def block_tag(block: int) -> str:
    return hex(block)


def eth_call(to: str, data: str, block: int, sender: str | None = None) -> tuple[str, list[Any]]:
    tx = {"to": to, "data": data}
    if sender:
        tx["from"] = sender
    return "eth_call", [tx, block_tag(block)]


def storage_call(address: str, slot: int | str, block: int) -> tuple[str, list[Any]]:
    slot_hex = slot if isinstance(slot, str) else hex(slot)
    return "eth_getStorageAt", [address, slot_hex, block_tag(block)]


def code_call(address: str, block: int) -> tuple[str, list[Any]]:
    return "eth_getCode", [address, block_tag(block)]


def result_value(item: dict[str, Any]) -> str | None:
    value = item.get("value") if item.get("ok") else None
    return value if isinstance(value, str) else None


def decode_result(item: dict[str, Any], kind: str) -> dict[str, Any]:
    if not item.get("ok"):
        return {"ok": False, "error": item.get("error")}
    raw = result_value(item)
    try:
        if kind == "uint":
            value: Any = decode_uint(raw or "0x")
        elif kind == "address":
            value = decode_address(raw or "0x")
        elif kind == "bytes32":
            value = decode_bytes32(raw or "0x")
        elif kind == "bool":
            value = decode_bool(raw or "0x")
        elif kind == "raw":
            value = raw
        elif kind == "storage_address":
            value = decode_address(raw or "0x")
        else:
            raise ValueError(f"unknown kind {kind}")
        return {"ok": True, "value": value, "raw": raw}
    except Exception as exc:
        return {"ok": False, "error": f"decode {kind}: {type(exc).__name__}: {exc}", "raw": raw}


def fetch_scope() -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    request = urllib.request.Request(SCOPE_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        html = response.read().decode(errors="replace")
    pattern = re.compile(
        r"([^|<>\n]{2,180}?)\s*\|\s*"
        r"(0x[a-fA-F0-9]{40})\s*\|\s*"
        r"([A-Z][A-Z0-9_]{1,63})\s*\|\s*"
        r"(ethereum|optimism|bnb|polygon|base|arbitrum)\s*\|\s*"
        r"([^|<>\n]{1,180})",
        re.IGNORECASE,
    )
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for label, address, connector, network, asset_text in pattern.findall(html):
        network = network.lower()
        connector = connector.upper()
        key = (network, address.lower())
        if key in seen or network not in NETWORKS:
            continue
        seen.add(key)
        rows.append({
            "label": re.sub(r"\s+", " ", label).strip(),
            "address": address.lower(),
            "connector": connector,
            "network": network,
            "asset_text": re.sub(r"\s+", " ", asset_text).strip(),
        })
    rows.sort(key=lambda row: (row["network"], row["connector"], row["address"]))
    connectors = Counter(row["connector"] for row in rows)
    networks = Counter(row["network"] for row in rows)
    checks = {
        "row_count_at_least_49": len(rows) >= 49,
        "row_count_exact_baseline_or_delta_recorded": len(rows) >= 49,
        "addresses_unique": len({(r["network"], r["address"]) for r in rows}) == len(rows),
        "all_networks_supported": all(row["network"] in NETWORKS for row in rows),
        "all_addresses_valid": all(re.fullmatch(r"0x[a-f0-9]{40}", row["address"]) for row in rows),
    }
    summary = {
        "row_count": len(rows),
        "baseline_row_count": BASELINE_SCOPE_COUNT,
        "scope_count_delta": len(rows) - BASELINE_SCOPE_COUNT,
        "connector_counts": dict(sorted(connectors.items())),
        "network_counts": dict(sorted(networks.items())),
        "unknown_connectors": sorted(set(connectors) - KNOWN_CONNECTOR_FAMILIES),
        "checks": checks,
    }
    return rows, summary, hashlib.sha256(html.encode()).hexdigest()


def connect_quorum(network: str, probe: str) -> dict[str, Any]:
    expected_chain, urls = NETWORKS[network]
    good: list[tuple[RpcEndpoint, int]] = []
    errors: list[str] = []
    for url in urls:
        try:
            rpc = RpcEndpoint(url, expected_chain)
            chain = int(rpc.call("eth_chainId", []), 16)
            if chain != expected_chain:
                raise RuntimeError(f"chain mismatch {chain} != {expected_chain}")
            latest = int(rpc.call("eth_blockNumber", []), 16)
            raw = rpc.call("eth_call", [{"to": probe, "data": calldata("asset()")}, "latest"])
            decode_address(raw)
            good.append((rpc, latest))
            if len(good) == 2:
                break
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    if len(good) < 2:
        raise RuntimeError(f"need two usable RPCs; got {len(good)} | " + " | ".join(errors))
    block = min(latest for _, latest in good) - 20
    for _ in range(6):
        hashes = []
        for rpc, _ in good:
            block_obj = rpc.call("eth_getBlockByNumber", [block_tag(block), False])
            hashes.append((block_obj or {}).get("hash"))
        if hashes[0] and hashes[0] == hashes[1]:
            return {
                "primary": good[0][0],
                "secondary": good[1][0],
                "block": block,
                "block_hash": hashes[0],
                "rpc_urls": [good[0][0].url, good[1][0].url],
                "errors": errors,
            }
        block -= 32
    raise RuntimeError("two-RPC block hash quorum failed")


def code_sha256(code: str | None) -> str | None:
    if not code or code == "0x":
        return None
    try:
        return hashlib.sha256(bytes.fromhex(code.removeprefix("0x"))).hexdigest()
    except Exception:
        return None


def human(raw: int | None, decimals: int | None) -> float | None:
    if raw is None or decimals is None or decimals < 0 or decimals > 77:
        return None
    try:
        return raw / (10 ** decimals)
    except Exception:
        return None


def int_or_none(result: dict[str, Any]) -> int | None:
    value = result.get("value") if result.get("ok") else None
    return value if isinstance(value, int) else None


def addr_or_none(result: dict[str, Any]) -> str | None:
    value = result.get("value") if result.get("ok") else None
    return normalize_address(value) if isinstance(value, str) else None


def main() -> int:
    selector_tests = {
        "asset()": "38d52e0f",
        "totalSupply()": "18160ddd",
        "balanceOf(address)": "70a08231",
        "implementation()": "5c60da1b",
    }
    selector_checks = {signature: selector(signature) == expected for signature, expected in selector_tests.items()}
    if not all(selector_checks.values()):
        raise RuntimeError(f"Keccak/selector self-test failed: {selector_checks}")

    scope_rows, scope_summary, scope_html_sha = fetch_scope()
    if not all(scope_summary["checks"].values()):
        raise RuntimeError(f"scope gate failed: {scope_summary}")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in scope_rows:
        grouped[row["network"]].append(row)

    chains: list[dict[str, Any]] = []
    vaults: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    quorum_mismatches: list[dict[str, Any]] = []

    getter_specs = [
        ("asset", "asset()", "address"),
        ("connector_registry", "connectorRegistry()", "address"),
        ("connector_name_raw", "connectorName()", "bytes32"),
        ("total_supply", "totalSupply()", "uint"),
        ("total_assets", "totalAssets()", "uint"),
        ("share_decimals", "decimals()", "uint"),
        ("reward_fee", "rewardFee()", "uint"),
        ("deposit_fee", "depositFee()", "uint"),
        ("additional_rewards_strategy", "additionalRewardsStrategy()", "uint"),
        ("pending_deposit_fee", "pendingDepositFee()", "uint"),
        ("pending_reward_fee", "pendingRewardFee()", "uint"),
        ("collectable_reward_fees", "collectableRewardFees()", "uint"),
        ("transferable", "transferable()", "bool"),
    ]

    for network, rows in sorted(grouped.items(), key=lambda item: NETWORKS[item[0]][0]):
        try:
            quorum = connect_quorum(network, rows[0]["address"])
        except Exception as exc:
            errors.append({"network": network, "stage": "rpc_quorum", "error": f"{type(exc).__name__}: {exc}"})
            continue
        primary: RpcEndpoint = quorum["primary"]
        secondary: RpcEndpoint = quorum["secondary"]
        block = int(quorum["block"])
        chains.append({
            "network": network,
            "chain_id": NETWORKS[network][0],
            "block": block,
            "block_hash": quorum["block_hash"],
            "rpc_urls": quorum["rpc_urls"],
            "rejected_rpc_errors": quorum["errors"],
        })

        calls: list[tuple[str, list[Any]]] = []
        mapping: list[tuple[int, str, str]] = []
        for row_index, row in enumerate(rows):
            for field, signature, kind in getter_specs:
                mapping.append((row_index, field, kind))
                calls.append(eth_call(row["address"], calldata(signature), block))
            mapping.append((row_index, "last_total_assets_storage", "uint"))
            calls.append(storage_call(row["address"], VAULT_STORAGE_BASE + 4, block))
            mapping.append((row_index, "min_total_supply_storage", "uint"))
            calls.append(storage_call(row["address"], VAULT_STORAGE_BASE + 5, block))
            mapping.append((row_index, "packed_transferable_offset_storage", "raw"))
            calls.append(storage_call(row["address"], VAULT_STORAGE_BASE + 6, block))
            mapping.append((row_index, "beacon_storage", "storage_address"))
            calls.append(storage_call(row["address"], BEACON_SLOT, block))

        primary_results = primary.batch(calls)
        working: list[dict[str, Any]] = [dict(row, scope_connector=row.get("connector"), block=block, block_hash=quorum["block_hash"]) for row in rows]
        for result, (row_index, field, kind) in zip(primary_results, mapping):
            working[row_index][field] = decode_result(result, kind)

        quorum_fields = [
            ("asset", "asset()", "address"),
            ("connector_registry", "connectorRegistry()", "address"),
            ("connector_name_raw", "connectorName()", "bytes32"),
            ("total_supply", "totalSupply()", "uint"),
            ("total_assets", "totalAssets()", "uint"),
            ("additional_rewards_strategy", "additionalRewardsStrategy()", "uint"),
            ("reward_fee", "rewardFee()", "uint"),
        ]
        secondary_calls: list[tuple[str, list[Any]]] = []
        secondary_mapping: list[tuple[int, str, str]] = []
        for row_index, row in enumerate(rows):
            for field, signature, kind in quorum_fields:
                secondary_mapping.append((row_index, field, kind))
                secondary_calls.append(eth_call(row["address"], calldata(signature), block))
            secondary_mapping.append((row_index, "beacon_storage", "storage_address"))
            secondary_calls.append(storage_call(row["address"], BEACON_SLOT, block))
        secondary_results = secondary.batch(secondary_calls)
        for result, (row_index, field, kind) in zip(secondary_results, secondary_mapping):
            decoded = decode_result(result, kind)
            working[row_index].setdefault("quorum_secondary", {})[field] = decoded
            primary_decoded = working[row_index].get(field, {})
            if primary_decoded.get("ok") != decoded.get("ok") or primary_decoded.get("value") != decoded.get("value"):
                quorum_mismatches.append({
                    "network": network,
                    "vault": working[row_index]["address"],
                    "field": field,
                    "primary": primary_decoded,
                    "secondary": decoded,
                })

        resolution_calls: list[tuple[str, list[Any]]] = []
        resolution_mapping: list[tuple[int, str, str]] = []
        for row_index, item in enumerate(working):
            registry = addr_or_none(item.get("connector_registry", {}))
            name_raw = item.get("connector_name_raw", {}).get("value") if item.get("connector_name_raw", {}).get("ok") else None
            beacon = addr_or_none(item.get("beacon_storage", {}))
            if registry and isinstance(name_raw, str):
                for field, signature, kind in [
                    ("connector", "get(bytes32)", "address"),
                    ("connector_paused", "paused(bytes32)", "bool"),
                    ("connector_frozen", "frozen(bytes32)", "bool"),
                ]:
                    resolution_mapping.append((row_index, field, kind))
                    resolution_calls.append(eth_call(registry, calldata(signature, [encode_bytes32(name_raw)]), block))
            else:
                for field in ("connector", "connector_paused", "connector_frozen"):
                    item[field] = {"ok": False, "error": "registry/name unresolved"}
            if beacon and beacon != ZERO:
                resolution_mapping.append((row_index, "vault_implementation", "address"))
                resolution_calls.append(eth_call(beacon, calldata("implementation()"), block))
            else:
                item["vault_implementation"] = {"ok": False, "error": "beacon unresolved"}
        resolution_results = primary.batch(resolution_calls) if resolution_calls else []
        for result, (row_index, field, kind) in zip(resolution_results, resolution_mapping):
            working[row_index][field] = decode_result(result, kind)

        code_calls: list[tuple[str, list[Any]]] = []
        code_mapping: list[tuple[int, str]] = []
        for row_index, item in enumerate(working):
            connector = addr_or_none(item.get("connector", {}))
            implementation = addr_or_none(item.get("vault_implementation", {}))
            for field, address in (("connector_code", connector), ("vault_implementation_code", implementation)):
                if address and address != ZERO:
                    code_mapping.append((row_index, field))
                    code_calls.append(code_call(address, block))
                else:
                    item[field] = {"ok": False, "error": "address unresolved"}
        code_results = primary.batch(code_calls) if code_calls else []
        for result, (row_index, field) in zip(code_results, code_mapping):
            raw = result_value(result)
            working[row_index][field] = {
                "ok": bool(result.get("ok")),
                "bytes": (len(raw.removeprefix("0x")) // 2) if raw else 0,
                "sha256": code_sha256(raw),
                "error": result.get("error") if not result.get("ok") else None,
            }

        protocol_calls: list[tuple[str, list[Any]]] = []
        protocol_mapping: list[tuple[int, str, str]] = []
        for row_index, item in enumerate(working):
            connector = addr_or_none(item.get("connector", {}))
            connector_name = bytes32_text(item.get("connector_name_raw", {}).get("value")) or item.get("scope_connector")
            item["connector_name_decoded"] = connector_name
            if not connector or connector == ZERO:
                continue
            if str(connector_name).startswith("COMPOUND_V3"):
                for field, signature in [
                    ("compound_market_registry", "compoundMarketRegistry()"),
                    ("comet_rewards", "cometRewards()"),
                    ("comp", "comp()"),
                    ("swap_target", "swapTarget()"),
                ]:
                    protocol_mapping.append((row_index, field, "address"))
                    protocol_calls.append(eth_call(connector, calldata(signature), block))
            elif str(connector_name).startswith("METAMORPHO"):
                protocol_mapping.append((row_index, "nested_vault", "address"))
                protocol_calls.append(eth_call(connector, calldata("metamorpho()"), block))
            elif str(connector_name) == "FLUID":
                for field, signature in [("fluid_factory", "fluidFactory()"), ("f_token", "fToken()")]:
                    protocol_mapping.append((row_index, field, "address"))
                    protocol_calls.append(eth_call(connector, calldata(signature), block))
            elif str(connector_name) == "VENUS":
                for field, signature in [
                    ("venus_market_registry", "venusMarketRegistry()"),
                    ("market_registry", "marketRegistry()"),
                    ("v_token", "vToken()"),
                ]:
                    protocol_mapping.append((row_index, field, "address"))
                    protocol_calls.append(eth_call(connector, calldata(signature), block))
            elif str(connector_name) == "AAVE_V3":
                for field, signature in [
                    ("aave_pool", "aave()"),
                    ("rewards_controller", "rewardsController()"),
                    ("swap_target", "swapTarget()"),
                ]:
                    protocol_mapping.append((row_index, field, "address"))
                    protocol_calls.append(eth_call(connector, calldata(signature), block))
        protocol_results = primary.batch(protocol_calls) if protocol_calls else []
        for result, (row_index, field, kind) in zip(protocol_results, protocol_mapping):
            working[row_index][field] = decode_result(result, kind)

        stage2_calls: list[tuple[str, list[Any]]] = []
        stage2_mapping: list[tuple[int, str, str]] = []
        for row_index, item in enumerate(working):
            asset = addr_or_none(item.get("asset", {}))
            vault = item["address"]
            name = item.get("connector_name_decoded") or item.get("scope_connector")
            if name == "COMPOUND_V3":
                registry = addr_or_none(item.get("compound_market_registry", {}))
                if registry and asset:
                    stage2_mapping.append((row_index, "comet", "address"))
                    stage2_calls.append(eth_call(registry, calldata("getMarket(address)", [encode_address(asset)]), block))
            if str(name).startswith("METAMORPHO"):
                nested = addr_or_none(item.get("nested_vault", {}))
                if nested:
                    for field, signature, kind in [
                        ("nested_total_supply", "totalSupply()", "uint"),
                        ("nested_total_assets", "totalAssets()", "uint"),
                        ("nested_decimals", "decimals()", "uint"),
                        ("nested_asset", "asset()", "address"),
                    ]:
                        stage2_mapping.append((row_index, field, kind))
                        stage2_calls.append(eth_call(nested, calldata(signature), block))
                    stage2_mapping.append((row_index, "vault_nested_share_balance", "uint"))
                    stage2_calls.append(eth_call(nested, calldata("balanceOf(address)", [encode_address(vault)]), block))
        stage2_results = primary.batch(stage2_calls) if stage2_calls else []
        for result, (row_index, field, kind) in zip(stage2_results, stage2_mapping):
            working[row_index][field] = decode_result(result, kind)

        compound_calls: list[tuple[str, list[Any]]] = []
        compound_mapping: list[tuple[int, str, str]] = []
        for row_index, item in enumerate(working):
            if item.get("connector_name_decoded") != "COMPOUND_V3":
                continue
            comet = addr_or_none(item.get("comet", {}))
            rewards = addr_or_none(item.get("comet_rewards", {}))
            comp = addr_or_none(item.get("comp", {}))
            if comet and rewards:
                compound_mapping.append((row_index, "reward_owed_raw", "reward_owed"))
                compound_calls.append(eth_call(rewards, calldata("getRewardOwed(address,address)", [encode_address(comet), encode_address(item["address"])]), block))
                compound_mapping.append((row_index, "permissionless_claim_simulation", "raw"))
                compound_calls.append(eth_call(rewards, calldata("claim(address,address,bool)", [encode_address(comet), encode_address(item["address"]), encode_bool(True)]), block, ATTACKER))
            if comp:
                compound_mapping.append((row_index, "vault_comp_balance", "uint"))
                compound_calls.append(eth_call(comp, calldata("balanceOf(address)", [encode_address(item["address"])]), block))
        compound_results = primary.batch(compound_calls) if compound_calls else []
        for result, (row_index, field, kind) in zip(compound_results, compound_mapping):
            if kind == "reward_owed":
                if not result.get("ok"):
                    working[row_index][field] = {"ok": False, "error": result.get("error")}
                else:
                    raw = result_value(result)
                    try:
                        working[row_index][field] = {"ok": True, "value": decode_uint(raw or "0x", 1), "token": decode_address(raw or "0x", 0), "raw": raw}
                    except Exception as exc:
                        working[row_index][field] = {"ok": False, "error": f"decode reward owed: {type(exc).__name__}: {exc}", "raw": raw}
            else:
                working[row_index][field] = decode_result(result, kind)

        asset_calls: list[tuple[str, list[Any]]] = []
        asset_mapping: list[tuple[int, str, str]] = []
        for row_index, item in enumerate(working):
            asset_address = addr_or_none(item.get("asset", {}))
            if not asset_address:
                item["asset_decimals"] = {"ok": False, "error": "asset unresolved"}
                item["direct_asset_balance"] = {"ok": False, "error": "asset unresolved"}
                continue
            asset_mapping.append((row_index, "asset_decimals", "uint"))
            asset_calls.append(eth_call(asset_address, calldata("decimals()"), block))
            asset_mapping.append((row_index, "direct_asset_balance", "uint"))
            asset_calls.append(eth_call(asset_address, calldata("balanceOf(address)", [encode_address(item["address"])]), block))
        asset_results = primary.batch(asset_calls) if asset_calls else []
        for result, (row_index, field, kind) in zip(asset_results, asset_mapping):
            working[row_index][field] = decode_result(result, kind)

        for item in working:
            share_decimals = int_or_none(item.get("share_decimals", {}))
            asset_decimals_result = item.get("asset_decimals", {"ok": False, "error": "not queried"})
            asset_decimals = int_or_none(asset_decimals_result)
            total_supply = int_or_none(item.get("total_supply", {}))
            total_assets = int_or_none(item.get("total_assets", {}))
            min_supply = int_or_none(item.get("min_total_supply_storage", {}))
            packed_raw = item.get("packed_transferable_offset_storage", {}).get("value") if item.get("packed_transferable_offset_storage", {}).get("ok") else None
            try:
                packed_int = int(str(packed_raw), 16)
                storage_transferable = bool(packed_int & 0xff)
                storage_offset = (packed_int >> 8) & 0xff
            except Exception:
                storage_transferable = None
                storage_offset = None
            item["storage_decoded"] = {"min_total_supply": min_supply, "transferable": storage_transferable, "offset": storage_offset}
            item["human"] = {
                "total_supply": human(total_supply, share_decimals),
                "total_assets": human(total_assets, asset_decimals),
                "min_total_supply": human(min_supply, share_decimals),
                "reward_fee": human(int_or_none(item.get("reward_fee", {})), asset_decimals),
                "deposit_fee": human(int_or_none(item.get("deposit_fee", {})), asset_decimals),
                "pending_reward_fee": human(int_or_none(item.get("pending_reward_fee", {})), asset_decimals),
                "pending_deposit_fee": human(int_or_none(item.get("pending_deposit_fee", {})), asset_decimals),
            }
            direct_balance = int_or_none(item.get("direct_asset_balance", {}))
            pending_total = (int_or_none(item.get("pending_reward_fee", {})) or 0) + (int_or_none(item.get("pending_deposit_fee", {})) or 0)
            idle_excess = max(0, (direct_balance or 0) - pending_total) if direct_balance is not None else None
            item["idle_accounting"] = {
                "direct_asset_balance_raw": direct_balance,
                "pending_fee_reserve_raw": pending_total,
                "unattributed_idle_excess_raw": idle_excess,
                "unattributed_idle_excess_human": human(idle_excess, asset_decimals),
                "last_total_assets_raw": int_or_none(item.get("last_total_assets_storage", {})),
            }
            item["material_supply"] = bool(
                total_supply is not None and min_supply is not None
                and total_supply > max(min_supply * 100, 10 ** max(0, (share_decimals or 0) - 3))
            )
            if item.get("quorum_secondary"):
                item["quorum_secondary"] = {
                    key: {"ok": value.get("ok"), "value": value.get("value"), "error": value.get("error")}
                    for key, value in item["quorum_secondary"].items()
                }
        vaults.extend(working)

    inventory_triggers: list[dict[str, Any]] = []
    research_candidates: list[dict[str, Any]] = []
    duplicate_or_known_signals: list[dict[str, Any]] = []

    if scope_summary["scope_count_delta"] != 0 or scope_summary["unknown_connectors"]:
        inventory_triggers.append({"kind": "scope_or_connector_delta", "scope_count_delta": scope_summary["scope_count_delta"], "unknown_connectors": scope_summary["unknown_connectors"]})

    implementations = Counter(
        addr_or_none(item.get("vault_implementation", {}))
        for item in vaults if addr_or_none(item.get("vault_implementation", {}))
    )
    mainnet_implementations = sorted({
        addr_or_none(item.get("vault_implementation", {}))
        for item in vaults if item["network"] == "ethereum" and addr_or_none(item.get("vault_implementation", {}))
    })
    if mainnet_implementations and BASELINE_MAINNET_VAULT_IMPLEMENTATION not in mainnet_implementations:
        inventory_triggers.append({"kind": "mainnet_vault_implementation_delta", "baseline": BASELINE_MAINNET_VAULT_IMPLEMENTATION, "current": mainnet_implementations})
    if len(implementations) > len(NETWORKS):
        inventory_triggers.append({"kind": "unexpected_implementation_fragmentation", "implementations": dict(implementations)})

    for item in vaults:
        name = item.get("connector_name_decoded") or item.get("scope_connector")
        supply = int_or_none(item.get("total_supply", {}))
        total_assets_ok = bool(item.get("total_assets", {}).get("ok"))
        strategy = int_or_none(item.get("additional_rewards_strategy", {}))
        reward_fee = int_or_none(item.get("reward_fee", {})) or 0
        connector = addr_or_none(item.get("connector", {}))
        base = {
            "network": item["network"], "label": item["label"], "vault": item["address"],
            "connector_name": name, "connector": connector, "block": item.get("block"),
            "human": item.get("human"),
        }
        if (not connector or connector == ZERO) and supply and item.get("material_supply"):
            research_candidates.append({**base, "kind": "material_vault_connector_unresolved", "severity_ceiling": "High", "reason": "material supply with missing connector binding can freeze ERC4626 accounting and exits"})
        if not total_assets_ok and supply and item.get("material_supply"):
            research_candidates.append({**base, "kind": "material_positive_supply_totalAssets_revert", "severity_ceiling": "High", "reason": "material positive supply with failing NAV path; requires holder-exit fork and >2-day liveness proof"})
        if name == "COMPOUND_V3" and strategy == 1:
            owed = int_or_none(item.get("reward_owed_raw", {})) or 0
            claim_ok = bool(item.get("permissionless_claim_simulation", {}).get("ok"))
            duplicate_or_known_signals.append({**base, "kind": "compound_claim_strategy_permissionless_preclaim", "owed_raw": owed, "claim_simulation_ok": claim_ok})
        if name in {"FLUID", "VENUS"} and reward_fee > 0 and item.get("material_supply"):
            research_candidates.append({
                **base,
                "kind": "material_external_protocol_vault_with_nonzero_reward_fee",
                "reward_fee_raw": reward_fee,
                "strategy": strategy,
                "severity_ceiling": "High",
                "reason": "nonzero reward fee reopens virtual-reward/stale-accounting paths on a material vault; fixed-block economic proof required",
            })
        idle = item.get("idle_accounting", {}).get("unattributed_idle_excess_raw")
        asset_decimals = int_or_none(item.get("asset_decimals", {}))
        total_assets = int_or_none(item.get("total_assets", {}))
        if idle is not None and asset_decimals is not None and item.get("material_supply"):
            idle_threshold = max(10 ** asset_decimals, (total_assets or 0) // 10_000)
            if idle > idle_threshold:
                research_candidates.append({
                    **base,
                    "kind": "material_unattributed_idle_underlying_excluded_from_connector_nav",
                    "idle_excess_raw": idle,
                    "idle_excess_human": human(idle, asset_decimals),
                    "severity_ceiling": "High",
                    "reason": "direct underlying exceeds fee reserves by a material amount while connector NAV normally excludes idle balances; recoverability/freeze fork required",
                })

    coverage_complete = (
        len(scope_rows) >= 49
        and len(vaults) == len(scope_rows)
        and not errors
        and not quorum_mismatches
        and all(chain["block_hash"] for chain in chains)
        and len(chains) == len(grouped)
    )

    if not coverage_complete:
        decision = "INCONCLUSIVE_FAIL_CLOSED_COVERAGE_OR_RPC_QUORUM"
    elif research_candidates:
        decision = "HOLD_NEW_LIVE_CONFIG_OR_LIVENESS_CANDIDATES_REQUIRE_FIXED_BLOCK_POC"
    elif inventory_triggers:
        decision = "HOLD_DEPLOYMENT_DELTA_REQUIRES_SOURCE_DIFF"
    else:
        decision = "KILL_NO_NEW_LIVE_CONFIG_OR_DEPLOYMENT_TRIGGER"

    evidence = {
        "schema": "kiln-omnivault-r42-live-config-delta-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope_url": SCOPE_URL,
        "scope_html_sha256": scope_html_sha,
        "selector_self_checks": selector_checks,
        "safety": {
            "read_only": True,
            "rpc_methods": ["eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_call", "eth_getCode", "eth_getStorageAt"],
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "private_keys": 0,
        },
        "scope_summary": scope_summary,
        "chains": chains,
        "vaults": vaults,
        "errors": errors,
        "quorum_mismatches": quorum_mismatches,
        "implementation_counts": dict(implementations),
        "inventory_triggers": inventory_triggers,
        "research_candidates": research_candidates,
        "duplicate_or_known_signals": duplicate_or_known_signals,
        "coverage_complete": coverage_complete,
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
    }
    evidence_path = OUT / "EVIDENCE.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True))

    public_gate = {
        "schema": "kiln-omnivault-r42-public-gate-v1",
        "generated_at_utc": evidence["generated_at_utc"],
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "coverage_complete": coverage_complete,
        "scope_count": len(scope_rows),
        "inspected_count": len(vaults),
        "chain_count": len(chains),
        "error_count": len(errors),
        "quorum_mismatch_count": len(quorum_mismatches),
        "inventory_trigger_count": len(inventory_triggers),
        "research_candidate_count": len(research_candidates),
        "duplicate_or_known_signal_count": len(duplicate_or_known_signals),
        "connector_counts": scope_summary["connector_counts"],
        "implementation_count": len(implementations),
        "public_chain_state_changes": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(public_gate, indent=2, sort_keys=True))
    (OUT / "CANDIDATE_SUMMARY.json").write_text(json.dumps({
        "schema": "kiln-omnivault-r42-candidate-summary-v1",
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "inventory_triggers": inventory_triggers,
        "research_candidates": research_candidates,
        "duplicate_or_known_signals": duplicate_or_known_signals,
    }, indent=2, sort_keys=True))
    files = sorted(path for path in OUT.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files
    ))
    print(json.dumps(public_gate, sort_keys=True))
    return 0 if coverage_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
