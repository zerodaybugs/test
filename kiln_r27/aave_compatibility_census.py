#!/usr/bin/env python3
"""Read-only current-state compatibility census for scoped Kiln Aave vaults.

Safety: JSON-RPC reads/eth_call only. No signing, broadcasting, impersonation or
public-chain mutation. Results are intended for encrypted CI delivery.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path("r27_results")
OUT.mkdir(exist_ok=True)
SCOPE_URL = "https://cantina.xyz/bounties/c9a4b51b-2e80-4713-a06f-13524c530fa6"
CALLER = Web3.to_checksum_address("0x000000000000000000000000000000000000bEEF")
ZERO = "0x0000000000000000000000000000000000000000"

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
        "https://arbitrum.llamarpc.com",
        "https://arb1.arbitrum.io/rpc",
    ]),
}

FALLBACK_SCOPE = """
bnb|0x696b456c1c79416CCE302D09e935b3cB80d0CDC5|Trust Wallet AAVE v3 USDT
bnb|0x4d1806C26A728f2e1b82b4549b9E074DBE5940B9|Cool Wallet AAVEv3 USDT
bnb|0x1F7Cf59d1ABd6F03dAf7CCA7817B634251B8723C|Cool Wallet AAVEv3 USDC
polygon|0x03441c89e7B751bb570f9Dc8C92702b127c52C51|Cool Wallet AAVEv3 USDT
polygon|0x66431b90985212D3B09E27ff9b83cb32F6dd79Dc|BITNOVO AAVE v3 DAI
polygon|0xebA6232DC52C2548e4b4aE1d9686e8e692436bA2|BITNOVO AAVE v3 USDT
polygon|0x6f15CDA2D68B00311614294A2b9b17400636133C|BITNOVO AAVE v3 USDC
base|0x29Eceb50C5C1cc52FAb72Ff258B5a46324693BE7|Bifrost AAVE v3 USDC
arbitrum|0xE9700FD4194722eb680C57ed3e07C8Bb1933Bb98|Waltio Aave V3 WETH
arbitrum|0xeA8c59C737d32e0EE78dbAd35C27b142356Ea4a3|Waltio Aave V3 USDT
arbitrum|0xe3657dFE299393eBdFC9D5059Ed85ef67eFEEcC1|Waltio Aave V3 USDC
arbitrum|0xEdf257f1429a4E0efBa1019348112Ff1b6Be2231|Rapidz Aave v3 USDC
arbitrum|0x96d6c438C704A2de8CDCE435803A10D329b72E68|Trust Wallet AAVE v3 DAI
arbitrum|0x15DCC1978f68c5E0D7A298A65fCc879E2D673D43|Trust Wallet AAVE v3 USDT
arbitrum|0x90788f682463D1Ac00Bd2230b15A4bD0D32a3E46|Trust Wallet AAVE v3 USDC
arbitrum|0xA7c500EB3069bAD292D9Bd57574a89Cd883118df|Bitnovo Aave v3 USDC
arbitrum|0xdB8C962e8A39d3E82d3EAA8F477bE90984C6Dfe8|Bitnovo Aave v3 USDT
arbitrum|0xdB4b6723f5659B4e78AaB29Fb1eD49Ccc18Fc5e6|Bitnovo Aave v3 DAI
arbitrum|0x552dAc42901b7559D31247B77fA550fb65688432|Crypto.com Defi Wallet AAVE DAI
arbitrum|0x9b855bA95bbD19C73d931977feB5140D40bC03F6|Crypto.com Defi Wallet AAVE USDC.e
arbitrum|0xf8df2Eee600A4Df8cc494D8B1ff34B7980AbA3aD|Crypto.com Defi Wallet AAVE USDT
arbitrum|0x97901Cf9f064c40F538C5f7b53420A02Cb68c644|Crypto.com Defi Wallet AAVE USDC
arbitrum|0x8A44861320c68b87C58A35d7110fAc5615233728|Bifrost AAVE v3 USDT
arbitrum|0xBD3D2a51824784F138A333055Fa91b590CD2B2CB|Bifrost AAVE v3 USDC
optimism|0xeEE5205D35747307c3650c82b86Acfd1Abc300b0|Bitnovo AAVE v3 DAI
optimism|0x0BA60A5bA2D59B3A52C1b27cCc1C7f28213b8C9b|Bitnovo AAVE v3 USDT
optimism|0xAEcC73782E5d6a6e9F6c1a6533bc68D90891f9b9|Bitnovo AAVE v3 USDC
optimism|0xB9EbFF375D5EADE50Ed561F611754902f70e34CF|Dakota AAVE v3 USDC
ethereum|0xafDb696b693F38996B4fa7B839f3E9CfdD758694|Waltio Aave V3 WETH
ethereum|0x7F8ca9b130ED8027a8dc2949542593Dc1a1c95DC|Waltio Aave V3 USDT
ethereum|0x8b1fE482062B9B5FF40c4473d47674A886022118|Waltio Aave V3 USDC
ethereum|0x5B38308f3dB29EA653f83db5E715189abCb83fd9|Bifrost AAVE v3 USDT
ethereum|0xCB575B3de1224469B6fb4d7f03AcE1bED5C92E0b|Bifrost AAVE v3 USDS
ethereum|0x56a5a7E7aD573ec8568727b87C881dffC30C84dA|Bifrost AAVE v3 USDC
ethereum|0xD88714E295da03a07BcB8aD4a4dbE87fa42d75f9|Yield Bearing AAVE USDS
ethereum|0x4Ef971774c77865FF8Ec35f274474CB0eD9c48FA|Yield Bearing AAVE DAI
ethereum|0xD2011d314aCAA68E5401E7f5AeC3Be6d2C574DCf|Yield Bearing AAVE USDC
ethereum|0x4D431856295413906075dD40266d83624E09C672|Yield Bearing AAVE USDT
ethereum|0x6C310b55D6728423B3bddB9D07A6c21Bb6eFBDCb|Trust Wallet AAVE v3 DAI
ethereum|0x2Df453aA9ac59Dc05030979CA67Af4BBff424333|Trust Wallet AAVE v3 USDT
ethereum|0xe7Bf38c635426caaCfa95966c4C6064e7637fE0A|Trust Wallet AAVE v3 USDC
ethereum|0xBd01d20e6897e4A148BafFCfa9ED7aA1ac05a4B0|Dakota AAVE v3 USDT
ethereum|0x6504158a43208150E5dbc0602d3F3Ac694e0158e|Bitnovo Aave v3 USDC
ethereum|0x815d9e5A6F9c9662b07570c801131e8942587132|Bitnovo Aave v3 USDT
ethereum|0xB59f4f16709Aa88e04B0addf15a3DF6Aa8B14524|Bitnovo Aave v3 DAI
ethereum|0xe2F86504C610EdbaE7A788b04785395fDe781577|Cool Wallet AAVEv3 DAI
ethereum|0x924e38bdFDa04990Fc78FEc258E8B83B3478B1Af|Cool Wallet AAVEv3 USDT
ethereum|0x2db0B0fa84C3c8B342183FD0B777C521ec054325|Cool Wallet AAVEv3 USDC
ethereum|0x15BEFDB812690D02eCB4cDE372f42BF0A8c24d68|Dakota AAVE v3 USDC
""".strip()

VAULT_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorRegistry","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorName","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]},
    {"type":"function","name":"additionalRewardsStrategy","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"rewardFee","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]
REGISTRY_ABI = [
    {"type":"function","name":"get","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"address"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"frozen","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"bool"}]},
]
CONNECTOR_ABI = [
    {"type":"function","name":"aave","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"poolAddressesProvider","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"rewardsController","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"swapTarget","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
PROVIDER_ABI = [{"type":"function","name":"getPoolDataProvider","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]
DATA_PROVIDER_ABI = [{"type":"function","name":"getReserveTokensAddresses","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"}]}]
REWARDS_ABI = [
    {"type":"function","name":"getRewardsByAsset","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address[]"}]},
    {"type":"function","name":"getAllUserRewards","stateMutability":"view","inputs":[{"type":"address[]"},{"type":"address"}],"outputs":[{"type":"address[]"},{"type":"uint256[]"}]},
    {"type":"function","name":"getClaimer","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address"}]},
    {"type":"function","name":"claimAllRewards","stateMutability":"nonpayable","inputs":[{"type":"address[]"},{"type":"address"}],"outputs":[{"type":"address[]"},{"type":"uint256[]"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]

@dataclass(frozen=True)
class ScopeRow:
    network: str
    vault: str
    label: str

def normalize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)): return "0x" + bytes(value).hex()
    if isinstance(value, (list, tuple)): return [normalize(v) for v in value]
    return value

def call(fn: Any, block: int, tx: dict[str, Any] | None = None) -> dict[str, Any]:
    try: return {"ok": True, "value": normalize(fn.call(tx or {}, block_identifier=block))}
    except Exception as exc: return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

def value(result: dict[str, Any]) -> Any: return result.get("value") if result.get("ok") else None

def checksum(address: str | None) -> str | None:
    if not address: return None
    try: return Web3.to_checksum_address(address)
    except Exception: return None

def parse_fallback() -> list[ScopeRow]:
    return [ScopeRow(n, Web3.to_checksum_address(v), l) for n, v, l in (line.split("|", 2) for line in FALLBACK_SCOPE.splitlines())]

def fetch_scope() -> tuple[list[ScopeRow], dict[str, Any]]:
    fallback = parse_fallback()
    meta: dict[str, Any] = {"url": SCOPE_URL, "fallback_count": len(fallback), "source": "fallback", "live_page_sha256": None, "live_parse_count": 0, "fallback_addresses_present_on_live_page": None}
    try:
        response = requests.get(SCOPE_URL, headers={"User-Agent": "Kiln-R27-Compatibility-Census/1.0"}, timeout=45)
        response.raise_for_status(); text = response.text
        meta["live_page_sha256"] = hashlib.sha256(text.encode()).hexdigest()
        pattern = re.compile(r"([^|<>\n]{2,120}?)\s*\|\s*(0x[a-fA-F0-9]{40})\s*\|\s*AAVE_V3\s*\|\s*(bnb|polygon|base|arbitrum|optimism|ethereum)\s*\|", re.IGNORECASE)
        seen: set[tuple[str, str]] = set(); live: list[ScopeRow] = []
        for label, address, network in pattern.findall(text):
            key = (network.lower(), address.lower())
            if key in seen: continue
            seen.add(key); live.append(ScopeRow(network.lower(), Web3.to_checksum_address(address), re.sub(r"\s+", " ", label).strip()))
        meta["live_parse_count"] = len(live); meta["fallback_addresses_present_on_live_page"] = all(row.vault.lower() in text.lower() for row in fallback)
        if len(live) >= 40:
            meta["source"] = "live_page"
            return sorted(live, key=lambda r: (NETWORKS[r.network][0], r.vault.lower())), meta
    except Exception as exc: meta["live_error"] = f"{type(exc).__name__}: {exc}"
    return sorted(fallback, key=lambda r: (NETWORKS[r.network][0], r.vault.lower())), meta

def connect_quorum(network: str, probe_vault: str) -> tuple[list[tuple[Web3, str, int]], int, str]:
    chain_id, urls = NETWORKS[network]; clients: list[tuple[Web3, str, int]] = []; errors: list[str] = []; probe = Web3.to_checksum_address(probe_vault)
    for url in urls:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 25}))
            if not w3.is_connected() or w3.eth.chain_id != chain_id: raise RuntimeError("chain mismatch or disconnected")
            latest = int(w3.eth.block_number); raw = w3.eth.call({"to": probe, "data": "0x38d52e0f"}, block_identifier=latest)
            if len(raw) < 32: raise RuntimeError("probe getter returned short data")
            clients.append((w3, url, latest))
            if len(clients) == 2: break
        except Exception as exc: errors.append(f"{url}: {type(exc).__name__}: {exc}")
    if not clients: raise RuntimeError("no usable RPC | " + " | ".join(errors))
    pinned = max(1, min(item[2] for item in clients) - 3); block_hash = clients[0][0].eth.get_block(pinned)["hash"].hex()
    if len(clients) > 1 and clients[1][0].eth.get_block(pinned)["hash"].hex().lower() != block_hash.lower(): raise RuntimeError(f"RPC block-hash disagreement at {pinned}")
    return clients, pinned, block_hash

def token_meta(w3: Web3, token_address: str, owner: str, block: int) -> dict[str, Any]:
    token = w3.eth.contract(Web3.to_checksum_address(token_address), abi=ERC20_ABI)
    return {"address": Web3.to_checksum_address(token_address), "symbol": call(token.functions.symbol(), block), "decimals": call(token.functions.decimals(), block), "balance_at_vault": call(token.functions.balanceOf(Web3.to_checksum_address(owner)), block), "code_sha256": hashlib.sha256(bytes(w3.eth.get_code(Web3.to_checksum_address(token_address), block_identifier=block))).hexdigest()}

def decode_name(raw: Any) -> str | None:
    try:
        if isinstance(raw, str) and raw.startswith("0x"): return bytes.fromhex(raw[2:]).rstrip(b"\x00").decode("utf-8", errors="replace")
    except Exception: pass
    return None

def pair_rewards(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) != 2: return []
    addresses, amounts = raw
    if not isinstance(addresses, list) or not isinstance(amounts, list): return []
    rows: list[dict[str, Any]] = []
    for index, address in enumerate(addresses):
        checked = checksum(address)
        if checked: rows.append({"reward": checked, "amount_raw": int(amounts[index]) if index < len(amounts) else 0})
    return rows

def query_vault(primary: Web3, network: str, row: ScopeRow, block: int, block_hash: str) -> dict[str, Any]:
    vault_address = Web3.to_checksum_address(row.vault); vault = primary.eth.contract(vault_address, abi=VAULT_ABI)
    item: dict[str, Any] = {"network": network, "chain_id": NETWORKS[network][0], "label": row.label, "vault": vault_address, "block": block, "block_hash": block_hash, "vault_code_sha256": hashlib.sha256(bytes(primary.eth.get_code(vault_address, block_identifier=block))).hexdigest()}
    for getter in ["asset", "connectorRegistry", "connectorName", "additionalRewardsStrategy", "rewardFee", "totalAssets", "totalSupply"]: item[getter] = call(getattr(vault.functions, getter)(), block)
    asset = checksum(value(item["asset"])); registry_address = checksum(value(item["connectorRegistry"])); connector_name_raw = value(item["connectorName"]); item["connector_name_text"] = decode_name(connector_name_raw)
    if not asset or not registry_address or not connector_name_raw: raise RuntimeError("vault binding unresolved")
    name_bytes = bytes.fromhex(str(connector_name_raw).removeprefix("0x")); registry = primary.eth.contract(registry_address, abi=REGISTRY_ABI)
    item["registry_paused"] = call(registry.functions.paused(name_bytes), block); item["registry_frozen"] = call(registry.functions.frozen(name_bytes), block); item["connector"] = call(registry.functions.get(name_bytes), block)
    connector_address = checksum(value(item["connector"]))
    if not connector_address or connector_address == ZERO: raise RuntimeError("connector unresolved")
    connector = primary.eth.contract(connector_address, abi=CONNECTOR_ABI); item["connector_address"] = connector_address; item["connector_code_sha256"] = hashlib.sha256(bytes(primary.eth.get_code(connector_address, block_identifier=block))).hexdigest()
    for getter in ["aave", "poolAddressesProvider", "rewardsController", "swapTarget"]: item[getter] = call(getattr(connector.functions, getter)(), block)
    provider_address = checksum(value(item["poolAddressesProvider"])); rewards_address = checksum(value(item["rewardsController"]))
    if not provider_address or not rewards_address: raise RuntimeError("connector immutable binding unresolved")
    provider = primary.eth.contract(provider_address, abi=PROVIDER_ABI); item["poolDataProvider"] = call(provider.functions.getPoolDataProvider(), block); data_provider_address = checksum(value(item["poolDataProvider"]))
    if not data_provider_address: raise RuntimeError("pool data provider unresolved")
    data_provider = primary.eth.contract(data_provider_address, abi=DATA_PROVIDER_ABI); item["reserveTokens"] = call(data_provider.functions.getReserveTokensAddresses(asset), block); reserve_tokens = value(item["reserveTokens"])
    if not isinstance(reserve_tokens, list) or not reserve_tokens: raise RuntimeError("reserve tokens unresolved")
    a_token = checksum(reserve_tokens[0])
    if not a_token or a_token == ZERO: raise RuntimeError("aToken unresolved")
    item["asset_token"] = token_meta(primary, asset, vault_address, block); item["aToken"] = token_meta(primary, a_token, vault_address, block)
    rewards = primary.eth.contract(rewards_address, abi=REWARDS_ABI)
    item["configured_rewards"] = call(rewards.functions.getRewardsByAsset(a_token), block); item["canonical_view"] = call(rewards.functions.getAllUserRewards([a_token], vault_address), block); item["canonical_claim_eth_call"] = call(rewards.functions.claimAllRewards([a_token], vault_address), block, {"from": vault_address}); item["authorized_claimer"] = call(rewards.functions.getClaimer(vault_address), block)
    configured = [checksum(x) for x in (value(item["configured_rewards"]) or [])]; configured = [x for x in configured if x]; canonical_pairs = pair_rewards(value(item["canonical_view"])); claim_pairs = pair_rewards(value(item["canonical_claim_eth_call"])); union: list[str] = []
    for address in configured + [x["reward"] for x in canonical_pairs] + [x["reward"] for x in claim_pairs]:
        if address and address.lower() not in {x.lower() for x in union}: union.append(address)
    reward_rows: list[dict[str, Any]] = []; canonical_amounts = {x["reward"].lower(): int(x["amount_raw"]) for x in canonical_pairs}; claim_amounts = {x["reward"].lower(): int(x["amount_raw"]) for x in claim_pairs}
    for reward in union:
        reward_view = call(rewards.functions.getAllUserRewards([reward], vault_address), block); reward_claim = call(rewards.functions.claimAllRewards([reward], vault_address), block, {"from": vault_address}); reward_view_pairs = pair_rewards(value(reward_view)); reward_claim_pairs = pair_rewards(value(reward_claim)); target_claimed = sum(x["amount_raw"] for x in reward_claim_pairs if x["reward"].lower() == reward.lower()); other_claimed = sum(x["amount_raw"] for x in reward_claim_pairs if x["reward"].lower() != reward.lower())
        reward_rows.append({"reward": reward, "canonical_owed_raw": canonical_amounts.get(reward.lower(), 0), "canonical_claim_raw": claim_amounts.get(reward.lower(), 0), "token": token_meta(primary, reward, vault_address, block), "reward_as_assets_view": reward_view, "reward_as_assets_view_pairs": reward_view_pairs, "reward_as_assets_claim_eth_call": reward_claim, "reward_as_assets_claim_pairs": reward_claim_pairs, "target_claimed_raw": target_claimed, "other_claimed_raw": other_claimed, "same_as_aToken": reward.lower() == a_token.lower()})
    item["reward_rows"] = reward_rows
    strategy_raw = value(item["additionalRewardsStrategy"]); strategy = int(strategy_raw) if strategy_raw is not None else None; strategy_name = {0: "None", 1: "Claim", 2: "Reinvest"}.get(strategy, "Unknown"); nonzero = [x for x in reward_rows if max(x["canonical_owed_raw"], x["canonical_claim_raw"]) > 0]; total_nonzero = sum(max(x["canonical_owed_raw"], x["canonical_claim_raw"]) for x in nonzero); working = [x for x in nonzero if x["target_claimed_raw"] > 0]; multi_stranding = [x for x in working if x["other_claimed_raw"] > 0]; direct_nonzero = [x for x in reward_rows if int(value(x["token"]["balance_at_vault"]) or 0) > 0 and x["reward"].lower() not in {asset.lower(), a_token.lower()}]
    reasons: list[str] = []
    if strategy in (1, 2) and total_nonzero > 0 and not working: reasons.append("canonical_rewards_not_reachable_with_any_reward_token_as_assets_input")
    if strategy in (1, 2) and multi_stranding: reasons.append("single_selected_reward_processing_while_call_returns_other_nonzero_rewards")
    if strategy in (1, 2) and direct_nonzero: reasons.append("direct_non_underlying_reward_balance_present_at_vault")
    item["gate"] = {"strategy": strategy, "strategy_name": strategy_name, "canonical_nonzero_reward_count": len(nonzero), "canonical_total_raw_unscaled": total_nonzero, "working_reward_input_count": len(working), "multi_reward_stranding_input_count": len(multi_stranding), "direct_non_underlying_reward_balance_count": len(direct_nonzero), "candidate": bool(reasons), "reasons": reasons}
    return item

def quorum_candidate(secondary: Web3, item: dict[str, Any]) -> dict[str, Any]:
    block = int(item["block"]); vault = Web3.to_checksum_address(item["vault"]); a_token = Web3.to_checksum_address(item["aToken"]["address"]); rewards_address = Web3.to_checksum_address(value(item["rewardsController"])); rewards = secondary.eth.contract(rewards_address, abi=REWARDS_ABI); canonical = call(rewards.functions.getAllUserRewards([a_token], vault), block); result: dict[str, Any] = {"block_hash": secondary.eth.get_block(block)["hash"].hex(), "canonical_view": canonical, "reward_inputs": []}
    for row in item.get("reward_rows", []):
        reward = Web3.to_checksum_address(row["reward"]); result["reward_inputs"].append({"reward": reward, "view": call(rewards.functions.getAllUserRewards([reward], vault), block), "claim_eth_call": call(rewards.functions.claimAllRewards([reward], vault), block, {"from": vault})})
    result["matches_primary_canonical"] = normalize(value(canonical)) == normalize(value(item["canonical_view"])); return result

def main() -> int:
    scope, scope_meta = fetch_scope(); grouped: dict[str, list[ScopeRow]] = {}
    for row in scope:
        if row.network in NETWORKS: grouped.setdefault(row.network, []).append(row)
    rows: list[dict[str, Any]] = []; errors: list[dict[str, Any]] = []; chain_meta: dict[str, Any] = {}
    for network, network_rows in sorted(grouped.items(), key=lambda kv: NETWORKS[kv[0]][0]):
        try:
            clients, block, block_hash = connect_quorum(network, network_rows[0].vault); chain_meta[network] = {"chain_id": NETWORKS[network][0], "rpc_urls": [x[1] for x in clients], "latest_heights": [x[2] for x in clients], "pinned_block": block, "pinned_block_hash": block_hash, "rpc_quorum_size": len(clients)}
        except Exception as exc:
            errors.append({"network": network, "scope_error": f"{type(exc).__name__}: {exc}"}); continue
        primary = clients[0][0]
        for source in network_rows:
            try:
                item = query_vault(primary, network, source, block, block_hash)
                if item["gate"]["candidate"] and len(clients) > 1:
                    item["secondary_quorum"] = quorum_candidate(clients[1][0], item)
                    if not item["secondary_quorum"].get("matches_primary_canonical"): item["gate"]["candidate"] = False; item["gate"]["reasons"].append("killed_rpc_quorum_mismatch")
                elif item["gate"]["candidate"]: item["gate"]["candidate"] = False; item["gate"]["reasons"].append("killed_no_second_rpc_quorum")
                rows.append(item)
            except Exception as exc: errors.append({"network": network, "label": source.label, "vault": source.vault, "error": f"{type(exc).__name__}: {exc}"})
    candidates = [row for row in rows if row.get("gate", {}).get("candidate")]; strategy_counts: dict[str, int] = {}
    for row in rows:
        name = row.get("gate", {}).get("strategy_name", "Unknown"); strategy_counts[name] = strategy_counts.get(name, 0) + 1
    result = {"schema": "kiln-r27-current-aave-compatibility-census-v1", "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "scope": scope_meta, "safety": {"read_only": True, "rpc_methods": ["eth_chainId", "eth_blockNumber", "eth_getBlockByNumber", "eth_getCode", "eth_call"], "public_chain_state_changes": 0, "transactions_signed": 0, "transactions_sent": 0, "private_keys_loaded": 0}, "chains": chain_meta, "rows": rows, "errors": errors, "summary": {"scope_count": len(scope), "inspected_count": len(rows), "error_count": len(errors), "strategy_counts": strategy_counts, "candidate_count": len(candidates), "candidate_vaults": [row["vault"] for row in candidates], "candidate_reasons": sorted({reason for row in candidates for reason in row["gate"]["reasons"]})}}
    evidence = OUT / "EVIDENCE.json"; evidence.write_text(json.dumps(result, indent=2, sort_keys=True))
    gate = {"schema": "kiln-r27-public-gate-v1", "decision": "PROMOTE_PRIVATE_FIXED_BLOCK_REVIEW" if candidates else "KILL_NO_CURRENT_AAVE_COMPATIBILITY_CANDIDATE", "submit_ready": False, "validated_critical": 0, "validated_high": 0, "candidate_count": len(candidates), "scope_count": len(scope), "inspected_count": len(rows), "error_count": len(errors), "source_scope": scope_meta.get("source"), "public_chain_state_changes": 0, "transactions_signed": 0, "transactions_sent": 0}
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True)); files = sorted(p for p in OUT.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt"); (OUT / "SHA256SUMS.txt").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files)); print(json.dumps(gate, sort_keys=True)); return 0 if rows else 2

if __name__ == "__main__": raise SystemExit(main())
