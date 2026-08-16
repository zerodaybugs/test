#!/usr/bin/env python3
"""Kiln R21 Aave V3 reward-token compatibility gate. Read-only only."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path("r21_aave_reward_results")
OUT.mkdir(exist_ok=True)
SCOPE_URL = (
    "https://raw.githubusercontent.com/zerodaybugs/test/"
    "agent/kiln-omnivault-r11-readonly/"
    "r13_persisted_results/31910466827/r13_generation/SCOPE.json"
)
CFG = {
    1: ("ethereum", ["https://ethereum-rpc.publicnode.com", "https://rpc.flashbots.net", "https://eth.llamarpc.com"]),
    10: ("optimism", ["https://optimism-rpc.publicnode.com", "https://optimism.llamarpc.com", "https://mainnet.optimism.io"]),
    56: ("bnb", ["https://bsc-rpc.publicnode.com", "https://binance.llamarpc.com", "https://bsc-dataseed.binance.org"]),
    137: ("polygon", ["https://polygon-bor-rpc.publicnode.com", "https://polygon.llamarpc.com", "https://polygon-rpc.com"]),
    8453: ("base", ["https://base-rpc.publicnode.com", "https://base.llamarpc.com", "https://mainnet.base.org"]),
    42161: ("arbitrum", ["https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.llamarpc.com", "https://arb1.arbitrum.io/rpc"]),
}
CALLER = Web3.to_checksum_address("0x000000000000000000000000000000000000bEEF")
ZERO = "0x" + "00" * 20

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
]
CONNECTOR_ABI = [
    {"type":"function","name":"aave","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"poolAddressesProvider","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"rewardsController","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"swapTarget","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
ADDRESSES_PROVIDER_ABI = [
    {"type":"function","name":"getPoolDataProvider","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
DATA_PROVIDER_ABI = [
    {"type":"function","name":"getReserveTokensAddresses","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"}]},
]
REWARDS_ABI = [
    {"type":"function","name":"getAllUserRewards","stateMutability":"view","inputs":[{"type":"address[]"},{"type":"address"}],"outputs":[{"type":"address[]"},{"type":"uint256[]"}]},
    {"type":"function","name":"getRewardsByAsset","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address[]"}]},
    {"type":"function","name":"getClaimer","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address"}]},
    {"type":"function","name":"claimAllRewards","stateMutability":"nonpayable","inputs":[{"type":"address[]"},{"type":"address"}],"outputs":[{"type":"address[]"},{"type":"uint256[]"}]},
]
ERC20_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]


def normalize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [normalize(v) for v in value]
    return value


def safe(fn, tx: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        return {"ok": True, "value": normalize(fn.call(tx or {}))}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def result_value(result: dict[str, Any]) -> Any:
    return result.get("value") if result.get("ok") else None


def connect(chain_id: int, probe_vault: str) -> tuple[Web3, str]:
    errors: list[str] = []
    probe = Web3.to_checksum_address(probe_vault)
    for url in CFG[chain_id][1]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
            if not w3.is_connected() or w3.eth.chain_id != chain_id:
                continue
            raw = w3.eth.call({"to": probe, "data": "0x38d52e0f"})
            if len(raw) < 32:
                raise RuntimeError("asset getter returned short data")
            return w3, url
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError("no provider passed exact vault getter | " + " | ".join(errors))


def token_meta(w3: Web3, address: str, owner: str) -> dict[str, Any]:
    token_address = Web3.to_checksum_address(address)
    token = w3.eth.contract(token_address, abi=ERC20_ABI)
    return {
        "address": token_address,
        "name": safe(token.functions.name()),
        "symbol": safe(token.functions.symbol()),
        "decimals": safe(token.functions.decimals()),
        "balance_at_vault": safe(token.functions.balanceOf(Web3.to_checksum_address(owner))),
    }


def main() -> int:
    response = requests.get(SCOPE_URL, headers={"User-Agent":"Kiln-R21-AaveGate/1.0"}, timeout=45)
    response.raise_for_status()
    scope = [row for row in response.json() if row.get("connector") == "AAVE_V3"]
    if not scope:
        raise RuntimeError("Aave scope is empty")

    by_chain: dict[int, list[dict[str, Any]]] = {}
    for row in scope:
        by_chain.setdefault(int(row["chain_id"]), []).append(row)

    clients: dict[int, tuple[Web3, str]] = {}
    chain_meta: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for chain_id, chain_rows in sorted(by_chain.items()):
        try:
            clients[chain_id] = connect(chain_id, chain_rows[0]["vault"])
            w3, rpc = clients[chain_id]
            chain_meta[str(chain_id)] = {"network":CFG[chain_id][0], "rpc":rpc, "block":w3.eth.block_number}
        except Exception as exc:
            errors.append({"chain_id":chain_id, "scope_error":f"{type(exc).__name__}: {exc}"})
            continue

        w3, rpc = clients[chain_id]
        for source in chain_rows:
            vault_address = Web3.to_checksum_address(source["vault"])
            try:
                vault = w3.eth.contract(vault_address, abi=VAULT_ABI)
                item: dict[str, Any] = {
                    "chain_id": chain_id,
                    "network": CFG[chain_id][0],
                    "rpc": rpc,
                    "block": w3.eth.block_number,
                    "label": source["label"],
                    "vault": vault_address,
                    "vault_code_sha256": hashlib.sha256(bytes(w3.eth.get_code(vault_address))).hexdigest(),
                }
                for getter in ["asset", "connectorRegistry", "connectorName", "additionalRewardsStrategy", "rewardFee", "totalAssets", "totalSupply"]:
                    item[getter] = safe(getattr(vault.functions, getter)())

                asset = result_value(item["asset"])
                registry_address = result_value(item["connectorRegistry"])
                connector_name = result_value(item["connectorName"])
                if not asset or not registry_address or not connector_name:
                    raise RuntimeError("vault binding unresolved")
                asset = Web3.to_checksum_address(asset)
                registry_address = Web3.to_checksum_address(registry_address)
                name_bytes = bytes.fromhex(connector_name.removeprefix("0x"))

                registry = w3.eth.contract(registry_address, abi=REGISTRY_ABI)
                item["connector"] = safe(registry.functions.get(name_bytes))
                connector_address = result_value(item["connector"])
                if not connector_address:
                    raise RuntimeError("connector unresolved")
                connector_address = Web3.to_checksum_address(connector_address)
                connector = w3.eth.contract(connector_address, abi=CONNECTOR_ABI)
                item["connector_address"] = connector_address
                item["connector_code_sha256"] = hashlib.sha256(bytes(w3.eth.get_code(connector_address))).hexdigest()
                for getter in ["aave", "poolAddressesProvider", "rewardsController", "swapTarget"]:
                    item[getter] = safe(getattr(connector.functions, getter)())

                provider_address = result_value(item["poolAddressesProvider"])
                rewards_address = result_value(item["rewardsController"])
                if not provider_address or not rewards_address:
                    raise RuntimeError("Aave connector immutables unresolved")
                provider = w3.eth.contract(Web3.to_checksum_address(provider_address), abi=ADDRESSES_PROVIDER_ABI)
                item["poolDataProvider"] = safe(provider.functions.getPoolDataProvider())
                data_provider_address = result_value(item["poolDataProvider"])
                if not data_provider_address:
                    raise RuntimeError("Aave data provider unresolved")
                data_provider = w3.eth.contract(Web3.to_checksum_address(data_provider_address), abi=DATA_PROVIDER_ABI)
                item["reserveTokens"] = safe(data_provider.functions.getReserveTokensAddresses(asset))
                reserve_tokens = result_value(item["reserveTokens"])
                if not reserve_tokens or not reserve_tokens[0] or reserve_tokens[0].lower() == ZERO.lower():
                    raise RuntimeError("aToken unresolved")
                a_token = Web3.to_checksum_address(reserve_tokens[0])
                item["aToken"] = token_meta(w3, a_token, vault_address)

                rewards = w3.eth.contract(Web3.to_checksum_address(rewards_address), abi=REWARDS_ABI)
                item["rewardsByAsset"] = safe(rewards.functions.getRewardsByAsset(a_token))
                item["allUserRewards"] = safe(rewards.functions.getAllUserRewards([a_token], vault_address))
                item["claimer"] = safe(rewards.functions.getClaimer(vault_address))
                item["claimAllRewards_eth_call_as_vault"] = safe(
                    rewards.functions.claimAllRewards([a_token], vault_address), {"from":vault_address}
                )

                configured = result_value(item["additionalRewardsStrategy"])
                strategy = int(configured) if configured is not None else None
                all_rewards = result_value(item["allUserRewards"])
                reward_addresses: list[str] = []
                owed_values: list[int] = []
                if all_rewards and len(all_rewards) == 2:
                    reward_addresses = [Web3.to_checksum_address(x) for x in all_rewards[0]]
                    owed_values = [int(x) for x in all_rewards[1]]
                configured_rewards = result_value(item["rewardsByAsset"]) or []
                for reward in configured_rewards:
                    reward = Web3.to_checksum_address(reward)
                    if reward not in reward_addresses:
                        reward_addresses.append(reward)
                        owed_values.append(0)

                reward_rows: list[dict[str, Any]] = []
                mismatch_owed = 0
                compatible_owed = 0
                for index, reward in enumerate(reward_addresses):
                    owed = owed_values[index] if index < len(owed_values) else 0
                    meta = token_meta(w3, reward, vault_address)
                    decimals = result_value(meta["decimals"])
                    human = owed / (10 ** int(decimals)) if decimals is not None else None
                    compatible = reward.lower() == a_token.lower()
                    if owed > 0:
                        if compatible:
                            compatible_owed += 1
                        else:
                            mismatch_owed += 1
                    reward_rows.append({
                        "reward": reward,
                        "owed_raw": owed,
                        "owed_human": human,
                        "same_as_incentivized_aToken": compatible,
                        "token": meta,
                    })
                item["reward_rows"] = reward_rows
                item["gate"] = {
                    "strategy": strategy,
                    "strategy_name": {0:"None",1:"Claim",2:"Reinvest"}.get(strategy,"Unknown"),
                    "configured_reward_count": len(reward_rows),
                    "nonzero_mismatched_reward_count": mismatch_owed,
                    "nonzero_compatible_reward_count": compatible_owed,
                    "current_candidate": strategy in (1,2) and mismatch_owed > 0,
                    "authorized_external_claimer": (
                        result_value(item["claimer"]) is not None
                        and result_value(item["claimer"]).lower() != ZERO.lower()
                    ),
                }
                rows.append(item)
            except Exception as exc:
                errors.append({
                    "chain_id": chain_id,
                    "network": CFG[chain_id][0],
                    "label": source["label"],
                    "vault": source["vault"],
                    "error": f"{type(exc).__name__}: {exc}",
                })

    candidates = [row for row in rows if row["gate"]["current_candidate"]]
    strategies: dict[str, int] = {}
    for row in rows:
        name = row["gate"]["strategy_name"]
        strategies[name] = strategies.get(name, 0) + 1
    summary = {
        "scope": len(scope),
        "inspected": len(rows),
        "errors": len(errors),
        "strategy_counts": strategies,
        "candidate_count": len(candidates),
        "candidate_vaults": [row["vault"] for row in candidates],
        "candidate_networks": sorted({row["network"] for row in candidates}),
        "candidate_reward_rows": sum(
            row["gate"]["nonzero_mismatched_reward_count"] for row in candidates
        ),
    }
    evidence = {
        "schema": "kiln-r21-aave-reward-compatibility-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope_source": SCOPE_URL,
        "safety": {
            "read_only": True,
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "rpc_methods": ["eth_call", "eth_getCode", "eth_blockNumber"],
        },
        "chains": chain_meta,
        "rows": rows,
        "errors": errors,
        "summary": summary,
    }
    gate = {
        "decision": "PROMOTE_AAVE_REWARD_MISMATCH_TO_FIXED_BLOCK_FORK" if candidates else "KILL_CURRENT_AAVE_REWARD_MISMATCH_GATE",
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "validated_medium": 0,
        "candidate_count": len(candidates),
        "blocking_gates": [
            "exact connector source/runtime binding",
            "fixed-block local-fork reproduction",
            "claim-manager execution and negative control",
            "materiality and duration",
            "official-audit duplicate clearance",
            "patched control",
        ] if candidates else ["no active non-aToken reward value under Claim/Reinvest"],
    }

    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, sort_keys=True))
    (OUT / "MASTER_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    (OUT / "CANDIDATES.json").write_text(json.dumps(candidates, indent=2, sort_keys=True))
    sums = []
    for path in sorted(OUT.glob("*.json")):
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    (OUT / "SHA256SUMS.txt").write_text("".join(sums))
    print("R21_AAVE_REWARD_GATE_COMPLETE")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
