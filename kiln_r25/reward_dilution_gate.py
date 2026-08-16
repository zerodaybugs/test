#!/usr/bin/env python3
"""Kiln R25: Compound V3 forced-claim reward dilution gate.

Authorized, read-only bug-bounty research. The script uses eth_call, eth_getCode,
eth_getBlockByNumber, eth_getLogs and public price/source data only. It never
signs or broadcasts a transaction.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path("r25_results")
OUT.mkdir(exist_ok=True)
MIRROR = Path(os.environ.get("KILN_MIRROR", "mirror"))
CALLER = Web3.to_checksum_address("0x000000000000000000000000000000000000bEEF")
ZERO = "0x" + "00" * 20
TIMEOUT = 30
LOOKBACK_DAYS = 45

CFG: dict[int, dict[str, Any]] = {
    1: {
        "name": "ethereum",
        "rpcs": [
            "https://ethereum-rpc.publicnode.com",
            "https://rpc.flashbots.net",
            "https://eth.llamarpc.com",
            "https://1rpc.io/eth",
        ],
        "gas_usd": 35.0,
    },
    137: {
        "name": "polygon",
        "rpcs": [
            "https://polygon-bor-rpc.publicnode.com",
            "https://polygon.llamarpc.com",
            "https://polygon-rpc.com",
        ],
        "gas_usd": 1.5,
    },
    8453: {
        "name": "base",
        "rpcs": [
            "https://base-rpc.publicnode.com",
            "https://base.llamarpc.com",
            "https://mainnet.base.org",
        ],
        "gas_usd": 1.5,
    },
    42161: {
        "name": "arbitrum",
        "rpcs": [
            "https://arbitrum-one-rpc.publicnode.com",
            "https://arbitrum.llamarpc.com",
            "https://arb1.arbitrum.io/rpc",
        ],
        "gas_usd": 2.0,
    },
}

VAULTS = [
    (137, "Bifrost Compound v3 USDT", "0xE194d6De7E9499116A9E7E923696A92d6944D2B2"),
    (8453, "Bifrost Compound v3 USDC", "0xd92249507B3ECe9600a3b1DaDC1e4DAc3B80128F"),
    (42161, "Bifrost Compound v3 USDT", "0xAd231a5aAc991089F1A4FEbFD95eE571A9826054"),
    (42161, "Bitnovo Compound v3 USDC", "0x19A0F016Ac3989e754ab8216810beD8503bDA37e"),
    (42161, "Crypto.com Compound USDC.e", "0xAB3aC228Cac84a8a1C855C3E08F869B65836c962"),
    (42161, "Crypto.com Compound USDC", "0x1C107c4233Ab3056254e717c7a67F9917079b615"),
    (42161, "Bifrost Compound v3 USDC", "0x1eB3061F96Ff927EA7CAeF216bB5872622052C1C"),
    (1, "Bifrost Compound v3 USDT", "0x96D595D35a0203d6e218852190b3E981ADEeab0B"),
    (1, "Bifrost Compound v3 USDS", "0x91422083A9947De4f0423c6829888BE7B83f06F5"),
    (1, "Bifrost Compound v3 USDC", "0x754A34e2f4582925F5E384c371f78db01A869572"),
    (1, "Yield Bearing Compound USDC", "0xB9E62Cb9b4cE8ec13c886FaE67369Da417EE2714"),
    (1, "Trust Wallet Compound v3 USDC", "0x804EE40b227B9003BB7bf2880cF502466544F208"),
    (1, "Bitnovo Compound v3 USDC", "0x4bf3499072103e9A4afC2Ce4ea09afccF163CD87"),
]

VA = [
    {"type": "function", "name": "asset", "stateMutability": "view", "inputs": [], "outputs": [{"type": "address"}]},
    {"type": "function", "name": "connectorRegistry", "stateMutability": "view", "inputs": [], "outputs": [{"type": "address"}]},
    {"type": "function", "name": "connectorName", "stateMutability": "view", "inputs": [], "outputs": [{"type": "bytes32"}]},
    {"type": "function", "name": "additionalRewardsStrategy", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint8"}]},
    {"type": "function", "name": "depositFee", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "rewardFee", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "totalAssets", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "totalSupply", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "decimals", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint8"}]},
    {"type": "function", "name": "previewDeposit", "stateMutability": "view", "inputs": [{"type": "uint256"}], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "maxDeposit", "stateMutability": "view", "inputs": [{"type": "address"}], "outputs": [{"type": "uint256"}]},
]
REGISTRY_ABI = [
    {"type": "function", "name": "get", "stateMutability": "view", "inputs": [{"type": "bytes32"}], "outputs": [{"type": "address"}]}
]
CONNECTOR_ABI = [
    {"type": "function", "name": name, "stateMutability": "view", "inputs": [], "outputs": [{"type": "address"}]}
    for name in ("compoundMarketRegistry", "cometRewards", "comp", "swapTarget")
]
MARKET_REGISTRY_ABI = [
    {"type": "function", "name": "getMarket", "stateMutability": "view", "inputs": [{"type": "address"}], "outputs": [{"type": "address"}]}
]
COMET_ABI = [
    {"type": "function", "name": "baseToken", "stateMutability": "view", "inputs": [], "outputs": [{"type": "address"}]},
    {"type": "function", "name": "balanceOf", "stateMutability": "view", "inputs": [{"type": "address"}], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "baseTrackingAccrued", "stateMutability": "view", "inputs": [{"type": "address"}], "outputs": [{"type": "uint64"}]},
    {"type": "function", "name": "isSupplyPaused", "stateMutability": "view", "inputs": [], "outputs": [{"type": "bool"}]},
    {"type": "function", "name": "isWithdrawPaused", "stateMutability": "view", "inputs": [], "outputs": [{"type": "bool"}]},
]
REWARDS_ABI = [
    {
        "type": "function",
        "name": "rewardConfig",
        "stateMutability": "view",
        "inputs": [{"type": "address"}],
        "outputs": [{"type": "address"}, {"type": "uint64"}, {"type": "bool"}, {"type": "uint256"}],
    },
    {
        "type": "function",
        "name": "rewardsClaimed",
        "stateMutability": "view",
        "inputs": [{"type": "address"}, {"type": "address"}],
        "outputs": [{"type": "uint256"}],
    },
    {
        "type": "function",
        "name": "getRewardOwed",
        "stateMutability": "nonpayable",
        "inputs": [{"type": "address"}, {"type": "address"}],
        "outputs": [{"components": [{"name": "token", "type": "address"}, {"name": "owed", "type": "uint256"}], "type": "tuple"}],
    },
    {
        "type": "function",
        "name": "claim",
        "stateMutability": "nonpayable",
        "inputs": [{"type": "address"}, {"type": "address"}, {"type": "bool"}],
        "outputs": [],
    },
]
ERC20_ABI = [
    {"type": "function", "name": "balanceOf", "stateMutability": "view", "inputs": [{"type": "address"}], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "decimals", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint8"}]},
    {"type": "function", "name": "symbol", "stateMutability": "view", "inputs": [], "outputs": [{"type": "string"}]},
]

REWARD_CLAIMED_TOPIC = Web3.keccak(text="RewardClaimed(address,address,address,uint256)").hex()


def norm(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (tuple, list)):
        return [norm(v) for v in value]
    return value


def safe_call(fn: Any, tx: dict[str, Any] | None = None, block: Any = "latest") -> dict[str, Any]:
    try:
        return {"ok": True, "value": norm(fn.call(tx or {}, block_identifier=block))}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect(chain_id: int) -> tuple[Web3, str]:
    errors: list[str] = []
    probe = Web3.to_checksum_address(next(v for c, _, v in VAULTS if c == chain_id))
    for url in CFG[chain_id]["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": TIMEOUT}))
            if not w3.is_connected() or w3.eth.chain_id != chain_id:
                continue
            code = w3.eth.get_code(probe)
            if not code:
                continue
            w3.eth.call({"to": probe, "data": "0x38d52e0f"})  # asset()
            return w3, url
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError("no usable RPC: " + " | ".join(errors))


def token_info(w3: Web3, address: str) -> dict[str, Any]:
    token = w3.eth.contract(Web3.to_checksum_address(address), abi=ERC20_ABI)
    dec = safe_call(token.functions.decimals())
    sym = safe_call(token.functions.symbol())
    return {
        "address": Web3.to_checksum_address(address),
        "decimals": int(dec["value"]) if dec.get("ok") else None,
        "symbol": str(sym["value"]) if sym.get("ok") else None,
        "decimals_call": dec,
        "symbol_call": sym,
    }


def topic_address(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def block_at_or_after_timestamp(w3: Web3, target_ts: int) -> int:
    lo, hi = 0, w3.eth.block_number
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            ts = int(w3.eth.get_block(mid)["timestamp"])
        except Exception:  # noqa: BLE001
            lo = mid + 1
            continue
        if ts < target_ts:
            lo = mid + 1
        else:
            hi = mid
    return lo


def get_logs_adaptive(
    w3: Web3,
    address: str,
    from_block: int,
    to_block: int,
    topics: list[Any],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cursor = from_block
    span = min(250_000, max(2_000, to_block - from_block + 1))
    while cursor <= to_block:
        end = min(to_block, cursor + span - 1)
        try:
            rows = w3.eth.get_logs({
                "address": Web3.to_checksum_address(address),
                "fromBlock": cursor,
                "toBlock": end,
                "topics": topics,
            })
            out.extend(dict(row) for row in rows)
            cursor = end + 1
            if len(rows) < 100 and span < 1_000_000:
                span = min(1_000_000, span * 2)
        except Exception as exc:  # noqa: BLE001
            if span <= 1_000:
                raise RuntimeError(f"eth_getLogs failed at {cursor}-{end}: {exc}") from exc
            span = max(1_000, span // 2)
    return out


def fetch_prices(tokens: list[tuple[str, str]]) -> dict[str, float]:
    keys = [f"{chain}:{address.lower()}" for chain, address in tokens]
    prices: dict[str, float] = {}
    for i in range(0, len(keys), 75):
        batch = keys[i : i + 75]
        url = "https://coins.llama.fi/prices/current/" + ",".join(batch)
        try:
            data = requests.get(url, headers={"User-Agent": "Kiln-R25/1.0"}, timeout=45).json()
            for key, value in (data.get("coins") or {}).items():
                if isinstance(value, dict) and value.get("price") is not None:
                    prices[key.lower()] = float(value["price"])
        except Exception:  # noqa: BLE001
            continue
    return prices


def static_source_gate() -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    if not MIRROR.exists():
        return {"mirror_present": False, "files": [], "full_balance_reinvest": False}
    for path in MIRROR.rglob("*.sol"):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if "cometRewards" not in text or "function reinvest" not in text:
            continue
        start = text.find("function reinvest")
        snippet = text[start : start + 5000]
        full_balance = bool(re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", snippet))
        claim_call = "cometRewards" in snippet and ".claim" in snippet
        files.append({
            "path": path.relative_to(MIRROR).as_posix(),
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "claim_call_in_reinvest": claim_call,
            "full_reward_balance_read": full_balance,
            "snippet": snippet,
        })
    return {
        "mirror_present": True,
        "files": files,
        "full_balance_reinvest": any(f["claim_call_in_reinvest"] and f["full_reward_balance_read"] for f in files),
    }


def duplicate_gate() -> dict[str, Any]:
    patterns = [
        re.compile(r"pre[- ]?claim", re.I),
        re.compile(r"reward.{0,100}(front[- ]?run|sandwich|dilut|stale nav)", re.I | re.S),
        re.compile(r"(front[- ]?run|sandwich|dilut).{0,100}reward", re.I | re.S),
        re.compile(r"unclaimed.{0,120}(deposit|share|vault|reward)", re.I | re.S),
        re.compile(r"claim.{0,120}deposit", re.I | re.S),
    ]
    hits: list[dict[str, Any]] = []
    official_roots = [MIRROR / "pdfextracts"]
    for root in official_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".txt", ".md"}:
                continue
            text = path.read_text(errors="replace")
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    lo = max(0, match.start() - 300)
                    hi = min(len(text), match.end() + 500)
                    hits.append({
                        "path": path.relative_to(MIRROR).as_posix(),
                        "pattern": pattern.pattern,
                        "context": text[lo:hi],
                    })
                    break
    exact = any(
        re.search(r"(permissionless|anyone).{0,180}claim", h["context"], re.I | re.S)
        and re.search(r"(deposit|share|dilut|front[- ]?run)", h["context"], re.I)
        for h in hits
    )
    return {"official_audit_hits": hits, "exact_duplicate_signal": exact}


def optimise_attack(row: dict[str, Any], prices: dict[str, float]) -> dict[str, Any]:
    asset = row["asset_info"]
    reward = row["reward_info"]
    if asset["decimals"] is None or reward["decimals"] is None:
        return {"ok": False, "reason": "token decimals unresolved"}
    chain_name = row["network"]
    asset_key = f"{chain_name}:{asset['address'].lower()}"
    reward_key = f"{chain_name}:{reward['address'].lower()}"
    asset_price = prices.get(asset_key.lower())
    reward_price = prices.get(reward_key.lower())
    if asset_price is None and (asset.get("symbol") or "").upper() in {"USDC", "USDT", "USDS", "DAI"}:
        asset_price = 1.0
    if not asset_price or not reward_price:
        return {
            "ok": False,
            "reason": "price unresolved",
            "asset_price_usd": asset_price,
            "reward_price_usd": reward_price,
        }

    asset_dec = int(asset["decimals"])
    reward_dec = int(reward["decimals"])
    total_assets = int(row["totalAssets"])
    total_supply = int(row["totalSupply"])
    reward_raw = int(row["reward_total_raw"])
    max_deposit = int(row["maxDeposit"])
    dep_fee_raw = int(row["depositFee"])
    rew_fee_raw = int(row["rewardFee"])
    dep_rate = dep_fee_raw / (100 * 10**asset_dec)
    rew_rate = rew_fee_raw / (100 * 10**asset_dec)
    reward_usd = reward_raw / 10**reward_dec * reward_price
    net_reward_usd = reward_usd * max(0.0, 1.0 - rew_rate)

    candidates: set[int] = set()
    for frac in (0.0001, 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10):
        candidates.add(max(1, int(total_assets * frac)))
    for usd in (100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000):
        candidates.add(max(1, int(usd / asset_price * 10**asset_dec)))
    if max_deposit < 2**255:
        candidates = {min(x, max_deposit) for x in candidates if max_deposit > 0}
    candidates = {x for x in candidates if x > 0}

    best: dict[str, Any] | None = None
    vault_contract = row["_vault_contract"]
    for amount in sorted(candidates):
        preview = safe_call(vault_contract.functions.previewDeposit(amount))
        if not preview.get("ok"):
            continue
        shares = int(preview["value"])
        if shares <= 0 or total_supply + shares <= 0:
            continue
        fraction = shares / (total_supply + shares)
        capture_usd = net_reward_usd * fraction
        deposit_fee_usd = amount / 10**asset_dec * asset_price * dep_rate
        net_profit_usd = capture_usd - deposit_fee_usd - float(CFG[row["chain_id"]]["gas_usd"])
        item = {
            "deposit_raw": amount,
            "deposit_usd": amount / 10**asset_dec * asset_price,
            "preview_shares": shares,
            "post_deposit_share_fraction": fraction,
            "reward_value_usd": reward_usd,
            "reward_value_after_protocol_fee_usd": net_reward_usd,
            "captured_reward_usd": capture_usd,
            "deposit_fee_usd": deposit_fee_usd,
            "gas_budget_usd": float(CFG[row["chain_id"]]["gas_usd"]),
            "estimated_net_profit_usd": net_profit_usd,
        }
        if best is None or item["estimated_net_profit_usd"] > best["estimated_net_profit_usd"]:
            best = item
    return {
        "ok": best is not None,
        "asset_price_usd": asset_price,
        "reward_price_usd": reward_price,
        "reward_total_usd": reward_usd,
        "deposit_fee_rate": dep_rate,
        "reward_fee_rate": rew_rate,
        "best": best,
    }


def main() -> int:
    source_gate = static_source_gate()
    dup_gate = duplicate_gate()
    connections: dict[int, tuple[Web3, str]] = {}
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for chain_id, label, vault_raw in VAULTS:
        try:
            if chain_id not in connections:
                connections[chain_id] = connect(chain_id)
            w3, rpc_url = connections[chain_id]
            vault = Web3.to_checksum_address(vault_raw)
            vc = w3.eth.contract(vault, abi=VA)
            calls = {}
            for name, args in (
                ("asset", ()),
                ("connectorRegistry", ()),
                ("connectorName", ()),
                ("additionalRewardsStrategy", ()),
                ("depositFee", ()),
                ("rewardFee", ()),
                ("totalAssets", ()),
                ("totalSupply", ()),
                ("decimals", ()),
                ("maxDeposit", (CALLER,)),
            ):
                calls[name] = safe_call(getattr(vc.functions, name)(*args))
            required = ("asset", "connectorRegistry", "connectorName", "additionalRewardsStrategy", "depositFee", "rewardFee", "totalAssets", "totalSupply", "maxDeposit")
            if not all(calls[name].get("ok") for name in required):
                raise RuntimeError("vault getter failure: " + json.dumps({k: calls[k] for k in required if not calls[k].get('ok')}))

            asset = Web3.to_checksum_address(calls["asset"]["value"])
            registry = Web3.to_checksum_address(calls["connectorRegistry"]["value"])
            connector_name = bytes.fromhex(calls["connectorName"]["value"][2:])
            registry_contract = w3.eth.contract(registry, abi=REGISTRY_ABI)
            connector_call = safe_call(registry_contract.functions.get(connector_name))
            if not connector_call.get("ok"):
                raise RuntimeError(f"connector unresolved: {connector_call}")
            connector = Web3.to_checksum_address(connector_call["value"])
            connector_contract = w3.eth.contract(connector, abi=CONNECTOR_ABI)
            immutables = {name: safe_call(getattr(connector_contract.functions, name)()) for name in ("compoundMarketRegistry", "cometRewards", "comp", "swapTarget")}
            if not immutables["compoundMarketRegistry"].get("ok") or not immutables["cometRewards"].get("ok"):
                raise RuntimeError("connector immutables unresolved")
            market_registry = Web3.to_checksum_address(immutables["compoundMarketRegistry"]["value"])
            rewards_address = Web3.to_checksum_address(immutables["cometRewards"]["value"])
            market_contract = w3.eth.contract(market_registry, abi=MARKET_REGISTRY_ABI)
            comet_call = safe_call(market_contract.functions.getMarket(asset))
            if not comet_call.get("ok") or int(comet_call["value"], 16) == 0:
                raise RuntimeError(f"Comet unresolved: {comet_call}")
            comet = Web3.to_checksum_address(comet_call["value"])
            comet_contract = w3.eth.contract(comet, abi=COMET_ABI)
            rewards_contract = w3.eth.contract(rewards_address, abi=REWARDS_ABI)
            reward_config = safe_call(rewards_contract.functions.rewardConfig(comet))
            reward_owed = safe_call(rewards_contract.functions.getRewardOwed(comet, vault), {"from": CALLER})
            if reward_owed.get("ok"):
                reward_address = Web3.to_checksum_address(reward_owed["value"][0])
                owed_raw = int(reward_owed["value"][1])
            elif reward_config.get("ok"):
                reward_address = Web3.to_checksum_address(reward_config["value"][0])
                owed_raw = 0
            else:
                raise RuntimeError("reward token unresolved")
            reward_token = w3.eth.contract(reward_address, abi=ERC20_ABI)
            reward_balance = safe_call(reward_token.functions.balanceOf(vault))
            reward_balance_raw = int(reward_balance["value"]) if reward_balance.get("ok") else 0
            claim_sim = safe_call(rewards_contract.functions.claim(comet, vault, True), {"from": CALLER})
            row: dict[str, Any] = {
                "chain_id": chain_id,
                "network": CFG[chain_id]["name"],
                "rpc": rpc_url,
                "block": w3.eth.block_number,
                "label": label,
                "vault": vault,
                "vault_code_sha256": hashlib.sha256(bytes(w3.eth.get_code(vault))).hexdigest(),
                "connector": connector,
                "connector_code_sha256": hashlib.sha256(bytes(w3.eth.get_code(connector))).hexdigest(),
                "asset": asset,
                "asset_info": token_info(w3, asset),
                "strategy": int(calls["additionalRewardsStrategy"]["value"]),
                "strategy_name": {0: "None", 1: "Claim", 2: "Reinvest"}.get(int(calls["additionalRewardsStrategy"]["value"]), "Unknown"),
                "depositFee": int(calls["depositFee"]["value"]),
                "rewardFee": int(calls["rewardFee"]["value"]),
                "totalAssets": int(calls["totalAssets"]["value"]),
                "totalSupply": int(calls["totalSupply"]["value"]),
                "maxDeposit": int(calls["maxDeposit"]["value"]),
                "comet": comet,
                "cometRewards": rewards_address,
                "reward_info": token_info(w3, reward_address),
                "reward_owed_raw": owed_raw,
                "reward_balance_raw": reward_balance_raw,
                "reward_total_raw": owed_raw + reward_balance_raw,
                "permissionless_claim_eth_call": claim_sim,
                "reward_config": reward_config,
                "rewards_claimed": safe_call(rewards_contract.functions.rewardsClaimed(comet, vault)),
                "comet_balance": safe_call(comet_contract.functions.balanceOf(vault)),
                "base_tracking_accrued": safe_call(comet_contract.functions.baseTrackingAccrued(vault)),
                "supply_paused": safe_call(comet_contract.functions.isSupplyPaused()),
                "withdraw_paused": safe_call(comet_contract.functions.isWithdrawPaused()),
                "_vault_contract": vc,
            }
            rows.append(row)
        except Exception as exc:  # noqa: BLE001
            errors.append({"chain_id": chain_id, "label": label, "vault": vault_raw, "error": f"{type(exc).__name__}: {exc}"})

    price_tokens: list[tuple[str, str]] = []
    for row in rows:
        price_tokens.append((row["network"], row["asset_info"]["address"]))
        price_tokens.append((row["network"], row["reward_info"]["address"]))
    prices = fetch_prices(sorted(set(price_tokens)))

    for row in rows:
        row["attack_model"] = optimise_attack(row, prices)
        row.pop("_vault_contract", None)

    # Historical reward claims, grouped by chain and rewards contract.
    history_errors: list[dict[str, Any]] = []
    by_group: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_group[(row["chain_id"], row["cometRewards"])].append(row)
    for (chain_id, rewards_address), group in by_group.items():
        w3, _ = connections[chain_id]
        try:
            latest = w3.eth.block_number
            target = int(time.time()) - LOOKBACK_DAYS * 86400
            start = block_at_or_after_timestamp(w3, target)
            alternatives = [topic_address(row["vault"]) for row in group]
            logs = get_logs_adaptive(w3, rewards_address, start, latest, [REWARD_CLAIMED_TOPIC, alternatives])
            sums: dict[str, int] = defaultdict(int)
            counts: dict[str, int] = defaultdict(int)
            txs: dict[str, list[str]] = defaultdict(list)
            for log in logs:
                topics = [t.hex() if hasattr(t, "hex") else str(t) for t in log["topics"]]
                if len(topics) < 2:
                    continue
                src = Web3.to_checksum_address("0x" + topics[1][-40:])
                amount = int.from_bytes(bytes(log["data"]), "big") if not isinstance(log["data"], str) else int(log["data"], 16)
                sums[src.lower()] += amount
                counts[src.lower()] += 1
                tx_hash = log["transactionHash"].hex() if hasattr(log["transactionHash"], "hex") else str(log["transactionHash"])
                txs[src.lower()].append(tx_hash)
            for row in group:
                key = row["vault"].lower()
                reward_dec = row["reward_info"]["decimals"]
                reward_price = prices.get(f"{row['network']}:{row['reward_info']['address'].lower()}".lower())
                raw = sums.get(key, 0)
                row["history"] = {
                    "lookback_days": LOOKBACK_DAYS,
                    "claim_count": counts.get(key, 0),
                    "claimed_raw": raw,
                    "claimed_usd": (raw / 10**reward_dec * reward_price) if reward_dec is not None and reward_price is not None else None,
                    "transaction_hashes": txs.get(key, [])[-20:],
                }
        except Exception as exc:  # noqa: BLE001
            history_errors.append({"chain_id": chain_id, "rewards": rewards_address, "error": f"{type(exc).__name__}: {exc}"})
            for row in group:
                row["history"] = {"lookback_days": LOOKBACK_DAYS, "error": f"{type(exc).__name__}: {exc}"}

    live_candidates = []
    historical_candidates = []
    for row in rows:
        model = row.get("attack_model") or {}
        best = model.get("best") or {}
        permissionless = bool(row.get("permissionless_claim_eth_call", {}).get("ok"))
        reinvest = row.get("strategy") == 2
        live_profit = float(best.get("estimated_net_profit_usd", -1e18))
        reward_usd = float(model.get("reward_total_usd", 0) or 0)
        history_usd = float((row.get("history") or {}).get("claimed_usd", 0) or 0)
        if permissionless and reinvest and reward_usd > 0 and live_profit > 25:
            live_candidates.append(row["vault"])
        if permissionless and reinvest and history_usd > 250:
            historical_candidates.append(row["vault"])

    exact_duplicate = bool(dup_gate.get("exact_duplicate_signal"))
    source_support = bool(source_gate.get("full_balance_reinvest"))
    candidate_count = len(set(live_candidates + historical_candidates)) if source_support and not exact_duplicate else 0
    if exact_duplicate:
        decision = "KILL_OFFICIAL_AUDIT_DUPLICATE_SIGNAL"
    elif not source_support:
        decision = "INCONCLUSIVE_CONNECTOR_SOURCE_SEMANTICS_NOT_PROVEN"
    elif candidate_count:
        decision = "PROMOTE_FIXED_BLOCK_LOCAL_FORK_POC"
    else:
        decision = "KILL_NO_MATERIAL_REWARD_DILUTION_AT_CURRENT_OR_RECENT_STATE"

    evidence = {
        "schema": "kiln-r25-compound-reward-dilution-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "safety": {
            "read_only": True,
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "methods": ["eth_call", "eth_getCode", "eth_getBlockByNumber", "eth_getLogs"],
        },
        "hypothesis": "Permissionless CometRewards.claim moves accrued rewards into the Vault while Vault.totalAssets excludes the reward token; a depositor before Reinvest may acquire part of pre-existing holders' yield.",
        "source_gate": source_gate,
        "duplicate_gate": dup_gate,
        "prices": prices,
        "rows": rows,
        "errors": errors,
        "history_errors": history_errors,
        "summary": {
            "scope": len(VAULTS),
            "inspected": len(rows),
            "errors": len(errors),
            "source_support": source_support,
            "exact_duplicate_signal": exact_duplicate,
            "live_candidate_count": len(live_candidates),
            "historical_candidate_count": len(historical_candidates),
            "candidate_count": candidate_count,
            "live_candidates": live_candidates,
            "historical_candidates": historical_candidates,
        },
    }
    gate = {
        "schema": "kiln-r25-master-gate-v1",
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "candidate_count": candidate_count,
        "source_support": source_support,
        "exact_duplicate_signal": exact_duplicate,
        "blocking_gates": [
            "fixed-block local-fork attack/control differential",
            "real historical reinvest payload replay",
            "5/5 reproducibility",
            "material victim loss and attacker net-profit assertion",
            "patched negative control",
        ] if candidate_count else [],
    }
    public_gate = {
        "schema": "kiln-r25-public-gate-v1",
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "candidate_count": candidate_count,
        "live_candidate_count": len(live_candidates),
        "historical_candidate_count": len(historical_candidates),
        "inspected": len(rows),
        "errors": len(errors),
        "source_support": source_support,
        "exact_duplicate_signal": exact_duplicate,
        "redacted": True,
        "public_chain_state_changes": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }

    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, sort_keys=True))
    (OUT / "MASTER_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(public_gate, indent=2, sort_keys=True))
    (OUT / "SHA256SUMS.txt").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(OUT.glob("*.json"))
        )
    )
    print(json.dumps(public_gate, indent=2, sort_keys=True))
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
