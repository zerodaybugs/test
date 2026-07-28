#!/usr/bin/env python3
"""Enrich public MakerHelper transaction data and bind the live proxy to verified source.

Safety boundary: public JSON-RPC reads and keyless indexed HTTPS GET requests
only. No private key, signer, transaction construction, or broadcast code exists.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
MAKER_HELPER = Web3.to_checksum_address("0x513690136500dEc06553385f7a00b010455dce92")
EIP1967_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
PINNED_COMMIT = "e314f3f849577dfecd4614f148c4df81fdf8c72d"
RAW_PINNED = (
    "https://raw.githubusercontent.com/term-structure/termmax-contract-v2/"
    + PINNED_COMMIT
    + "/contracts/v2/router/MakerHelper.sol"
)
RAW_MAIN = (
    "https://raw.githubusercontent.com/term-structure/termmax-contract-v2/"
    "main/contracts/v2/router/MakerHelper.sol"
)
RPC_URLS = [
    os.environ.get("ETH_RPC_URL", "").strip(),
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
]
RPC_URLS = [url for url in RPC_URLS if url]

MARKET_ABI = [
    {
        "type": "function",
        "name": "tokens",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [
            {"type": "address", "name": "ft"},
            {"type": "address", "name": "xt"},
            {"type": "address", "name": "gt"},
            {"type": "address", "name": "collateral"},
            {"type": "address", "name": "debtToken"},
        ],
    },
    {
        "type": "function",
        "name": "config",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [
            {
                "type": "tuple",
                "components": [
                    {"type": "address", "name": "treasurer"},
                    {"type": "uint64", "name": "maturity"},
                    {
                        "type": "tuple",
                        "name": "feeConfig",
                        "components": [
                            {"type": "uint32", "name": "lendTakerFeeRatio"},
                            {"type": "uint32", "name": "lendMakerFeeRatio"},
                            {"type": "uint32", "name": "borrowTakerFeeRatio"},
                            {"type": "uint32", "name": "borrowMakerFeeRatio"},
                            {"type": "uint32", "name": "mintGtFeeRatio"},
                            {"type": "uint32", "name": "mintGtFeeRef"},
                        ],
                    },
                ],
            }
        ],
    },
]
GT_ABI = [
    {
        "type": "function",
        "name": "loanInfo",
        "stateMutability": "view",
        "inputs": [{"type": "uint256", "name": "id"}],
        "outputs": [
            {"type": "address", "name": "owner"},
            {"type": "uint128", "name": "debtAmt"},
            {"type": "bytes", "name": "collateralData"},
        ],
    },
    {
        "type": "function",
        "name": "getCollateralValue",
        "stateMutability": "view",
        "inputs": [{"type": "bytes", "name": "collateralData"}],
        "outputs": [{"type": "uint256", "name": "collateralValue"}],
    },
    {
        "type": "function",
        "name": "nonces",
        "stateMutability": "view",
        "inputs": [{"type": "address", "name": "owner"}],
        "outputs": [{"type": "uint256"}],
    },
]
ERC20_ABI = [
    {
        "type": "function",
        "name": "symbol",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"type": "string"}],
    },
    {
        "type": "function",
        "name": "decimals",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"type": "uint8"}],
    },
]


def json_default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if hasattr(value, "items"):
        return dict(value)
    return str(value)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def routescan(params: dict[str, Any]) -> Any:
    last: Exception | None = None
    for attempt in range(7):
        try:
            response = requests.get(
                ROUTESCAN,
                params=params,
                timeout=60,
                headers={"User-Agent": "termmax-public-binding/1"},
            )
            if response.status_code == 429:
                time.sleep(2.0 * (attempt + 1))
                continue
            response.raise_for_status()
            return response.json()
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"Routescan request failed: params={params}: {last}")


def connect_rpc() -> tuple[Web3 | None, str | None, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPC_URLS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            chain_id = w3.eth.chain_id
            block = w3.eth.block_number
            if chain_id != 1:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "chainId": chain_id, "block": block})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    return None, None, attempts


def safe_call(function, block_identifier: int | str = "latest") -> dict[str, Any]:
    try:
        value = function.call(block_identifier=block_identifier)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def token_meta(w3: Web3, address: str, block: int | str) -> dict[str, Any]:
    token = w3.eth.contract(address=Web3.to_checksum_address(address), abi=ERC20_ABI)
    return {
        "address": Web3.to_checksum_address(address),
        "symbol": safe_call(token.functions.symbol(), block),
        "decimals": safe_call(token.functions.decimals(), block),
    }


def implementation_from_slot() -> tuple[str, dict[str, Any]]:
    payload = routescan(
        {
            "module": "proxy",
            "action": "eth_getStorageAt",
            "address": MAKER_HELPER,
            "position": EIP1967_IMPLEMENTATION_SLOT,
            "tag": "latest",
        }
    )
    raw = str(payload.get("result", "0x0"))
    if not raw.startswith("0x") or len(raw) < 42:
        raise RuntimeError(f"invalid EIP-1967 storage response: {payload}")
    implementation = Web3.to_checksum_address("0x" + raw[-40:])
    return implementation, payload


def get_verified_source(address: str) -> dict[str, Any]:
    payload = routescan(
        {"module": "contract", "action": "getsourcecode", "address": address}
    )
    rows = payload.get("result", []) if isinstance(payload, dict) else []
    if not isinstance(rows, list) or not rows:
        raise RuntimeError(f"verified source not returned: {payload}")
    return {"payload": payload, "row": rows[0]}


def extract_makerhelper_source(source_code: str) -> tuple[str | None, dict[str, Any] | None]:
    text = source_code.strip()
    parsed: dict[str, Any] | None = None
    candidates = [text]
    if text.startswith("{{") and text.endswith("}}"):
        candidates.insert(0, text[1:-1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
            if isinstance(value, dict):
                parsed = value
                break
        except json.JSONDecodeError:
            continue
    if parsed is None:
        return (text if "contract MakerHelper" in text else None), None
    sources = parsed.get("sources", {})
    for path, entry in sources.items():
        if str(path).endswith("contracts/v2/router/MakerHelper.sol"):
            if isinstance(entry, dict):
                return str(entry.get("content", "")), parsed
    return None, parsed


def fetch_text(url: str) -> str:
    response = requests.get(url, timeout=60, headers={"User-Agent": "termmax-public-binding/1"})
    response.raise_for_status()
    return response.text


def diff_text(left_name: str, left: str, right_name: str, right: str) -> str:
    return "".join(
        difflib.unified_diff(
            left.splitlines(keepends=True),
            right.splitlines(keepends=True),
            fromfile=left_name,
            tofile=right_name,
        )
    )


def source_binding(w3: Web3 | None) -> dict[str, Any]:
    implementation, slot_payload = implementation_from_slot()
    verified = get_verified_source(implementation)
    row = verified["row"]
    deployed_source, standard_json = extract_makerhelper_source(str(row.get("SourceCode", "")))
    pinned_source = fetch_text(RAW_PINNED)
    main_source = fetch_text(RAW_MAIN)

    (OUT / "ROUTESCAN_IMPLEMENTATION_SLOT_RAW.json").write_text(
        json.dumps(slot_payload, indent=2), encoding="utf-8"
    )
    (OUT / "ROUTESCAN_VERIFIED_SOURCE_RAW.json").write_text(
        json.dumps(verified["payload"], indent=2), encoding="utf-8"
    )
    (OUT / "PINNED_MAKERHELPER_SOURCE.sol").write_text(pinned_source, encoding="utf-8")
    (OUT / "MAIN_MAKERHELPER_SOURCE.sol").write_text(main_source, encoding="utf-8")
    if deployed_source is not None:
        (OUT / "DEPLOYED_MAKERHELPER_SOURCE.sol").write_text(deployed_source, encoding="utf-8")
        (OUT / "DEPLOYED_VS_PINNED.diff").write_text(
            diff_text("deployed", deployed_source, "pinned-e314", pinned_source), encoding="utf-8"
        )
        (OUT / "DEPLOYED_VS_MAIN.diff").write_text(
            diff_text("deployed", deployed_source, "github-main", main_source), encoding="utf-8"
        )
    if standard_json is not None:
        (OUT / "DEPLOYED_STANDARD_JSON.json").write_text(
            json.dumps(standard_json, indent=2), encoding="utf-8"
        )

    proxy_code_hash = None
    implementation_code_hash = None
    latest_block = None
    if w3 is not None:
        latest_block = w3.eth.block_number
        proxy_code_hash = Web3.keccak(w3.eth.get_code(MAKER_HELPER)).hex()
        implementation_code_hash = Web3.keccak(w3.eth.get_code(implementation)).hex()

    deployed_sha = sha256_text(deployed_source) if deployed_source is not None else None
    binding = {
        "proxy": MAKER_HELPER,
        "implementation": implementation,
        "eip1967Slot": EIP1967_IMPLEMENTATION_SLOT,
        "latestRpcBlock": latest_block,
        "proxyRuntimeKeccak256": proxy_code_hash,
        "implementationRuntimeKeccak256": implementation_code_hash,
        "contractName": row.get("ContractName"),
        "compilerVersion": row.get("CompilerVersion"),
        "optimizationUsed": row.get("OptimizationUsed"),
        "runs": row.get("Runs"),
        "evmVersion": row.get("EVMVersion"),
        "deployedSourceSha256": deployed_sha,
        "pinnedSourceSha256": sha256_text(pinned_source),
        "mainSourceSha256": sha256_text(main_source),
        "deployedEqualsPinned": deployed_source == pinned_source if deployed_source is not None else None,
        "deployedEqualsMain": deployed_source == main_source if deployed_source is not None else None,
    }
    (OUT / "DEPLOYED_BINDING.json").write_text(json.dumps(binding, indent=2), encoding="utf-8")
    return binding


def enrich_existing_gt_flows(w3: Web3 | None) -> dict[str, Any]:
    decoded_path = OUT / "MAKERHELPER_TXS_DECODED.json"
    if not decoded_path.exists():
        raise RuntimeError(f"missing decoder output: {decoded_path}")
    decoded = json.loads(decoded_path.read_text(encoding="utf-8"))
    flows = list(decoded.get("existingGtDelegatedV2", []))
    enriched: list[dict[str, Any]] = []

    for flow in flows:
        item = dict(flow)
        if w3 is None:
            item["historicalState"] = {"ok": False, "error": "no public RPC connected"}
            enriched.append(item)
            continue
        block = int(item["blockNumber"])
        pre_block = max(0, block - 1)
        market_address = Web3.to_checksum_address(item["market"])
        market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
        tokens_result = safe_call(market.functions.tokens(), pre_block)
        config_result = safe_call(market.functions.config(), pre_block)
        state: dict[str, Any] = {
            "blockBeforeTransaction": pre_block,
            "marketTokens": tokens_result,
            "marketConfig": config_result,
        }
        tokens = tokens_result.get("value") if tokens_result.get("ok") else None
        if tokens and len(tokens) == 5:
            ft, xt, gt_address, collateral, debt_token = [Web3.to_checksum_address(x) for x in tokens]
            gt = w3.eth.contract(address=gt_address, abi=GT_ABI)
            loan_result = safe_call(gt.functions.loanInfo(int(item["gtId"])), pre_block)
            state.update(
                {
                    "ft": token_meta(w3, ft, pre_block),
                    "xt": token_meta(w3, xt, pre_block),
                    "gt": gt_address,
                    "collateral": token_meta(w3, collateral, pre_block),
                    "debtToken": token_meta(w3, debt_token, pre_block),
                    "loanInfoBeforeTransaction": loan_result,
                    "delegatorNonceBeforeTransaction": safe_call(
                        gt.functions.nonces(Web3.to_checksum_address(item["delegator"])), pre_block
                    ),
                    "delegatorNonceAfterTransaction": safe_call(
                        gt.functions.nonces(Web3.to_checksum_address(item["delegator"])), block
                    ),
                }
            )
            loan = loan_result.get("value") if loan_result.get("ok") else None
            if loan and len(loan) == 3:
                owner, debt_amt, collateral_data = loan
                collateral_value_result = safe_call(
                    gt.functions.getCollateralValue(collateral_data), pre_block
                )
                state["loanDecoded"] = {
                    "owner": owner,
                    "debtAmtRaw": int(debt_amt),
                    "collateralData": json_default(collateral_data),
                    "collateralValueBase1e8": collateral_value_result,
                    "delegatorMatchesOwner": str(owner).lower() == str(item["delegator"]).lower(),
                }
                debt_decimals = state["debtToken"]["decimals"].get("value") if state["debtToken"]["decimals"].get("ok") else None
                if debt_decimals is not None:
                    state["loanDecoded"]["debtHuman"] = int(debt_amt) / (10 ** int(debt_decimals))
                if collateral_value_result.get("ok"):
                    state["loanDecoded"]["collateralValueUsd"] = (
                        int(collateral_value_result["value"]) / 1e8
                    )
        item["historicalState"] = state
        enriched.append(item)

    summary = {
        "schema": "termmax-makerhelper-existing-gt-enrichment/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "existingGtDelegatedV2Count": len(enriched),
        "flows": enriched,
    }
    (OUT / "EXISTING_GT_FLOWS_ENRICHED.json").write_text(
        json.dumps(summary, indent=2, default=json_default), encoding="utf-8"
    )
    return summary


def main() -> int:
    w3, rpc_url, rpc_attempts = connect_rpc()
    (OUT / "RPC_ATTEMPTS.json").write_text(json.dumps(rpc_attempts, indent=2), encoding="utf-8")
    binding = source_binding(w3)
    enrichment = enrich_existing_gt_flows(w3)
    summary = {
        "schema": "termmax-makerhelper-production-binding/v1",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "rpc": rpc_url,
        "binding": binding,
        "existingGtDelegatedV2Count": enrichment["existingGtDelegatedV2Count"],
    }
    (OUT / "BINDING_AND_USAGE_SUMMARY.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
