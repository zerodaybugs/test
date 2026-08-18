#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

import requests
from web3 import Web3
try:
    from web3.middleware import ExtraDataToPOAMiddleware
except ImportError:
    ExtraDataToPOAMiddleware = None

OUT = Path("r38_results")
OUT.mkdir(exist_ok=True)
SCOPE = Path("r30_scope/SCOPE.json")
ZERO = "0x0000000000000000000000000000000000000000"
NETWORKS = {
    "ethereum": (1, ["https://ethereum-rpc.publicnode.com", "https://rpc.flashbots.net", "https://eth.llamarpc.com"]),
    "optimism": (10, ["https://optimism-rpc.publicnode.com", "https://optimism.llamarpc.com", "https://mainnet.optimism.io"]),
    "bnb": (56, ["https://bsc-rpc.publicnode.com", "https://binance.llamarpc.com", "https://bsc-dataseed.binance.org"]),
    "polygon": (137, ["https://polygon-bor-rpc.publicnode.com", "https://polygon.llamarpc.com", "https://polygon-rpc.com"]),
    "base": (8453, ["https://base-rpc.publicnode.com", "https://base.llamarpc.com", "https://mainnet.base.org"]),
    "arbitrum": (42161, ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.llamarpc.com"]),
}
VABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorRegistry","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"connectorName","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]},
]
RABI = [{"type":"function","name":"get","stateMutability":"view","inputs":[{"type":"bytes32"}],"outputs":[{"type":"address"}]}]
COMMON_GETTERS = [
    "aave()", "poolAddressesProvider()", "rewardsController()", "swapTarget()",
    "compoundMarketRegistry()", "cometRewards()", "comp()", "metamorpho()",
    "sDAI()", "sUSDS()", "stakingVault()", "fluidFactory()", "venusMarketRegistry()",
    "marketRegistry()", "vToken()", "vtoken()", "venus()", "pool()", "fToken()",
]


def normalize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return [normalize(x) for x in value]
    return value


def safe(fn: Any, block: int) -> dict[str, Any]:
    try:
        return {"ok": True, "value": normalize(fn.call(block_identifier=block))}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def value(result: dict[str, Any]) -> Any:
    return result.get("value") if result.get("ok") else None


def checksum(address: Any) -> str | None:
    try:
        return Web3.to_checksum_address(address)
    except Exception:
        return None


def codehash(w3: Web3, address: str, block: int) -> str | None:
    try:
        code = bytes(w3.eth.get_code(Web3.to_checksum_address(address), block_identifier=block))
        return hashlib.sha256(code).hexdigest() if code else None
    except Exception:
        return None


def connect(network: str, probe: str) -> tuple[Web3, str, int, str]:
    chain_id, urls = NETWORKS[network]
    errors = []
    for url in urls:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
            if network in {"bnb", "polygon"} and ExtraDataToPOAMiddleware:
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            if not w3.is_connected() or int(w3.eth.chain_id) != chain_id:
                raise RuntimeError("chain mismatch")
            latest = int(w3.eth.block_number)
            raw = bytes(w3.eth.call({
                "to": Web3.to_checksum_address(probe),
                "data": Web3.keccak(text="asset()")[:4],
            }, block_identifier=latest))
            if len(raw) < 32:
                raise RuntimeError("probe getter returned short data")
            block = max(1, latest - 5)
            block_hash = w3.eth.get_block(block)["hash"].hex()
            return w3, url, block, block_hash
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError("no usable RPC | " + " | ".join(errors))


def raw_address_getter(w3: Web3, target: str, signature: str, block: int) -> dict[str, Any]:
    try:
        data = Web3.keccak(text=signature)[:4]
        raw = bytes(w3.eth.call({"to": Web3.to_checksum_address(target), "data": data}, block_identifier=block))
        if len(raw) < 32:
            raise RuntimeError("short return")
        address = Web3.to_checksum_address("0x" + raw[-20:].hex())
        return {"ok": True, "value": address, "code_sha256": codehash(w3, address, block) if address != ZERO else None}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def decode_name(raw: Any) -> str | None:
    try:
        if isinstance(raw, str) and raw.startswith("0x"):
            return bytes.fromhex(raw[2:]).rstrip(b"\x00").decode(errors="replace")
    except Exception:
        pass
    return None


def fetch_source(chain_id: int, address: str) -> dict[str, Any]:
    endpoint = f"https://api.routescan.io/v2/network/mainnet/evm/{chain_id}/etherscan/api"
    try:
        response = requests.get(
            endpoint,
            params={"module":"contract", "action":"getsourcecode", "address":address},
            headers={"User-Agent":"Kiln-R38-SourceInventory/1.0"},
            timeout=40,
        )
        response.raise_for_status()
        payload = response.json()
        result = payload.get("result")
        if not isinstance(result, list) or not result:
            return {"ok": False, "error": f"unexpected response: {payload!r}"}
        row = result[0]
        source = row.get("SourceCode") or ""
        if source.startswith("{{") and source.endswith("}}"):
            source = source[1:-1]
        flattened = source
        if source.lstrip().startswith("{"):
            try:
                parsed = json.loads(source)
                sources = parsed.get("sources", {}) if isinstance(parsed, dict) else {}
                flattened = "\n\n".join(
                    f"// FILE: {name}\n{(entry or {}).get('content','')}"
                    for name, entry in sorted(sources.items())
                )
            except Exception:
                pass
        return {
            "ok": bool(flattened.strip()),
            "contract_name": row.get("ContractName"),
            "compiler_version": row.get("CompilerVersion"),
            "optimization_used": row.get("OptimizationUsed"),
            "runs": row.get("Runs"),
            "proxy": row.get("Proxy"),
            "implementation": row.get("Implementation"),
            "source_bytes": len(flattened.encode()),
            "source_sha256": hashlib.sha256(flattened.encode()).hexdigest() if flattened else None,
            "source": flattened,
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def extract_function(source: str, name: str) -> str | None:
    match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", source)
    if not match:
        return None
    start = match.start()
    brace = source.find("{", match.end())
    semi = source.find(";", match.end())
    if brace < 0 or (semi >= 0 and semi < brace):
        return source[start:(semi + 1 if semi >= 0 else min(len(source), start + 1000))]
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    return source[start:start + 5000]


def semantic_scan(source: str) -> dict[str, Any]:
    functions = {name: extract_function(source, name) for name in ("totalAssets", "deposit", "withdraw", "claim", "reinvest")}
    signals = []
    withdraw = functions.get("withdraw") or ""
    deposit = functions.get("deposit") or ""
    total_assets = functions.get("totalAssets") or ""
    claim = functions.get("claim") or ""
    reinvest = functions.get("reinvest") or ""

    def body_uses_amount(text: str) -> bool:
        if not text:
            return False
        body = text[text.find("{") + 1:] if "{" in text else text
        return bool(re.search(r"\bamount\b", body))

    if withdraw and not body_uses_amount(withdraw):
        signals.append("withdraw_amount_parameter_not_used")
    if deposit and not body_uses_amount(deposit):
        signals.append("deposit_amount_parameter_not_used")
    if withdraw and re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)|type\s*\(\s*uint256\s*\)\.max", withdraw):
        signals.append("withdraw_may_sweep_full_position")
    if total_assets and "address(this)" in total_assets and "msg.sender" not in total_assets:
        signals.append("view_totalAssets_uses_connector_address_not_vault_sender")
    for name, text in (("deposit", deposit), ("withdraw", withdraw), ("claim", claim), ("reinvest", reinvest)):
        if text and "msg.sender" in text and "address(this)" not in text:
            signals.append(f"{name}_may_use_original_caller_in_delegatecall_context")
    if withdraw and re.search(r"\.(redeemUnderlying|redeem|mint)\s*\(", withdraw) and not re.search(r"require\s*\(|if\s*\([^)]*!=\s*0", withdraw):
        if "redeemUnderlying" in withdraw:
            signals.append("compound_style_withdraw_return_code_may_be_unchecked")
    return {
        "signals": sorted(set(signals)),
        "function_sha256": {name: hashlib.sha256(text.encode()).hexdigest() if text else None for name, text in functions.items()},
        "function_excerpts": {name: text[:5000] if text else None for name, text in functions.items()},
    }


def main() -> int:
    scope = json.loads(SCOPE.read_text()).get("rows", [])
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in scope:
        grouped.setdefault(row["network"], []).append(row)
    chain_rows = []
    vault_rows = []
    errors = []
    unique: dict[tuple[int, str], dict[str, Any]] = {}

    for network, rows in sorted(grouped.items(), key=lambda item: NETWORKS[item[0]][0]):
        try:
            w3, rpc, block, block_hash = connect(network, rows[0]["address"])
            chain_rows.append({"network":network, "chain_id":NETWORKS[network][0], "rpc":rpc, "block":block, "block_hash":block_hash})
        except Exception as exc:
            errors.append({"network":network, "scope_error":f"{type(exc).__name__}: {exc}"})
            continue
        for row in rows:
            vault = Web3.to_checksum_address(row["address"])
            try:
                contract = w3.eth.contract(vault, abi=VABI)
                asset_result = safe(contract.functions.asset(), block)
                registry_result = safe(contract.functions.connectorRegistry(), block)
                name_result = safe(contract.functions.connectorName(), block)
                registry = checksum(value(registry_result))
                raw_name = value(name_result)
                if not registry or not isinstance(raw_name, str):
                    raise RuntimeError("vault binding unresolved")
                registry_contract = w3.eth.contract(registry, abi=RABI)
                connector_result = safe(registry_contract.functions.get(bytes.fromhex(raw_name[2:])), block)
                connector = checksum(value(connector_result))
                if not connector or connector == ZERO:
                    raise RuntimeError("connector unresolved")
                item = {
                    "network":network, "chain_id":NETWORKS[network][0], "label":row["label"], "vault":vault,
                    "scope_connector":row["connector"], "asset":checksum(value(asset_result)),
                    "connector_registry":registry, "connector_name_raw":raw_name, "connector_name":decode_name(raw_name),
                    "connector":connector, "connector_code_sha256":codehash(w3, connector, block),
                    "block":block, "block_hash":block_hash,
                }
                vault_rows.append(item)
                key = (NETWORKS[network][0], connector.lower())
                if key not in unique:
                    unique[key] = {
                        "network":network, "chain_id":NETWORKS[network][0], "connector_name":item["connector_name"],
                        "connector":connector, "connector_code_sha256":item["connector_code_sha256"],
                        "scope_labels":[], "scope_vaults":[],
                        "common_getters":{signature: raw_address_getter(w3, connector, signature, block) for signature in COMMON_GETTERS},
                    }
                unique[key]["scope_labels"].append(row["label"])
                unique[key]["scope_vaults"].append(vault)
            except Exception as exc:
                errors.append({"network":network, "vault":row["address"], "label":row["label"], "error":f"{type(exc).__name__}: {exc}"})

    connectors = []
    for key, item in sorted(unique.items()):
        source = fetch_source(item["chain_id"], item["connector"])
        semantic = semantic_scan(source.get("source", "")) if source.get("ok") else {"signals":[], "function_sha256":{}, "function_excerpts":{}}
        source.pop("source", None)
        item["source"] = source
        item["semantic"] = semantic
        item["scope_labels"] = sorted(set(item["scope_labels"]))
        item["scope_vaults"] = sorted(set(item["scope_vaults"]))
        connectors.append(item)

    candidates = [item for item in connectors if item.get("semantic", {}).get("signals")]
    signal_counts: dict[str, int] = {}
    for item in candidates:
        for signal in item["semantic"]["signals"]:
            signal_counts[signal] = signal_counts.get(signal, 0) + 1

    result = {
        "schema":"kiln-r38-connector-source-inventory-v1",
        "generated_at_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_scope_sha256":hashlib.sha256(SCOPE.read_bytes()).hexdigest(),
        "safety":{"read_only":True,"public_chain_state_changes":0,"transactions_signed":0,"transactions_sent":0},
        "chains":chain_rows, "vault_rows":vault_rows, "connectors":connectors, "errors":errors,
        "summary":{"scope_count":len(scope),"inspected_vault_count":len(vault_rows),"error_count":len(errors),
                   "unique_connector_count":len(connectors),"verified_source_count":sum(bool(x.get("source",{}).get("ok")) for x in connectors),
                   "candidate_count":len(candidates),"signal_counts":signal_counts},
    }
    (OUT / "INVENTORY.json").write_text(json.dumps(result, indent=2, sort_keys=True))
    public = {
        "schema":"kiln-r38-public-gate-v1",
        "decision":"HOLD_SOURCE_SEMANTIC_REVIEW" if candidates else ("INCONCLUSIVE_RUNTIME_OR_SOURCE_ERRORS" if errors else "KILL_NO_CONNECTOR_SOURCE_SIGNAL"),
        "submit_ready":False,"validated_critical":0,"validated_high":0,
        "scope_count":len(scope),"inspected_vault_count":len(vault_rows),"error_count":len(errors),
        "unique_connector_count":len(connectors),"verified_source_count":result["summary"]["verified_source_count"],
        "candidate_count":len(candidates),"signal_counts":signal_counts,
        "public_chain_state_changes":0,"transactions_signed":0,"transactions_sent":0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(public, indent=2, sort_keys=True))
    compact = {
        "schema":"kiln-r38-candidate-summary-v1","submit_ready":False,"validated_critical":0,"validated_high":0,
        "candidates":[{"network":x["network"],"connector_name":x["connector_name"],"connector":x["connector"],
                       "code_sha256":x["connector_code_sha256"],"source":x["source"],"semantic":x["semantic"],
                       "scope_vaults":x["scope_vaults"]} for x in candidates],
    }
    (OUT / "CANDIDATE_SUMMARY.json").write_text(json.dumps(compact, indent=2, sort_keys=True))
    files = sorted(p for p in OUT.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text("".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files))
    print(json.dumps(public, sort_keys=True))
    return 0 if vault_rows else 2


if __name__ == "__main__":
    raise SystemExit(main())
