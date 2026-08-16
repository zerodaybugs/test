#!/usr/bin/env python3
"""Kiln OmniVault R21 current-scope source/runtime delta scanner.

Safety boundary:
- public data and read-only JSON-RPC only;
- eth_call / eth_getCode / eth_blockNumber only;
- no keys, signing, raw transactions, or public-chain mutations.

The scanner resolves current Kiln-like vaults from the last structured scope,
public mirror documentation, and the current Cantina page. It then checks
vault->registry->connector->target bindings and generic nested ERC-4626
accounting invariants. Detailed output is intended to be encrypted by CI.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import math
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import requests
from eth_abi import decode, encode
from web3 import Web3

OUT = Path("r21_delta_results")
OUT.mkdir(exist_ok=True)

CANTINA = "https://cantina.xyz/bounties/c9a4b51b-2e80-4713-a06f-13524c530fa6"
OLD_SCOPE = (
    "https://raw.githubusercontent.com/zerodaybugs/test/"
    "agent/kiln-omnivault-r11-readonly/"
    "r13_persisted_results/31910466827/r13_generation/SCOPE.json"
)
MIRROR_ACTIVE = (
    "https://raw.githubusercontent.com/dumebi042/kiln-vault/"
    "33359ff399fd9fbf31ca87e3671446eb37a7ee61/"
    "Batches/Batch-01-Architecture-Deployment-Mapping/active-vaults.md"
)
ROUTESCAN = "https://api.routescan.io/v2/network/mainnet/evm/{chain}/etherscan/api"

CFG = {
    1: ("ethereum", [
        "https://eth.llamarpc.com",
        "https://1rpc.io/eth",
        "https://rpc.flashbots.net",
        "https://ethereum-rpc.publicnode.com",
    ]),
    10: ("optimism", [
        "https://optimism.llamarpc.com",
        "https://optimism-rpc.publicnode.com",
        "https://mainnet.optimism.io",
    ]),
    56: ("bnb", [
        "https://binance.llamarpc.com",
        "https://bsc-rpc.publicnode.com",
        "https://bsc-dataseed.binance.org",
    ]),
    137: ("polygon", [
        "https://polygon.llamarpc.com",
        "https://polygon-bor-rpc.publicnode.com",
        "https://polygon-rpc.com",
    ]),
    8453: ("base", [
        "https://base.llamarpc.com",
        "https://base-rpc.publicnode.com",
        "https://mainnet.base.org",
    ]),
    42161: ("arbitrum", [
        "https://arbitrum.llamarpc.com",
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arb1.arbitrum.io/rpc",
    ]),
}

ZERO = "0x" + "00" * 20
CALLER = "0x000000000000000000000000000000000000bEEF"
UA = {"User-Agent": "Kiln-R21-ReadOnly/1.0"}


def selector(signature: str) -> str:
    return "0x" + Web3.keccak(text=signature)[:4].hex()


def calldata(signature: str, types: list[str] | None = None, values: list[Any] | None = None) -> str:
    body = Web3.keccak(text=signature)[:4]
    if types:
        body += encode(types, values or [])
    return "0x" + body.hex()


class Rpc:
    def __init__(self, chain: int):
        self.chain = chain
        self.network, urls = CFG[chain]
        self.session = requests.Session()
        self.session.headers.update(UA)
        self.url = None
        self._id = 0
        errors = []
        for url in urls:
            try:
                got = self._request_url(url, "eth_chainId", [])
                if int(got, 16) == chain:
                    self.url = url
                    break
            except Exception as exc:
                errors.append(f"{url}: {exc}")
        if not self.url:
            raise RuntimeError(f"no RPC for {chain}: {' | '.join(errors)}")

    def _request_url(self, url: str, method: str, params: list[Any]) -> Any:
        self._id += 1
        r = self.session.post(
            url,
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params},
            timeout=25,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("error"):
            raise RuntimeError(data["error"])
        return data["result"]

    def request(self, method: str, params: list[Any]) -> dict[str, Any]:
        forbidden = {
            "eth_sendTransaction", "eth_sendRawTransaction", "eth_sign",
            "personal_sendTransaction", "personal_sign",
        }
        if method in forbidden:
            raise AssertionError(f"forbidden RPC method: {method}")
        try:
            return {"ok": True, "raw": self._request_url(self.url, method, params)}
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def code(self, address: str) -> bytes:
        r = self.request("eth_getCode", [Web3.to_checksum_address(address), "latest"])
        if not r["ok"]:
            return b""
        return bytes.fromhex(r["raw"][2:])

    def block(self) -> int:
        r = self.request("eth_blockNumber", [])
        if not r["ok"]:
            raise RuntimeError(r["error"])
        return int(r["raw"], 16)

    def call_raw(self, to: str, data: str, from_addr: str | None = None) -> dict[str, Any]:
        tx = {"to": Web3.to_checksum_address(to), "data": data}
        if from_addr:
            tx["from"] = Web3.to_checksum_address(from_addr)
        return self.request("eth_call", [tx, "latest"])

    def call(self, to: str, signature: str, out_types: list[str], in_types: list[str] | None = None,
             values: list[Any] | None = None, from_addr: str | None = None) -> dict[str, Any]:
        r = self.call_raw(to, calldata(signature, in_types, values), from_addr)
        if not r["ok"]:
            return r
        try:
            raw = bytes.fromhex(r["raw"][2:])
            vals = decode(out_types, raw)
            norm = []
            for value, typ in zip(vals, out_types):
                if typ == "address":
                    norm.append(Web3.to_checksum_address(value))
                elif typ == "bytes32":
                    norm.append("0x" + bytes(value).hex())
                elif typ.endswith("[]"):
                    norm.append(list(value))
                else:
                    norm.append(value)
            return {"ok": True, "value": norm[0] if len(norm) == 1 else norm, "raw": r["raw"]}
        except Exception as exc:
            return {"ok": False, "error": f"decode {out_types}: {exc}", "raw": r.get("raw")}


def get_text(url: str) -> str:
    last = None
    for attempt in range(5):
        try:
            r = requests.get(url, headers=UA, timeout=45)
            r.raise_for_status()
            return r.text
        except Exception as exc:
            last = exc
            time.sleep(attempt + 1)
    raise RuntimeError(f"fetch failed {url}: {last}")


def get_json(url: str) -> Any:
    return json.loads(get_text(url))


def routescan(chain: int, params: dict[str, Any]) -> dict[str, Any]:
    url = ROUTESCAN.format(chain=chain)
    last = None
    for attempt in range(5):
        try:
            r = requests.get(url, params=params, headers=UA, timeout=45)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            last = exc
            time.sleep(attempt + 1)
    return {"status": "0", "message": "error", "result": str(last)}


def explorer_source(chain: int, address: str) -> dict[str, Any]:
    data = routescan(chain, {"module": "contract", "action": "getsourcecode", "address": address})
    result = data.get("result")
    if not isinstance(result, list) or not result:
        return {"verified": False, "raw": data}
    meta = result[0]
    src = meta.get("SourceCode") or ""
    if src.startswith("{{") and src.endswith("}}"):
        src = src[1:-1]
    joined = src
    if src.lstrip().startswith("{"):
        try:
            obj = json.loads(src)
            joined = "\n\n".join(
                f"// FILE: {name}\n{body.get('content', '')}"
                for name, body in (obj.get("sources") or {}).items()
            )
        except Exception:
            pass
    abi = None
    try:
        abi = json.loads(meta.get("ABI") or "null")
    except Exception:
        pass
    return {
        "verified": bool(joined.strip()),
        "contract_name": meta.get("ContractName"),
        "compiler": meta.get("CompilerVersion"),
        "proxy": meta.get("Proxy"),
        "implementation": meta.get("Implementation"),
        "source_sha256": hashlib.sha256(joined.encode()).hexdigest() if joined else None,
        "source_bytes": len(joined.encode()),
        "source": joined,
        "abi": abi,
    }


def token_meta(rpc: Rpc, address: str) -> dict[str, Any]:
    dec = rpc.call(address, "decimals()", ["uint8"])
    symbol = rpc.call(address, "symbol()", ["string"])
    return {
        "address": Web3.to_checksum_address(address),
        "decimals": dec,
        "symbol": symbol,
    }


def extract_scope() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    old = get_json(OLD_SCOPE)
    structured: dict[tuple[int, str], dict[str, Any]] = {}
    for row in old:
        try:
            chain = int(row["chain_id"])
            vault = Web3.to_checksum_address(row["vault"])
        except Exception:
            continue
        structured[(chain, vault.lower())] = {
            "chain_id": chain,
            "network": CFG.get(chain, (row.get("network"), []))[0],
            "vault": vault,
            "label": row.get("label"),
            "connector_label": row.get("connector"),
            "origin": ["structured-r13-scope"],
        }

    raw_sources = {}
    for name, url in (("cantina", CANTINA), ("mirror_active", MIRROR_ACTIVE)):
        try:
            raw_sources[name] = get_text(url)
        except Exception as exc:
            raw_sources[name] = f"FETCH_ERROR: {exc}"

    addresses: set[str] = set()
    for text in raw_sources.values():
        for match in re.findall(r"0x[a-fA-F0-9]{40}", text):
            try:
                addresses.add(Web3.to_checksum_address(match))
            except Exception:
                pass

    known_addresses = {v.lower() for _, v in structured}
    extras = sorted(a for a in addresses if a.lower() not in known_addresses)

    rpcs: dict[int, Rpc] = {}
    for chain in CFG:
        try:
            rpcs[chain] = Rpc(chain)
        except Exception:
            pass

    def probe(pair: tuple[int, str]) -> dict[str, Any] | None:
        chain, address = pair
        rpc = rpcs.get(chain)
        if not rpc or not rpc.code(address):
            return None
        asset = rpc.call(address, "asset()", ["address"])
        registry = rpc.call(address, "connectorRegistry()", ["address"])
        cname = rpc.call(address, "connectorName()", ["bytes32"])
        if not (asset.get("ok") and registry.get("ok") and cname.get("ok")):
            return None
        if asset["value"].lower() == ZERO or registry["value"].lower() == ZERO:
            return None
        return {
            "chain_id": chain,
            "network": CFG[chain][0],
            "vault": Web3.to_checksum_address(address),
            "label": None,
            "connector_label": None,
            "origin": ["current-page-or-mirror-address-probe"],
        }

    pairs = [(chain, address) for address in extras for chain in rpcs]
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        for row in pool.map(probe, pairs):
            if row:
                key = (row["chain_id"], row["vault"].lower())
                if key in structured:
                    structured[key]["origin"].extend(row["origin"])
                else:
                    structured[key] = row

    meta = {
        "old_structured_count": len(old),
        "page_and_mirror_address_count": len(addresses),
        "extra_address_count": len(extras),
        "resolved_vault_count": len(structured),
        "raw_sha256": {
            name: hashlib.sha256(text.encode()).hexdigest() for name, text in raw_sources.items()
        },
        "available_chains": sorted(rpcs),
    }
    return sorted(structured.values(), key=lambda x: (x["chain_id"], x["vault"])), meta


def source_flags(source: str) -> list[str]:
    flags = []
    checks = {
        "uses_msg_sender": r"\bmsg\.sender\b",
        "uses_address_this": r"\baddress\(this\)\b",
        "full_balance_reference": r"balanceOf\s*\(\s*address\(this\)\s*\)",
        "raw_approve": r"\.approve\s*\(",
        "force_approve": r"forceApprove",
        "redeem_underlying": r"redeemUnderlying\s*\(",
        "return_code_style_mint": r"\.mint\s*\([^;]+\);",
        "low_level_call": r"\.(?:call|delegatecall|staticcall)\s*\(",
        "nested_erc4626_preview": r"previewRedeem|convertToAssets",
        "nested_erc4626_withdraw": r"\.withdraw\s*\(",
        "nested_erc4626_redeem": r"\.redeem\s*\(",
        "reward_claim": r"function\s+(?:claim|reinvest)\s*\(",
    }
    for name, pattern in checks.items():
        if re.search(pattern, source, re.S):
            flags.append(name)
    return flags


def analyze_vault(rpc: Rpc, row: dict[str, Any], connector_cache: dict[tuple[int, str], dict[str, Any]]) -> dict[str, Any]:
    chain = row["chain_id"]
    vault = row["vault"]
    out = dict(row)
    out.update({"rpc": rpc.url, "block": rpc.block(), "vault_code_sha256": hashlib.sha256(rpc.code(vault)).hexdigest()})

    calls = {
        "asset": ("asset()", ["address"], None, None),
        "registry": ("connectorRegistry()", ["address"], None, None),
        "connector_name": ("connectorName()", ["bytes32"], None, None),
        "total_assets": ("totalAssets()", ["uint256"], None, None),
        "total_supply": ("totalSupply()", ["uint256"], None, None),
        "share_decimals": ("decimals()", ["uint8"], None, None),
        "pending_deposit_fee": ("pendingDepositFee()", ["uint256"], None, None),
        "pending_reward_fee": ("pendingRewardFee()", ["uint256"], None, None),
        "deposit_fee": ("depositFee()", ["uint256"], None, None),
        "reward_fee": ("rewardFee()", ["uint256"], None, None),
        "reward_strategy": ("additionalRewardsStrategy()", ["uint8"], None, None),
        "max_deposit": ("maxDeposit(address)", ["uint256"], ["address"], [CALLER]),
    }
    for name, (sig, outs, ins, vals) in calls.items():
        out[name] = rpc.call(vault, sig, outs, ins, vals)

    asset = out["asset"].get("value") if out["asset"].get("ok") else None
    registry = out["registry"].get("value") if out["registry"].get("ok") else None
    cname = out["connector_name"].get("value") if out["connector_name"].get("ok") else None
    out["token"] = token_meta(rpc, asset) if asset else None
    if asset:
        out["direct_asset_balance"] = rpc.call(asset, "balanceOf(address)", ["uint256"], ["address"], [vault])
    if not (asset and registry and cname):
        out["fatal"] = "vault binding unresolved"
        return out

    name_bytes = bytes.fromhex(cname[2:])
    connector = rpc.call(registry, "get(bytes32)", ["address"], ["bytes32"], [name_bytes])
    if not connector.get("ok"):
        connector = rpc.call(registry, "connectorAddress(bytes32)", ["address"], ["bytes32"], [name_bytes])
    out["connector"] = connector
    caddr = connector.get("value") if connector.get("ok") else None
    if not caddr or caddr.lower() == ZERO:
        out["fatal"] = "connector unresolved or absent"
        return out

    cache_key = (chain, caddr.lower())
    if cache_key not in connector_cache:
        src = explorer_source(chain, caddr)
        src["address"] = caddr
        src["code_sha256"] = hashlib.sha256(rpc.code(caddr)).hexdigest()
        src["flags"] = source_flags(src.get("source") or "")
        connector_cache[cache_key] = src
    out["connector_source_ref"] = {
        k: v for k, v in connector_cache[cache_key].items()
        if k not in {"source", "abi"}
    }

    src = connector_cache[cache_key]
    targets = []
    abi = src.get("abi") if isinstance(src.get("abi"), list) else []
    for item in abi:
        if item.get("type") != "function" or item.get("stateMutability") not in {"view", "pure"}:
            continue
        if item.get("inputs") or len(item.get("outputs") or []) != 1:
            continue
        if item["outputs"][0].get("type") != "address":
            continue
        fname = item.get("name")
        if not fname:
            continue
        got = rpc.call(caddr, f"{fname}()", ["address"])
        if not got.get("ok"):
            continue
        address = got["value"]
        if address.lower() == ZERO or not rpc.code(address):
            continue
        targets.append({"getter": fname, "address": address})

    # ABI may be unavailable. Probe high-value conventional immutable getters.
    fallback_getters = [
        "metamorpho", "savings", "sUSDS", "susds", "vault", "underlyingVault",
        "target", "fToken", "eVault", "pool", "aToken", "comet", "market",
        "venus", "vToken", "vtoken", "sdai", "stEUR", "steur", "strategy",
    ]
    known = {(x["getter"], x["address"].lower()) for x in targets}
    for fname in fallback_getters:
        got = rpc.call(caddr, f"{fname}()", ["address"])
        if got.get("ok") and got["value"].lower() != ZERO and rpc.code(got["value"]):
            key = (fname, got["value"].lower())
            if key not in known:
                targets.append({"getter": fname, "address": got["value"]})
                known.add(key)

    out["targets"] = []
    ta = int(out["total_assets"].get("value", 0)) if out["total_assets"].get("ok") else None
    token_dec = None
    if out.get("token") and out["token"]["decimals"].get("ok"):
        token_dec = int(out["token"]["decimals"]["value"])

    for target in targets:
        taddr = target["address"]
        t = dict(target)
        t["code_sha256"] = hashlib.sha256(rpc.code(taddr)).hexdigest()
        t["asset"] = rpc.call(taddr, "asset()", ["address"])
        t["vault_share_balance"] = rpc.call(taddr, "balanceOf(address)", ["uint256"], ["address"], [vault])
        t["connector_share_balance"] = rpc.call(taddr, "balanceOf(address)", ["uint256"], ["address"], [caddr])
        shares = int(t["vault_share_balance"].get("value", 0)) if t["vault_share_balance"].get("ok") else None
        if shares is not None:
            t["preview_redeem"] = rpc.call(taddr, "previewRedeem(uint256)", ["uint256"], ["uint256"], [shares])
            t["convert_to_assets"] = rpc.call(taddr, "convertToAssets(uint256)", ["uint256"], ["uint256"], [shares])
        t["max_withdraw_vault"] = rpc.call(taddr, "maxWithdraw(address)", ["uint256"], ["address"], [vault])
        t["max_deposit_vault"] = rpc.call(taddr, "maxDeposit(address)", ["uint256"], ["address"], [vault])
        out["targets"].append(t)

    candidates = []
    leads = []
    unit = 10 ** token_dec if token_dec is not None and token_dec <= 30 else 1
    material = 100 * unit

    for t in out["targets"]:
        target_asset = t["asset"].get("value") if t["asset"].get("ok") else None
        if target_asset and target_asset.lower() != asset.lower():
            candidates.append({
                "class": "TARGET_ASSET_MISMATCH",
                "severity_ceiling": "Critical/High",
                "target_getter": t["getter"],
                "target": t["address"],
                "target_asset": target_asset,
                "vault_asset": asset,
            })

        preview = t.get("preview_redeem", {})
        if ta is not None and preview.get("ok"):
            independent = int(preview["value"])
            diff = abs(ta - independent)
            threshold = max(10, ta // 1_000_000, unit // 100)
            if diff > threshold and max(ta, independent) >= material:
                candidates.append({
                    "class": "NESTED_ERC4626_ACCOUNTING_MISMATCH",
                    "severity_ceiling": "High",
                    "target_getter": t["getter"],
                    "target": t["address"],
                    "vault_total_assets": ta,
                    "independent_claim": independent,
                    "absolute_delta": diff,
                })

        vb = t["vault_share_balance"].get("value") if t["vault_share_balance"].get("ok") else None
        cb = t["connector_share_balance"].get("value") if t["connector_share_balance"].get("ok") else None
        if vb is not None and cb is not None and int(vb) == 0 and int(cb) > 0:
            leads.append({
                "class": "CONNECTOR_ADDRESS_HOLDS_EXTERNAL_SHARES",
                "target_getter": t["getter"],
                "connector_share_balance": int(cb),
            })

        maxw = t["max_withdraw_vault"].get("value") if t["max_withdraw_vault"].get("ok") else None
        preview_value = preview.get("value") if preview.get("ok") else None
        if maxw is not None and preview_value is not None and int(preview_value) >= material:
            if int(maxw) * 100 < int(preview_value) * 90:
                leads.append({
                    "class": "EXTERNAL_LIQUIDITY_GAP",
                    "target_getter": t["getter"],
                    "preview_claim": int(preview_value),
                    "max_withdraw": int(maxw),
                })

    direct = int(out.get("direct_asset_balance", {}).get("value", 0)) if out.get("direct_asset_balance", {}).get("ok") else 0
    pending_d = int(out.get("pending_deposit_fee", {}).get("value", 0)) if out.get("pending_deposit_fee", {}).get("ok") else 0
    pending_r = int(out.get("pending_reward_fee", {}).get("value", 0)) if out.get("pending_reward_fee", {}).get("ok") else 0
    idle_excess = max(0, direct - pending_d - pending_r)
    if idle_excess >= material:
        leads.append({
            "class": "MATERIAL_IDLE_ASSET_EXCESS",
            "direct_balance": direct,
            "pending_fees": pending_d + pending_r,
            "excess": idle_excess,
        })

    flags = set(src.get("flags") or [])
    contract_name = (src.get("contract_name") or "").lower()
    known_silent = any(x in contract_name for x in ("venus", "compoundv2", "compound_v2"))
    if ("redeem_underlying" in flags or "return_code_style_mint" in flags) and not known_silent:
        candidates.append({
            "class": "NEW_CONNECTOR_UNCHECKED_RETURN_CODE_PATTERN",
            "severity_ceiling": "High",
            "contract_name": src.get("contract_name"),
            "source_sha256": src.get("source_sha256"),
        })

    out["candidates"] = candidates
    out["leads"] = leads
    return out


def main() -> int:
    scope, scope_meta = extract_scope()
    rpcs: dict[int, Rpc] = {}
    rpc_errors = {}
    for chain in sorted({int(x["chain_id"]) for x in scope}):
        if chain not in CFG:
            continue
        try:
            rpcs[chain] = Rpc(chain)
        except Exception as exc:
            rpc_errors[str(chain)] = str(exc)

    connector_cache: dict[tuple[int, str], dict[str, Any]] = {}
    vaults = []
    errors = []
    for index, row in enumerate(scope):
        rpc = rpcs.get(int(row["chain_id"]))
        if not rpc:
            errors.append({"row": row, "error": "chain RPC unavailable"})
            continue
        try:
            vaults.append(analyze_vault(rpc, row, connector_cache))
        except Exception as exc:
            errors.append({"row": row, "error": f"{type(exc).__name__}: {exc}"})

    candidates = []
    leads = []
    fatals = []
    for vault in vaults:
        for candidate in vault.get("candidates", []):
            candidates.append({"chain_id": vault["chain_id"], "vault": vault["vault"], **candidate})
        for lead in vault.get("leads", []):
            leads.append({"chain_id": vault["chain_id"], "vault": vault["vault"], **lead})
        if vault.get("fatal"):
            fatals.append({"chain_id": vault["chain_id"], "vault": vault["vault"], "fatal": vault["fatal"],
                           "total_supply": vault.get("total_supply")})

    connector_groups = []
    for (chain, address), src in connector_cache.items():
        connector_groups.append({
            "chain_id": chain,
            "network": CFG[chain][0],
            "address": address,
            "contract_name": src.get("contract_name"),
            "verified": src.get("verified"),
            "code_sha256": src.get("code_sha256"),
            "source_sha256": src.get("source_sha256"),
            "source_bytes": src.get("source_bytes"),
            "flags": src.get("flags"),
        })

    evidence = {
        "schema": "kiln-r21-source-runtime-delta-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "safety": {
            "read_only": True,
            "public_chain_mutations": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "private_keys": 0,
            "rpc_methods": ["eth_chainId", "eth_blockNumber", "eth_getCode", "eth_call"],
        },
        "scope_meta": scope_meta,
        "rpc_errors": rpc_errors,
        "vaults": vaults,
        "connector_groups": connector_groups,
        "errors": errors,
        "summary": {
            "resolved_scope": len(scope),
            "inspected_vaults": len(vaults),
            "connector_code_groups": len(connector_groups),
            "candidate_count": len(candidates),
            "lead_count": len(leads),
            "fatal_binding_count": len(fatals),
            "error_count": len(errors),
            "candidate_classes": dict(sorted((k, sum(1 for x in candidates if x["class"] == k))
                                               for k in {x["class"] for x in candidates})),
            "lead_classes": dict(sorted((k, sum(1 for x in leads if x["class"] == k))
                                         for k in {x["class"] for x in leads})),
        },
        "candidates": candidates,
        "leads": leads,
        "fatals": fatals,
    }
    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, sort_keys=True, default=str))

    promote_classes = {
        "TARGET_ASSET_MISMATCH",
        "NESTED_ERC4626_ACCOUNTING_MISMATCH",
        "NEW_CONNECTOR_UNCHECKED_RETURN_CODE_PATTERN",
    }
    promotable = [x for x in candidates if x["class"] in promote_classes]
    decision = "PROMOTE_TARGETED_FIXED_BLOCK_FORK" if promotable else "NO_SUBMIT_READY_SOURCE_DELTA"
    gate = {
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "validated_medium": 0,
        "promotable_candidate_count": len(promotable),
        "candidate_count": len(candidates),
        "lead_count": len(leads),
        "blocking_gates": [
            "fixed-block local-fork reproduction",
            "material attacker/victim delta",
            "patched negative control",
            "duplicate and known-issue clearance",
        ] if promotable else ["no new source/runtime invariant break passed the promotion gate"],
    }
    (OUT / "MASTER_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    public_gate = {
        "schema": "kiln-r21-public-gate-v1",
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "resolved_scope": len(scope),
        "inspected_vaults": len(vaults),
        "connector_code_groups": len(connector_groups),
        "promotable_candidate_count": len(promotable),
        "candidate_class_counts": evidence["summary"]["candidate_classes"],
        "lead_class_counts": evidence["summary"]["lead_classes"],
        "public_chain_mutations": 0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(public_gate, indent=2, sort_keys=True))
    (OUT / "SCOPE_RESOLVED.json").write_text(json.dumps(scope, indent=2, sort_keys=True))
    sums = []
    for path in sorted(OUT.glob("*.json")):
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    (OUT / "SHA256SUMS.txt").write_text("".join(sums))
    print(json.dumps(public_gate, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
