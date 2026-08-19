#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from Crypto.Hash import keccak

OUT = Path("r45_results")
OUT.mkdir(exist_ok=True)
CANTINA_URL = "https://cantina.xyz/bounties/c9a4b51b-2e80-4713-a06f-13524c530fa6"
SOURCE_REPO = "https://github.com/dumebi042/kiln-vault.git"
VAULT_SOURCE = Path("r45_source/src/Vault.sol")
VAULT_STORAGE_BASE = int("6bb5a2a0ae924c2ea94f037035a09f65614421e2a7d96c9bcbd59acdd32e6000", 16)
ZERO = "0x" + "00" * 20
TRANSFER_TOPIC = "0x" + keccak.new(digest_bits=256, data=b"Transfer(address,address,uint256)").hexdigest()

NETWORKS: dict[str, dict[str, Any]] = {
    "ethereum": {
        "chain_id": 1,
        "rpcs": [
            "https://ethereum-rpc.publicnode.com",
            "https://eth.llamarpc.com",
            "https://1rpc.io/eth",
            "https://rpc.flashbots.net",
        ],
    },
    "arbitrum": {
        "chain_id": 42161,
        "rpcs": [
            "https://arb1.arbitrum.io/rpc",
            "https://arbitrum.llamarpc.com",
            "https://1rpc.io/arb",
            "https://arbitrum-one-rpc.publicnode.com",
        ],
    },
    "base": {
        "chain_id": 8453,
        "rpcs": [
            "https://mainnet.base.org",
            "https://base.llamarpc.com",
            "https://base-rpc.publicnode.com",
            "https://1rpc.io/base",
        ],
    },
    "bnb": {
        "chain_id": 56,
        "rpcs": [
            "https://bsc-dataseed.binance.org",
            "https://binance.llamarpc.com",
            "https://bsc-rpc.publicnode.com",
            "https://1rpc.io/bnb",
        ],
    },
    "polygon": {
        "chain_id": 137,
        "rpcs": [
            "https://polygon-rpc.com",
            "https://polygon.llamarpc.com",
            "https://polygon-bor-rpc.publicnode.com",
            "https://1rpc.io/matic",
        ],
    },
    "optimism": {
        "chain_id": 10,
        "rpcs": [
            "https://mainnet.optimism.io",
            "https://optimism.llamarpc.com",
            "https://optimism-rpc.publicnode.com",
            "https://1rpc.io/op",
        ],
    },
}


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def selector(signature: str) -> str:
    return keccak.new(digest_bits=256, data=signature.encode()).hexdigest()[:8]


def address_word(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def decode_uint(raw: str | None) -> int | None:
    if not raw or raw == "0x":
        return None
    try:
        return int(raw, 16)
    except Exception:
        return None


def decode_address(raw: str | None) -> str | None:
    if not raw or len(raw) < 42:
        return None
    candidate = "0x" + raw[-40:]
    if candidate.lower() == ZERO.lower():
        return None
    return candidate


def http_get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Kiln-R45-Research/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def rpc(url: str, method: str, params: list[Any], timeout: int = 30) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Kiln-R45-Research/1.0"},
    )
    last: Exception | None = None
    for delay in (0, 1, 3):
        if delay:
            time.sleep(delay)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = json.loads(response.read())
            if body.get("error"):
                raise RuntimeError(body["error"])
            return body.get("result")
        except Exception as exc:
            last = exc
    raise RuntimeError(f"{method} failed on {url}: {type(last).__name__}: {last}")


def choose_quorum(network: str) -> dict[str, Any]:
    info = NETWORKS[network]
    healthy: list[tuple[str, int]] = []
    for url in info["rpcs"]:
        try:
            cid = int(rpc(url, "eth_chainId", []), 16)
            if cid != info["chain_id"]:
                continue
            height = int(rpc(url, "eth_blockNumber", []), 16)
            healthy.append((url, height))
        except Exception:
            continue
    if len(healthy) < 2:
        raise RuntimeError(f"{network}: fewer than two healthy RPCs")
    healthy.sort(key=lambda item: item[1], reverse=True)
    for i, (left, lh) in enumerate(healthy):
        for right, rh in healthy[i + 1 :]:
            height = min(lh, rh) - 2
            tag = hex(height)
            try:
                lb = rpc(left, "eth_getBlockByNumber", [tag, False])
                rb = rpc(right, "eth_getBlockByNumber", [tag, False])
                if lb and rb and lb.get("hash") == rb.get("hash"):
                    return {
                        "primary": left,
                        "secondary": right,
                        "block_number": height,
                        "block_tag": tag,
                        "block_hash": lb["hash"],
                    }
            except Exception:
                continue
    raise RuntimeError(f"{network}: no exact-block two-RPC quorum")


def parse_scope() -> tuple[list[dict[str, Any]], str]:
    page = http_get(CANTINA_URL).decode(errors="replace")
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
    for label, address, connector, network, asset_text in pattern.findall(page):
        key = (network.lower(), address.lower())
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "label": re.sub(r"\s+", " ", label).strip(),
                "address": address,
                "connector": connector.upper(),
                "network": network.lower(),
                "asset_text": re.sub(r"\s+", " ", asset_text).strip(),
            }
        )
    rows.sort(key=lambda row: (row["network"], row["connector"], row["address"].lower()))
    if len(rows) < 49:
        raise RuntimeError(f"scope parser returned only {len(rows)} rows")
    return rows, hashlib.sha256(page.encode()).hexdigest()


def function_excerpt(source: str, needle: str) -> str:
    match = re.search(rf"\bfunction\s+{re.escape(needle)}\b", source)
    if not match:
        return ""
    start = match.start()
    brace = source.find("{", match.end())
    if brace < 0:
        return source[start : source.find(";", match.end()) + 1]
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    return source[start : start + 6000]


def source_gate() -> dict[str, Any]:
    source = VAULT_SOURCE.read_text()
    names = [
        "collectRewardFees",
        "_collectRewardFees",
        "_withdraw",
        "_update",
        "_checkMinTotalSupply",
        "_setMinTotalSupply",
        "minTotalSupply",
    ]
    excerpts = {name: function_excerpt(source, name) for name in names}
    joined = "\n".join(excerpts.values())
    findings = {
        "min_supply_referenced": "minTotalSupply" in source,
        "collectable_fee_shares_referenced": "collectableRewardFeesShares" in source,
        "withdraw_path_mentions_min_supply": "minTotalSupply" in excerpts.get("_withdraw", "")
        or "_checkMinTotalSupply" in excerpts.get("_withdraw", ""),
        "collect_path_role_guarded": "FEE_COLLECTOR_ROLE" in excerpts.get("collectRewardFees", "")
        or "onlyRole" in excerpts.get("collectRewardFees", ""),
        "fee_collection_burn_or_withdraw": any(
            token in excerpts.get("collectRewardFees", "") + excerpts.get("_collectRewardFees", "")
            for token in ("_burn", "withdraw", "redeem")
        ),
    }
    (OUT / "SOURCE_EXCERPTS.txt").write_text(
        "\n\n".join(f"===== {name} =====\n{body}" for name, body in excerpts.items())
    )
    return {
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "checks": findings,
        "source_supports_hypothesis": all(
            [
                findings["min_supply_referenced"],
                findings["collectable_fee_shares_referenced"],
                findings["withdraw_path_mentions_min_supply"],
                findings["collect_path_role_guarded"],
            ]
        ),
    }


def call(url: str, to: str, data: str, block_tag: str) -> str | None:
    try:
        return rpc(url, "eth_call", [{"to": to, "data": data}, block_tag])
    except Exception:
        return None


def storage(url: str, address: str, offset: int, block_tag: str) -> int | None:
    try:
        return int(rpc(url, "eth_getStorageAt", [address, hex(VAULT_STORAGE_BASE + offset), block_tag]), 16)
    except Exception:
        return None


def inspect_vault(row: dict[str, Any], quorum: dict[str, Any]) -> dict[str, Any]:
    url = quorum["primary"]
    check_url = quorum["secondary"]
    block_tag = quorum["block_tag"]
    vault = row["address"]
    total_supply_raw = call(url, vault, "0x" + selector("totalSupply()"), block_tag)
    total_assets_raw = call(url, vault, "0x" + selector("totalAssets()"), block_tag)
    asset_raw = call(url, vault, "0x" + selector("asset()"), block_tag)
    balance_raw = call(url, vault, "0x" + selector("balanceOf(address)") + address_word(vault), block_tag)
    decimals_raw = call(url, vault, "0x" + selector("decimals()"), block_tag)
    total_supply = decode_uint(total_supply_raw)
    total_assets = decode_uint(total_assets_raw)
    asset = decode_address(asset_raw)
    vault_share_balance = decode_uint(balance_raw)
    share_decimals = decode_uint(decimals_raw)
    min_supply = storage(url, vault, 5, block_tag)
    collectable = storage(url, vault, 7, block_tag)
    # Cross-RPC compare the core state only. Any disagreement fails the row closed.
    secondary = {
        "total_supply": decode_uint(call(check_url, vault, "0x" + selector("totalSupply()"), block_tag)),
        "asset": decode_address(call(check_url, vault, "0x" + selector("asset()"), block_tag)),
        "vault_share_balance": decode_uint(
            call(check_url, vault, "0x" + selector("balanceOf(address)") + address_word(vault), block_tag)
        ),
        "min_supply": storage(check_url, vault, 5, block_tag),
        "collectable": storage(check_url, vault, 7, block_tag),
    }
    primary_core = {
        "total_supply": total_supply,
        "asset": asset,
        "vault_share_balance": vault_share_balance,
        "min_supply": min_supply,
        "collectable": collectable,
    }
    quorum_match = primary_core == secondary
    external_shares = None
    external_assets_estimate = None
    if total_supply is not None and vault_share_balance is not None:
        external_shares = max(0, total_supply - vault_share_balance)
    if (
        total_assets is not None
        and total_supply not in (None, 0)
        and external_shares is not None
    ):
        external_assets_estimate = total_assets * external_shares // total_supply
    structural_candidate = bool(
        quorum_match
        and total_supply not in (None, 0)
        and min_supply not in (None, 0)
        and collectable not in (None, 0)
        and vault_share_balance is not None
        and vault_share_balance >= collectable
        and collectable < min_supply
        and external_shares not in (None, 0)
    )
    # Fail closed on materiality. For stablecoin-like six/eighteen decimal assets, this is deliberately low.
    economic_floor_raw = 10 ** max(0, min(int(share_decimals or 18), 18))
    material_candidate = bool(
        structural_candidate
        and external_assets_estimate is not None
        and external_assets_estimate >= 10_000 * economic_floor_raw
    )
    return {
        **row,
        "block_number": quorum["block_number"],
        "block_hash": quorum["block_hash"],
        "total_supply": total_supply,
        "total_assets": total_assets,
        "asset": asset,
        "share_decimals": share_decimals,
        "vault_share_balance": vault_share_balance,
        "min_total_supply": min_supply,
        "collectable_reward_fee_shares": collectable,
        "external_shares": external_shares,
        "external_assets_estimate": external_assets_estimate,
        "quorum_match": quorum_match,
        "structural_candidate": structural_candidate,
        "material_candidate": material_candidate,
    }


def audit_duplicate_gate() -> dict[str, Any]:
    corpus = []
    audit_root = Path("r45_source")
    terms = re.compile(
        r"min(?:imum)?\s+total\s+supply|collectableRewardFeesShares|last holder|reward fee shares|"
        r"fee shares.*(?:lock|freeze)|(?:lock|freeze).*fee shares",
        re.IGNORECASE,
    )
    for path in audit_root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".md", ".txt"}:
            continue
        try:
            text = path.read_text(errors="replace")
        except Exception:
            continue
        matches = []
        for match in terms.finditer(text):
            start = max(0, match.start() - 240)
            end = min(len(text), match.end() + 500)
            matches.append(text[start:end].replace("\n", " "))
            if len(matches) >= 5:
                break
        if matches:
            corpus.append({"path": path.as_posix(), "matches": matches})
    return {
        "match_file_count": len(corpus),
        "matches": corpus[:40],
        "duplicate_clear": len(corpus) == 0,
    }


def main() -> int:
    generated = now()
    source = source_gate()
    rows, page_hash = parse_scope()
    quorums: dict[str, Any] = {}
    quorum_errors: list[str] = []
    for network in sorted({row["network"] for row in rows}):
        try:
            quorums[network] = choose_quorum(network)
        except Exception as exc:
            quorum_errors.append(f"{network}: {type(exc).__name__}: {exc}")
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=14) as executor:
        future_map = {}
        for row in rows:
            quorum = quorums.get(row["network"])
            if not quorum:
                errors.append(f"{row['network']}:{row['address']}: no quorum")
                continue
            future_map[executor.submit(inspect_vault, row, quorum)] = row
        for future in concurrent.futures.as_completed(future_map):
            row = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                errors.append(f"{row['network']}:{row['address']}: {type(exc).__name__}: {exc}")
    results.sort(key=lambda row: (row["network"], row["address"].lower()))
    duplicate = audit_duplicate_gate()
    structural = [row for row in results if row["structural_candidate"]]
    material = [row for row in results if row["material_candidate"]]
    coverage_complete = (
        len(results) == len(rows)
        and not errors
        and not quorum_errors
        and all(row["quorum_match"] for row in results)
    )
    if not coverage_complete:
        decision = "INCONCLUSIVE_R45_COVERAGE_OR_RPC_QUORUM_FAILURE"
    elif not source["source_supports_hypothesis"]:
        decision = "KILL_R45_SOURCE_DOES_NOT_SUPPORT_FEE_SHARE_MINSUPPLY_LOCK"
    elif not structural:
        decision = "KILL_R45_NO_LIVE_STRUCTURAL_FEE_SHARE_MINSUPPLY_STATE"
    elif not material:
        decision = "KILL_R45_STRUCTURAL_STATE_NOT_MATERIAL"
    elif not duplicate["duplicate_clear"]:
        decision = "KILL_R45_OFFICIAL_AUDIT_DUPLICATE_SIGNAL"
    else:
        decision = "HOLD_R45_MATERIAL_CANDIDATE_REQUIRES_EXACT_HOLDER_FORK_POC"
    evidence = {
        "schema": "kiln-omnivault-r45-fee-share-minsupply-evidence-v1",
        "generated_at_utc": generated,
        "cantina_page_sha256": page_hash,
        "scope_count": len(rows),
        "source_gate": source,
        "quorums": quorums,
        "quorum_errors": quorum_errors,
        "rows": results,
        "errors": errors,
        "structural_candidates": structural,
        "material_candidates": material,
        "duplicate_gate": duplicate,
        "safety": {
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "rpc_methods": [
                "eth_chainId",
                "eth_blockNumber",
                "eth_getBlockByNumber",
                "eth_call",
                "eth_getStorageAt",
            ],
        },
    }
    (OUT / "EVIDENCE.json").write_text(json.dumps(evidence, indent=2, sort_keys=True))
    gate = {
        "schema": "kiln-omnivault-r45-fee-share-minsupply-public-gate-v1",
        "generated_at_utc": generated,
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "scope_count": len(rows),
        "inspected_count": len(results),
        "coverage_complete": coverage_complete,
        "error_count": len(errors) + len(quorum_errors),
        "structural_candidate_count": len(structural),
        "material_candidate_count": len(material),
        "duplicate_match_file_count": duplicate["match_file_count"],
        "source_supports_hypothesis": source["source_supports_hypothesis"],
        "public_chain_state_changes": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    files = sorted(path for path in OUT.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    (OUT / "SHA256SUMS.txt").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files)
    )
    print(json.dumps(gate, sort_keys=True))
    return 0 if coverage_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
