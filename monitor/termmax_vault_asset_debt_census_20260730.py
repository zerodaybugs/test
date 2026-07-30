#!/usr/bin/env python3
"""Read-only current TermMax V2 vault asset/debt-token consistency census.

The V1 OrderManager checked that a vault's ERC-4626 asset equals every accepted
market's debt token. The V2 createOrder path no longer contains that check. This
scanner determines whether any current official deployment has an active order
whose market debt token differs from the vault asset.

Safety boundary: public JSON-RPC eth_call/getLogs and indexed HTTPS GET only.
No signer, private key, transaction construction, or state mutation.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests
from hexbytes import HexBytes
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)
TERMMAX_REPO = Path(os.environ.get("TERMMAX_REPO", "/tmp/termmax-contract-v2"))
CHAIN_NAME = os.environ.get("CHAIN", "ethereum").strip().lower()
PINNED_COMMIT = "e314f3f849577dfecd4614f148c4df81fdf8c72d"
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

CHAINS: dict[str, dict[str, Any]] = {
    "ethereum": {
        "chainId": 1, "routescanId": 1, "deployDir": "eth-mainnet", "startBlock": 23_400_000,
        "rpcs": ["https://ethereum-rpc.publicnode.com", "https://rpc.mevblocker.io", "https://eth.drpc.org"],
        "poa": False,
    },
    "arbitrum": {
        "chainId": 42161, "routescanId": 42161, "deployDir": "arb-mainnet", "startBlock": 385_000_000,
        "rpcs": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.drpc.org"],
        "poa": False,
    },
    "bnb": {
        "chainId": 56, "routescanId": 56, "deployDir": "bnb-mainnet", "startBlock": 63_000_000,
        "rpcs": ["https://bsc-dataseed.binance.org", "https://bsc-rpc.publicnode.com", "https://bsc.drpc.org"],
        "poa": True,
    },
    "base": {
        "chainId": 8453, "routescanId": 8453, "deployDir": "base-mainnet", "startBlock": 43_000_000,
        "rpcs": ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"],
        "poa": False,
    },
    "b2": {
        "chainId": 223, "routescanId": 223, "deployDir": "b2-mainnet", "startBlock": 31_000_000,
        "rpcs": ["https://rpc.bsquared.network", "https://b2-mainnet.alt.technology"],
        "poa": False,
    },
    "berachain": {
        "chainId": 80094, "routescanId": 80094, "deployDir": "bera-mainnet", "startBlock": 19_000_000,
        "rpcs": ["https://rpc.berachain.com", "https://berachain-rpc.publicnode.com"],
        "poa": False,
    },
    "xlayer": {
        "chainId": 196, "routescanId": 196, "deployDir": "xlayer-mainnet", "startBlock": 57_000_000,
        "rpcs": ["https://rpc.xlayer.tech", "https://xlayerrpc.okx.com"],
        "poa": False,
    },
    "pharos": {
        "chainId": 688688, "routescanId": 688688, "deployDir": "pharos", "startBlock": 5_000_000,
        "rpcs": ["https://rpc.pharosnetwork.xyz", "https://api.pharosnetwork.xyz"],
        "poa": False,
    },
}

VAULT_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ORDER_ABI = [
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address","name":"ft"},{"type":"address","name":"xt"},{"type":"address","name":"gt"},
        {"type":"address","name":"collateral"},{"type":"address","name":"debtToken"}
    ]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address","name":"treasurer"},{"type":"uint64","name":"maturity"},
        {"type":"tuple","name":"feeConfig","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]

VAULT_CREATED_TOPIC = Web3.keccak(
    text="VaultCreated(address,address,(address,address,address,uint256,address,address,uint256,string,string,uint64,uint64))"
).hex()
NEW_ORDER_TOPIC = Web3.keccak(text="NewOrderCreated(address,address,address)").hex()


def jdefault(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, HexBytes)):
        return "0x" + bytes(value).hex()
    if hasattr(value, "items"):
        return dict(value)
    return str(value)


def safe_call(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def value(result: dict[str, Any], default: Any = None) -> Any:
    return result.get("value", default) if result.get("ok") else default


def parse_int(raw: Any) -> int:
    if isinstance(raw, int):
        return raw
    text = str(raw or "0")
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address.lower().replace("0x", "")


def address_from_topic(topic: Any) -> str:
    raw = topic.hex() if hasattr(topic, "hex") else str(topic)
    raw = raw[2:] if raw.startswith("0x") else raw
    return Web3.to_checksum_address("0x" + raw[-40:])


def connect(config: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    urls = [os.environ.get(f"{CHAIN_NAME.upper()}_RPC_URL", "").strip(), *config["rpcs"]]
    for url in [x for x in urls if x]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            if config.get("poa"):
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            latest = w3.eth.block_number
            block = w3.eth.get_block(latest)
            if chain_id != config["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url":url,"ok":True,"block":latest,"hash":block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def walk_json(value_: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value_, dict):
        for key, child in value_.items():
            yield from walk_json(child, (*path, str(key)))
    elif isinstance(value_, list):
        for index, child in enumerate(value_):
            yield from walk_json(child, (*path, str(index)))
    elif isinstance(value_, str):
        for address in ADDRESS_RE.findall(value_):
            yield path, address


def manifest_candidates(deploy_dir: Path) -> tuple[set[str], set[str], list[dict[str, Any]]]:
    vaults: set[str] = set()
    factories: set[str] = set()
    evidence: list[dict[str, Any]] = []
    if not deploy_dir.exists():
        return vaults, factories, evidence
    for path in sorted(deploy_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".json", ".env", ".txt"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if path.suffix.lower() == ".json":
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
            if parsed is not None:
                for key_path, address in walk_json(parsed):
                    context = ".".join(key_path).lower()
                    if "vault" not in context:
                        continue
                    row = {"file":str(path.relative_to(TERMMAX_REPO)),"context":context,"address":address}
                    if "factory" in context:
                        factories.add(Web3.to_checksum_address(address)); row["kind"] = "factory"
                    elif not any(x in context for x in ("implementation","impl","library","admin","curator","guardian","owner")):
                        vaults.add(Web3.to_checksum_address(address)); row["kind"] = "vault-candidate"
                    else:
                        row["kind"] = "ignored"
                    evidence.append(row)
        for line_number, line in enumerate(text.splitlines(), start=1):
            if "=" not in line:
                continue
            key, raw = line.split("=", 1)
            key_l = key.strip().lower()
            addresses = ADDRESS_RE.findall(raw)
            if not addresses or "vault" not in key_l:
                continue
            for address in addresses:
                row = {"file":str(path.relative_to(TERMMAX_REPO)),"line":line_number,"context":key.strip(),"address":address}
                if "factory" in key_l:
                    factories.add(Web3.to_checksum_address(address)); row["kind"] = "factory"
                elif not any(x in key_l for x in ("implementation","impl","library","admin","curator","guardian","owner")):
                    vaults.add(Web3.to_checksum_address(address)); row["kind"] = "vault-candidate"
                else:
                    row["kind"] = "ignored"
                evidence.append(row)
    return vaults, factories, evidence


def routescan_logs(config: dict[str, Any], address: str, topic0: str, latest: int) -> list[dict[str, Any]]:
    url = f"https://api.routescan.io/v2/network/mainnet/evm/{config['routescanId']}/etherscan/api"
    page = 1
    output: list[dict[str, Any]] = []
    while True:
        params = {
            "module":"logs","action":"getLogs","address":address,
            "fromBlock":config["startBlock"],"toBlock":latest,
            "topic0":topic0,"page":page,"offset":1000,
        }
        payload = None
        last_error: Exception | None = None
        for attempt in range(6):
            try:
                response = requests.get(url, params=params, timeout=60, headers={"User-Agent":"ZeroDayBugs-TermMax-Vault-Census/1"})
                if response.status_code == 429:
                    time.sleep(1.5 * (attempt + 1)); continue
                response.raise_for_status(); payload = response.json(); break
            except Exception as exc:  # noqa: BLE001
                last_error = exc; time.sleep(1.25 * (attempt + 1))
        if payload is None:
            raise RuntimeError(f"Routescan failed: {last_error}")
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            if "No" in rows or "not found" in rows.lower():
                break
            raise RuntimeError(f"unexpected Routescan result: {payload}")
        if not rows:
            break
        output.extend(rows)
        if len(rows) < 1000:
            break
        page += 1
        time.sleep(0.2)
    return output


def rpc_logs(w3: Web3, config: dict[str, Any], address: str, topic0: str, latest: int) -> list[Any]:
    output: list[Any] = []
    cursor = config["startBlock"]
    sizes = [100_000, 20_000, 5_000, 1_000]
    size_index = 0
    while cursor <= latest:
        end = min(latest, cursor + sizes[size_index] - 1)
        try:
            output.extend(w3.eth.get_logs({
                "fromBlock":cursor,"toBlock":end,"address":address,"topics":[topic0]
            }))
            cursor = end + 1; size_index = 0
        except Exception:
            if size_index + 1 < len(sizes):
                size_index += 1
            else:
                raise
    return output


def get_logs(w3: Web3, config: dict[str, Any], address: str, topic0: str, latest: int) -> tuple[list[Any], dict[str, Any]]:
    try:
        rows = routescan_logs(config, address, topic0, latest)
        return rows, {"source":"routescan","ok":True,"count":len(rows)}
    except Exception as exc:  # noqa: BLE001
        try:
            rows = rpc_logs(w3, config, address, topic0, latest)
            return rows, {"source":"rpc","ok":True,"count":len(rows),"routescanError":f"{type(exc).__name__}: {exc}"}
        except Exception as rpc_exc:  # noqa: BLE001
            return [], {"source":"none","ok":False,"routescanError":f"{type(exc).__name__}: {exc}","rpcError":f"{type(rpc_exc).__name__}: {rpc_exc}"}


def log_topics(row: Any) -> list[Any]:
    if isinstance(row, dict):
        return row.get("topics", [])
    return list(row["topics"])


def log_block(row: Any) -> int:
    if isinstance(row, dict):
        return parse_int(row.get("blockNumber"))
    return int(row["blockNumber"])


def log_tx(row: Any) -> str:
    if isinstance(row, dict):
        return str(row.get("transactionHash"))
    return row["transactionHash"].hex()


def probe_vault(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    contract = w3.eth.contract(address=address, abi=VAULT_ABI)
    row = {
        "vault":address,"codeBytes":len(w3.eth.get_code(address, block_identifier=block)),
        "name":safe_call(contract.functions.name().call, block_identifier=block),
        "symbol":safe_call(contract.functions.symbol().call, block_identifier=block),
        "asset":safe_call(contract.functions.asset().call, block_identifier=block),
        "totalSupply":safe_call(contract.functions.totalSupply().call, block_identifier=block),
        "totalAssets":safe_call(contract.functions.totalAssets().call, block_identifier=block),
        "paused":safe_call(contract.functions.paused().call, block_identifier=block),
    }
    row["isVault"] = bool(row["codeBytes"] and row["asset"]["ok"] and row["totalSupply"]["ok"])
    return row


def token_meta(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    token = w3.eth.contract(address=address, abi=ERC20_ABI)
    return {
        "address":address,
        "symbol":safe_call(token.functions.symbol().call, block_identifier=block),
        "name":safe_call(token.functions.name().call, block_identifier=block),
        "decimals":safe_call(token.functions.decimals().call, block_identifier=block),
        "totalSupply":safe_call(token.functions.totalSupply().call, block_identifier=block),
    }


def inspect_order(w3: Web3, vault_address: str, market_hint: str | None, order_address: str, block: int, timestamp: int) -> dict[str, Any]:
    vault = w3.eth.contract(address=vault_address, abi=VAULT_ABI)
    order_address = Web3.to_checksum_address(order_address)
    order = w3.eth.contract(address=order_address, abi=ORDER_ABI)
    market_r = safe_call(order.functions.market().call, block_identifier=block)
    market_address = value(market_r, market_hint)
    row: dict[str, Any] = {
        "order":order_address,"marketHint":market_hint,"market":market_r,
        "orderMaturity":safe_call(vault.functions.orderMaturity(order_address).call, block_identifier=block),
    }
    if not market_address:
        return row
    market_address = Web3.to_checksum_address(market_address)
    market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
    tokens_r = safe_call(market.functions.tokens().call, block_identifier=block)
    config_r = safe_call(market.functions.config().call, block_identifier=block)
    paused_r = safe_call(market.functions.paused().call, block_identifier=block)
    row.update({"marketAddress":market_address,"tokens":tokens_r,"config":config_r,"paused":paused_r})
    tokens = value(tokens_r)
    if not tokens or len(tokens) != 5:
        return row
    ft, xt, gt, collateral, debt = [Web3.to_checksum_address(x) for x in tokens]
    asset = Web3.to_checksum_address(value(safe_call(vault.functions.asset().call, block_identifier=block)))
    order_maturity = int(value(row["orderMaturity"], 0) or 0)
    cfg = value(config_r)
    market_maturity = int(cfg[1]) if cfg else 0
    ft_token = w3.eth.contract(address=ft, abi=ERC20_ABI)
    row.update({
        "ft":token_meta(w3,ft,block),"xt":xt,"gt":gt,
        "collateral":token_meta(w3,collateral,block),
        "debtToken":token_meta(w3,debt,block),"vaultAsset":token_meta(w3,asset,block),
        "ftBalanceAtOrder":safe_call(ft_token.functions.balanceOf(order_address).call, block_identifier=block),
        "marketMaturity":market_maturity,"marketMatured":bool(market_maturity and timestamp >= market_maturity),
        "activeInVault":order_maturity > 0,
        "assetDebtMatch":asset.lower() == debt.lower(),
    })
    row["activeMismatch"] = bool(row["activeInVault"] and not row["assetDebtMatch"] and value(paused_r, False) is not True)
    return row


def main() -> int:
    if CHAIN_NAME not in CHAINS:
        raise SystemExit(f"unsupported CHAIN={CHAIN_NAME}")
    config = CHAINS[CHAIN_NAME]
    w3, rpc, rpc_attempts = connect(config)
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    timestamp = int(block.timestamp)
    deploy_dir = TERMMAX_REPO / "deployments" / config["deployDir"]
    manifest_vaults, manifest_factories, manifest_evidence = manifest_candidates(deploy_dir)

    discovered_vaults = set(manifest_vaults)
    factory_diagnostics: list[dict[str, Any]] = []
    for factory in sorted(manifest_factories):
        rows, diagnostics = get_logs(w3, config, factory, VAULT_CREATED_TOPIC, latest)
        diagnostics.update({"factory":factory})
        factory_diagnostics.append(diagnostics)
        for event in rows:
            topics = log_topics(event)
            if len(topics) >= 2:
                try:
                    discovered_vaults.add(address_from_topic(topics[1]))
                except Exception:
                    pass

    vault_rows = [probe_vault(w3, address, latest) for address in sorted(discovered_vaults)]
    actual_vaults = [row for row in vault_rows if row["isVault"]]
    orders: list[dict[str, Any]] = []
    order_diagnostics: list[dict[str, Any]] = []
    for vault_row in actual_vaults:
        vault_address = vault_row["vault"]
        rows, diagnostics = get_logs(w3, config, vault_address, NEW_ORDER_TOPIC, latest)
        diagnostics.update({"vault":vault_address})
        order_diagnostics.append(diagnostics)
        seen: set[str] = set()
        for event in rows:
            topics = log_topics(event)
            if len(topics) < 4:
                continue
            try:
                market_hint = address_from_topic(topics[2])
                order_address = address_from_topic(topics[3])
            except Exception:
                continue
            if order_address.lower() in seen:
                continue
            seen.add(order_address.lower())
            row = inspect_order(w3, vault_address, market_hint, order_address, latest, timestamp)
            row.update({"vault":vault_address,"vaultName":vault_row["name"],"vaultTotalAssets":vault_row["totalAssets"],"creationBlock":log_block(event),"creationTx":log_tx(event)})
            orders.append(row)

    mismatches = [row for row in orders if row.get("assetDebtMatch") is False]
    active_mismatches = [row for row in orders if row.get("activeMismatch")]
    verdict = {
        "chain":CHAIN_NAME,
        "manifestVaultCandidateCount":len(manifest_vaults),
        "manifestFactoryCount":len(manifest_factories),
        "actualVaultCount":len(actual_vaults),
        "orderCount":len(orders),
        "mismatchCount":len(mismatches),
        "activeMismatchCount":len(active_mismatches),
        "nextStep":"BUILD_CURRENT_FORK_EXPLOIT" if active_mismatches else "KILL_NO_CURRENT_ACTIVE_MISCONFIGURATION",
    }
    result = {
        "schema":"termmax-vault-asset-debt-census/v1",
        "generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "pinnedSourceCommit":PINNED_COMMIT,
        "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "chain":CHAIN_NAME,"chainId":config["chainId"],"rpc":rpc,"rpcAttempts":rpc_attempts,
        "block":{"number":latest,"hash":block.hash.hex(),"timestamp":timestamp,"timestampUtc":datetime.fromtimestamp(timestamp,tz=timezone.utc).isoformat()},
        "deployDir":str(deploy_dir),"manifestEvidence":manifest_evidence,
        "manifestVaultCandidates":sorted(manifest_vaults),"manifestFactories":sorted(manifest_factories),
        "factoryDiagnostics":factory_diagnostics,"vaultProbeRows":vault_rows,"actualVaults":actual_vaults,
        "orderDiagnostics":order_diagnostics,"orders":orders,"mismatches":mismatches,"activeMismatches":active_mismatches,
        "verdict":verdict,
    }
    compact = {
        "generatedAtUtc":result["generatedAtUtc"],"chain":CHAIN_NAME,"block":result["block"],
        "actualVaults":[{"vault":r["vault"],"name":r["name"],"asset":r["asset"],"totalAssets":r["totalAssets"]} for r in actual_vaults],
        "mismatches":mismatches,"activeMismatches":active_mismatches,"verdict":verdict,
    }
    (OUT / "VAULT_ASSET_DEBT_FULL.json").write_text(json.dumps(result, indent=2, default=jdefault), encoding="utf-8")
    (OUT / "VAULT_ASSET_DEBT_COMPACT.json").write_text(json.dumps(compact, indent=2, default=jdefault), encoding="utf-8")
    (OUT / "VERDICT.txt").write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    if active_mismatches:
        (OUT / "ACTIVE_MISMATCH.marker").write_text(json.dumps(active_mismatches, indent=2, default=jdefault), encoding="utf-8")
    else:
        (OUT / "NO_ACTIVE_MISMATCH.marker").write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    print(json.dumps(compact, indent=2, default=jdefault))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
