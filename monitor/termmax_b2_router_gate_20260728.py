#!/usr/bin/env python3
"""Read-only live gate for the TermMax B2 Router V1 persistent-allowance candidate.

Safety boundary:
- public JSON-RPC and public HTTPS GET requests only;
- no private key, signer, transaction construction, or broadcast;
- no state-changing RPC methods;
- no exploit execution on a live chain.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from hexbytes import HexBytes
from web3 import Web3

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

CHAIN = {
    "name": "b2-mainnet",
    "chainId": 223,
    "rpcs": [
        "https://rpc.bsquared.network",
        "https://mainnet.b2-rpc.com",
        "https://b2-mainnet.alt.technology",
        "https://223.rpc.thirdweb.com",
    ],
    "deploymentBlock": 31_535_305,
    "factoryV2": "0x5BA2d33fB50d08D7755787E729183FedD6a3F3e7",
    "vaultFactoryV2": "0x3Ebb9e9C855Bd03b275167DD2418193E3b69C22f",
    "whitelistManager": "0x03c4FCF963E5FBC0dC5851d2340624E70492acb9",
    "routerV1": "0x3cb5fa87703c7165cc5f2087B3e80b58fb6d8CE8",
    "routerV2": "0x830fBad7Cd1c3Cc5B693Dc64b985f2901B253C5B",
    "uniswapV3AdapterV2": "0xBd795F755dbB5A5358D6c60AED53ceB486Fa8517",
}

ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"allowance","stateMutability":"view","inputs":[{"type":"address"},{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]
MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
]
VAULT_ABI = [
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
WHITELIST_ABI = [
    {"type":"function","name":"isWhitelisted","stateMutability":"view","inputs":[{"type":"address"},{"type":"uint8"}],"outputs":[{"type":"bool"}]},
]
ROUTER_ABI = [
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"owner","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
ADAPTER_PROBES_ABI = [
    {"type":"function","name":"router","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"selectorWhitelist","stateMutability":"pure","inputs":[{"type":"bytes4"}],"outputs":[{"type":"bool"}]},
]

MARKET_CREATED_SIG = "MarketCreated(address,address,address,(address,address,address,address,(address,uint64,(uint32,uint32,uint32,uint32,uint32,uint32)),(address,uint32,uint32,bool),bytes,string,string))"
VAULT_CREATED_SIG = "VaultCreated(address,address,(address,address,address,uint256,address,address,uint256,string,string,uint64,uint64))"
MARKET_CREATED_TOPIC = "0x" + Web3.keccak(text=MARKET_CREATED_SIG).hex()
VAULT_CREATED_TOPIC = "0x" + Web3.keccak(text=VAULT_CREATED_SIG).hex()
TRANSFER_TOPIC = "0x" + Web3.keccak(text="Transfer(address,address,uint256)").hex()
APPROVAL_TOPIC = "0x" + Web3.keccak(text="Approval(address,address,uint256)").hex()
ZERO = "0x0000000000000000000000000000000000000000"


def default(value: Any) -> Any:
    if isinstance(value, (HexBytes, bytes, bytearray)):
        return "0x" + bytes(value).hex()
    return str(value)


def checksum(value: str) -> str:
    return Web3.to_checksum_address(value)


def topic_address(value: Any) -> str:
    raw = HexBytes(value).hex()
    raw = raw[2:] if raw.startswith("0x") else raw
    return checksum("0x" + raw[-40:])


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in CHAIN["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 45}))
            chain_id = w3.eth.chain_id
            block_number = w3.eth.block_number
            block = w3.eth.get_block(block_number)
            if chain_id != CHAIN["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url":url,"ok":True,"block":block_number,"hash":"0x"+bytes(block.hash).hex()})
            return w3, url, attempts
        except Exception as exc:
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        return {"ok":True,"value":list(value) if isinstance(value,tuple) else value}
    except Exception as exc:
        return {"ok":False,"error":f"{type(exc).__name__}: {exc}"}


def value(result: dict[str, Any], fallback: Any = None) -> Any:
    return result.get("value", fallback) if result.get("ok") else fallback


def rpc_logs(
    w3: Web3,
    address: str | None,
    topics: list[Any],
    start: int,
    end: int,
    preferred_step: int = 1_000_000,
) -> list[Any]:
    output: list[Any] = []
    cursor = int(start)
    while cursor <= end:
        step = preferred_step
        rows = None
        while rows is None:
            window_end = min(end, cursor + step - 1)
            request: dict[str, Any] = {"topics":topics,"fromBlock":cursor,"toBlock":window_end}
            if address:
                request["address"] = checksum(address)
            try:
                rows = w3.eth.get_logs(request)
            except Exception:
                if step <= 1_000:
                    raise
                step = max(1_000, step // 2)
        output.extend(rows)
        cursor = min(end, cursor + step - 1) + 1
    return output


def discover_markets_and_vaults(w3: Web3, latest: int) -> tuple[list[str], list[str], dict[str, Any]]:
    market_logs = rpc_logs(w3, CHAIN["factoryV2"], [MARKET_CREATED_TOPIC], CHAIN["deploymentBlock"], latest)
    vault_logs = rpc_logs(w3, CHAIN["vaultFactoryV2"], [VAULT_CREATED_TOPIC], CHAIN["deploymentBlock"], latest)
    markets = list(dict.fromkeys(topic_address(row["topics"][1]) for row in market_logs if len(row["topics"]) >= 4))
    vaults = list(dict.fromkeys(topic_address(row["topics"][1]) for row in vault_logs if len(row["topics"]) >= 3))
    meta = {
        "marketLogCount":len(market_logs),
        "vaultLogCount":len(vault_logs),
        "marketTransactions":["0x"+bytes(row["transactionHash"]).hex() for row in market_logs],
        "vaultTransactions":["0x"+bytes(row["transactionHash"]).hex() for row in vault_logs],
    }
    return markets, vaults, meta


def collect_tokens(w3: Web3, markets: list[str], vaults: list[str], block: int) -> tuple[list[str], list[dict[str, Any]]]:
    tokens: dict[str, str] = {}
    failures: list[dict[str, Any]] = []
    for market_address in markets:
        market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
        result = safe(market.functions.tokens().call, block_identifier=block)
        items = value(result)
        if not items:
            failures.append({"kind":"market","address":market_address,"result":result})
            continue
        for token in items:
            if int(token,16) != 0:
                tokens[token.lower()] = checksum(token)
    for vault_address in vaults:
        vault = w3.eth.contract(address=vault_address, abi=VAULT_ABI)
        for name in ["asset","pool"]:
            result = safe(getattr(vault.functions,name)().call, block_identifier=block)
            token = value(result)
            if token and int(token,16) != 0:
                tokens[token.lower()] = checksum(token)
            elif not result.get("ok"):
                failures.append({"kind":f"vault-{name}","address":vault_address,"result":result})
    return list(tokens.values()), failures


def token_price(address: str) -> dict[str, Any]:
    keys = [f"b2:{address.lower()}", f"b2-mainnet:{address.lower()}", f"b2-network:{address.lower()}"]
    for key in keys:
        try:
            response = requests.get(
                f"https://coins.llama.fi/prices/current/{key}",
                timeout=30,
                headers={"User-Agent":"termmax-b2-readonly/1"},
            )
            response.raise_for_status()
            item = response.json().get("coins",{}).get(key)
            if item and item.get("price") is not None:
                return {"ok":True,"key":key,"price":item.get("price"),"symbol":item.get("symbol"),"timestamp":item.get("timestamp")}
        except Exception as exc:
            last = exc
    return {"ok":False,"error":f"price unavailable: {last!r}" if 'last' in locals() else "price unavailable"}


def inspect_token(w3: Web3, address: str, block: int, routers: list[str]) -> dict[str, Any]:
    token = w3.eth.contract(address=address, abi=ERC20_ABI)
    symbol = safe(token.functions.symbol().call, block_identifier=block)
    name = safe(token.functions.name().call, block_identifier=block)
    decimals = safe(token.functions.decimals().call, block_identifier=block)
    dec = int(value(decimals,18) or 18)
    price = token_price(address)
    balances: dict[str, Any] = {}
    for router in routers:
        balance = safe(token.functions.balanceOf(router).call, block_identifier=block)
        raw = int(value(balance,0) or 0)
        usd = None
        if price.get("ok"):
            usd = raw * float(price["price"]) / (10**dec)
        balances[router] = {"raw":raw,"human":raw/(10**dec),"usd":usd,"call":balance}
    return {"address":address,"symbol":symbol,"name":name,"decimals":decimals,"price":price,"balances":balances}


def historical_token_addresses(w3: Web3, router: str, latest: int) -> list[str]:
    # Token contracts are the emitting addresses. Query the Router as indexed sender and recipient.
    padded = "0x" + "0"*24 + router[2:].lower()
    output: dict[str,str] = {}
    for topics in ([TRANSFER_TOPIC,padded,None],[TRANSFER_TOPIC,None,padded]):
        try:
            rows = rpc_logs(w3,None,list(topics),CHAIN["deploymentBlock"],latest,preferred_step=250_000)
            for row in rows:
                output[row["address"].lower()] = checksum(row["address"])
        except Exception as exc:
            (OUT/"transfer_scan_errors.log").open("a",encoding="utf-8").write(f"{router} {topics}: {type(exc).__name__}: {exc}\n")
    return list(output.values())


def main() -> int:
    w3, rpc, attempts = connect()
    latest = w3.eth.block_number
    block = w3.eth.get_block(latest)
    router_v1 = checksum(CHAIN["routerV1"])
    router_v2 = checksum(CHAIN["routerV2"])
    adapter = checksum(CHAIN["uniswapV3AdapterV2"])
    whitelist_manager = checksum(CHAIN["whitelistManager"])

    markets, vaults, discovery = discover_markets_and_vaults(w3, latest)
    tokens, token_failures = collect_tokens(w3, markets, vaults, latest)
    for router in [router_v1,router_v2]:
        for token in historical_token_addresses(w3,router,latest):
            if token.lower() not in {item.lower() for item in tokens}:
                tokens.append(token)

    inspected = [inspect_token(w3,address,latest,[router_v1,router_v2]) for address in sorted(tokens,key=str.lower)]
    current_nonzero = []
    for item in inspected:
        for router,data in item["balances"].items():
            if data["raw"]:
                current_nonzero.append({"token":item["address"],"symbol":value(item["symbol"]),"router":router,**data})

    whitelist = w3.eth.contract(address=whitelist_manager, abi=WHITELIST_ABI)
    router_contracts = {addr:w3.eth.contract(address=addr,abi=ROUTER_ABI) for addr in [router_v1,router_v2]}
    adapter_contract = w3.eth.contract(address=adapter,abi=ADAPTER_PROBES_ABI)
    runtime = w3.eth.get_code(adapter,block_identifier=latest)
    fixed_router_probe = safe(adapter_contract.functions.router().call,block_identifier=latest)

    result = {
        "schema":"termmax-b2-router-live-gate/v1",
        "generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0,"methods":["eth_call","eth_getLogs","eth_getCode","public HTTPS GET"]},
        "rpc":rpc,
        "rpcAttempts":attempts,
        "block":{"number":latest,"hash":"0x"+bytes(block.hash).hex(),"timestamp":int(block.timestamp),"timestampUtc":datetime.fromtimestamp(int(block.timestamp),tz=timezone.utc).isoformat()},
        "addresses":{"routerV1":router_v1,"routerV2":router_v2,"adapter":adapter,"whitelistManager":whitelist_manager,"factoryV2":checksum(CHAIN["factoryV2"]),"vaultFactoryV2":checksum(CHAIN["vaultFactoryV2"])},
        "code":{"routerV1Bytes":len(w3.eth.get_code(router_v1,block_identifier=latest)),"routerV2Bytes":len(w3.eth.get_code(router_v2,block_identifier=latest)),"adapterBytes":len(runtime),"adapterRuntimeKeccak":"0x"+Web3.keccak(runtime).hex(),"adapterContainsCanonicalUniswapRouter":bytes.fromhex("b971ef87ede563556b2ed4b1c0b0019111dd85d2") in bytes(runtime),"fixedRouterGetterProbe":fixed_router_probe},
        "configuration":{"adapterWhitelisted":safe(whitelist.functions.isWhitelisted(adapter,0).call,block_identifier=latest),"routerV1Paused":safe(router_contracts[router_v1].functions.paused().call,block_identifier=latest),"routerV2Paused":safe(router_contracts[router_v2].functions.paused().call,block_identifier=latest),"routerV1Owner":safe(router_contracts[router_v1].functions.owner().call,block_identifier=latest),"routerV2Owner":safe(router_contracts[router_v2].functions.owner().call,block_identifier=latest)},
        "discovery":discovery,
        "markets":markets,
        "vaults":vaults,
        "tokenCollectionFailures":token_failures,
        "tokens":inspected,
        "currentNonzeroRouterBalances":sorted(current_nonzero,key=lambda row:float(row.get("usd") or 0),reverse=True),
    }
    result["decision"] = {
        "vulnerableAdapterLikelyDeployed": bool(value(result["configuration"]["adapterWhitelisted"],False)) and len(runtime)>0 and not bool(value(fixed_router_probe)),
        "materialCurrentBalanceUsd": sum(float(row.get("usd") or 0) for row in current_nonzero if row["router"].lower()==router_v1.lower()),
        "currentNonzeroBalanceCount": sum(1 for row in current_nonzero if row["router"].lower()==router_v1.lower()),
        "note":"A report still requires exact deployed-bytecode/source binding and a local-fork exploit. This monitor performs no live exploit.",
    }
    (OUT/"B2_ROUTER_GATE_FULL.json").write_text(json.dumps(result,indent=2,default=default),encoding="utf-8")
    compact = {"generatedAtUtc":result["generatedAtUtc"],"block":result["block"],"addresses":result["addresses"],"code":result["code"],"configuration":result["configuration"],"marketCount":len(markets),"vaultCount":len(vaults),"tokenCount":len(inspected),"currentNonzeroRouterBalances":result["currentNonzeroRouterBalances"],"decision":result["decision"]}
    (OUT/"B2_ROUTER_GATE_COMPACT.json").write_text(json.dumps(compact,indent=2,default=default),encoding="utf-8")
    print(json.dumps(compact,indent=2,default=default))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
