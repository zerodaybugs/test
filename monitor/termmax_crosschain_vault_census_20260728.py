#!/usr/bin/env python3
"""Public read-only TermMax V2 vault census for Base, BNB Chain and Arbitrum.

Only public JSON-RPC calls and indexed explorer GET requests are used. The
program has no signer, private key, or transaction-broadcast capability.
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
from web3._utils.events import get_event_data

OUT = Path(os.environ.get("OUT_DIR", "evidence"))
OUT.mkdir(parents=True, exist_ok=True)

CHAINS = [
    {
        "name": "base",
        "chainId": 8453,
        "routescanId": 8453,
        "factory": "0x28e47A7d7E710d796DBAFd8081c052444deEcF10",
        "factoryBlock": 44_722_441,
        "rpcs": ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"],
        "staticVaults": [],
    },
    {
        "name": "bnb",
        "chainId": 56,
        "routescanId": 56,
        "factory": "0x310ec798C59894c0eC6ce5c18060f63a37592BC7",
        "factoryBlock": 92_629_573,
        "rpcs": ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.binance.org", "https://bsc.drpc.org"],
        "staticVaults": [],
    },
    {
        "name": "arbitrum",
        "chainId": 42161,
        "routescanId": 42161,
        "factory": "0x85C5B725841bE392384aa7df599c00aE7516E4d3",
        "factoryBlock": 452_661_450,
        "rpcs": ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.drpc.org"],
        "staticVaults": [
            ("0xCb94ABCffbF5CC76a55f9c1496632A26D19f9947", 385_285_536),
            ("0xb6692aCb982c2dA0775c947Cb329B04EBFB4e0ac", 385_285_536),
        ],
    },
]

VAULT_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"pool","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"totalFt","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalAssets","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"paused","stateMutability":"view","inputs":[],"outputs":[{"type":"bool"}]},
    {"type":"function","name":"orderMaturity","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"previewWithdraw","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
]
ORDER_ABI = [
    {"type":"function","name":"market","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
]
MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}]},
    {"type":"function","name":"previewRedeem","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"},{"type":"bytes"}]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}]}]}]},
]
GT_ABI = [
    {"type":"function","name":"getCollateralValue","stateMutability":"view","inputs":[{"type":"bytes"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"uint64"},{"type":"tuple","components":[{"type":"address"},{"type":"uint32"},{"type":"uint32"},{"type":"bool"}]}]}]},
]
ORACLE_ABI = [{"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]}]
ERC20_ABI = [
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
]

VAULT_CREATED_TOPIC = "0x" + bytes(Web3.keccak(text="VaultCreated(address,address,(address,address,address,uint256,address,address,uint256,string,string,uint64,uint64))")).hex()
NEW_ORDER_TOPIC = "0x" + bytes(Web3.keccak(text="NewOrderCreated(address,address,address)")).hex()


def default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, HexBytes)):
        return "0x" + bytes(value).hex()
    return str(value)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        return {"ok": True, "value": list(value) if isinstance(value, tuple) else value}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def val(result: dict[str, Any], fallback: Any = None) -> Any:
    return result.get("value", fallback) if result.get("ok") else fallback


def parse_num(value: Any) -> int:
    if value is None or str(value).strip().lower() in {"", "0x"}:
        return 0
    if isinstance(value, int):
        return value
    text = str(value)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def connect(config: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts = []
    for url in config["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 40}))
            chain_id = w3.eth.chain_id
            block = w3.eth.block_number
            if chain_id != config["chainId"]:
                raise RuntimeError(f"chainId={chain_id}")
            attempts.append({"url": url, "ok": True, "block": block})
            return w3, url, attempts
        except Exception as exc:
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def routescan_logs(chain_id: int, address: str, start: int, end: int, topic0: str) -> list[dict[str, Any]]:
    url = f"https://api.routescan.io/v2/network/mainnet/evm/{chain_id}/etherscan/api"
    page = 1
    output = []
    while True:
        params = {"module":"logs","action":"getLogs","address":address,"fromBlock":start,"toBlock":end,"topic0":topic0,"page":page,"offset":1000}
        last = None
        for attempt in range(6):
            try:
                response = requests.get(url, params=params, timeout=60, headers={"User-Agent":"termmax-public-census/1"})
                if response.status_code == 429:
                    time.sleep(2 * (attempt + 1)); continue
                response.raise_for_status(); payload = response.json(); break
            except Exception as exc:
                last = exc; time.sleep(1.5 * (attempt + 1))
        else:
            raise RuntimeError(f"Routescan failed: {last}")
        rows = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(rows, str):
            if "No" in rows: break
            raise RuntimeError(str(payload))
        if not rows: break
        output.extend(rows)
        if len(rows) < 1000: break
        page += 1
    return output


def topic_address(topic_value: str) -> str:
    raw = topic_value[2:] if topic_value.startswith("0x") else topic_value
    return Web3.to_checksum_address("0x" + raw[-40:])


def discover_vaults(config: dict[str, Any], latest: int) -> list[tuple[str, int]]:
    output = [(Web3.to_checksum_address(address), block) for address, block in config["staticVaults"]]
    rows = routescan_logs(config["routescanId"], Web3.to_checksum_address(config["factory"]), config["factoryBlock"], latest, VAULT_CREATED_TOPIC)
    for row in rows:
        topics = row.get("topics", [])
        if len(topics) >= 2:
            output.append((topic_address(topics[1]), parse_num(row.get("blockNumber"))))
    unique = {}
    for address, block in output:
        unique.setdefault(address.lower(), (address, block))
    return list(unique.values())


def discover_orders(config: dict[str, Any], vault: str, start: int, latest: int) -> list[str]:
    rows = routescan_logs(config["routescanId"], vault, start, latest, NEW_ORDER_TOPIC)
    output = []
    for row in rows:
        topics = row.get("topics", [])
        if len(topics) >= 4:
            output.append(topic_address(topics[3]))
    return list(dict.fromkeys(output))


def token_meta(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    contract = w3.eth.contract(address=address, abi=ERC20_ABI)
    return {"address":address,"symbol":safe(contract.functions.symbol().call,block_identifier=block),"decimals":safe(contract.functions.decimals().call,block_identifier=block)}


def inspect_order(w3: Web3, vault, address: str, block: int, timestamp: int) -> dict[str, Any]:
    address = Web3.to_checksum_address(address)
    order = w3.eth.contract(address=address, abi=ORDER_ABI)
    row = {"order":address,"orderMaturity":safe(vault.functions.orderMaturity(address).call,block_identifier=block),"market":safe(order.functions.market().call,block_identifier=block)}
    market_address = val(row["market"])
    if not market_address: return row
    market_address = Web3.to_checksum_address(market_address)
    market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
    row["tokens"] = safe(market.functions.tokens().call,block_identifier=block)
    row["marketConfig"] = safe(market.functions.config().call,block_identifier=block)
    tokens = val(row["tokens"]); config = val(row["marketConfig"])
    if not tokens: return row
    ft, xt, gt, collateral, debt = [Web3.to_checksum_address(item) for item in tokens]
    row["addresses"] = {"ft":ft,"xt":xt,"gt":gt,"collateral":collateral,"debt":debt}
    ft_contract = w3.eth.contract(address=ft, abi=ERC20_ABI)
    row["ftBalance"] = safe(ft_contract.functions.balanceOf(address).call,block_identifier=block)
    amount = int(val(row["ftBalance"], 0) or 0)
    maturity = int(config[1]) if config else int(val(row["orderMaturity"],0) or 0)
    row["marketMaturity"] = maturity; row["matured"] = bool(maturity and timestamp >= maturity)
    row["debtMeta"] = token_meta(w3, debt, block)
    if amount <= 0 or not row["matured"]: return row
    row["previewRedeem"] = safe(market.functions.previewRedeem(amount).call,block_identifier=block)
    preview = val(row["previewRedeem"])
    if not preview: return row
    debt_out = int(preview[0]); delivery = bytes(preview[1])
    gt_contract = w3.eth.contract(address=gt, abi=GT_ABI)
    collateral_value = safe(gt_contract.functions.getCollateralValue(delivery).call,block_identifier=block)
    gt_config = safe(gt_contract.functions.getGtConfig().call,block_identifier=block)
    row["collateralValue1e8"] = collateral_value; row["gtConfig"] = gt_config
    recovery = None; debt_price_result = None
    gt_cfg = val(gt_config); cv = val(collateral_value); debt_decimals = int(val(row["debtMeta"]["decimals"],18) or 18)
    if gt_cfg and cv is not None:
        oracle_address = Web3.to_checksum_address(gt_cfg[5][0])
        oracle = w3.eth.contract(address=oracle_address, abi=ORACLE_ABI)
        debt_price_result = safe(oracle.functions.getPrice(debt).call,block_identifier=block)
        price = val(debt_price_result)
        if price and int(price[0]) > 0:
            debt_price, price_decimals = int(price[0]), int(price[1])
            collateral_debt = int(cv) * 10**debt_decimals * 10**price_decimals // (debt_price * 10**8)
            recovery = debt_out + collateral_debt
            row["debtPriceDecoded"] = {"price":debt_price,"decimals":price_decimals}
    row["debtPrice"] = debt_price_result
    row["economics"] = {"nominal":amount,"debtOut":debt_out,"recovery":recovery,"loss":max(0,amount-recovery) if recovery is not None else None,"quality1e18":recovery*10**18//amount if recovery is not None else None}
    return row


def inspect_vault(w3: Web3, config: dict[str, Any], address: str, created_block: int, latest: int, timestamp: int) -> dict[str, Any]:
    vault = w3.eth.contract(address=address, abi=VAULT_ABI)
    state = {name:safe(getattr(vault.functions,name)().call,block_identifier=latest) for name in ["name","symbol","asset","pool","totalFt","totalAssets","totalSupply","paused"]}
    total_assets = int(val(state["totalAssets"],0) or 0); total_supply=int(val(state["totalSupply"],0) or 0); asset=val(state["asset"])
    result={"vault":address,"createdBlock":created_block,"state":state,"assetMeta":token_meta(w3,asset,latest) if asset else None,"orders":[]}
    if not total_assets or not total_supply:
        result["economics"]={"status":"empty"}; return result
    order_addresses = discover_orders(config,address,created_block,latest)
    orders=[inspect_order(w3,vault,order,latest,timestamp) for order in order_addresses]; result["orders"]=orders
    active=[row for row in orders if int(val(row.get("orderMaturity",{}),0) or 0)>0]
    mature=[row for row in active if row.get("matured") and row.get("economics",{}).get("recovery") is not None]
    impaired=[row for row in mature if int(row["economics"].get("loss") or 0)>0]
    good=[row for row in mature if int(row["economics"].get("quality1e18") or 0)>=999_900_000_000_000_000]
    loss=sum(int(row["economics"]["loss"]) for row in impaired); capacity=sum(int(row["economics"]["nominal"]) for row in good); transfer=capacity*loss//total_assets if total_assets else 0
    decimals=int(val((result["assetMeta"] or {}).get("decimals",{}),18) or 18); price=None; pdec=None
    for row in mature:
        decoded=row.get("debtPriceDecoded")
        if decoded: price=int(decoded["price"]); pdec=int(decoded["decimals"]); break
    transfer_usd=transfer*price/(10**decimals*10**pdec) if price is not None else None
    tvl_usd=total_assets*price/(10**decimals*10**pdec) if price is not None else None
    result["economics"]={"status":"scanned","createdOrderCount":len(orders),"activeOrderCount":len(active),"matureOrderCount":len(mature),"impairedOrderCount":len(impaired),"nearParOrderCount":len(good),"knownLatentLossRaw":loss,"knownGoodCapacityRaw":capacity,"maximumFairProRataTransferRaw":transfer,"maximumFairProRataTransferUsd":transfer_usd,"totalAssetsUsd":tvl_usd,"assetDecimals":decimals,"assetPrice":price,"assetPriceDecimals":pdec,"worstOrder":max(impaired,key=lambda row:int(row["economics"]["loss"]),default=None),"bestOrder":max(good,key=lambda row:int(row["economics"]["quality1e18"]),default=None)}
    return result


def main() -> int:
    all_results=[]
    for config in CHAINS:
        try:
            w3,rpc,attempts=connect(config); latest=w3.eth.block_number; block=w3.eth.get_block(latest); timestamp=int(block.timestamp)
            vaults=discover_vaults(config,latest); rows=[]
            for index,(address,created) in enumerate(vaults,start=1):
                try: rows.append(inspect_vault(w3,config,address,created,latest,timestamp))
                except Exception as exc: rows.append({"vault":address,"createdBlock":created,"fatalError":f"{type(exc).__name__}: {exc}"})
                print(f"{config['name']} [{index}/{len(vaults)}] {address}",flush=True); time.sleep(0.2)
            ranking=sorted([{"chain":config["name"],"vault":row["vault"],"name":val(row.get("state",{}).get("name",{})),**row.get("economics",{})} for row in rows if row.get("economics",{}).get("status")=="scanned"],key=lambda row:float(row.get("maximumFairProRataTransferUsd") or 0),reverse=True)
            all_results.append({"chain":config["name"],"chainId":config["chainId"],"rpc":rpc,"rpcAttempts":attempts,"block":{"number":latest,"hash":"0x"+bytes(block.hash).hex(),"timestamp":timestamp,"timestampUtc":datetime.fromtimestamp(timestamp,tz=timezone.utc).isoformat()},"vaultCount":len(vaults),"ranking":ranking,"vaults":rows})
        except Exception as exc:
            all_results.append({"chain":config["name"],"chainId":config["chainId"],"fatalError":f"{type(exc).__name__}: {exc}"})
    global_ranking=sorted([row for chain in all_results for row in chain.get("ranking",[])],key=lambda row:float(row.get("maximumFairProRataTransferUsd") or 0),reverse=True)
    result={"schema":"termmax-crosschain-vault-census/v1","generatedAtUtc":datetime.now(timezone.utc).isoformat(),"safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},"globalRanking":global_ranking,"chains":all_results}
    compact={"generatedAtUtc":result["generatedAtUtc"],"globalRanking":global_ranking,"chains":[{"chain":row["chain"],"chainId":row["chainId"],"block":row.get("block"),"vaultCount":row.get("vaultCount"),"fatalError":row.get("fatalError"),"ranking":row.get("ranking",[])} for row in all_results]}
    (OUT/"CROSSCHAIN_CENSUS_FULL.json").write_text(json.dumps(result,indent=2,default=default),encoding="utf-8"); (OUT/"CROSSCHAIN_CENSUS_COMPACT.json").write_text(json.dumps(compact,indent=2,default=default),encoding="utf-8"); print(json.dumps(compact,indent=2,default=default)); return 0

if __name__=="__main__": raise SystemExit(main())
