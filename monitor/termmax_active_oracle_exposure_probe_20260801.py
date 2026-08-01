#!/usr/bin/env python3
"""Read-only TermMax active-market oracle and exposure census.

Public Ethereum state only. No signer, private key, transaction construction,
broadcast, impersonation, or state mutation.
"""
from __future__ import annotations

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

CHAIN_ID = 1
IMPLEMENTATION_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)
MARKETS = [
    "0x02d59E7C407CA565BACb0CDB1929d678786Eb2Af",
    "0xB42E5A5CddC97b1e459723f012ce99269fC3EfB7",
    "0x5fbA8eA801ea1Cf389A50e1379BaD614908C5360",
    "0x68d6fdec9e8AF84B0b8241519F488177BafD43FC",
    "0xf61d02aE5D19fA11fC825dc565cFaf264720F6C4",
    "0x546C6395be470FAeA356706d66c89429ee0D1Ef4",
    "0x4A640c87d048DBcDB1F27e1a5882fb7947446E7d",
    "0x8896204f4c3948C939Bcc556AD2361904d9A72AA",
    "0x17FbF5883eF9a8e0a756de8FDc95A4B5E20A3DA8",
    "0x57e92D2c565BaF64958a4fC820563621Dfb8f88D",
    "0xb7cf2714E3be17ea4082A4528076a97A8F3F4Fc4",
    "0x7A708678A40FEeD9eE43A83E594B29FAf9Ca0d12",
    "0x163c7607D9838793Af8dB2C6940cf275D503b379",
    "0x6c510aAe362d45A35CE60321a3f2e44ea4ea0ABe",
]

RPCS = [
    os.environ.get("ETH_RPC_URL", "").strip(),
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://rpc.mevblocker.io",
    "https://1rpc.io/eth",
    "https://eth.llamarpc.com",
]
RPCS = [x for x in RPCS if x]

MARKET_ABI = [
    {"type":"function","name":"tokens","stateMutability":"view","inputs":[],"outputs":[
        {"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"},{"type":"address"}
    ]},
    {"type":"function","name":"config","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address","name":"treasurer"},{"type":"uint64","name":"maturity"},
        {"type":"tuple","name":"feeConfig","components":[
            {"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"},{"type":"uint32"}
        ]}
    ]}]},
]
GT_ABI = [
    {"type":"function","name":"getGtConfig","stateMutability":"view","inputs":[],"outputs":[{"type":"tuple","components":[
        {"type":"address","name":"collateral"},{"type":"address","name":"debtToken"},
        {"type":"address","name":"ft"},{"type":"address","name":"treasurer"},
        {"type":"uint64","name":"maturity"},{"type":"tuple","name":"loanConfig","components":[
            {"type":"address","name":"oracle"},{"type":"uint32","name":"liquidationLtv"},
            {"type":"uint32","name":"maxLtv"},{"type":"bool","name":"liquidatable"}
        ]}
    ]}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"tokenByIndex","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"loanInfo","stateMutability":"view","inputs":[{"type":"uint256"}],"outputs":[
        {"type":"address"},{"type":"uint128"},{"type":"bytes"}
    ]},
]
ORACLE_ABI = [
    {"type":"function","name":"oracles","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[
        {"type":"address","name":"aggregator"},{"type":"address","name":"backupAggregator"},
        {"type":"int256","name":"maxPrice"},{"type":"int256","name":"minPrice"},
        {"type":"uint32","name":"heartbeat"},{"type":"uint32","name":"backupHeartbeat"}
    ]},
    {"type":"function","name":"getPrice","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"},{"type":"uint8"}]},
]
ERC20_ABI = [
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
]
ROUND_ABI = [
    {"type":"function","name":"latestRoundData","stateMutability":"view","inputs":[],"outputs":[
        {"type":"uint80"},{"type":"int256"},{"type":"uint256"},{"type":"uint256"},{"type":"uint80"}
    ]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"description","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"version","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
]

PROBE_SPECS: list[tuple[str, list[dict[str, Any]]]] = [
    ("asset", [{"type":"function","name":"asset","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("assetPriceFeed", [{"type":"function","name":"assetPriceFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("uspcOracle", [{"type":"function","name":"uspcOracle","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("linearDiscountOracle", [{"type":"function","name":"linearDiscountOracle","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("innerOracle", [{"type":"function","name":"innerOracle","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("underlyingOracle", [{"type":"function","name":"underlyingOracle","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("ondoOracle", [{"type":"function","name":"ondoOracle","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("beefyVault", [{"type":"function","name":"beefyVault","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("lpToken", [{"type":"function","name":"lpToken","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("token0PriceFeed", [{"type":"function","name":"token0PriceFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("token1PriceFeed", [{"type":"function","name":"token1PriceFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("pharosOracle", [{"type":"function","name":"pharosOracle","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("supraSValueFeed", [{"type":"function","name":"supraSValueFeed","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]}]),
    ("pairIndex", [{"type":"function","name":"pairIndex","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]}]),
    ("maxUpdateInterval", [{"type":"function","name":"maxUpdateInterval","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]}]),
    ("maturity", [{"type":"function","name":"maturity","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]}]),
]


def jdefault(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if hasattr(value, "items"):
        return dict(value)
    return str(value)


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def connect() -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in RPCS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 40}))
            chain_id = w3.eth.chain_id
            block = w3.eth.get_block("latest")
            if chain_id != CHAIN_ID:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": block.number, "hash": block.hash.hex()})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def checksum(address: str) -> str:
    return Web3.to_checksum_address(address)


def implementation(w3: Web3, address: str, block: int) -> str | None:
    raw = w3.eth.get_storage_at(checksum(address), IMPLEMENTATION_SLOT, block_identifier=block)
    if int.from_bytes(raw, "big") == 0:
        return None
    return checksum("0x" + raw[-20:].hex())


def code_info(w3: Web3, address: str, block: int) -> dict[str, Any]:
    address = checksum(address)
    code = bytes(w3.eth.get_code(address, block_identifier=block))
    impl = implementation(w3, address, block)
    row: dict[str, Any] = {
        "address": address,
        "codeBytes": len(code),
        "runtimeSha256": hashlib.sha256(code).hexdigest(),
        "implementation": impl,
    }
    if impl:
        impl_code = bytes(w3.eth.get_code(impl, block_identifier=block))
        row["implementationCodeBytes"] = len(impl_code)
        row["implementationRuntimeSha256"] = hashlib.sha256(impl_code).hexdigest()
    return row


def token_meta(w3: Web3, address: str, block: int, balance_holder: str | None = None) -> dict[str, Any]:
    address = checksum(address)
    c = w3.eth.contract(address=address, abi=ERC20_ABI)
    row = code_info(w3, address, block)
    for fn in ("symbol", "name", "decimals", "totalSupply"):
        row[fn] = safe(getattr(c.functions, fn)().call, block_identifier=block)
    if balance_holder:
        row["balanceAtHolder"] = safe(c.functions.balanceOf(checksum(balance_holder)).call, block_identifier=block)
    return row


def source_lookup(address: str) -> dict[str, Any]:
    address = checksum(address)
    endpoint = "https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api"
    try:
        response = requests.get(
            endpoint,
            params={"module":"contract","action":"getsourcecode","address":address},
            timeout=35,
            headers={"User-Agent":"ZeroDayBugs-TermMax-Readonly/4"},
        )
        response.raise_for_status()
        payload = response.json()
        result = payload.get("result", []) if isinstance(payload, dict) else []
        if isinstance(result, list) and result:
            item = result[0]
            return {
                "ok": True,
                "contractName": item.get("ContractName"),
                "compilerVersion": item.get("CompilerVersion"),
                "optimizationUsed": item.get("OptimizationUsed"),
                "runs": item.get("Runs"),
                "proxy": item.get("Proxy"),
                "implementation": item.get("Implementation"),
                "sourcePresent": bool(item.get("SourceCode")),
            }
        return {"ok": False, "error": f"unexpected response: {payload}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def inspect_feed(w3: Web3, address: str, block: int, timestamp: int) -> dict[str, Any]:
    address = checksum(address)
    row = code_info(w3, address, block)
    row["source"] = source_lookup(address)
    c = w3.eth.contract(address=address, abi=ROUND_ABI)
    for fn in ("decimals", "description", "version", "latestRoundData"):
        row[fn] = safe(getattr(c.functions, fn)().call, block_identifier=block)
    rd = row["latestRoundData"].get("value") if row["latestRoundData"].get("ok") else None
    if rd and len(rd) >= 4:
        updated = int(rd[3])
        row["updatedAt"] = updated
        row["ageSeconds"] = max(timestamp - updated, 0)
        row["updatedAtUtc"] = datetime.fromtimestamp(updated, tz=timezone.utc).isoformat() if updated else None
    probes: dict[str, Any] = {}
    for name, abi in PROBE_SPECS:
        probe = w3.eth.contract(address=address, abi=abi)
        probes[name] = safe(getattr(probe.functions, name)().call, block_identifier=block)
    row["probes"] = probes
    return row


def inspect_oracle_side(w3: Web3, oracle_address: str, asset: str, block: int, timestamp: int) -> dict[str, Any]:
    oracle_address = checksum(oracle_address)
    asset = checksum(asset)
    oracle = w3.eth.contract(address=oracle_address, abi=ORACLE_ABI)
    config_r = safe(oracle.functions.oracles(asset).call, block_identifier=block)
    price_r = safe(oracle.functions.getPrice(asset).call, block_identifier=block)
    row: dict[str, Any] = {
        "oracle": code_info(w3, oracle_address, block),
        "asset": asset,
        "configuration": config_r,
        "getPrice": price_r,
    }
    if config_r.get("ok"):
        cfg = config_r["value"]
        primary = checksum(cfg[0])
        backup = checksum(cfg[1]) if int(cfg[1], 16) else None
        row["primary"] = inspect_feed(w3, primary, block, timestamp)
        row["backup"] = inspect_feed(w3, backup, block, timestamp) if backup else None
        row["maxPrice"] = int(cfg[2])
        row["minPrice"] = int(cfg[3])
        row["heartbeat"] = int(cfg[4])
        row["backupHeartbeat"] = int(cfg[5])
    return row


def inspect_market(w3: Web3, raw_market: str, block: int, timestamp: int) -> dict[str, Any]:
    market_address = checksum(raw_market)
    market = w3.eth.contract(address=market_address, abi=MARKET_ABI)
    tokens = list(market.functions.tokens().call(block_identifier=block))
    ft, xt, gt_addr, collateral, debt = map(checksum, tokens)
    config = market.functions.config().call(block_identifier=block)
    gt = w3.eth.contract(address=gt_addr, abi=GT_ABI)
    gt_config = gt.functions.getGtConfig().call(block_identifier=block)
    loan_config = gt_config[5]
    oracle_address = checksum(loan_config[0])
    gt_supply = int(gt.functions.totalSupply().call(block_identifier=block))
    loans: list[dict[str, Any]] = []
    debt_total = 0
    for idx in range(gt_supply):
        token_id = int(gt.functions.tokenByIndex(idx).call(block_identifier=block))
        owner, debt_amt, collateral_data = gt.functions.loanInfo(token_id).call(block_identifier=block)
        debt_amt = int(debt_amt)
        debt_total += debt_amt
        loans.append({
            "tokenId": token_id,
            "owner": checksum(owner),
            "debtRaw": debt_amt,
            "collateralData": Web3.to_hex(collateral_data),
        })
    collateral_meta = token_meta(w3, collateral, block, gt_addr)
    debt_meta = token_meta(w3, debt, block, gt_addr)
    ft_meta = token_meta(w3, ft, block, market_address)
    xt_meta = token_meta(w3, xt, block, market_address)
    debt_dec = int(debt_meta["decimals"].get("value", 18)) if debt_meta["decimals"].get("ok") else 18
    debt_price = inspect_oracle_side(w3, oracle_address, debt, block, timestamp)
    collateral_price = inspect_oracle_side(w3, oracle_address, collateral, block, timestamp)
    debt_oracle_value = debt_price["getPrice"].get("value") if debt_price["getPrice"].get("ok") else None
    total_debt_value_1e8 = None
    if debt_oracle_value:
        p, p_dec = map(int, debt_oracle_value)
        total_debt_value_1e8 = debt_total * p * 10**8 // (10**debt_dec * 10**p_dec)
    maturity = int(config[1])
    return {
        "market": code_info(w3, market_address, block),
        "maturity": maturity,
        "maturityUtc": datetime.fromtimestamp(maturity, tz=timezone.utc).isoformat(),
        "active": timestamp < maturity,
        "tokens": {"ft":ft,"xt":xt,"gt":gt_addr,"collateral":collateral,"debt":debt},
        "gtConfig": {
            "treasurer": checksum(gt_config[3]),
            "maturity": int(gt_config[4]),
            "oracle": oracle_address,
            "liquidationLtv": int(loan_config[1]),
            "maxLtv": int(loan_config[2]),
            "liquidatable": bool(loan_config[3]),
        },
        "gtSupply": gt_supply,
        "loanCount": len(loans),
        "loans": loans,
        "totalDebtRaw": debt_total,
        "totalDebtValue1e8": total_debt_value_1e8,
        "collateral": collateral_meta,
        "debtToken": debt_meta,
        "ft": ft_meta,
        "xt": xt_meta,
        "collateralOracle": collateral_price,
        "debtOracle": debt_price,
    }


def main() -> int:
    w3, rpc, attempts = connect()
    block = w3.eth.get_block("latest")
    block_number = int(block.number)
    timestamp = int(block.timestamp)
    rows: list[dict[str, Any]] = []
    for index, market in enumerate(MARKETS):
        try:
            rows.append(inspect_market(w3, market, block_number, timestamp))
        except Exception as exc:  # noqa: BLE001
            rows.append({"market":{"address":market},"fatalError":f"{type(exc).__name__}: {exc}"})
        time.sleep(0.05)
    active = [r for r in rows if r.get("active")]
    material = [r for r in active if int(r.get("totalDebtValue1e8") or 0) >= 1000 * 10**8]
    result = {
        "schema":"termmax-active-oracle-exposure/v1",
        "generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signers":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "rpc":rpc,
        "rpcAttempts":attempts,
        "block":{"number":block_number,"hash":block.hash.hex(),"timestamp":timestamp,"timestampUtc":datetime.fromtimestamp(timestamp,tz=timezone.utc).isoformat()},
        "marketCount":len(rows),
        "activeMarketCount":len(active),
        "materialActiveMarketCount":len(material),
        "markets":rows,
    }
    (OUT/"ACTIVE_ORACLE_EXPOSURE_FULL.json").write_text(json.dumps(result,indent=2,default=jdefault),encoding="utf-8")
    compact=[]
    for r in rows:
        if r.get("fatalError"):
            compact.append({"market":r["market"]["address"],"fatalError":r["fatalError"]}); continue
        compact.append({
            "market":r["market"]["address"],
            "active":r["active"],
            "maturityUtc":r["maturityUtc"],
            "collateral":r["collateral"]["symbol"],
            "debtToken":r["debtToken"]["symbol"],
            "gtSupply":r["gtSupply"],
            "totalDebtRaw":r["totalDebtRaw"],
            "totalDebtValue1e8":r["totalDebtValue1e8"],
            "collateralBalanceAtGt":r["collateral"].get("balanceAtHolder"),
            "maxLtv":r["gtConfig"]["maxLtv"],
            "collateralFeed":r["collateralOracle"].get("primary",{}).get("address"),
            "collateralFeedSource":r["collateralOracle"].get("primary",{}).get("source"),
            "collateralFeedDescription":r["collateralOracle"].get("primary",{}).get("description"),
            "collateralFeedAgeSeconds":r["collateralOracle"].get("primary",{}).get("ageSeconds"),
            "collateralHeartbeat":r["collateralOracle"].get("heartbeat"),
        })
    (OUT/"ACTIVE_ORACLE_EXPOSURE_COMPACT.json").write_text(json.dumps(compact,indent=2,default=jdefault),encoding="utf-8")
    print(json.dumps({"block":result["block"],"marketCount":len(rows),"activeMarketCount":len(active),"materialActiveMarketCount":len(material)},indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
