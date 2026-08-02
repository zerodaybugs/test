#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

ACCOUNTANT = "0xc315D6e14DDCDC7407784e2Caf815d131Bc1D3E7"
TELLER = "0x4DE413a26fC24c3FC27Cc983be70aA9c5C299387"
VAULT = "0x08c6F91e2B681FaF5e17227F2a44C307b3C1364C"
QUEUE = "0x38FC1BA73b7ED289955a07d9F11A85b6E388064A"
SCROLL_USDC = "0x06eFdBFf2a14a7c8E15944D1F4A48F9F95F663A4"
ETH_USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
ATTACKER = "0x00000000000000000000000000000000000A11cE"
ETH_EID = 30101
SCROLL_EID = 30214
ONE_SHARE = 10**6
CHAINS = {
    "ethereum": {
        "id": 1,
        "rpcs": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://rpc.mevblocker.io"],
        "lookback": 120000,
    },
    "scroll": {
        "id": 534352,
        "rpcs": ["https://scroll-rpc.publicnode.com", "https://rpc.scroll.io", "https://scroll.drpc.org"],
        "lookback": 500000,
    },
}


def cast(*args: str) -> str:
    return subprocess.check_output(["cast", *args], text=True).strip()


SIG = {name: cast("sig", name) for name in [
    "getRate()", "getRateInQuoteSafe(address)", "authority()", "canCall(address,address,bytes4)",
    "depositAndBridge(address,uint256,uint256,address,bytes,address,uint256)",
    "getAmountCanBeSent(uint32)", "getAmountCanBeReceived(uint32)", "idToChains(uint32)",
    "assetData(address)", "shareLockPeriod()", "isPaused()", "balanceOf(address)",
    "withdrawAssets(address)", "requestOnChainWithdraw(address,uint128,uint16,uint24)"
]}
EXCHANGE_TOPIC = cast("keccak", "ExchangeRateUpdated(uint96,uint96,uint64)")


def rpc(url: str, method: str, params: list, timeout: int = 35):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "content-type": "application/json", "user-agent": "ledger-consistency-gate/1"
    })
    with urllib.request.urlopen(req, timeout=timeout) as response:
        out = json.loads(response.read().decode())
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def choose(chain: str):
    failures = {}
    for url in CHAINS[chain]["rpcs"]:
        try:
            if int(rpc(url, "eth_chainId", []), 16) != CHAINS[chain]["id"]:
                raise RuntimeError("wrong chain")
            latest = int(rpc(url, "eth_blockNumber", []), 16)
            return url, latest, failures
        except Exception as exc:
            failures[url] = repr(exc)
    raise RuntimeError({"chain": chain, "failures": failures})


def h(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def aw(value: str) -> str:
    return h(value).lower().rjust(64, "0")


def bw(value: str) -> str:
    return h(value).lower().ljust(64, "0")


def uw(value: int) -> str:
    return hex(value)[2:].rjust(64, "0")


def call(url: str, to: str, data: str, block: str | int = "latest"):
    tag = hex(block) if isinstance(block, int) else block
    return rpc(url, "eth_call", [{"to": to, "data": data}, tag])


def words(raw: str) -> list[int]:
    data = h(raw)
    if not data or len(data) % 64:
        return []
    return [int(data[i:i+64], 16) for i in range(0, len(data), 64)]


def address(raw: str) -> str:
    return "0x" + h(raw)[-40:].lower()


def can_call(url: str, authority: str, user: str, target: str, selector: str) -> bool:
    data = SIG["canCall(address,address,bytes4)"] + aw(user) + aw(target) + bw(selector)
    return bool(int(call(url, authority, data), 16))


def snapshot_block(url: str):
    number = int(rpc(url, "eth_blockNumber", []), 16)
    obj = rpc(url, "eth_getBlockByNumber", [hex(number), False])
    return {"number": number, "hash": obj["hash"], "timestamp": int(obj["timestamp"], 16)}


def rate(url: str, block: str | int = "latest") -> int:
    return int(call(url, ACCOUNTANT, SIG["getRate()"], block), 16)


def fetch_events(chain: str, url: str, latest: int):
    start = max(1, latest - CHAINS[chain]["lookback"])
    events, errors = [], []
    for lo in range(start, latest + 1, 10000):
        hi = min(latest, lo + 9999)
        try:
            logs = rpc(url, "eth_getLogs", [{
                "address": ACCOUNTANT,
                "fromBlock": hex(lo),
                "toBlock": hex(hi),
                "topics": [EXCHANGE_TOPIC],
            }], 60)
            for log in logs:
                data = words(log["data"])
                if len(data) >= 3:
                    events.append({
                        "chain": chain,
                        "block": int(log["blockNumber"], 16),
                        "tx": log["transactionHash"],
                        "oldRate": data[0], "newRate": data[1], "timestamp": data[2],
                    })
        except Exception as exc:
            errors.append({"from": lo, "to": hi, "error": repr(exc)})
    events.sort(key=lambda row: (row["timestamp"], row["block"]))
    return {"startBlock": start, "endBlock": latest, "events": events, "errors": errors}


def derive_windows(histories: dict, now_ts: int):
    ee, se = histories["ethereum"]["events"], histories["scroll"]["events"]
    if not ee or not se:
        return {"complete": False, "windows": []}
    start = max(ee[0]["timestamp"], se[0]["timestamp"])
    er, sr = ee[0]["oldRate"], se[0]["oldRate"]
    timeline = sorted(ee + se, key=lambda row: (row["timestamp"], row["chain"]))
    for event in timeline:
        if event["timestamp"] > start:
            break
        if event["chain"] == "ethereum": er = event["newRate"]
        else: sr = event["newRate"]
    points = [row for row in timeline if row["timestamp"] > start] + [{"timestamp": now_ts, "chain": "terminal"}]
    windows, cursor = [], start
    for event in points:
        if event["timestamp"] > cursor and er != sr:
            windows.append({
                "kind": "scroll_to_ethereum_positive" if er > sr else "ethereum_to_scroll_positive",
                "start": cursor, "end": event["timestamp"],
                "durationSeconds": event["timestamp"] - cursor,
                "ethereumRate": er, "scrollRate": sr,
                "edgeRaw": abs(er - sr),
                "edgeBps": abs(er - sr) * 10000 / min(er, sr),
            })
        cursor = event["timestamp"]
        if event["chain"] == "ethereum": er = event["newRate"]
        elif event["chain"] == "scroll": sr = event["newRate"]
    return {"complete": True, "windows": windows}


def route_gate(eth: str, scroll: str):
    source_auth = address(call(scroll, TELLER, SIG["authority()"]))
    queue_auth = address(call(eth, QUEUE, SIG["authority()"]))
    source_asset = words(call(scroll, TELLER, SIG["assetData(address)"] + aw(SCROLL_USDC)))
    outbound = words(call(scroll, TELLER, SIG["getAmountCanBeSent(uint32)"] + uw(ETH_EID)))
    inbound = words(call(eth, TELLER, SIG["getAmountCanBeReceived(uint32)"] + uw(SCROLL_EID)))
    source_chain = words(call(scroll, TELLER, SIG["idToChains(uint32)"] + uw(ETH_EID)))
    destination_chain = words(call(eth, TELLER, SIG["idToChains(uint32)"] + uw(SCROLL_EID)))
    withdraw = words(call(eth, QUEUE, SIG["withdrawAssets(address)"] + aw(ETH_USDT)))
    liquidity = int(call(eth, ETH_USDT, SIG["balanceOf(address)"] + aw(VAULT)), 16)
    source_quote = int(call(scroll, ACCOUNTANT, SIG["getRateInQuoteSafe(address)"] + aw(SCROLL_USDC)), 16)
    destination_quote = int(call(eth, ACCOUNTANT, SIG["getRateInQuoteSafe(address)"] + aw(ETH_USDT)), 16)
    deposit_open = can_call(scroll, source_auth, ATTACKER, TELLER, SIG["depositAndBridge(address,uint256,uint256,address,bytes,address,uint256)"])
    request_open = can_call(eth, queue_auth, ATTACKER, QUEUE, SIG["requestOnChainWithdraw(address,uint128,uint16,uint24)"])
    lock = int(call(scroll, TELLER, SIG["shareLockPeriod()"]), 16)
    paused = bool(int(call(scroll, TELLER, SIG["isPaused()"]), 16))
    can_send = outbound[1] if len(outbound) > 1 else 0
    can_receive = inbound[1] if len(inbound) > 1 else 0
    capacity = withdraw[6] if len(withdraw) > 6 else 2**256 - 1
    by_liquidity = liquidity * ONE_SHARE // destination_quote if destination_quote else 0
    executable_shares = min(can_send, can_receive, capacity, by_liquidity)
    route_open = bool(deposit_open and request_open and source_asset and source_asset[0]
                      and len(source_chain) > 1 and source_chain[1]
                      and destination_chain and destination_chain[0]
                      and withdraw and withdraw[0] and lock == 0 and not paused)
    return {
        "routeOpen": route_open, "depositAndBridgeOpen": deposit_open,
        "queueRequestOpen": request_open, "sourceAssetData": source_asset,
        "outboundCapacity": outbound, "inboundCapacity": inbound,
        "sourceChainConfig": source_chain, "destinationChainConfig": destination_chain,
        "withdrawConfig": withdraw, "shareLockPeriod": lock, "paused": paused,
        "destinationLiquidityRaw": liquidity, "sourceQuote": source_quote,
        "destinationQuote": destination_quote, "executableSharesRaw": executable_shares,
    }


def main():
    outdir = Path("ledger-gate-evidence")
    outdir.mkdir(exist_ok=True)
    endpoints, latest, failures = {}, {}, {}
    for chain in CHAINS:
        endpoints[chain], latest[chain], failures[chain] = choose(chain)
    histories = {chain: fetch_events(chain, endpoints[chain], latest[chain]) for chain in CHAINS}
    windows = derive_windows(histories, int(time.time()))
    route = route_gate(endpoints["ethereum"], endpoints["scroll"])

    samples, trigger, maximum = [], None, None
    deadline = time.time() + 300
    while time.time() < deadline:
        try:
            eb, sb = snapshot_block(endpoints["ethereum"]), snapshot_block(endpoints["scroll"])
            er, sr = rate(endpoints["ethereum"]), rate(endpoints["scroll"])
            row = {
                "wallclock": int(time.time()),
                "ethereum": {**eb, "rate": er}, "scroll": {**sb, "rate": sr},
                "edgeRaw": er - sr, "edgeBps": (er - sr) * 10000 / sr,
            }
            samples.append(row)
            if maximum is None or row["edgeRaw"] > maximum["edgeRaw"]: maximum = row
            if er > sr and route["routeOpen"]:
                trigger = row
                break
        except Exception as exc:
            samples.append({"wallclock": int(time.time()), "error": repr(exc)})
        time.sleep(5)

    er, sr = rate(endpoints["ethereum"]), rate(endpoints["scroll"])
    max_shares = route["executableSharesRaw"]
    current = {
        "ethereumRate": er, "scrollRate": sr, "edgeRaw": er - sr,
        "edgeBps": (er - sr) * 10000 / sr,
        "maximumSourceInputRaw": max_shares * route["sourceQuote"] // ONE_SHARE,
        "maximumDestinationOutputRaw": max_shares * route["destinationQuote"] // ONE_SHARE,
    }
    current["maximumGrossEdgeRaw"] = max(0, current["maximumDestinationOutputRaw"] - current["maximumSourceInputRaw"])
    result = {
        "generatedAt": int(time.time()), "endpoints": endpoints, "endpointFailures": failures,
        "route": route, "histories": histories, "windows": windows,
        "samples": samples, "maximumObserved": maximum, "trigger": trigger, "current": current,
        "verdict": {"routeOpen": route["routeOpen"], "liveSubmissionConditionObserved": trigger is not None},
        "safety": {"readOnly": True, "transactionsSigned": 0, "transactionsBroadcast": 0},
    }
    (outdir / "live-gate.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    positive = [row for row in windows.get("windows", []) if row["kind"] == "scroll_to_ethereum_positive"]
    summary = {
        "routeOpen": route["routeOpen"], "liveSubmissionConditionObserved": trigger is not None,
        "sampleCount": len(samples), "currentEdgeRaw": er - sr,
        "historicalPositiveWindowCount": len(positive),
        "longestPositiveWindowSeconds": max([row["durationSeconds"] for row in positive], default=0),
        "maximumHistoricalEdgeBps": max([row["edgeBps"] for row in positive], default=0),
    }
    (outdir / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
