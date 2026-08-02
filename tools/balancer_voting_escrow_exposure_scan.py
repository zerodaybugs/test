#!/usr/bin/env python3
import json
import os
import time
import urllib.request

RPCS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://rpc.flashbots.net",
    "https://eth.llamarpc.com",
]
VE = "0xC128a9954e6c874eA3d62ce62B468bA073093F25"
START_BLOCK = 14_200_000
HEADERS = {
    "content-type": "application/json",
    "accept": "application/json",
    "user-agent": "Mozilla/5.0 Balancer-read-only-security-research/1.0",
}
rpc_id = 0
active_rpc = None


def rpc(method, params, retries=4):
    global rpc_id, active_rpc
    last = None
    candidates = ([active_rpc] if active_rpc else []) + [url for url in RPCS if url != active_rpc]
    for url in candidates:
        if not url:
            continue
        for attempt in range(retries):
            rpc_id += 1
            payload = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params}
            req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=HEADERS)
            try:
                with urllib.request.urlopen(req, timeout=60) as response:
                    result = json.load(response)
                if "error" in result:
                    raise RuntimeError(result["error"])
                active_rpc = url
                return result["result"]
            except Exception as exc:
                last = exc
                time.sleep(min(2**attempt, 8))
    raise RuntimeError(f"{method} failed across all RPCs: {last}")


def batch(calls, chunk_size=40):
    global rpc_id, active_rpc
    all_results = []
    for offset in range(0, len(calls), chunk_size):
        part = calls[offset : offset + chunk_size]
        request_items = []
        ids = []
        for method, params in part:
            rpc_id += 1
            ids.append(rpc_id)
            request_items.append({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params})

        last = None
        candidates = ([active_rpc] if active_rpc else []) + [url for url in RPCS if url != active_rpc]
        succeeded = False
        for url in candidates:
            if not url:
                continue
            try:
                req = urllib.request.Request(url, data=json.dumps(request_items).encode(), headers=HEADERS)
                with urllib.request.urlopen(req, timeout=90) as response:
                    result = json.load(response)
                if not isinstance(result, list):
                    raise RuntimeError(f"batch response is not a list: {result}")
                by_id = {item["id"]: item for item in result}
                ordered = []
                for request_id in ids:
                    item = by_id[request_id]
                    if "error" in item:
                        raise RuntimeError(item["error"])
                    ordered.append(item["result"])
                all_results.extend(ordered)
                active_rpc = url
                succeeded = True
                break
            except Exception as exc:
                last = exc
        if not succeeded:
            # Conservative fallback: perform the same read-only calls one by one.
            for method, params in part:
                all_results.append(rpc(method, params))
        time.sleep(0.05)
    return all_results


def encode_address(selector, address):
    return selector + address[2:].lower().rjust(64, "0")


def main():
    sel_token = os.environ["SEL_TOKEN"]
    sel_locked = os.environ["SEL_LOCKED"]
    sel_balance = os.environ["SEL_BALANCE"]
    sel_allowance = os.environ["SEL_ALLOWANCE"]
    topic_deposit = os.environ["TOPIC_DEPOSIT"]

    latest_hex = rpc("eth_blockNumber", [])
    latest = int(latest_hex, 16)
    latest_block = rpc("eth_getBlockByNumber", [latest_hex, False])
    now = int(latest_block["timestamp"], 16)

    token_raw = rpc("eth_call", [{"to": VE, "data": sel_token}, latest_hex])
    token = "0x" + token_raw[-40:]

    logs = []
    step = 100_000
    start = START_BLOCK
    while start <= latest:
        end = min(start + step - 1, latest)
        try:
            part = rpc(
                "eth_getLogs",
                [
                    {
                        "fromBlock": hex(start),
                        "toBlock": hex(end),
                        "address": VE,
                        "topics": [topic_deposit],
                    }
                ],
                retries=2,
            )
            logs.extend(part)
            print(f"{start}-{end}: {len(part)} deposits", flush=True)
            start = end + 1
        except Exception as exc:
            if step <= 2_000:
                raise
            step //= 2
            print(f"reducing block range to {step}: {exc}", flush=True)

    providers = sorted({"0x" + log["topics"][1][-40:] for log in logs})
    print(f"unique historical deposit providers: {len(providers)}", flush=True)

    locked_calls = [
        ("eth_call", [{"to": VE, "data": encode_address(sel_locked, provider)}, latest_hex])
        for provider in providers
    ]
    locked_raw = batch(locked_calls)
    active = []
    for provider, raw in zip(providers, locked_raw):
        if not raw or raw == "0x":
            continue
        body = raw[2:].ljust(128, "0")
        amount_word = int(body[:64], 16)
        amount = amount_word & ((1 << 128) - 1)
        if amount >= 1 << 127:
            amount -= 1 << 128
        lock_end = int(body[64:128], 16)
        if amount > 0 and lock_end > now:
            active.append((provider, amount, lock_end))

    balance_calls = [
        ("eth_call", [{"to": token, "data": encode_address(sel_balance, provider)}, latest_hex])
        for provider, _, _ in active
    ]
    allowance_calls = [
        (
            "eth_call",
            [
                {
                    "to": token,
                    "data": sel_allowance
                    + provider[2:].lower().rjust(64, "0")
                    + VE[2:].lower().rjust(64, "0"),
                },
                latest_hex,
            ],
        )
        for provider, _, _ in active
    ]
    balances = batch(balance_calls) if balance_calls else []
    allowances = batch(allowance_calls) if allowance_calls else []

    rows = []
    for (provider, locked_amount, lock_end), balance_raw, allowance_raw in zip(active, balances, allowances):
        balance = int(balance_raw, 16)
        allowance = int(allowance_raw, 16)
        force_lockable = min(balance, allowance)
        rows.append(
            {
                "provider": provider,
                "locked_amount": locked_amount,
                "lock_end": lock_end,
                "free_balance": balance,
                "allowance": allowance,
                "force_lockable": force_lockable,
            }
        )
    rows.sort(key=lambda item: item["force_lockable"], reverse=True)
    exposed = [item for item in rows if item["force_lockable"] > 0]

    summary = {
        "rpc": active_rpc,
        "block": latest,
        "block_timestamp": now,
        "voting_escrow": VE,
        "token": token,
        "deposit_event_count": len(logs),
        "historical_provider_count": len(providers),
        "active_lock_count": len(active),
        "currently_exposed_wallet_count": len(exposed),
        "total_force_lockable_raw": sum(item["force_lockable"] for item in exposed),
        "max_single_wallet_force_lockable_raw": max(
            (item["force_lockable"] for item in exposed), default=0
        ),
    }
    with open("summary.json", "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)
    with open("active-locks.json", "w", encoding="utf-8") as file:
        json.dump(rows, file, indent=2)
    with open("exposed-wallets.json", "w", encoding="utf-8") as file:
        json.dump(exposed, file, indent=2)
    with open("exposed-wallets.tsv", "w", encoding="utf-8") as file:
        file.write("provider\tlocked_amount\tlock_end\tfree_balance\tallowance\tforce_lockable\n")
        for item in exposed:
            file.write(
                f"{item['provider']}\t{item['locked_amount']}\t{item['lock_end']}\t"
                f"{item['free_balance']}\t{item['allowance']}\t{item['force_lockable']}\n"
            )
    print(json.dumps(summary, indent=2))
    print(open("exposed-wallets.tsv", encoding="utf-8").read())


if __name__ == "__main__":
    main()
