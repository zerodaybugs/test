#!/usr/bin/env python3
"""Read-only historical allowance and spender audit for the in-scope Synthetix custody proxy.

Only public Ethereum JSON-RPC reads are used. No transactions are signed or submitted.
"""

from __future__ import annotations

import json
import pathlib
import time
import urllib.request
from typing import Any

OUT = pathlib.Path("allowance_history")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)

PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
COW_VAULT_RELAYER = "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110"
ZERO_ADDRESS = "0x" + "0" * 40
CREATION_BLOCK = 23_739_792
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

# keccak256("Approval(address,address,uint256)")
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"

EVENT_SIGNATURES = {
    "SLPVaultSet": "SLPVaultSet(address)",
    "SLPVaultApproved": "SLPVaultApproved(uint256)",
    "CowVaultRelayerApproved": "CowVaultRelayerApproved(address,uint256)",
    "CowApprovalRevoked": "CowApprovalRevoked(address)",
    "Upgraded": "Upgraded(address)",
    "AuthorizedTraderRoleGranted": "AuthorizedTraderRoleGranted(address)",
    "AuthorizedTraderRoleRevoked": "AuthorizedTraderRoleRevoked(address)",
}

ALLOWANCE_SELECTOR = "dd62ed3e"
SLP_VAULT_SELECTOR = "7aa4f99d"
SLP_ALLOWANCE_SELECTOR = "68d9416f"


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> Any:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "authorized-read-only-security-review/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read())


def rpc(method: str, params: list[Any]) -> Any:
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            data = post_json(url, payload)
            if "error" in data:
                errors.append(f"{url}: {data['error']}")
                continue
            return data["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def event_topic(signature: str) -> str:
    result = rpc("web3_sha3", ["0x" + signature.encode().hex()])
    if not isinstance(result, str) or len(result) != 66:
        raise ValueError(f"invalid topic for {signature}: {result!r}")
    return result.lower()


def topic_address(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def decode_topic_address(topic: str) -> str:
    return "0x" + topic[-40:]


def decode_address_word(raw: str) -> str:
    return "0x" + raw[-40:]


def decode_uint(raw: str) -> int:
    return int(raw, 16)


def word_address(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def eth_call(to: str, data: str) -> str:
    return rpc("eth_call", [{"to": to, "data": data}, "latest"])


def allowance(token: str, spender: str) -> int:
    data = "0x" + ALLOWANCE_SELECTOR + word_address(PROXY) + word_address(spender)
    return int(eth_call(token, data), 16)


def fetch_logs_range(
    address: str,
    topics: list[Any],
    start: int,
    end: int,
    *,
    min_span: int = 1_000,
) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [{"address": address, "fromBlock": hex(start), "toBlock": hex(end), "topics": topics}],
        )
    except Exception:
        if start >= end or end - start + 1 <= min_span:
            raise
        middle = (start + end) // 2
        return fetch_logs_range(address, topics, start, middle, min_span=min_span) + fetch_logs_range(
            address, topics, middle + 1, end, min_span=min_span
        )


def fetch_logs_chunked(
    address: str,
    topics: list[Any],
    start: int,
    end: int,
    *,
    chunk_size: int = 100_000,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    cursor = start
    while cursor <= end:
        chunk_end = min(end, cursor + chunk_size - 1)
        output.extend(fetch_logs_range(address, topics, cursor, chunk_end))
        cursor = chunk_end + 1
        time.sleep(0.03)
    return output


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    owner_topic = topic_address(PROXY)
    contract_topics = {name: event_topic(signature) for name, signature in EVENT_SIGNATURES.items()}
    topic_to_name = {topic: name for name, topic in contract_topics.items()}

    contract_logs = fetch_logs_chunked(PROXY, [list(contract_topics.values())], CREATION_BLOCK, latest)

    token_logs: dict[str, list[dict[str, Any]]] = {}
    for symbol, token in (("USDT", USDT), ("WETH", WETH)):
        token_logs[symbol] = fetch_logs_chunked(
            token,
            [APPROVAL_TOPIC, owner_topic],
            CREATION_BLOCK,
            latest,
        )

    decoded_contract: list[dict[str, Any]] = []
    spender_candidates: set[str] = {COW_VAULT_RELAYER.lower()}

    for log in contract_logs:
        topics = log.get("topics", [])
        if not topics:
            continue
        name = topic_to_name.get(str(topics[0]).lower(), "unknown")
        record: dict[str, Any] = {
            "event": name,
            "blockNumber": int(log["blockNumber"], 16),
            "transactionHash": log["transactionHash"],
            "logIndex": int(log["logIndex"], 16),
            "topics": topics,
            "data": log.get("data"),
        }
        if name in {
            "SLPVaultSet",
            "Upgraded",
            "AuthorizedTraderRoleGranted",
            "AuthorizedTraderRoleRevoked",
        } and len(topics) > 1:
            record["address"] = decode_topic_address(topics[1])
            if name == "SLPVaultSet" and record["address"].lower() != ZERO_ADDRESS:
                spender_candidates.add(record["address"].lower())
        elif name in {"CowVaultRelayerApproved", "CowApprovalRevoked"} and len(topics) > 1:
            record["token"] = decode_topic_address(topics[1])
            if name == "CowVaultRelayerApproved":
                record["amount"] = decode_uint(log.get("data", "0x0"))
        elif name == "SLPVaultApproved":
            record["amount"] = decode_uint(log.get("data", "0x0"))
        decoded_contract.append(record)

    decoded_approvals: list[dict[str, Any]] = []
    for symbol, logs in token_logs.items():
        for log in logs:
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            spender = decode_topic_address(topics[2]).lower()
            if spender != ZERO_ADDRESS:
                spender_candidates.add(spender)
            decoded_approvals.append(
                {
                    "token": symbol,
                    "spender": spender,
                    "amount": decode_uint(log.get("data", "0x0")),
                    "blockNumber": int(log["blockNumber"], 16),
                    "transactionHash": log["transactionHash"],
                    "logIndex": int(log["logIndex"], 16),
                }
            )

    current_slp_vault = decode_address_word(eth_call(PROXY, "0x" + SLP_VAULT_SELECTOR)).lower()
    reported_slp_allowance = int(eth_call(PROXY, "0x" + SLP_ALLOWANCE_SELECTOR), 16)

    spender_state: list[dict[str, Any]] = []
    for spender in sorted(spender_candidates):
        code = rpc("eth_getCode", [spender, "latest"])
        row: dict[str, Any] = {
            "spender": spender,
            "isCurrentSlpVault": spender == current_slp_vault,
            "isCowVaultRelayer": spender == COW_VAULT_RELAYER.lower(),
            "codeBytes": max(0, (len(code) - 2) // 2),
            "usdtAllowance": allowance(USDT, spender),
            "wethAllowance": allowance(WETH, spender),
        }
        spender_state.append(row)
        time.sleep(0.05)

    positive_nonstandard = [
        row
        for row in spender_state
        if (row["usdtAllowance"] > 0 or row["wethAllowance"] > 0)
        and not row["isCurrentSlpVault"]
        and not row["isCowVaultRelayer"]
    ]

    implementation = decode_address_word(
        rpc("eth_getStorageAt", [PROXY, EIP1967_IMPL_SLOT, "latest"])
    ).lower()
    result = {
        "latestBlock": latest,
        "proxy": PROXY,
        "implementation": implementation,
        "currentSlpVault": current_slp_vault,
        "reportedSlpAllowance": reported_slp_allowance,
        "eventTopics": contract_topics,
        "contractEvents": sorted(decoded_contract, key=lambda x: (x["blockNumber"], x["logIndex"])),
        "tokenApprovalEvents": sorted(decoded_approvals, key=lambda x: (x["blockNumber"], x["logIndex"])),
        "currentSpenderState": spender_state,
        "positiveNonstandardAllowances": positive_nonstandard,
    }
    (OUT / "allowance_history.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "latestBlock": latest,
                "contractEventCount": len(decoded_contract),
                "approvalEventCount": len(decoded_approvals),
                "currentSlpVault": current_slp_vault,
                "reportedSlpAllowance": reported_slp_allowance,
                "positiveNonstandardAllowances": positive_nonstandard,
                "spenders": spender_state,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
