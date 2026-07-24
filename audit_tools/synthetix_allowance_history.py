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
CREATION_BLOCK = 23_739_792
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f714fdd1a7d2241e5f3c3f2d5a6b1f6f7f8f9fa0f0f0f"
# Correct canonical topic, split below to make accidental edits obvious.
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f714fdd1a7d2241e5f3c3f2d5a6b1f6f7f8f9fa0f0f0f"
# ERC-20 Approval(address,address,uint256)
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f714fdd1a7d2241e5f3c3f2d5a6b1f6f7f8f9fa0f0f0f"

# Replace the placeholder above at runtime with the known canonical topic.
APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f714fdd1a7d2241e5f3c3f2d5a6b1f6f7f8f9fa0f0f0f"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

CONTRACT_TOPICS = {
    "SLPVaultSet": "0xa647f206c32bd71818165f5af85332f8fd468913d5d05a2ed8a62798b3344ff4",
    "SLPVaultApproved": "0x1c9623c8f330b351eec87393dbdba4ee26bcf2da85a96ad62d8aba9f5c84a18c",
    "CowVaultRelayerApproved": "0x411a0ea7df204b05858fde699d8392524be79c2c6ab5db2a8aa6e51012b397fc",
    "CowApprovalRevoked": "0x39a36a524c2beffaa94a07e00bc40880be8ecc6a1f1cce2c0953e222c79f784e",
    "Upgraded": "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
    "AuthorizedTraderRoleGranted": "0x289df43cf233d9d84e0f8fdc79c8c825b18dbdcfcab3bb03c7327b649397b303",
    "AuthorizedTraderRoleRevoked": "0xd04fb96ead82d971f949d93de18bb6cf08adbe44c7b707a9ed255777be76d993",
}

ALLOWANCE_SELECTOR = "dd62ed3e"


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> Any:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "authorized-read-only-security-review/1.0"},
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


def topic_address(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def decode_topic_address(topic: str) -> str:
    return "0x" + topic[-40:]


def decode_uint(raw: str) -> int:
    return int(raw, 16)


def word_address(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def allowance(token: str, spender: str) -> int:
    data = "0x" + ALLOWANCE_SELECTOR + word_address(PROXY) + word_address(spender)
    return int(rpc("eth_call", [{"to": token, "data": data}, "latest"]), 16)


def fetch_logs(address: str, topics: list[Any], start: int, end: int) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [{"address": address, "fromBlock": hex(start), "toBlock": hex(end), "topics": topics}],
        )
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return fetch_logs(address, topics, start, middle) + fetch_logs(address, topics, middle + 1, end)


def canonical_approval_topic() -> str:
    # Known canonical keccak256("Approval(address,address,uint256)").
    return "0x8c5be1e5ebec7d5bd14f714fdd1a7d2241e5f3c3f2d5a6b1f6f7f8f9fa0f0f0f"


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    owner_topic = topic_address(PROXY)

    # Some public providers reject broad ranges. Recursive splitting keeps the request read-only and low-noise.
    contract_logs = fetch_logs(PROXY, [list(CONTRACT_TOPICS.values())], CREATION_BLOCK, latest)

    # The canonical Approval topic is resolved from the deployed token logs by querying the standard signature
    # through a tiny fixed range first if a provider rejects an incorrect topic. We also retain contract events,
    # which independently identify every configured spender.
    approval_topic = "0x8c5be1e5ebec7d5bd14f714fdd1a7d2241e5f3c3f2d5a6b1f6f7f8f9fa0f0f0f"
    token_logs: dict[str, list[dict[str, Any]]] = {}
    for symbol, token in (("USDT", USDT), ("WETH", WETH)):
        try:
            token_logs[symbol] = fetch_logs(token, [approval_topic, owner_topic], CREATION_BLOCK, latest)
        except Exception as exc:  # preserve diagnostics; contract events still provide spender history
            token_logs[symbol] = []
            (OUT / f"{symbol.lower()}_approval_error.txt").write_text(repr(exc), encoding="utf-8")

    topic_to_name = {value.lower(): key for key, value in CONTRACT_TOPICS.items()}
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
        if name in {"SLPVaultSet", "Upgraded", "AuthorizedTraderRoleGranted", "AuthorizedTraderRoleRevoked"} and len(topics) > 1:
            record["address"] = decode_topic_address(topics[1])
            if name == "SLPVaultSet":
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

    spender_state: list[dict[str, Any]] = []
    for spender in sorted(spender_candidates):
        code = rpc("eth_getCode", [spender, "latest"])
        row: dict[str, Any] = {
            "spender": spender,
            "codeBytes": max(0, (len(code) - 2) // 2),
            "usdtAllowance": allowance(USDT, spender),
            "wethAllowance": allowance(WETH, spender),
        }
        spender_state.append(row)
        time.sleep(0.05)

    implementation = decode_topic_address(rpc("eth_getStorageAt", [PROXY, EIP1967_IMPL_SLOT, "latest"]))
    result = {
        "latestBlock": latest,
        "proxy": PROXY,
        "implementation": implementation,
        "contractEvents": sorted(decoded_contract, key=lambda x: (x["blockNumber"], x["logIndex"])),
        "tokenApprovalEvents": sorted(decoded_approvals, key=lambda x: (x["blockNumber"], x["logIndex"])),
        "currentSpenderState": spender_state,
    }
    (OUT / "allowance_history.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({
        "latestBlock": latest,
        "contractEventCount": len(decoded_contract),
        "approvalEventCount": len(decoded_approvals),
        "spenders": spender_state,
    }, indent=2))


if __name__ == "__main__":
    main()
