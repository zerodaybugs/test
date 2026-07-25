#!/usr/bin/env python3
"""Correlate PermissionsRegistry manager revocations with public account discovery.

Read-only operations only:
- Ethereum JSON-RPC logs/calls against the in-scope PermissionsRegistry;
- unsigned PAPI `getSubAccountIds(includeDelegations=true)` queries.
No signature, credential, transaction, account mutation, or private response is used.
Raw owner/manager addresses are not retained; output contains hashes and counts only.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Any

from eth_utils import keccak

OUT = pathlib.Path("manager_revocation_history")
OUT.mkdir(parents=True, exist_ok=True)

REGISTRY = "0x45F91031b33Da2585932c8f1cdFF0faa6cD329ae"
START_BLOCK = 24_500_000
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
PAPI_INFO = "https://papi.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 5 * 1024 * 1024
MAX_MANAGER_QUERIES = 60

MANAGER_PERMISSION = "0x" + keccak(text="MANAGER_PERMISSION").hex()
GRANTED_TOPIC = "0x" + keccak(text="PermissionGranted(address,address,bytes32)").hex()
REVOKED_TOPIC = "0x" + keccak(text="PermissionRevoked(address,address,bytes32)").hex()
IS_MANAGER_SELECTOR = "0x" + keccak(text="isManager(address,address)")[:4].hex()


def digest(value: str) -> str:
    return hashlib.sha256(value.lower().encode()).hexdigest()


def post_json(url: str, payload: dict[str, Any], timeout: int = 45) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_BODY + 1)


def rpc(method: str, params: list[Any]) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    errors: list[str] = []
    for url in RPC_URLS:
        try:
            status, body = post_json(url, payload)
            parsed = json.loads(body)
            if status >= 400 or "error" in parsed:
                error = parsed.get("error")
                code = error.get("code") if isinstance(error, dict) else None
                errors.append(f"status={status},code={code}")
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def get_logs(start: int, end: int) -> list[dict[str, Any]]:
    try:
        return rpc(
            "eth_getLogs",
            [
                {
                    "address": REGISTRY,
                    "fromBlock": hex(start),
                    "toBlock": hex(end),
                    "topics": [[GRANTED_TOPIC, REVOKED_TOPIC], None, None, MANAGER_PERMISSION],
                }
            ],
        )
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return get_logs(start, middle) + get_logs(middle + 1, end)


def topic_address(topic: str) -> str:
    return "0x" + topic[-40:]


def word_address(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def onchain_is_manager(owner: str, manager: str) -> bool:
    data = IS_MANAGER_SELECTOR + word_address(owner) + word_address(manager)
    raw = rpc("eth_call", [{"to": REGISTRY, "data": data}, "latest"])
    return int(raw, 16) != 0


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def account_discovery(manager: str) -> dict[str, Any]:
    status, body = post_json(
        PAPI_INFO,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": manager,
                "includeDelegations": True,
            }
        },
    )
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    counts = {"owned": 0, "delegated": 0, "managed": 0}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            counts["owned"] = len(response)
        elif isinstance(response, dict):
            counts["owned"] = len(response.get("subAccountIds", []) or [])
            counts["delegated"] = len(response.get("delegatedSubAccountIds", []) or [])
            counts["managed"] = len(response.get("managedSubAccountIds", []) or [])
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    return {
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorMessageSha256": hashlib.sha256(str(error_message).encode()).hexdigest()
        if error_message is not None
        else None,
        "responseSchema": schema(response),
        "counts": counts,
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "bodyBytes": len(body),
    }


def main() -> None:
    latest = int(rpc("eth_blockNumber", []), 16)
    logs = get_logs(START_BLOCK, latest)
    logs.sort(key=lambda item: (int(item["blockNumber"], 16), int(item["logIndex"], 16)))

    pair_state: dict[tuple[str, str], bool] = {}
    pair_history: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    manager_owners: dict[str, set[str]] = defaultdict(set)

    for log in logs:
        topics = log.get("topics", [])
        if len(topics) < 4:
            continue
        event_topic = str(topics[0]).lower()
        if event_topic not in {GRANTED_TOPIC.lower(), REVOKED_TOPIC.lower()}:
            continue
        owner = topic_address(topics[1]).lower()
        manager = topic_address(topics[2]).lower()
        granted = event_topic == GRANTED_TOPIC.lower()
        pair = (owner, manager)
        pair_state[pair] = granted
        manager_owners[manager].add(owner)
        pair_history[pair].append(
            {
                "event": "granted" if granted else "revoked",
                "blockNumber": int(log["blockNumber"], 16),
                "transactionHashSha256": hashlib.sha256(str(log["transactionHash"]).encode()).hexdigest(),
                "logIndex": int(log["logIndex"], 16),
            }
        )

    # Verify the reconstructed final state against the contract itself.
    state_mismatches: list[dict[str, Any]] = []
    for (owner, manager), reconstructed in pair_state.items():
        actual = onchain_is_manager(owner, manager)
        if actual != reconstructed:
            state_mismatches.append(
                {
                    "ownerSha256": digest(owner),
                    "managerSha256": digest(manager),
                    "reconstructed": reconstructed,
                    "onchain": actual,
                }
            )
        time.sleep(0.04)

    fully_revoked: list[str] = []
    for manager, owners in manager_owners.items():
        if all(not pair_state.get((owner, manager), False) for owner in owners):
            fully_revoked.append(manager)

    # Most recently revoked first, bounded to keep the unsigned API probe low-noise.
    def last_event_block(manager: str) -> int:
        return max(
            event["blockNumber"]
            for owner in manager_owners[manager]
            for event in pair_history[(owner, manager)]
        )

    fully_revoked.sort(key=last_event_block, reverse=True)
    queried = fully_revoked[:MAX_MANAGER_QUERIES]
    manager_results: list[dict[str, Any]] = []
    for manager in queried:
        histories = [
            event
            for owner in manager_owners[manager]
            for event in pair_history[(owner, manager)]
        ]
        histories.sort(key=lambda item: (item["blockNumber"], item["logIndex"]))
        discovery = account_discovery(manager)
        manager_results.append(
            {
                "managerSha256": digest(manager),
                "ownerCountEver": len(manager_owners[manager]),
                "grantCount": sum(event["event"] == "granted" for event in histories),
                "revokeCount": sum(event["event"] == "revoked" for event in histories),
                "lastEvent": histories[-1] if histories else None,
                "discovery": discovery,
            }
        )
        time.sleep(0.45)

    summary = {
        "safety": "Public Ethereum read-only RPC and unsigned account-discovery queries only; raw identities and account IDs are not retained.",
        "registry": REGISTRY,
        "startBlock": START_BLOCK,
        "latestBlock": latest,
        "managerPermission": MANAGER_PERMISSION,
        "managerEventCount": len(logs),
        "uniqueOwnerManagerPairs": len(pair_state),
        "uniqueManagersEver": len(manager_owners),
        "fullyRevokedManagerCount": len(fully_revoked),
        "queriedFullyRevokedManagerCount": len(queried),
        "stateMismatchCount": len(state_mismatches),
        "stateMismatches": state_mismatches,
        "fullyRevokedWithManagedIds": sum(
            item["discovery"]["counts"]["managed"] > 0 for item in manager_results
        ),
        "fullyRevokedWithDelegatedIds": sum(
            item["discovery"]["counts"]["delegated"] > 0 for item in manager_results
        ),
        "fullyRevokedWithOwnedIds": sum(
            item["discovery"]["counts"]["owned"] > 0 for item in manager_results
        ),
        "managerResults": manager_results,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "managerEventCount",
                    "uniqueOwnerManagerPairs",
                    "uniqueManagersEver",
                    "fullyRevokedManagerCount",
                    "queriedFullyRevokedManagerCount",
                    "stateMismatchCount",
                    "fullyRevokedWithManagedIds",
                    "fullyRevokedWithDelegatedIds",
                    "fullyRevokedWithOwnedIds",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
