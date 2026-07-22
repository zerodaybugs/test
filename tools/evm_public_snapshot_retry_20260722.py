#!/usr/bin/env python3
"""Run the public EVM snapshot with transparent multi-provider fallback.

The wrapper preserves historical-call gaps per claim and replaces broad block-range RPC
log scans with four paginated Routescan topic scans. It is read-only and sends no
transaction.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlencode

import evm_public_snapshot_20260722 as snapshot

BLOCKSCOUT_RPC = "https://eth.blockscout.com/api/eth-rpc"
_original_endpoints = list(snapshot.RPC_ENDPOINTS) + [BLOCKSCOUT_RPC]
_rpc_counter = 0


def routescan_fallback(method: str, params: list[Any], timeout: int) -> Any:
    if method == "eth_getLogs":
        flt = params[0]
        query: dict[str, str] = {
            "module": "logs",
            "action": "getLogs",
            "fromBlock": str(int(flt.get("fromBlock", "0x0"), 16)),
            "toBlock": str(int(flt.get("toBlock", "0x0"), 16)),
        }
        if flt.get("address"):
            query["address"] = flt["address"]
        for index in range(4):
            key = f"topic{index}"
            if flt.get(key):
                query[key] = flt[key]
        url = snapshot.ROUTESCAN + "?" + urlencode(query)
    else:
        query = {"module": "proxy", "action": method}
        if method in {"eth_getTransactionByHash", "eth_getTransactionReceipt"}:
            query["txhash"] = params[0]
        elif method == "eth_getCode":
            query["address"] = params[0]
            query["tag"] = params[1]
        elif method == "eth_getBlockByNumber":
            query["tag"] = params[0]
            query["boolean"] = "true" if params[1] else "false"
        elif method == "eth_call":
            query["to"] = params[0]["to"]
            query["data"] = params[0]["data"]
            query["tag"] = params[1]
        elif method in {"eth_blockNumber", "eth_chainId"}:
            pass
        else:
            raise RuntimeError(f"Routescan fallback not implemented for {method}")
        url = snapshot.ROUTESCAN + "?" + urlencode(query)

    response = snapshot.SESSION.get(url, timeout=timeout)
    response.raise_for_status()
    body = response.json()
    result = body.get("result") if isinstance(body, dict) else None
    if isinstance(result, str) and result.lower().startswith("error"):
        raise RuntimeError(result)
    if isinstance(body, dict) and body.get("status") == "0" and not isinstance(result, list):
        raise RuntimeError(str(body))
    if result is None:
        raise RuntimeError(str(body))
    time.sleep(0.12)
    return result


def robust_rpc(endpoint: str, method: str, params: list[Any], timeout: int = 60) -> Any:
    global _rpc_counter
    candidates = [endpoint] + [item for item in _original_endpoints if item != endpoint]
    errors: list[dict[str, str]] = []
    for candidate in candidates:
        _rpc_counter += 1
        payload = {
            "jsonrpc": "2.0",
            "id": _rpc_counter,
            "method": method,
            "params": params,
        }
        try:
            response = snapshot.SESSION.post(candidate, json=payload, timeout=timeout)
            response.raise_for_status()
            body = response.json()
            if "error" in body:
                raise RuntimeError(str(body["error"]))
            return body["result"]
        except Exception as exc:
            errors.append({"endpoint": candidate, "error": repr(exc)})

    try:
        return routescan_fallback(method, params, timeout)
    except Exception as exc:
        errors.append({"endpoint": "routescan", "error": repr(exc)})

    raise RuntimeError(json.dumps({"method": method, "errors": errors}, sort_keys=True))


_original_read_claim_state = snapshot.read_claim_state


def safe_read_claim_state(endpoint: str, entry: dict[str, Any], block: int) -> dict[str, Any]:
    try:
        return _original_read_claim_state(endpoint, entry, block)
    except Exception as exc:
        return {
            "block": block,
            "error": repr(exc),
            "proof_valid": None,
            "claimed": None,
            "merkle_root": None,
            "get_claimable": None,
            "distributor_token_balance": None,
            "entitlement_delta": None,
        }


def paginated_topic_logs(address: str, from_block: int, to_block: int) -> list[dict[str, Any]]:
    signatures = [
        "MerkleRootUpdated(bytes32,bytes32,bytes32)",
        "Claimed(bytes32,address,address,uint256)",
        "RoleGranted(bytes32,address,address)",
        "RoleRevoked(bytes32,address,address)",
    ]
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for signature in signatures:
        topic0 = "0x" + snapshot.keccak(text=signature).hex()
        page = 1
        while True:
            query = {
                "module": "logs",
                "action": "getLogs",
                "fromBlock": str(from_block),
                "toBlock": str(to_block),
                "address": address,
                "topic0": topic0,
                "page": str(page),
                "offset": "1000",
            }
            response = snapshot.SESSION.get(
                snapshot.ROUTESCAN + "?" + urlencode(query), timeout=120
            )
            response.raise_for_status()
            body = response.json()
            rows = body.get("result") if isinstance(body, dict) else None
            if body.get("status") == "0" and isinstance(rows, str):
                if "No records found" in rows:
                    break
                raise RuntimeError(str(body))
            if not isinstance(rows, list):
                raise RuntimeError(str(body))
            for row in rows:
                key = (row.get("transactionHash", ""), row.get("logIndex", ""))
                if key not in seen:
                    seen.add(key)
                    output.append(row)
            if len(rows) < 1000:
                break
            page += 1
            if page > 100:
                raise RuntimeError(f"pagination exceeded for {signature}")
            time.sleep(0.2)
    output.sort(
        key=lambda row: (
            int(row.get("blockNumber", "0x0"), 16),
            int(row.get("transactionIndex", "0x0"), 16),
            int(row.get("logIndex", "0x0"), 16),
        )
    )
    return output


snapshot.RPC_ENDPOINTS = _original_endpoints
snapshot.rpc = robust_rpc
snapshot.read_claim_state = safe_read_claim_state
snapshot.chunked_logs = lambda endpoint, address, from_block, to_block: paginated_topic_logs(
    address, from_block, to_block
)
snapshot.main()
