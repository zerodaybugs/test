#!/usr/bin/env python3
"""Run the public EVM snapshot with transparent multi-provider fallback."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlencode

import evm_public_snapshot_20260722 as snapshot

_original_endpoints = list(snapshot.RPC_ENDPOINTS)
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


snapshot.rpc = robust_rpc
snapshot.main()
