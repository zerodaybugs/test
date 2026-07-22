#!/usr/bin/env python3
"""Run the public EVM snapshot with transparent multi-RPC fallback."""

from __future__ import annotations

import json
from typing import Any

import requests

import evm_public_snapshot_20260722 as snapshot

_original_endpoints = list(snapshot.RPC_ENDPOINTS)
_rpc_counter = 0


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
    raise RuntimeError(json.dumps({"method": method, "errors": errors}, sort_keys=True))


snapshot.rpc = robust_rpc
snapshot.main()
