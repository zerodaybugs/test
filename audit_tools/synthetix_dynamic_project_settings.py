#!/usr/bin/env python3
"""Passive audit of the public Dynamic project settings used by Synthetix Exchange.

The production browser performs this unauthenticated GET during page load. This collector
repeats that exact request, inventories the response schema, and redacts secret-like values
before persistence. No login, wallet, signature, token, POST request, or mutation is used.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import urllib.error
import urllib.request
from typing import Any

OUT = pathlib.Path("synthetix_dynamic_project_settings")
OUT.mkdir(parents=True, exist_ok=True)
ENVIRONMENT_ID = "d5f379e2-ec2d-4e7c-b541-8117684d3e98"
URL = f"https://app.dynamicauth.com/api/v0/sdk/{ENVIRONMENT_ID}/settings"
UA = "Mozilla/5.0 (compatible; authorized-passive-security-review/1.0)"
MAX_BODY = 10 * 1024 * 1024

SECRET_KEY_PATTERN = re.compile(
    r"(?:secret|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|credential|api[_-]?key)",
    re.IGNORECASE,
)
TOKEN_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}\b"),
    re.compile(r"\b0x[a-fA-F0-9]{64}\b"),
]


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 8:
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


def walk(value: Any, path: str = "$") -> tuple[Any, list[dict[str, Any]], list[dict[str, Any]]]:
    key_signals: list[dict[str, Any]] = []
    value_signals: list[dict[str, Any]] = []
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if SECRET_KEY_PATTERN.search(str(key)):
                key_signals.append({
                    "path": child_path,
                    "key": str(key),
                    "valueType": type(item).__name__,
                    "valueLength": len(str(item)) if item is not None else 0,
                    "valueSha256": digest(str(item)) if item is not None else None,
                })
                result[str(key)] = "<redacted-secret-like-field>"
                continue
            redacted, child_keys, child_values = walk(item, child_path)
            result[str(key)] = redacted
            key_signals.extend(child_keys)
            value_signals.extend(child_values)
        return result, key_signals, value_signals
    if isinstance(value, list):
        output = []
        for index, item in enumerate(value):
            redacted, child_keys, child_values = walk(item, f"{path}[{index}]")
            output.append(redacted)
            key_signals.extend(child_keys)
            value_signals.extend(child_values)
        return output, key_signals, value_signals
    if isinstance(value, str):
        matched = [pattern.pattern for pattern in TOKEN_VALUE_PATTERNS if pattern.search(value)]
        if matched:
            value_signals.append({
                "path": path,
                "patterns": matched,
                "valueLength": len(value),
                "valueSha256": digest(value),
            })
            return "<redacted-secret-like-value>", key_signals, value_signals
    return value, key_signals, value_signals


def main() -> None:
    request = urllib.request.Request(
        URL,
        headers={"User-Agent": UA, "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            headers = dict(response.headers.items())
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        final_url = exc.geturl()
    if len(body) > MAX_BODY:
        raise ValueError("response too large")

    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None

    if parsed is not None:
        redacted, key_signals, value_signals = walk(parsed)
        (OUT / "redacted_response.json").write_text(json.dumps(redacted, indent=2), encoding="utf-8")
    else:
        key_signals = []
        value_signals = []
        (OUT / "redacted_response.txt").write_text(body[:4096].decode("utf-8", "replace"), encoding="utf-8")

    summary = {
        "safety": "Exact unauthenticated production GET only; no login, wallet, signature, token, POST, or mutation.",
        "url": URL,
        "finalUrl": final_url,
        "status": status,
        "contentType": headers.get("Content-Type"),
        "accessControlAllowOrigin": headers.get("Access-Control-Allow-Origin"),
        "accessControlAllowCredentials": headers.get("Access-Control-Allow-Credentials"),
        "cacheControl": headers.get("Cache-Control"),
        "bodyBytes": len(body),
        "bodySha256": digest(body),
        "json": parsed is not None,
        "schema": schema(parsed) if parsed is not None else None,
        "secretLikeKeyCount": len(key_signals),
        "secretLikeKeys": key_signals,
        "secretLikeValueCount": len(value_signals),
        "secretLikeValues": value_signals,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
