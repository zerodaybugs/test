#!/usr/bin/env python3
"""Fixed read-only Snaxpot epoch and public-statistics disclosure probe.

The probe calls only the unauthenticated PAPI info endpoint and performs no
trading, ticket mutation, signing, or state change. Public responses are saved
verbatim so premature winning data or randomness material can be reviewed.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

OUT = pathlib.Path("snaxpot_public_epoch")
OUT.mkdir(parents=True, exist_ok=True)
URL = "https://papi.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 5 * 1024 * 1024


def post(params: dict[str, Any]) -> dict[str, Any]:
    payload = {"params": params}
    data = json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        URL,
        data=data,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read(MAX_BODY + 1)
            status = response.status
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY + 1)
        status = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
    if len(body) > MAX_BODY:
        raise ValueError("response too large")
    elapsed_ms = round((time.monotonic() - started) * 1000, 2)
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    return {
        "request": payload,
        "httpStatus": status,
        "elapsedMs": elapsed_ms,
        "headers": {
            "contentType": headers.get("Content-Type"),
            "cacheControl": headers.get("Cache-Control"),
            "requestId": headers.get("X-Request-Id") or headers.get("x-request-id"),
        },
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "bodyBytes": len(body),
        "json": parsed,
        "text": body.decode("utf-8", errors="replace") if parsed is None else None,
    }


def response_value(record: dict[str, Any]) -> Any:
    parsed = record.get("json")
    if isinstance(parsed, dict) and parsed.get("status") == "ok":
        return parsed.get("response")
    return None


def find_epoch_id(value: Any) -> int | None:
    if isinstance(value, dict):
        for key in ("epochId", "epoch_id", "id", "drawNumber", "draw_number"):
            candidate = value.get(key)
            if isinstance(candidate, int):
                return candidate
            if isinstance(candidate, str) and candidate.isdigit():
                return int(candidate)
        for nested in value.values():
            found = find_epoch_id(nested)
            if found is not None:
                return found
    if isinstance(value, list):
        for nested in value:
            found = find_epoch_id(nested)
            if found is not None:
                return found
    return None


def sensitive_paths(value: Any, path: str = "$") -> list[dict[str, Any]]:
    indicators = (
        "winning", "winner", "random", "seed", "entropy", "vrf", "reveal",
        "secret", "proof", "signature", "commit", "drawresult", "draw_result",
    )
    hits: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            normalized = str(key).replace("-", "").replace("_", "").lower()
            if any(indicator in normalized for indicator in indicators):
                hits.append({"path": child, "value": item})
            hits.extend(sensitive_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            hits.extend(sensitive_paths(item, f"{path}[{index}]"))
    return hits


def main() -> None:
    records: list[dict[str, Any]] = []
    current = post({"action": "getSnaxpotEpoch"})
    current["name"] = "current_epoch"
    records.append(current)
    current_value = response_value(current)
    epoch_id = find_epoch_id(current_value)

    time.sleep(0.75)
    stats = post({"action": "getSnaxpotTicketStats"})
    stats["name"] = "ticket_stats_default"
    records.append(stats)

    if epoch_id is not None:
        for name, candidate in (
            ("previous_epoch", max(0, epoch_id - 1)),
            ("current_epoch_explicit", epoch_id),
            ("next_epoch", epoch_id + 1),
        ):
            time.sleep(0.75)
            record = post({"action": "getSnaxpotEpoch", "epochId": candidate})
            record["name"] = name
            records.append(record)

        time.sleep(0.75)
        stats_window = post({
            "action": "getSnaxpotTicketStats",
            "startEpochId": max(0, epoch_id - 1),
            "endEpochId": epoch_id + 1,
        })
        stats_window["name"] = "ticket_stats_window"
        records.append(stats_window)

    review: list[dict[str, Any]] = []
    for record in records:
        value = response_value(record)
        review.append({
            "name": record["name"],
            "httpStatus": record["httpStatus"],
            "apiStatus": record.get("json", {}).get("status") if isinstance(record.get("json"), dict) else None,
            "request": record["request"],
            "responseType": type(value).__name__,
            "sensitiveNamedFields": sensitive_paths(value),
            "bodySha256": record["bodySha256"],
        })

    result = {
        "safety": "Unauthenticated PAPI info reads only; no signing, ticket mutation, trading, or state change.",
        "observedAtUnixMs": int(time.time() * 1000),
        "detectedCurrentEpochId": epoch_id,
        "records": records,
        "review": review,
    }
    (OUT / "epoch_responses.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    summary = {
        "detectedCurrentEpochId": epoch_id,
        "requestCount": len(records),
        "review": review,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
