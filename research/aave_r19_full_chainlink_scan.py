#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

REST = os.environ.get("REST", "https://api.mainnet.aptoslabs.com/v1").rstrip("/")
GRAPHQL = os.environ.get("GRAPHQL", "https://indexer.mainnet.aptoslabs.com/v1/graphql")
AAVE = os.environ.get(
    "DATA_FEEDS",
    "0x3f985798ce4975f430ef5c75776ff98a77b9f9d0fb38184d225adc9c1cc6b79b",
).lower()
PLATFORMS = [x.strip().lower() for x in os.environ.get(
    "PLATFORMS",
    "0x9976bb288ed9177b542d568fa1ac386819dc99141630e582315804840f41928a,"
    "0x3bcacb561438c55ce2a9da479df6ab486af55b2fb7070b700df36c097da732b8",
).split(",") if x.strip()]
MAX_ROWS = int(os.environ.get("MAX_ROWS_PER_PLATFORM", "1000"))
PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "100"))
ROOT = pathlib.Path(os.environ.get("EVIDENCE_DIR", "evidence/aave-r19-chainlink"))


def request_json(url: str, body: dict[str, Any] | None = None, attempts: int = 18) -> Any:
    encoded = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json", "User-Agent": "aave-r19-chainlink-scan/1.0"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, data=encoded, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            last = exc
            retry_after = exc.headers.get("Retry-After")
            if exc.code != 429 and exc.code < 500:
                raw = exc.read().decode(errors="replace")
                raise RuntimeError(f"HTTP {exc.code} {url}: {raw[:1000]}") from exc
            delay = float(retry_after) if retry_after else min(60.0, 2.0 + attempt * 3.0)
            time.sleep(delay)
        except Exception as exc:
            last = exc
            time.sleep(min(30.0, 1.0 + attempt * 2.0))
    raise RuntimeError(f"request failed for {url}: {last!r}")


def view(function: str) -> Any:
    return request_json(REST + "/view", {
        "function": function,
        "type_arguments": [],
        "arguments": [],
    })


def as_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, str):
        text = value[2:] if value.startswith("0x") else value
        try:
            return bytes.fromhex(text)
        except ValueError:
            return value.encode()
    if isinstance(value, list):
        return bytes(int(v) for v in value)
    raise TypeError(type(value))


def parse_data(data: bytes) -> list[dict[str, Any]]:
    if len(data) < 64 or int.from_bytes(data[:32], "big") != 32:
        return []
    count = int.from_bytes(data[32:64], "big")
    if count > 100:
        return []

    # Current compact format: feed id, timestamp, benchmark for each row.
    if len(data) == 64 + count * 96:
        out = []
        offset = 64
        for _ in range(count):
            outer = data[offset:offset + 32]
            timestamp = int.from_bytes(data[offset + 32:offset + 64], "big")
            benchmark = int.from_bytes(data[offset + 64:offset + 96], "big")
            out.append({
                "format": "benchmark_timestamp",
                "outer": "0x" + outer.hex(),
                "timestamp": timestamp,
                "benchmark": str(benchmark),
                "report_len": 0,
            })
            offset += 96
        return out

    # ABI dynamic reports format.
    offset = 64 + count * 32
    out = []
    for _ in range(count):
        if offset + 96 > len(data):
            return []
        outer = data[offset:offset + 32]
        marker = int.from_bytes(data[offset + 32:offset + 64], "big")
        length = int.from_bytes(data[offset + 64:offset + 96], "big")
        offset += 96
        if marker != 64 or length > 4096 or offset + length > len(data):
            return []
        report = data[offset:offset + length]
        offset += length
        inner = report[:32] if len(report) >= 32 else b""
        schema = int.from_bytes(inner[:2], "big") if len(inner) >= 2 else None
        timestamp = None
        benchmark = None
        if schema in (3, 4) and len(report) >= 224:
            timestamp = int.from_bytes(report[92:96], "big")
            benchmark = int.from_bytes(report[192:224], "big")
        out.append({
            "format": "mercury",
            "outer": "0x" + outer.hex(),
            "inner": "0x" + inner.hex(),
            "schema": schema,
            "timestamp": timestamp,
            "benchmark": str(benchmark) if benchmark is not None else None,
            "report_len": len(report),
        })
    return out


def query_rows(platform: str) -> list[dict[str, Any]]:
    query = """query Reports($platform: String!, $limit: Int!, $offset: Int!) {
      user_transactions(
        where: {
          entry_function_contract_address: {_eq: $platform},
          entry_function_module_name: {_eq: \"forwarder\"},
          entry_function_function_name: {_eq: \"report\"}
        },
        order_by: {version: desc},
        limit: $limit,
        offset: $offset
      ) { version sender timestamp entry_function_id_str }
    }"""
    rows: list[dict[str, Any]] = []
    platform_dir = ROOT / "indexer" / platform
    platform_dir.mkdir(parents=True, exist_ok=True)
    for offset in range(0, MAX_ROWS, PAGE_SIZE):
        payload = request_json(GRAPHQL, {
            "query": query,
            "variables": {"platform": platform, "limit": PAGE_SIZE, "offset": offset},
        })
        (platform_dir / f"page_{offset:05d}.json").write_text(json.dumps(payload, indent=2) + "\n")
        if payload.get("errors"):
            raise RuntimeError(payload["errors"])
        page = payload.get("data", {}).get("user_transactions", [])
        for row in page:
            row = dict(row)
            row["platform"] = platform
            rows.append(row)
        if len(page) < PAGE_SIZE:
            break
        time.sleep(1.5)
    return rows


def fetch_transaction(row: dict[str, Any]) -> tuple[str, dict[str, Any] | None, str | None]:
    version = str(row["version"])
    target = ROOT / "transactions" / f"{version}.json"
    if target.exists():
        return version, json.loads(target.read_text()), None
    try:
        tx = request_json(REST + f"/transactions/by_version/{version}", attempts=12)
        target.write_text(json.dumps(tx, indent=2) + "\n")
        time.sleep(0.08)
        return version, tx, None
    except Exception as exc:
        return version, None, repr(exc)


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "transactions").mkdir(exist_ok=True)

    workflow = view(f"{AAVE}::registry::get_workflow_config")[0]
    feed_entries = view(f"{AAVE}::registry::get_feeds")[0]
    (ROOT / "workflow.json").write_text(json.dumps(workflow, indent=2) + "\n")
    (ROOT / "feeds.json").write_text(json.dumps(feed_entries, indent=2) + "\n")

    allowed_owners = {"0x" + as_bytes(x).hex() for x in workflow.get("allowed_workflow_owners", [])}
    allowed_names = {"0x" + as_bytes(x).hex() for x in workflow.get("allowed_workflow_names", [])}
    feeds: dict[str, dict[str, Any]] = {}
    for entry in feed_entries:
        outer = "0x" + as_bytes(entry.get("feed_id")).hex()
        feed = entry.get("feed", {})
        feeds[outer] = {
            "description": feed.get("description"),
            "timestamp": int(str(feed.get("observation_timestamp") or 0)),
            "benchmark": str(feed.get("benchmark")),
        }

    rows: list[dict[str, Any]] = []
    platform_failures = []
    for platform in PLATFORMS:
        try:
            rows.extend(query_rows(platform))
        except Exception as exc:
            platform_failures.append({"platform": platform, "error": repr(exc)})
    (ROOT / "indexer_rows.json").write_text(json.dumps(rows, indent=2) + "\n")
    (ROOT / "platform_failures.json").write_text(json.dumps(platform_failures, indent=2) + "\n")

    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        unique.setdefault(str(row["version"]), row)

    txs: dict[str, dict[str, Any]] = {}
    errors = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for version, tx, error in pool.map(fetch_transaction, unique.values()):
            if tx is None:
                errors.append({"version": version, "error": error})
            else:
                txs[version] = tx
    (ROOT / "fetch_errors.json").write_text(json.dumps(errors, indent=2) + "\n")

    parsed = []
    candidates = []
    material = []
    receiver_counts: dict[str, int] = {}
    owner_counts: dict[str, int] = {}
    format_counts: dict[str, int] = {}

    for version, row in unique.items():
        tx = txs.get(version)
        if tx is None:
            continue
        payload = tx.get("payload", {})
        args = payload.get("arguments", [])
        function = str(payload.get("function", "")).lower()
        if not function.endswith("::forwarder::report") or len(args) < 3:
            continue
        receiver = str(args[0]).lower()
        raw = as_bytes(args[1])
        if len(raw) < 205:
            continue
        report = raw[96:]
        if len(report) < 109 or report[0] != 1:
            continue
        metadata = report[45:109]
        owner = "0x" + metadata[42:62].hex()
        name = "0x" + metadata[32:42].hex()
        report_rows = parse_data(report[109:])
        receiver_counts[receiver] = receiver_counts.get(receiver, 0) + 1
        owner_counts[owner] = owner_counts.get(owner, 0) + 1
        for item in report_rows:
            format_counts[item["format"]] = format_counts.get(item["format"], 0) + 1

        intersections = []
        for item in report_rows:
            current = feeds.get(item["outer"])
            if current is None:
                continue
            ts = item.get("timestamp")
            value = item.get("benchmark")
            intersections.append({
                **item,
                "aave_description": current["description"],
                "aave_timestamp": current["timestamp"],
                "aave_benchmark": current["benchmark"],
                "newer_than_aave": ts is not None and int(ts) > current["timestamp"],
                "different_benchmark": value is not None and str(value) != current["benchmark"],
            })

        record = {
            "version": version,
            "platform": row.get("platform"),
            "success": tx.get("success"),
            "sender": tx.get("sender"),
            "transaction_timestamp": tx.get("timestamp"),
            "receiver": receiver,
            "receiver_is_aave": receiver == AAVE,
            "workflow_owner": owner,
            "workflow_name": name,
            "owner_allowed": owner in allowed_owners,
            "name_allowed": not allowed_names or name in allowed_names,
            "workflow_execution_id": "0x" + report[1:33].hex(),
            "report_id": int.from_bytes(metadata[62:64], "big"),
            "feed_count": len(report_rows),
            "intersections": intersections,
        }
        parsed.append(record)
        if (tx.get("success") and receiver != AAVE and record["owner_allowed"]
                and record["name_allowed"] and intersections):
            candidates.append(record)
            m = [x for x in intersections if x["newer_than_aave"] and x["different_benchmark"]]
            if m:
                material.append({**record, "material_intersections": m})

    (ROOT / "parsed_reports.json").write_text(json.dumps(parsed, indent=2) + "\n")
    (ROOT / "cross_receiver_candidates.json").write_text(json.dumps(candidates, indent=2) + "\n")
    (ROOT / "material_candidates.json").write_text(json.dumps(material, indent=2) + "\n")

    summary = {
        "platforms": PLATFORMS,
        "platform_failures": platform_failures,
        "indexer_rows": len(rows),
        "unique_transactions": len(unique),
        "fetched_transactions": len(txs),
        "fetch_errors": len(errors),
        "parsed_reports": len(parsed),
        "cross_receiver_candidates": len(candidates),
        "material_candidates": len(material),
        "allowed_owners": sorted(allowed_owners),
        "allowed_names": sorted(allowed_names),
        "receiver_counts": receiver_counts,
        "owner_counts": owner_counts,
        "format_counts": format_counts,
        "aave_feed_count": len(feeds),
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    marker = "MATERIAL_CANDIDATE_FOUND" if material else "NO_MATERIAL_CANDIDATE"
    (ROOT / marker).write_text(marker + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
