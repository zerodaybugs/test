#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REST = os.environ.get("REST", "https://api.mainnet.aptoslabs.com/v1").rstrip("/")
GRAPHQL = os.environ.get(
    "GRAPHQL", "https://indexer.mainnet.aptoslabs.com/v1/graphql"
)
AAVE = os.environ.get(
    "DATA_FEEDS",
    "0x3f985798ce4975f430ef5c75776ff98a77b9f9d0fb38184d225adc9c1cc6b79b",
).lower()
PLATFORMS = [
    value.strip().lower()
    for value in os.environ.get(
        "PLATFORMS",
        "0x9976bb288ed9177b542d568fa1ac386819dc99141630e582315804840f41928a,"
        "0x3bcacb561438c55ce2a9da479df6ab486af55b2fb7070b700df36c097da732b8",
    ).split(",")
    if value.strip()
]
ROOT = Path(os.environ.get("EVIDENCE_DIR", "evidence/chainlink-cross-receiver"))
MAX_ROWS_PER_PLATFORM = int(os.environ.get("MAX_ROWS_PER_PLATFORM", "10000"))
PAGE_SIZE = 100


def http_json(url: str, body: dict[str, Any] | None = None) -> Any:
    encoded = None if body is None else json.dumps(body).encode()
    headers = {
        "Accept": "application/json",
        "User-Agent": "aave-aptos-round7-chainlink-scan",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for attempt in range(7):
        try:
            request = urllib.request.Request(url, data=encoded, headers=headers)
            with urllib.request.urlopen(request, timeout=120) as response:
                return json.loads(response.read())
        except Exception as exc:
            last = exc
            time.sleep(min(8.0, 0.75 * (attempt + 1)))
    raise RuntimeError(f"request failed for {url}: {last!r}")


def view(function: str, arguments: list[Any] | None = None) -> Any:
    return http_json(
        REST + "/view",
        {
            "function": function,
            "type_arguments": [],
            "arguments": arguments or [],
        },
    )


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
        return bytes(int(item) for item in value)
    raise TypeError(type(value))


def parse_payload_data(data: bytes) -> list[dict[str, Any]]:
    if len(data) < 64 or int.from_bytes(data[:32], "big") != 32:
        return []
    count = int.from_bytes(data[32:64], "big")
    if count > 100:
        return []

    rows: list[dict[str, Any]] = []
    if len(data) == 64 + count * 3 * 32:
        offset = 64
        for _ in range(count):
            outer = data[offset : offset + 32]
            timestamp = int.from_bytes(data[offset + 32 : offset + 64], "big")
            benchmark = int.from_bytes(data[offset + 64 : offset + 96], "big")
            rows.append(
                {
                    "format": "benchmark_timestamp",
                    "outer": "0x" + outer.hex(),
                    "inner": None,
                    "schema": None,
                    "timestamp": timestamp,
                    "benchmark": str(benchmark),
                    "report_len": 64,
                }
            )
            offset += 96
        return rows

    if len(data) == 64 + count * 13 * 32:
        offset = 64 + 32 * count
        for _ in range(count):
            if offset + 96 > len(data):
                return []
            outer = data[offset : offset + 32]
            marker = int.from_bytes(data[offset + 32 : offset + 64], "big")
            length = int.from_bytes(data[offset + 64 : offset + 96], "big")
            offset += 96
            if marker != 64 or offset + length > len(data):
                return []
            report = data[offset : offset + length]
            offset += length
            inner = report[:32] if len(report) >= 32 else b""
            schema = int.from_bytes(inner[:2], "big") if len(inner) >= 2 else None
            timestamp = (
                int.from_bytes(report[92:96], "big")
                if len(report) >= 96 and schema in (3, 4)
                else None
            )
            benchmark = (
                int.from_bytes(report[192:224], "big")
                if len(report) >= 224 and schema in (3, 4)
                else None
            )
            rows.append(
                {
                    "format": "mercury_v03",
                    "outer": "0x" + outer.hex(),
                    "inner": "0x" + inner.hex(),
                    "schema": schema,
                    "timestamp": timestamp,
                    "benchmark": str(benchmark) if benchmark is not None else None,
                    "report_len": len(report),
                }
            )
        return rows

    return []


def query_indexer(platform: str) -> list[dict[str, Any]]:
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
      ) {
        version
        sender
        timestamp
        entry_function_id_str
      }
    }"""
    rows: list[dict[str, Any]] = []
    platform_dir = ROOT / "indexer" / platform
    platform_dir.mkdir(parents=True, exist_ok=True)
    for offset in range(0, MAX_ROWS_PER_PLATFORM, PAGE_SIZE):
        payload = http_json(
            GRAPHQL,
            {
                "query": query,
                "variables": {
                    "platform": platform,
                    "limit": PAGE_SIZE,
                    "offset": offset,
                },
            },
        )
        (platform_dir / f"page_{offset:05d}.json").write_text(
            json.dumps(payload, indent=2) + "\n"
        )
        if payload.get("errors"):
            raise RuntimeError(payload["errors"])
        page = payload.get("data", {}).get("user_transactions", [])
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
    return rows


def fetch_transaction(version: str) -> tuple[str, dict[str, Any] | None, str | None]:
    target = ROOT / "transactions" / f"{version}.json"
    if target.exists():
        return version, json.loads(target.read_text()), None
    last: Exception | None = None
    for attempt in range(7):
        try:
            transaction = http_json(REST + f"/transactions/by_version/{version}")
            target.write_text(json.dumps(transaction, indent=2) + "\n")
            return version, transaction, None
        except Exception as exc:
            last = exc
            time.sleep(min(8.0, 0.75 * (attempt + 1)))
    return version, None, repr(last)


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "transactions").mkdir(exist_ok=True)

    workflow = view(f"{AAVE}::registry::get_workflow_config")[0]
    feeds_response = view(f"{AAVE}::registry::get_feeds")[0]
    allowed_owners = {
        "0x" + as_bytes(item).hex()
        for item in workflow.get("allowed_workflow_owners", [])
    }
    allowed_names = {
        "0x" + as_bytes(item).hex()
        for item in workflow.get("allowed_workflow_names", [])
    }
    aave_feeds: dict[str, dict[str, Any]] = {}
    for entry in feeds_response:
        feed_id = "0x" + as_bytes(entry.get("feed_id")).hex()
        feed = entry.get("feed", {})
        aave_feeds[feed_id] = {
            "description": feed.get("description"),
            "timestamp": int(str(feed.get("observation_timestamp") or 0)),
            "benchmark": str(feed.get("benchmark")),
        }

    (ROOT / "workflow.json").write_text(json.dumps(workflow, indent=2) + "\n")
    (ROOT / "feeds.json").write_text(json.dumps(feeds_response, indent=2) + "\n")

    indexer_rows: list[dict[str, Any]] = []
    for platform in PLATFORMS:
        rows = query_indexer(platform)
        for row in rows:
            row = dict(row)
            row["platform"] = platform
            indexer_rows.append(row)
    (ROOT / "indexer_rows.json").write_text(
        json.dumps(indexer_rows, indent=2) + "\n"
    )

    versions: list[str] = []
    platform_by_version: dict[str, str] = {}
    for row in indexer_rows:
        version = str(row["version"])
        if version not in platform_by_version:
            versions.append(version)
            platform_by_version[version] = str(row["platform"])

    transactions: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        for version, transaction, error in executor.map(fetch_transaction, versions):
            if error is not None or transaction is None:
                errors.append({"version": version, "error": error or "unknown"})
            else:
                transactions[version] = transaction
    (ROOT / "fetch_errors.json").write_text(json.dumps(errors, indent=2) + "\n")
    if errors:
        raise RuntimeError(f"transaction fetch failures: {errors[:5]}")

    parsed: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    material_candidates: list[dict[str, Any]] = []
    format_counts: dict[str, int] = {}
    receiver_counts: dict[str, int] = {}
    owner_counts: dict[str, int] = {}

    for version in versions:
        transaction = transactions[version]
        payload = transaction.get("payload", {})
        arguments = payload.get("arguments", [])
        function = str(payload.get("function", "")).lower()
        if not function.endswith("::forwarder::report") or len(arguments) < 3:
            continue
        receiver = str(arguments[0]).lower()
        raw = as_bytes(arguments[1])
        if len(raw) < 205:
            continue
        report = raw[96:]
        if len(report) < 109 or report[0] != 1:
            continue
        metadata = report[45:109]
        workflow_name = "0x" + metadata[32:42].hex()
        workflow_owner = "0x" + metadata[42:62].hex()
        feeds = parse_payload_data(report[109:])
        for feed in feeds:
            format_counts[feed["format"]] = format_counts.get(feed["format"], 0) + 1
        receiver_counts[receiver] = receiver_counts.get(receiver, 0) + 1
        owner_counts[workflow_owner] = owner_counts.get(workflow_owner, 0) + 1

        intersections: list[dict[str, Any]] = []
        for feed in feeds:
            current = aave_feeds.get(feed["outer"])
            if current is None:
                continue
            item = {
                **feed,
                "aave_description": current["description"],
                "aave_current_timestamp": current["timestamp"],
                "aave_current_benchmark": current["benchmark"],
                "newer_than_aave": (
                    feed["timestamp"] is not None
                    and int(feed["timestamp"]) > current["timestamp"]
                ),
                "different_benchmark": (
                    feed["benchmark"] is not None
                    and str(feed["benchmark"]) != current["benchmark"]
                ),
            }
            intersections.append(item)

        row = {
            "version": version,
            "platform": platform_by_version[version],
            "sender": transaction.get("sender"),
            "success": transaction.get("success"),
            "transaction_timestamp": transaction.get("timestamp"),
            "receiver": receiver,
            "receiver_is_aave": receiver == AAVE,
            "workflow_execution_id": "0x" + report[1:33].hex(),
            "report_header_timestamp": int.from_bytes(report[33:37], "big"),
            "don_id": int.from_bytes(report[37:41], "big"),
            "config_version": int.from_bytes(report[41:45], "big"),
            "workflow_cid": "0x" + metadata[:32].hex(),
            "workflow_name": workflow_name,
            "workflow_owner": workflow_owner,
            "owner_allowed_by_aave": workflow_owner in allowed_owners,
            "name_allowed_by_aave": not allowed_names or workflow_name in allowed_names,
            "metadata_report_id": int.from_bytes(metadata[62:64], "big"),
            "feed_count": len(feeds),
            "feeds": feeds,
            "aave_intersections": intersections,
        }
        parsed.append(row)

        if (
            transaction.get("success")
            and receiver != AAVE
            and row["owner_allowed_by_aave"]
            and row["name_allowed_by_aave"]
            and intersections
        ):
            candidates.append(row)
            material = [
                item
                for item in intersections
                if item["newer_than_aave"] and item["different_benchmark"]
            ]
            if material:
                material_candidates.append({**row, "material_intersections": material})

    (ROOT / "parsed_reports.json").write_text(json.dumps(parsed, indent=2) + "\n")
    (ROOT / "cross_receiver_candidates.json").write_text(
        json.dumps(candidates, indent=2) + "\n"
    )
    (ROOT / "current_material_candidates.json").write_text(
        json.dumps(material_candidates, indent=2) + "\n"
    )

    summary = [
        f"platforms={','.join(PLATFORMS)}",
        f"indexer_rows={len(indexer_rows)}",
        f"unique_transactions={len(versions)}",
        f"parsed_reports={len(parsed)}",
        f"allowed_owner_count={len(allowed_owners)}",
        f"allowed_name_count={len(allowed_names)}",
        f"cross_receiver_candidates={len(candidates)}",
        f"current_material_candidates={len(material_candidates)}",
        f"format_counts={json.dumps(format_counts, sort_keys=True)}",
        f"receiver_counts={json.dumps(receiver_counts, sort_keys=True)}",
        f"owner_counts={json.dumps(owner_counts, sort_keys=True)}",
    ]
    for candidate in candidates:
        summary.append(
            f"candidate version={candidate['version']} platform={candidate['platform']} "
            f"receiver={candidate['receiver']} owner={candidate['workflow_owner']} "
            f"intersections={len(candidate['aave_intersections'])}"
        )
    (ROOT / "summary.txt").write_text("\n".join(summary) + "\n")
    marker = (
        "CURRENT_MATERIAL_CROSS_RECEIVER_CANDIDATE"
        if material_candidates
        else "NO_CURRENT_MATERIAL_CROSS_RECEIVER_CANDIDATE"
    )
    (ROOT / marker).write_text(marker + "\n")
    print((ROOT / "summary.txt").read_text())


if __name__ == "__main__":
    main()
