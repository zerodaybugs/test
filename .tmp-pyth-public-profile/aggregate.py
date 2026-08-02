#!/usr/bin/env python3
"""Aggregate bounded shard summaries into a fail-closed global verdict."""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(os.environ.get("SHARDS_DIR", "shards"))
OUT = Path(os.environ.get("OUT_DIR", "aggregate"))
EXPECTED_SHARDS = int(os.environ.get("EXPECTED_SHARDS", "12"))
OUT.mkdir(parents=True, exist_ok=True)


def top_merge(rows: list[dict[str, Any]], key: str, limit: int = 200) -> list[dict[str, Any]]:
    rows.sort(key=lambda item: float(item.get(key) or -1e100), reverse=True)
    seen = set()
    out = []
    for row in rows:
        ident = (row.get("messageSha256"), row.get("feedId"))
        if ident in seen:
            continue
        seen.add(ident)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def main() -> int:
    summaries = [json.loads(path.read_text()) for path in sorted(ROOT.rglob("shard-*-summary.json"))]
    witnesses_by_hash: dict[str, dict[str, Any]] = {}
    for path in sorted(ROOT.rglob("shard-*-witnesses.json")):
        for row in json.loads(path.read_text()):
            witnesses_by_hash[row["messageSha256"]] = row

    channels: Counter[str] = Counter()
    parents: Counter[str] = Counter()
    target_by_feed: Counter[str] = Counter()
    schemas: Counter[str] = Counter()
    top_under: list[dict[str, Any]] = []
    top_age: list[dict[str, Any]] = []
    top_conf: list[dict[str, Any]] = []
    for summary in summaries:
        channels.update(summary.get("channels", {}))
        parents.update(summary.get("parentPrograms", {}))
        target_by_feed.update(summary.get("targetRecordsByFeed", {}))
        for row in summary.get("schemas", []):
            key = f"{row['feedId']}|{row['channel']}|{','.join(map(str, row['properties']))}"
            schemas[key] += int(row["count"])
        top_under.extend(summary.get("topConfidenceUnderstatement", []))
        top_age.extend(summary.get("topFeedAge", []))
        top_conf.extend(summary.get("topSignedConfidence", []))

    top_under = top_merge(top_under, "confidenceUnderstatementBps")
    top_age = top_merge(top_age, "feedAgeSeconds")
    top_conf = top_merge(top_conf, "signedConfidenceBps")
    witnesses = list(witnesses_by_hash.values())

    selected = sum(int(s.get("selectedTransactions", 0)) for s in summaries)
    fetched = sum(int(s.get("fetchedTransactions", 0)) for s in summaries)
    coverage = fetched / selected if selected else 0.0
    positive_under = sum(int(s.get("positiveConfidenceUnderstatementRecords", 0)) for s in summaries)
    age_4 = sum(int(s.get("targetFeedAgeAtLeast4Seconds", 0)) for s in summaries)
    age_48 = sum(int(s.get("targetFeedAgeAtLeast48Seconds", 0)) for s in summaries)
    non_default = sum(int(s.get("nonDefaultChannelMessages", 0)) for s in summaries)
    non_default_compatible = sum(int(s.get("nonDefaultChannelCompatibleTargetMessages", 0)) for s in summaries)
    parse_failures = sum(int(s.get("parseFailures", 0)) for s in summaries)

    schema_rows = []
    for key, count in schemas.most_common():
        feed_id, channel, props = key.split("|", 2)
        schema_rows.append({
            "feedId": int(feed_id),
            "channel": int(channel),
            "properties": [int(v) for v in props.split(",") if v],
            "count": count,
        })

    strongest_under = top_under[0].get("confidenceUnderstatementBps") if top_under else None
    strongest_age = top_age[0].get("feedAgeSeconds") if top_age else None
    complete = (
        len(summaries) == EXPECTED_SHARDS
        and coverage >= 0.99
        and all(s.get("status") == "PASS_PUBLIC_PAYLOAD_PROFILE_SHARD" for s in summaries)
    )
    positive = (
        (isinstance(strongest_under, (int, float)) and strongest_under > 0)
        or (isinstance(strongest_age, (int, float)) and strongest_age >= 4)
        or non_default_compatible > 0
    )
    if not complete:
        verdict = "INCOMPLETE_NO_NEGATIVE_INFERENCE"
    elif positive:
        verdict = "POSITIVE_PUBLIC_PAYLOAD_WITNESS_PRESENT"
    else:
        verdict = "COMPLETE_SAMPLE_NO_MATERIAL_WITNESS"

    summary = {
        "verdict": verdict,
        "complete": complete,
        "expectedShards": EXPECTED_SHARDS,
        "shardsFound": len(summaries),
        "selectedTransactions": selected,
        "fetchedTransactions": fetched,
        "fetchFailures": selected - fetched,
        "coverage": coverage,
        "verifiedMessages": sum(int(s.get("verifiedMessages", 0)) for s in summaries),
        "targetFeedRecords": sum(int(s.get("targetFeedRecords", 0)) for s in summaries),
        "targetRecordsByFeed": dict(target_by_feed),
        "channels": dict(channels),
        "parentPrograms": dict(parents),
        "schemas": schema_rows,
        "positiveConfidenceUnderstatementRecords": positive_under,
        "targetFeedAgeAtLeast4Seconds": age_4,
        "targetFeedAgeAtLeast48Seconds": age_48,
        "nonDefaultChannelMessages": non_default,
        "nonDefaultChannelCompatibleTargetMessages": non_default_compatible,
        "parseFailures": parse_failures,
        "strongestConfidenceUnderstatementBps": strongest_under,
        "strongestFeedAgeSeconds": strongest_age,
        "exactWitnessCount": len(witnesses),
        "topConfidenceUnderstatement": top_under,
        "topFeedAge": top_age,
        "topSignedConfidence": top_conf,
        "publicChainTransactionsSigned": 0,
        "publicChainTransactionsSent": 0,
        "publicChainWrites": 0,
    }
    (OUT / "GLOBAL_SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (OUT / "EXACT_WITNESSES.json").write_text(json.dumps(witnesses, indent=2, sort_keys=True) + "\n")

    entries = []
    for path in sorted(p for p in OUT.iterdir() if p.is_file() and p.name not in {"MANIFEST.json", "SHA256SUMS.txt"}):
        data = path.read_bytes()
        entries.append({"name": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    (OUT / "MANIFEST.json").write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n")
    with (OUT / "SHA256SUMS.txt").open("w") as handle:
        for row in entries:
            handle.write(f"{row['sha256']}  {row['name']}\n")
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
