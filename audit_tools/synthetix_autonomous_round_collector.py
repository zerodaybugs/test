#!/usr/bin/env python3
"""Poll and consolidate the current safe Synthetix runtime sweeps.

The collector downloads only short-lived artifacts produced in this repository, derives conservative
submission gates from their redacted summary JSON, and packages the evidence. It never interacts with
Synthetix itself.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import shutil
import time
import urllib.parse
import urllib.request
import zipfile
from typing import Any

OUT = pathlib.Path("synthetix_autonomous_round")
OUT.mkdir(parents=True, exist_ok=True)
EVIDENCE = OUT / "evidence"
EVIDENCE.mkdir(exist_ok=True)
REPO = "zerodaybugs/test"
NAMES = (
    "synthetix-query-taint-sweep",
    "synthetix-storage-taint-sweep",
    "synthetix-postmessage-fuzz",
)
POLL_SECONDS = 30
MAX_POLLS = 50


def api_json(path: str, token: str) -> Any:
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "synthetix-authorized-round-collector/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def api_bytes(path: str, token: str) -> bytes:
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "synthetix-authorized-round-collector/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read(50 * 1024 * 1024)


def newest_artifacts(token: str) -> dict[str, dict[str, Any]]:
    payload = api_json(f"/repos/{REPO}/actions/artifacts?per_page=100", token)
    output: dict[str, dict[str, Any]] = {}
    for item in payload.get("artifacts", []):
        name = item.get("name")
        if name not in NAMES or item.get("expired"):
            continue
        existing = output.get(name)
        if existing is None or str(item.get("created_at")) > str(existing.get("created_at")):
            output[name] = item
    return output


def find_summary(raw: bytes) -> tuple[str, dict[str, Any]]:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        candidates = [n for n in archive.namelist() if n.lower().endswith("summary.json")]
        if not candidates:
            raise RuntimeError("artifact contains no summary.json")
        # Prefer the shallowest canonical summary.
        name = sorted(candidates, key=lambda n: (n.count("/"), len(n)))[0]
        return name, json.loads(archive.read(name))


def scalar(document: dict[str, Any], key: str, default: Any = 0) -> Any:
    value = document.get(key, default)
    return value


def classify(name: str, summary: dict[str, Any]) -> dict[str, Any]:
    if name in {"synthetix-query-taint-sweep", "synthetix-storage-taint-sweep"}:
        execution = int(scalar(summary, "highConfidenceExecutionCount", 0) or 0)
        sinks = int(scalar(summary, "dangerousSinkCaseCount", 0) or 0)
        cross = int(scalar(summary, "crossOriginCanaryAttemptCaseCount", 0) or 0)
        if execution:
            gate = "CANDIDATE"
            reason = "inert canary executed in first-party context"
        elif sinks or cross:
            gate = "HOLD"
            reason = "taint reached a sink or attempted a cross-origin flow; manual semantics required"
        else:
            gate = "KILL"
            reason = "no dangerous sink, execution, or cross-origin canary flow"
        metrics = {"execution": execution, "sinkCases": sinks, "crossOriginCases": cross}
    elif name == "synthetix-postmessage-fuzz":
        provider = int(scalar(summary, "sensitiveProviderCallCount", 0) or 0)
        replies = int(scalar(summary, "canaryOutgoingCount", 0) or 0)
        sinks = int(scalar(summary, "sinkHitCount", 0) or 0)
        if provider:
            gate = "CANDIDATE"
            reason = "cross-origin message reached a sensitive synthetic-wallet method"
        elif replies or sinks:
            gate = "HOLD"
            reason = "cross-origin message produced a canary reply or DOM sink hit"
        else:
            gate = "KILL"
            reason = "no sensitive provider call, reply, or DOM sink hit"
        metrics = {"sensitiveProviderCalls": provider, "canaryReplies": replies, "sinkHits": sinks}
    else:
        gate, reason, metrics = "HOLD", "unknown artifact classifier", {}
    return {
        "name": name,
        "gate": gate,
        "reason": reason,
        "metrics": metrics,
        "reportedVerdict": str(summary.get("verdict", ""))[:300],
        "caseCount": summary.get("caseCount"),
    }


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required")
    artifacts: dict[str, dict[str, Any]] = {}
    for attempt in range(MAX_POLLS):
        artifacts = newest_artifacts(token)
        missing = [name for name in NAMES if name not in artifacts]
        print(json.dumps({"poll": attempt + 1, "found": sorted(artifacts), "missing": missing}))
        if not missing:
            break
        time.sleep(POLL_SECONDS)
    missing = [name for name in NAMES if name not in artifacts]
    if missing:
        raise RuntimeError(f"timed out waiting for artifacts: {missing}")

    classifications = []
    provenance = []
    for name in NAMES:
        item = artifacts[name]
        artifact_id = int(item["id"])
        raw = api_bytes(f"/repos/{REPO}/actions/artifacts/{artifact_id}/zip", token)
        archive_path = EVIDENCE / f"{name}.zip"
        archive_path.write_bytes(raw)
        summary_name, summary = find_summary(raw)
        classification = classify(name, summary)
        classification["artifactId"] = artifact_id
        classification["artifactDigest"] = item.get("digest")
        classification["summaryPath"] = summary_name
        classifications.append(classification)
        provenance.append({
            "name": name,
            "artifactId": artifact_id,
            "createdAt": item.get("created_at"),
            "digest": item.get("digest"),
            "workflowRun": item.get("workflow_run"),
        })

    overall = "CANDIDATE" if any(x["gate"] == "CANDIDATE" for x in classifications) else (
        "HOLD" if any(x["gate"] == "HOLD" for x in classifications) else "NO_SUBMISSION"
    )
    result = {
        "safety": "Consolidation only; source artifacts were generated by bounded synthetic/GET-only probes.",
        "overallGate": overall,
        "classifications": classifications,
        "provenance": provenance,
    }
    (OUT / "round_summary.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    lines = [
        "# Synthetix Autonomous Runtime Round",
        "",
        f"**Overall gate: {overall}**",
        "",
        "No item is submission-ready unless the overall gate is CANDIDATE and a separate manual root-cause, scope, impact, and duplicate review passes.",
        "",
    ]
    for item in classifications:
        lines += [
            f"## {item['name']}",
            "",
            f"- Gate: **{item['gate']}**",
            f"- Reason: {item['reason']}",
            f"- Metrics: `{json.dumps(item['metrics'], sort_keys=True)}`",
            f"- Reported verdict: `{item['reportedVerdict']}`",
            f"- Artifact digest: `{item['artifactDigest']}`",
            "",
        ]
    (OUT / "ROUND_STATUS.md").write_text("\n".join(lines), encoding="utf-8")

    zip_name = OUT / "Synthetix_Autonomous_Runtime_Round_Result.zip"
    with zipfile.ZipFile(zip_name, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(OUT.rglob("*")):
            if path.is_file() and path != zip_name:
                archive.write(path, path.relative_to(OUT))
    print(json.dumps({"overallGate": overall, "classifications": classifications, "resultZipBytes": zip_name.stat().st_size}, indent=2))


if __name__ == "__main__":
    main()
