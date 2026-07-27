#!/usr/bin/env python3
"""Download selected short-lived Synthetix research artifacts and emit a sanitized status summary.

This helper publishes no raw requests, signatures, wallet identifiers, secrets, source excerpts, or
exploit material. It keeps only artifact metadata, JSON file names, and selected scalar status fields.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import re
import urllib.request
import zipfile
from typing import Any

OUT = pathlib.Path("audit_status")
OUT.mkdir(parents=True, exist_ok=True)
REPO = "zerodaybugs/test"
ARTIFACTS = {
    "cancelall_schedule": 8652015011,
    "market_query_xss": 8659629117,
    "full_frontend_graph": 8660005480,
}
KEY_RE = re.compile(
    r"verdict|finding|vulner|exploit|bypass|xss|execut|canary|sink|match|leak|secret|credential|"
    r"private|truncat|queue|assetcount|casecount|success|accept|recover|status|error|mutation|"
    r"redirect|telemetry|danger|untrusted|source|iframe|innerhtml|postmessage|api|origin|route|"
    r"endpoint|graph|wallet|signature|account|cancel|schedule|leverage",
    re.I,
)
HEX_RE = re.compile(r"0x[0-9a-fA-F]{16,}")
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{80,}")


def redact_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    text = ADDRESS_RE.sub("<address>", text)
    text = HEX_RE.sub("<hex>", text)
    text = LONG_TOKEN_RE.sub("<long-token>", text)
    return text[:500]


def selected_scalars(value: Any, path: str = "$") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            if isinstance(item, (dict, list)):
                out.extend(selected_scalars(item, child))
            elif KEY_RE.search(str(key)):
                out.append({"path": child, "value": redact_scalar(item)})
    elif isinstance(value, list):
        # Only inspect a bounded prefix; counts are recorded separately.
        for index, item in enumerate(value[:80]):
            child = f"{path}[{index}]"
            if isinstance(item, (dict, list)):
                out.extend(selected_scalars(item, child))
    return out


def download_artifact(artifact_id: int, token: str) -> bytes:
    url = f"https://api.github.com/repos/{REPO}/actions/artifacts/{artifact_id}/zip"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "synthetix-authorized-artifact-status/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(25 * 1024 * 1024)


def inspect_zip(label: str, raw: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "label": label,
        "archiveBytes": len(raw),
        "jsonFiles": [],
        "selectedScalars": [],
    }
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        result["fileCount"] = len(names)
        result["fileNames"] = [name for name in names if not name.endswith("/")][:120]
        for name in names:
            if not name.lower().endswith(".json"):
                continue
            try:
                data = archive.read(name)
                if len(data) > 8 * 1024 * 1024:
                    continue
                parsed = json.loads(data)
            except Exception as exc:  # noqa: BLE001
                result["jsonFiles"].append({"name": name, "parseError": type(exc).__name__})
                continue
            scalars = selected_scalars(parsed)
            result["jsonFiles"].append({
                "name": name,
                "topLevelType": type(parsed).__name__,
                "topLevelKeys": sorted(parsed)[:100] if isinstance(parsed, dict) else None,
                "selectedScalarCount": len(scalars),
            })
            for item in scalars:
                item["file"] = name
                result["selectedScalars"].append(item)
        result["selectedScalars"] = result["selectedScalars"][:500]
    return result


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required")
    results = []
    for label, artifact_id in ARTIFACTS.items():
        try:
            raw = download_artifact(artifact_id, token)
            inspected = inspect_zip(label, raw)
            inspected["artifactId"] = artifact_id
            inspected["downloaded"] = True
        except Exception as exc:  # noqa: BLE001
            inspected = {
                "label": label,
                "artifactId": artifact_id,
                "downloaded": False,
                "errorType": type(exc).__name__,
                "error": str(exc)[:300],
            }
        results.append(inspected)
    output = {
        "safety": "Sanitized status only; no raw request, signature, secret, identifier, or exploit material.",
        "artifacts": results,
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "downloaded": {item["label"]: item.get("downloaded") for item in results},
        "selectedScalarCounts": {item["label"]: len(item.get("selectedScalars", [])) for item in results},
    }, indent=2))


if __name__ == "__main__":
    main()
