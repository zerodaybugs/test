#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def read_hex(path: Path) -> bytes:
    text = "".join(path.read_text().split()).lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        raise ValueError(f"empty bytecode: {path}")
    return bytes.fromhex(text)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strip_solidity_metadata(data: bytes) -> tuple[bytes, bytes, int]:
    if len(data) < 2:
        return data, b"", 0
    declared = int.from_bytes(data[-2:], "big")
    total = declared + 2
    if declared == 0 or total > len(data):
        return data, b"", 0
    metadata = data[-total:]
    if not (0xA0 <= metadata[0] <= 0xBF):
        return data, b"", 0
    return data[:-total], metadata, total


def diff_ranges(left: bytes, right: bytes) -> list[dict[str, Any]]:
    maximum = max(len(left), len(right))
    points = [
        i
        for i in range(maximum)
        if (left[i] if i < len(left) else None) != (right[i] if i < len(right) else None)
    ]
    if not points:
        return []
    ranges: list[dict[str, Any]] = []
    start = prev = points[0]
    for point in points[1:]:
        if point == prev + 1:
            prev = point
            continue
        ranges.append({"start": start, "end": prev, "length": prev - start + 1})
        start = prev = point
    ranges.append({"start": start, "end": prev, "length": prev - start + 1})
    return ranges


def describe(path: Path) -> dict[str, Any]:
    raw = read_hex(path)
    executable, metadata, metadata_total = strip_solidity_metadata(raw)
    return {
        "path": str(path),
        "raw_bytes": len(raw),
        "raw_sha256": sha(raw),
        "executable_bytes": len(executable),
        "executable_sha256": sha(executable),
        "metadata_total_bytes": metadata_total,
        "metadata_sha256": sha(metadata) if metadata else None,
        "raw": raw,
        "executable": executable,
        "metadata": metadata,
    }


def compare(name: str, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": name,
        "raw_equal": left["raw"] == right["raw"],
        "executable_equal": left["executable"] == right["executable"],
        "raw_diff_ranges": diff_ranges(left["raw"], right["raw"])[:100],
        "executable_diff_ranges": diff_ranges(left["executable"], right["executable"])[:100],
        "left_raw_sha256": left["raw_sha256"],
        "right_raw_sha256": right["raw_sha256"],
        "left_executable_sha256": left["executable_sha256"],
        "right_executable_sha256": right["executable_sha256"],
        "left_metadata_sha256": left["metadata_sha256"],
        "right_metadata_sha256": right["metadata_sha256"],
    }


def public_descriptor(item: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in item.items() if k not in {"raw", "executable", "metadata"}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    contracts: dict[str, dict[str, dict[str, Any]]] = {}
    for contract in ("staker", "accumulator"):
        contracts[contract] = {}
        for label in ("pinned", "deployment", "live_official", "live_independent"):
            contracts[contract][label] = describe(args.input / f"{label}-{contract}.hex")

    comparisons: dict[str, list[dict[str, Any]]] = {}
    classifications: dict[str, str] = {}
    for contract, versions in contracts.items():
        rows = [
            compare("official_vs_independent", versions["live_official"], versions["live_independent"]),
            compare("deployment_vs_live", versions["deployment"], versions["live_official"]),
            compare("pinned_vs_live", versions["pinned"], versions["live_official"]),
            compare("pinned_vs_deployment", versions["pinned"], versions["deployment"]),
        ]
        comparisons[contract] = rows
        live_consensus = rows[0]["raw_equal"]
        deployment_exec = rows[1]["executable_equal"]
        pinned_exec = rows[2]["executable_equal"]
        if not live_consensus:
            classifications[contract] = "RPC_DISAGREEMENT"
        elif deployment_exec and pinned_exec:
            classifications[contract] = "METADATA_ONLY_DIFFERENCE"
        elif deployment_exec and not pinned_exec:
            classifications[contract] = "PINNED_EXECUTABLE_DIFFERS_FROM_DEPLOYED"
        elif not deployment_exec:
            classifications[contract] = "DEPLOYMENT_BUILD_EXECUTABLE_DIFFERS_FROM_LIVE"
        else:
            classifications[contract] = "UNRESOLVED"

    overall = all(value == "METADATA_ONLY_DIFFERENCE" for value in classifications.values())
    result = {
        "target": "Horizen Phase B staking",
        "pinned_commit": "ab92502e9da98784dfe3bd3ef933d4e9345ff628",
        "deployment_commit": "0559c9c2d55ab97f69d9f2c33f7fae93d5f8ad3c",
        "contracts": {
            contract: {
                "classification": classifications[contract],
                "versions": {label: public_descriptor(item) for label, item in versions.items()},
                "comparisons": comparisons[contract],
            }
            for contract, versions in contracts.items()
        },
        "all_executable_code_equal": overall,
        "security_verdict": "KILL_METADATA_ONLY" if overall else "HOLD_EXECUTABLE_DELTA",
        "public_network_writes": 0,
    }
    (args.output / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    lines = [
        "# Horizen runtime differential",
        "",
        f"- Overall executable-code equality: **{'PASS' if overall else 'HOLD'}**",
        f"- Security verdict: **{result['security_verdict']}**",
        "- Public-network writes: **0**",
        "",
    ]
    for contract in ("staker", "accumulator"):
        lines += [f"## {contract}", "", f"- Classification: `{classifications[contract]}`"]
        for row in comparisons[contract]:
            lines.append(
                f"- `{row['name']}`: raw_equal={str(row['raw_equal']).lower()}, "
                f"executable_equal={str(row['executable_equal']).lower()}"
            )
        lines.append("")
    (args.output / "RESULT.md").write_text("\n".join(lines))

    for contract, versions in contracts.items():
        for label, item in versions.items():
            (args.output / f"{label}-{contract}-executable.hex").write_text(
                "0x" + item["executable"].hex() + "\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
