#!/usr/bin/env python3
"""Scan one public Synthetix repository's full Git history for a controlled test identity.

The eight target wallets were discovered from public Deposit events plus the unsigned official test
account directory. This script reads public Git history only, derives addresses from key-shaped
literals locally, and compares them to those targets. Raw key material is never persisted or printed.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import time
from typing import Any

from eth_account import Account

OUT = pathlib.Path("synthetix_test_key_history_batch")
OUT.mkdir(parents=True, exist_ok=True)
WORK = pathlib.Path("/tmp/synthetix-test-key-history-batch")
shutil.rmtree(WORK, ignore_errors=True)
WORK.mkdir(parents=True, exist_ok=True)

REPO = os.environ.get("SOURCE_REPO", "").strip()
if not REPO or "/" not in REPO:
    raise SystemExit("SOURCE_REPO must be owner/name")

TARGETS = {
    "0x0d3dabaf73be51e2c4b7ba17c1106fb52b6c74b4",
    "0x5af764190593a723ec89b9c3e3e5a2627a3f0bb4",
    "0x797d183c50bbbae9da061488d2ecb61ec915756b",
    "0x8e474e776c2493ee997ea772ce0155215ebfafba",
    "0xc0e65f1429cf4204b1d81d41aa626bb0139fabfb",
    "0xda807318571cd0d256654889f96e2867a79e680d",
    "0xf911f95d32677a171bacb6d4e4fd29168a3d978f",
    "0xc3cf311e04c1f8c74ecf6a795ae760dc6312f345",
}
HEX64_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")
TEXT_PATH_RE = re.compile(
    r"\.(?:js|jsx|ts|tsx|mjs|cjs|py|sol|vy|rs|go|java|kt|json|toml|ya?ml|md|txt|env|sh|bash|zsh|ini|cfg|conf|properties|csv|graphql|gql|lock)$",
    re.I,
)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def derive(candidate: str) -> str | None:
    try:
        value = int(candidate, 16)
        if not (0 < value < SECP256K1_N):
            return None
        return Account.from_key(bytes.fromhex(candidate)).address.lower()
    except Exception:
        return None


def main() -> None:
    mirror = WORK / (REPO.replace("/", "__") + ".git")
    started = time.monotonic()
    clone = subprocess.run(
        ["git", "clone", "--mirror", f"https://github.com/{REPO}.git", str(mirror)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=1800,
        check=False,
    )
    clone_meta: dict[str, Any] = {
        "repository": REPO,
        "success": clone.returncode == 0,
        "returnCode": clone.returncode,
        "elapsedSeconds": round(time.monotonic() - started, 2),
        "stderrSha256": digest(clone.stderr),
        "stderrExcerpt": clone.stderr[-1000:] if clone.returncode else None,
    }
    if clone.returncode != 0:
        (OUT / "summary.json").write_text(json.dumps({"clone": clone_meta}, indent=2), encoding="utf-8")
        raise SystemExit("clone failed")

    proc = subprocess.Popen(
        [
            "git", "--git-dir", str(mirror), "log", "--all", "--reverse",
            "--format=@@COMMIT:%H", "--patch", "--unified=0", "--no-renames", "--",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
        bufsize=1,
    )
    assert proc.stdout is not None
    commit = None
    path = None
    new_line = 0
    added_lines = 0
    text_added_lines = 0
    literal_occurrences = 0
    candidate_hashes: set[str] = set()
    derived_addresses: set[str] = set()
    matches: list[dict[str, Any]] = []

    for line in proc.stdout:
        if line.startswith("@@COMMIT:"):
            commit = line.strip().split(":", 1)[1]
            path = None
            continue
        if line.startswith("+++ b/"):
            path = line[6:].strip()
            continue
        if line.startswith("@@ "):
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            new_line = int(match.group(1)) if match else 0
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added_lines += 1
        line_number = new_line
        new_line += 1
        if path and not (TEXT_PATH_RE.search(path) or pathlib.PurePosixPath(path).name in {"Dockerfile", "Makefile"}):
            continue
        text_added_lines += 1
        content = line[1:]
        for found in HEX64_RE.finditer(content):
            literal_occurrences += 1
            candidate = found.group(1).lower()
            candidate_hash = digest(candidate)
            if candidate_hash in candidate_hashes:
                continue
            candidate_hashes.add(candidate_hash)
            address = derive(candidate)
            if not address:
                continue
            derived_addresses.add(address)
            if address in TARGETS:
                matches.append({
                    "targetAddress": address,
                    "repository": REPO,
                    "commit": commit,
                    "path": path,
                    "line": line_number,
                    "publicLiteralSha256": candidate_hash,
                    "addedLineSha256": digest(content.strip()),
                })

    stderr = proc.stderr.read() if proc.stderr else ""
    return_code = proc.wait(timeout=300)
    summary = {
        "safety": "Public Git history only; raw key material is never retained; no auth/signing/state change.",
        "repository": REPO,
        "targetCount": len(TARGETS),
        "clone": clone_meta,
        "gitLogReturnCode": return_code,
        "gitLogStderrSha256": digest(stderr),
        "addedLineCount": added_lines,
        "textAddedLineCount": text_added_lines,
        "literalOccurrences": literal_occurrences,
        "uniquePrivateKeyShapedLiterals": len(candidate_hashes),
        "uniqueDerivedAddresses": len(derived_addresses),
        "matchCount": len(matches),
        "matches": matches,
        "verdict": "CONTROLLED_TEST_ACCOUNT_KEY_FOUND" if matches else "NO_MATCH_IN_REPOSITORY_HISTORY",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({k: summary[k] for k in (
        "repository", "addedLineCount", "uniquePrivateKeyShapedLiterals", "uniqueDerivedAddresses", "matchCount", "verdict"
    )}, indent=2))


if __name__ == "__main__":
    main()
