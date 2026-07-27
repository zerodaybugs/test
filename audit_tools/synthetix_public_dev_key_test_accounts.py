#!/usr/bin/env python3
"""Find a controlled Synthetix test-API account among public development keys.

Safety:
- scans only current public source trees and ubiquitous public development mnemonics;
- queries only unsigned `getSubAccountIds` on the official test info endpoint;
- no signatures, authenticated reads, writes, trades, transactions, or account mutation;
- raw private keys and mnemonics are never written to the artifact or stdout.

A positive match would provide a deliberately public development identity suitable for later,
separately reviewed non-victim test-environment validation. This workflow itself is read-only.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from typing import Any

from eth_account import Account
from eth_utils import to_checksum_address

Account.enable_unaudited_hdwallet_features()

OUT = pathlib.Path("synthetix_public_dev_key_test_accounts")
OUT.mkdir(parents=True, exist_ok=True)
TMP = pathlib.Path("/tmp/synthetix-public-dev-key-test-accounts")
shutil.rmtree(TMP, ignore_errors=True)
TMP.mkdir(parents=True, exist_ok=True)

TEST_INFO = "https://api.test.synthetix.io/v1/info"
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024
DELAY = 0.18
MAX_CANDIDATES = 1_500
MAX_DIAGNOSTICS = 20

REPOS = (
    "Synthetixio/synthetix-deployments",
    "Synthetixio/synthetix-v3",
    "Synthetixio/synthetix-sdk",
    "Synthetixio/governance.synthetix.eth",
)

MNEMONICS = (
    "test test test test test test test test test test test junk",
    "myth like bonus scare over problem client lizard pioneer submit female collect",
    "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
    "concert load couple harbor equip island argue ramp clarify fence smart topic",
    "gesture rather obey video awake genuine patient base soon parrot upset lounge",
)

KEY_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")
TEXT_EXTENSIONS = {
    ".sol", ".js", ".jsx", ".ts", ".tsx", ".py", ".rs", ".go", ".json", ".toml",
    ".yaml", ".yml", ".md", ".txt", ".env", ".sh", ".bash", ".mjs", ".cjs",
}
SKIP_PARTS = {".git", "node_modules", "dist", "build", "artifacts", "cache", "coverage", "vendor"}


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def clone(repo: str) -> tuple[pathlib.Path | None, dict[str, Any]]:
    dest = TMP / repo.split("/")[-1]
    started = time.monotonic()
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", f"https://github.com/{repo}.git", str(dest)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180,
        check=False,
    )
    return (dest if proc.returncode == 0 else None), {
        "repository": repo,
        "success": proc.returncode == 0,
        "returnCode": proc.returncode,
        "elapsedSeconds": round(time.monotonic() - started, 2),
        "stderrSha256": sha(proc.stderr),
        "stderrExcerpt": proc.stderr[:500] if proc.returncode else None,
    }


def valid_key(hex_key: str) -> bool:
    value = int(hex_key, 16)
    return 0 < value < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def scan_repo(repo: str, root: pathlib.Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    by_address: dict[str, list[dict[str, Any]]] = defaultdict(list)
    file_count = 0
    occurrence_count = 0
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {"Dockerfile", "Makefile"}:
            continue
        try:
            if path.stat().st_size > 5_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        file_count += 1
        rel = str(path.relative_to(root))
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in KEY_RE.finditer(line):
                key = match.group(1).lower()
                if not valid_key(key):
                    continue
                occurrence_count += 1
                try:
                    address = Account.from_key("0x" + key).address.lower()
                except Exception:
                    continue
                record = {"repository": repo, "path": rel, "line": line_no, "keySha256": sha(key)}
                if record not in by_address[address]:
                    by_address[address].append(record)
    return by_address, {
        "repository": repo,
        "filesScanned": file_count,
        "literalOccurrences": occurrence_count,
        "uniqueDerivedAddresses": len(by_address),
    }


def mnemonic_candidates() -> dict[str, list[dict[str, Any]]]:
    output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for mnemonic_index, mnemonic in enumerate(MNEMONICS):
        mnemonic_hash = sha(mnemonic)
        for account_index in range(100):
            path = f"m/44'/60'/0'/0/{account_index}"
            try:
                account = Account.from_mnemonic(mnemonic, account_path=path)
            except Exception:
                continue
            output[account.address.lower()].append({
                "source": "common-public-development-mnemonic",
                "mnemonicSha256": mnemonic_hash,
                "mnemonicIndex": mnemonic_index,
                "derivationPath": path,
            })
    return output


def post_json(payload: dict[str, Any]) -> tuple[int, bytes]:
    body_bytes = json.dumps(payload, separators=(",", ":")).encode()
    last_status = 0
    last_body = b""
    for attempt in range(3):
        req = urllib.request.Request(
            TEST_INFO,
            data=body_bytes,
            headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as response:
                body = response.read(MAX_BODY + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            body = exc.read(MAX_BODY + 1)
            status = exc.code
        last_status, last_body = status, body
        if status != 429 and status < 500:
            break
        time.sleep(1.5 * (attempt + 1))
    if len(last_body) > MAX_BODY:
        raise RuntimeError("response exceeds safety cap")
    return last_status, last_body


def parse_access(status: int, body: bytes) -> tuple[dict[str, list[str]], dict[str, Any]]:
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    response = parsed.get("response") if isinstance(parsed, dict) else None
    roles = {"owned": [], "managed": [], "delegated": []}
    if status == 200 and isinstance(parsed, dict) and parsed.get("status") == "ok":
        if isinstance(response, list):
            roles["owned"] = [str(x) for x in response]
        elif isinstance(response, dict):
            roles["owned"] = [str(x) for x in (response.get("subAccountIds") or [])]
            roles["managed"] = [str(x) for x in (response.get("managedSubAccountIds") or [])]
            roles["delegated"] = [str(x) for x in (response.get("delegatedSubAccountIds") or [])]
    error = parsed.get("error") if isinstance(parsed, dict) else None
    message = error.get("message") if isinstance(error, dict) else error
    return roles, {
        "httpStatus": status,
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error.get("code") if isinstance(error, dict) else None,
        "messageSha256": sha(str(message)) if message is not None else None,
        "messageExcerpt": str(message)[:300] if message is not None else None,
        "bodySha256": sha(body),
        "bodyBytes": len(body),
    }


def main() -> None:
    candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
    clone_results = []
    repo_results = []
    for repo in REPOS:
        root, clone_meta = clone(repo)
        clone_results.append(clone_meta)
        if root is None:
            repo_results.append({"repository": repo, "cloneFailed": True})
            continue
        derived, scan_meta = scan_repo(repo, root)
        repo_results.append(scan_meta)
        for address, origins in derived.items():
            candidates[address].extend(origins)

    mnemonic_map = mnemonic_candidates()
    for address, origins in mnemonic_map.items():
        candidates[address].extend(origins)

    if len(candidates) > MAX_CANDIDATES:
        raise RuntimeError(f"candidate count {len(candidates)} exceeds safety cap {MAX_CANDIDATES}")

    positives = []
    non_ok = 0
    role_totals = defaultdict(int)
    status_counts: Counter[str] = Counter()
    diagnostics = []
    addresses = sorted(candidates)
    for index, address_lower in enumerate(addresses):
        address = to_checksum_address(address_lower)
        status, body = post_json({
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": address,
                "includeDelegations": True,
            }
        })
        roles, meta = parse_access(status, body)
        access_count = sum(len(values) for values in roles.values())
        status_key = f"http={meta['httpStatus']};api={meta['apiStatus']};code={meta['errorCode']}"
        status_counts[status_key] += 1
        if meta["httpStatus"] != 200 or meta["apiStatus"] != "ok":
            non_ok += 1
            if len(diagnostics) < MAX_DIAGNOSTICS:
                diagnostics.append({"addressSha256": sha(address_lower), "response": meta})
        if access_count:
            for role, values in roles.items():
                role_totals[role] += len(values)
            positives.append({
                "address": address,
                "addressSha256": sha(address_lower),
                "origins": candidates[address_lower],
                "counts": {role: len(values) for role, values in roles.items()},
                "accountIdSha256": {
                    role: sorted(sha(value) for value in values)
                    for role, values in roles.items()
                },
                "response": meta,
            })
        (OUT / "progress.json").write_text(json.dumps({
            "processed": index + 1,
            "total": len(addresses),
            "positiveCount": len(positives),
            "nonOkCount": non_ok,
            "statusCounts": dict(status_counts),
        }, indent=2), encoding="utf-8")
        if index + 1 < len(addresses):
            time.sleep(DELAY)

    reliable = non_ok == 0
    summary = {
        "safety": "Unsigned official test-info queries only; no raw private key or mnemonic retained.",
        "repositoryScans": repo_results,
        "cloneResults": clone_results,
        "commonMnemonicCount": len(MNEMONICS),
        "commonMnemonicDerivedAddressCount": len(mnemonic_map),
        "uniqueCandidateAddressCount": len(addresses),
        "queryNonOkCount": non_ok,
        "queryStatusCounts": dict(status_counts),
        "diagnostics": diagnostics,
        "positiveAddressCount": len(positives),
        "positiveRoleTotals": dict(role_totals),
        "positives": positives,
        "resultReliable": reliable,
        "verdict": (
            "CONTROLLED_PUBLIC_TEST_ACCOUNT_FOUND"
            if positives
            else "NO_CONTROLLED_PUBLIC_TEST_ACCOUNT_FOUND"
            if reliable
            else "INCONCLUSIVE_TEST_API_REJECTED_CANDIDATES"
        ),
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "uniqueCandidateAddressCount": summary["uniqueCandidateAddressCount"],
        "queryNonOkCount": summary["queryNonOkCount"],
        "queryStatusCounts": summary["queryStatusCounts"],
        "positiveAddressCount": summary["positiveAddressCount"],
        "positiveRoleTotals": summary["positiveRoleTotals"],
        "resultReliable": summary["resultReliable"],
        "verdict": summary["verdict"],
    }, indent=2))


if __name__ == "__main__":
    main()
