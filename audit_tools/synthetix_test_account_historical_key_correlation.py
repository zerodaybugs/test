#!/usr/bin/env python3
"""Find an intentionally public key for an official Synthetix test-API account.

Eight wallets were independently discovered through public production Deposit events plus unsigned
`api.test.synthetix.io` account discovery. This workflow scans the complete public Git history of
selected Synthetix repositories and common public development mnemonics, derives addresses from
private-key-shaped literals, and compares them with those eight test-account wallets.

A match would provide a non-victim, publicly provisioned test account for controlled backend
atomicity/authorization research. Raw key material is never persisted or printed.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import time
from typing import Any

from eth_account import Account
from eth_utils import to_checksum_address

OUT = pathlib.Path("synthetix_test_account_historical_key_correlation")
OUT.mkdir(parents=True, exist_ok=True)
WORK = pathlib.Path("/tmp/synthetix-test-account-key-correlation")
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir(parents=True)

TARGETS = {
    "0x0d3DABaF73BE51E2C4b7BA17C1106Fb52b6C74B4": ["2003358770012360704"],
    "0x5AF764190593a723EC89B9C3e3e5a2627a3f0Bb4": ["2009730014160883712"],
    "0x797D183C50bbbaE9DA061488d2Ecb61ec915756B": ["2012031247559168000"],
    "0x8e474E776c2493EE997Ea772cE0155215eBfAFbA": ["2001293319249858560"],
    "0xC0e65F1429Cf4204B1D81D41aa626BB0139FaBfB": ["2003466144417058816"],
    "0xDA807318571Cd0d256654889f96E2867A79E680d": ["2001287807179427840"],
    "0xF911f95D32677a171BACB6d4E4FD29168a3D978f": ["2001293305760976896"],
    "0xc3Cf311e04c1f8C74eCF6a795Ae760dc6312F345": ["2001290706823417856"],
}
TARGET_LOWER = {address.lower(): ids for address, ids in TARGETS.items()}

REPOSITORIES = (
    "Synthetixio/synthetix-deployments",
    "Synthetixio/synthetix-v3",
    "Synthetixio/synthetix-sdk",
    "Synthetixio/governance.synthetix.eth",
)
PUBLIC_DEV_MNEMONICS = (
    "test test test test test test test test test test test junk",
    "myth like bonus scare over problem client lizard pioneer submit female collect",
    "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
    "concert load couple harbor equip island argue ramp clarify fence smart topic",
    "gesture rather obey video awake genuine patient base soon parrot upset lounge",
)
HEX64_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")
TEXT_PATH_RE = re.compile(
    r"\.(?:js|jsx|ts|tsx|py|sol|rs|go|java|kt|json|toml|ya?ml|md|txt|env|sh|bash|zsh|ini|cfg|conf|properties|csv|graphql|lock)$",
    re.I,
)


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def derive(candidate: str) -> str | None:
    try:
        if int(candidate, 16) <= 0:
            return None
        return Account.from_key(bytes.fromhex(candidate)).address
    except Exception:
        return None


def clone_mirror(repo: str) -> tuple[pathlib.Path, dict[str, Any]]:
    target = WORK / (repo.split("/", 1)[1] + ".git")
    started = time.monotonic()
    proc = subprocess.run(
        ["git", "clone", "--mirror", f"https://github.com/{repo}.git", str(target)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=900,
        check=False,
    )
    return target, {
        "repository": repo,
        "success": proc.returncode == 0,
        "returnCode": proc.returncode,
        "elapsedSeconds": round(time.monotonic() - started, 2),
        "stderrSha256": digest(proc.stderr),
        "stderrExcerpt": proc.stderr[-500:] if proc.returncode else None,
    }


def scan_history(repo: str, mirror: pathlib.Path) -> dict[str, Any]:
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
            derived_addresses.add(address.lower())
            account_ids = TARGET_LOWER.get(address.lower())
            if account_ids:
                matches.append(
                    {
                        "address": to_checksum_address(address),
                        "testAccountIds": account_ids,
                        "repository": repo,
                        "commit": commit,
                        "path": path,
                        "line": line_number,
                        "publicLiteralSha256": candidate_hash,
                        "addedLineSha256": digest(content.strip()),
                    }
                )
    stderr = proc.stderr.read() if proc.stderr else ""
    return_code = proc.wait(timeout=120)
    return {
        "repository": repo,
        "gitLogReturnCode": return_code,
        "stderrSha256": digest(stderr),
        "addedLineCount": added_lines,
        "literalOccurrences": literal_occurrences,
        "uniquePrivateKeyShapedLiterals": len(candidate_hashes),
        "uniqueDerivedAddresses": len(derived_addresses),
        "matches": matches,
    }


def scan_mnemonics() -> dict[str, Any]:
    Account.enable_unaudited_hdwallet_features()
    matches = []
    derived = 0
    valid = 0
    for mnemonic_index, mnemonic in enumerate(PUBLIC_DEV_MNEMONICS):
        phrase_valid = False
        for account_index in range(200):
            path = f"m/44'/60'/0'/0/{account_index}"
            try:
                account = Account.from_mnemonic(mnemonic, account_path=path)
            except Exception:
                break
            phrase_valid = True
            derived += 1
            ids = TARGET_LOWER.get(account.address.lower())
            if ids:
                matches.append(
                    {
                        "address": account.address,
                        "testAccountIds": ids,
                        "mnemonicSha256": digest(mnemonic),
                        "mnemonicIndex": mnemonic_index,
                        "accountPath": path,
                    }
                )
        if phrase_valid:
            valid += 1
    return {
        "configuredMnemonicCount": len(PUBLIC_DEV_MNEMONICS),
        "validMnemonicCount": valid,
        "derivedAddressCount": derived,
        "matches": matches,
    }


def main() -> None:
    clone_results = []
    scans = []
    for repo in REPOSITORIES:
        mirror, meta = clone_mirror(repo)
        clone_results.append(meta)
        if meta["success"]:
            scans.append(scan_history(repo, mirror))
        else:
            scans.append(
                {
                    "repository": repo,
                    "gitLogReturnCode": None,
                    "addedLineCount": 0,
                    "literalOccurrences": 0,
                    "uniquePrivateKeyShapedLiterals": 0,
                    "uniqueDerivedAddresses": 0,
                    "matches": [],
                    "cloneFailed": True,
                }
            )
    mnemonic = scan_mnemonics()
    matches = [match for scan in scans for match in scan["matches"]] + mnemonic["matches"]
    output = {
        "safety": "Public Git history and already-public unsigned test-account identities only; raw candidate keys are never retained.",
        "targetCount": len(TARGETS),
        "targets": TARGETS,
        "cloneResults": clone_results,
        "historyScans": scans,
        "commonMnemonicScan": mnemonic,
        "matchCount": len(matches),
        "matches": matches,
        "verdict": "CONTROLLED_TEST_ACCOUNT_KEY_FOUND" if matches else "NO_PUBLIC_KEY_MATCH_FOR_DISCOVERED_TEST_ACCOUNTS",
        "limitations": [
            "Only the selected public repositories and configured public development mnemonics are covered.",
            "A negative result does not prove the keys were never exposed elsewhere.",
        ],
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "targetCount": len(TARGETS),
                "historyScans": [
                    {
                        "repository": scan["repository"],
                        "addedLineCount": scan["addedLineCount"],
                        "uniquePrivateKeyShapedLiterals": scan["uniquePrivateKeyShapedLiterals"],
                        "uniqueDerivedAddresses": scan["uniqueDerivedAddresses"],
                        "matchCount": len(scan["matches"]),
                    }
                    for scan in scans
                ],
                "mnemonicDerivedAddressCount": mnemonic["derivedAddressCount"],
                "matchCount": len(matches),
                "verdict": output["verdict"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
