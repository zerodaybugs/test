#!/usr/bin/env python3
"""Correlate public Synthetix development identities with known official test accounts.

Authorization/safety:
- target wallet addresses were obtained from public production Deposit events and unsigned official
  test-API account discovery;
- scans only public repository working trees and ubiquitous public development mnemonics;
- derives Ethereum addresses locally and compares them with the eight public target wallets;
- never authenticates, signs, submits an API write, accesses account data, or changes state;
- raw private-key literals and mnemonic phrases are never written to the artifact or stdout.

A positive match would identify an intentionally public development identity suitable for a later,
separately reviewed, non-victim test-environment reproduction.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import time
from collections import defaultdict
from typing import Any

from eth_account import Account

Account.enable_unaudited_hdwallet_features()

OUT = pathlib.Path("synthetix_expanded_test_key_correlation")
OUT.mkdir(parents=True, exist_ok=True)
TMP = pathlib.Path("/tmp/synthetix-expanded-test-key-correlation")
shutil.rmtree(TMP, ignore_errors=True)
TMP.mkdir(parents=True, exist_ok=True)

TARGETS = {
    address.lower()
    for address in (
        "0x0d3DABaF73BE51E2C4b7BA17C1106Fb52b6C74B4",
        "0x5AF764190593a723EC89B9C3e3e5a2627a3f0Bb4",
        "0x797D183C50bbbaE9DA061488d2Ecb61ec915756B",
        "0x8e474E776c2493EE997Ea772cE0155215eBfAFbA",
        "0xC0e65F1429Cf4204B1D81D41aa626BB0139FaBfB",
        "0xDA807318571Cd0d256654889f96E2867A79E680d",
        "0xF911f95D32677a171BACB6d4E4FD29168a3D978f",
        "0xc3Cf311e04c1f8C74eCF6a795Ae760dc6312F345",
    )
}

REPOS = (
    "Synthetixio/synthetix-exchange",
    "Synthetixio/js-monorepo",
    "Synthetixio/staking",
    "Synthetixio/synthetix-website",
    "Synthetixio/perps-keepers",
    "Synthetixio/kwenta",
    "Synthetixio/simulation",
    "Synthetixio/synthetix-mintr",
    "Synthetixio/synthetix-data",
    "Synthetixio/SIPs",
    "Synthetixio/snx-grants-dao",
    "Synthetixio/synthetix-deployments",
    "Synthetixio/synthetix-v3",
    "Synthetixio/synthetix-sdk",
    "Synthetixio/governance.synthetix.eth",
)

# Ubiquitous public development phrases only. They must never hold real funds.
MNEMONICS = (
    "test test test test test test test test test test test junk",
    "myth like bonus scare over problem client lizard pioneer submit female collect",
    "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
    "concert load couple harbor equip island argue ramp clarify fence smart topic",
    "gesture rather obey video awake genuine patient base soon parrot upset lounge",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
)

KEY_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")
ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
TEXT_EXTENSIONS = {
    ".sol", ".vy", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".rs",
    ".go", ".java", ".kt", ".json", ".toml", ".yaml", ".yml", ".md", ".txt",
    ".env", ".sh", ".bash", ".zsh", ".ini", ".cfg", ".conf", ".graphql", ".gql",
}
SKIP_PARTS = {
    ".git", "node_modules", "dist", "build", "artifacts", "cache", "coverage", "vendor",
    ".next", ".turbo", "out", "target", "venv", ".venv",
}
MAX_FILE_BYTES = 20_000_000
MAX_TOTAL_FILES = 250_000
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def sha(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def clone(repo: str) -> tuple[pathlib.Path | None, dict[str, Any]]:
    dest = TMP / repo.replace("/", "__")
    started = time.monotonic()
    proc = subprocess.run(
        [
            "git", "clone", "--depth", "1", "--filter=blob:none", "--no-tags",
            f"https://github.com/{repo}.git", str(dest),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
        check=False,
    )
    head = None
    branch = None
    if proc.returncode == 0:
        head_proc = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
        )
        branch_proc = subprocess.run(
            ["git", "-C", str(dest), "branch", "--show-current"], capture_output=True, text=True, check=False
        )
        head = head_proc.stdout.strip() or None
        branch = branch_proc.stdout.strip() or None
    return (dest if proc.returncode == 0 else None), {
        "repository": repo,
        "success": proc.returncode == 0,
        "returnCode": proc.returncode,
        "elapsedSeconds": round(time.monotonic() - started, 2),
        "head": head,
        "branch": branch,
        "stderrSha256": sha(proc.stderr),
        "stderrExcerpt": proc.stderr[-800:] if proc.returncode else None,
    }


def valid_key(value: str) -> bool:
    number = int(value, 16)
    return 0 < number < SECP256K1_N


def scan_repo(repo: str, root: pathlib.Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    file_count = 0
    byte_count = 0
    literal_count = 0
    unique_addresses: set[str] = set()
    direct_target_mentions: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []

    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_PARTS for part in path.parts):
            continue
        if file_count >= MAX_TOTAL_FILES:
            raise RuntimeError("global file cap exceeded")
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {
            "Dockerfile", "Makefile", "Procfile", "CMakeLists.txt", "package-lock.json", "yarn.lock",
        }:
            continue
        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        file_count += 1
        byte_count += size
        rel = str(path.relative_to(root))

        for line_no, line in enumerate(text.splitlines(), 1):
            for address_match in ADDRESS_RE.finditer(line):
                address = address_match.group(0).lower()
                if address in TARGETS:
                    direct_target_mentions.append({
                        "repository": repo,
                        "path": rel,
                        "line": line_no,
                        "targetAddressSha256": sha(address),
                        "lineSha256": sha(line),
                    })
            for key_match in KEY_RE.finditer(line):
                key = key_match.group(1).lower()
                if not valid_key(key):
                    continue
                literal_count += 1
                try:
                    address = Account.from_key("0x" + key).address.lower()
                except Exception:
                    continue
                unique_addresses.add(address)
                if address in TARGETS:
                    matches.append({
                        "source": "current-public-repository-tree",
                        "repository": repo,
                        "path": rel,
                        "line": line_no,
                        "head": subprocess.run(
                            ["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False,
                        ).stdout.strip(),
                        "targetAddress": Account.from_key("0x" + key).address,
                        "targetAddressSha256": sha(address),
                        "keySha256": sha(key),
                        "lineSha256": sha(line),
                    })

    return {
        "repository": repo,
        "filesScanned": file_count,
        "bytesScanned": byte_count,
        "validPrivateKeyShapedOccurrences": literal_count,
        "uniqueDerivedAddresses": len(unique_addresses),
        "directTargetMentionCount": len(direct_target_mentions),
        "matchCount": len(matches),
        "directTargetMentions": direct_target_mentions,
    }, matches


def scan_mnemonics() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    derived = 0
    matches: list[dict[str, Any]] = []
    for mnemonic_index, mnemonic in enumerate(MNEMONICS):
        mnemonic_hash = sha(mnemonic)
        # Cover common EOA, change-address, and first-account derivation spaces.
        paths = []
        for account in range(5):
            for change in range(2):
                for index in range(250):
                    paths.append(f"m/44'/60'/{account}'/{change}/{index}")
        for path in paths:
            try:
                account = Account.from_mnemonic(mnemonic, account_path=path)
            except Exception:
                continue
            derived += 1
            address = account.address.lower()
            if address in TARGETS:
                matches.append({
                    "source": "ubiquitous-public-development-mnemonic",
                    "mnemonicIndex": mnemonic_index,
                    "mnemonicSha256": mnemonic_hash,
                    "derivationPath": path,
                    "targetAddress": account.address,
                    "targetAddressSha256": sha(address),
                    "privateKeySha256": sha(account.key.hex()),
                })
    return {
        "mnemonicCount": len(MNEMONICS),
        "derivedAddressCount": derived,
        "matchCount": len(matches),
    }, matches


def main() -> None:
    clone_results = []
    repo_results = []
    matches: list[dict[str, Any]] = []
    for repo in REPOS:
        root, clone_meta = clone(repo)
        clone_results.append(clone_meta)
        if root is None:
            repo_results.append({"repository": repo, "cloneFailed": True})
            continue
        result, found = scan_repo(repo, root)
        repo_results.append(result)
        matches.extend(found)
        (OUT / "progress.json").write_text(json.dumps({
            "repositoriesProcessed": len(repo_results),
            "repositoriesTotal": len(REPOS),
            "matchCount": len(matches),
        }, indent=2), encoding="utf-8")

    mnemonic_result, mnemonic_matches = scan_mnemonics()
    matches.extend(mnemonic_matches)

    summary = {
        "safety": "Public repository reads and local address derivation only; no authentication, signature, API write, or state mutation.",
        "targetWalletCount": len(TARGETS),
        "targetWalletSha256": sorted(sha(address) for address in TARGETS),
        "repositoryCount": len(REPOS),
        "cloneResults": clone_results,
        "repositoryScans": repo_results,
        "mnemonicScan": mnemonic_result,
        "matchCount": len(matches),
        "matches": matches,
        "verdict": "CONTROLLED_PUBLIC_TEST_IDENTITY_FOUND" if matches else "NO_CONTROLLED_PUBLIC_TEST_IDENTITY_FOUND",
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({
        "repositoryCount": summary["repositoryCount"],
        "cloneSuccessCount": sum(1 for item in clone_results if item["success"]),
        "filesScanned": sum(item.get("filesScanned", 0) for item in repo_results),
        "validPrivateKeyShapedOccurrences": sum(item.get("validPrivateKeyShapedOccurrences", 0) for item in repo_results),
        "mnemonicDerivedAddressCount": mnemonic_result["derivedAddressCount"],
        "matchCount": summary["matchCount"],
        "verdict": summary["verdict"],
    }, indent=2))


if __name__ == "__main__":
    main()
