#!/usr/bin/env python3
"""Read-only correlation of live Synthetix privileged addresses with public development keys.

Purpose
-------
A production role or Safe owner controlled by a publicly committed test/development key would be a
production control-plane compromise. This workflow independently reconstructs the current Deposit
AccessControl members, expands any Safe owners, scans selected current public Synthetix repositories
for private-key-shaped literals, derives their Ethereum addresses, and compares them with the live
privileged address set. It also checks several ubiquitous public development mnemonics.

Safety
------
- public Ethereum JSON-RPC reads only;
- public GitHub repository clones only;
- no transaction, signature, wallet login, protocol account or state mutation;
- raw private-key candidates are never written to disk or printed;
- findings retain only derived address, source path/line and SHA-256 of the public literal.
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
import urllib.error
import urllib.request
from collections import defaultdict
from typing import Any, Iterable

from eth_account import Account
from eth_utils import keccak, to_checksum_address

OUT = pathlib.Path("synthetix_privileged_public_key_correlation")
OUT.mkdir(parents=True, exist_ok=True)
WORK = pathlib.Path("/tmp/synthetix-public-key-correlation")
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir(parents=True)

DEPOSIT = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.mevblocker.io",
    "https://eth.drpc.org",
)
UA = "Mozilla/5.0 (compatible; authorized-read-only-security-review/1.0)"
MAX_RPC_BODY = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 5 * 1024 * 1024

ROLE_NAMES = (
    "DEFAULT_ADMIN_ROLE",
    "OWNER_ROLE",
    "MANAGER_ROLE",
    "RELAYER_ROLE",
    "WATCHER_ROLE",
    "TELLER_ROLE",
    "GUARDIAN_ROLE",
    "AUTHORIZED_TRADER_ROLE",
)

REPOSITORIES = (
    "Synthetixio/synthetix-deployments",
    "Synthetixio/synthetix-sdk",
    "Synthetixio/synthetix-v3",
    "Synthetixio/synthetix",
    "Synthetixio/synthetix-governance",
    "Synthetixio/governance.synthetix.eth",
)

# Ubiquitous, intentionally public local-development mnemonics. Invalid checksum phrases are skipped.
PUBLIC_DEV_MNEMONICS = (
    "test test test test test test test test test test test junk",
    "myth like bonus scare over problem client lizard pioneer submit female collect",
    "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat",
    "concert load couple harbor equip island argue ramp clarify fence smart topic",
    "gesture rather obey video awake genuine patient base soon parrot upset lounge",
)

HEX64_RE = re.compile(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])")
TEXT_EXTENSIONS = {
    ".js", ".ts", ".tsx", ".jsx", ".py", ".sol", ".rs", ".go", ".java", ".kt",
    ".json", ".toml", ".yaml", ".yml", ".md", ".txt", ".env", ".sh", ".bash",
    ".zsh", ".ini", ".cfg", ".conf", ".properties", ".lock", ".csv", ".graphql",
}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "coverage", ".next", ".cache", "artifacts", "cache"}


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def rpc(method: str, params: list[Any]) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, separators=(",", ":")).encode()
    errors: list[str] = []
    for url in RPC_URLS:
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=40) as response:
                body = response.read(MAX_RPC_BODY + 1)
            if len(body) > MAX_RPC_BODY:
                raise RuntimeError("RPC response exceeds cap")
            parsed = json.loads(body)
            if "error" in parsed:
                errors.append(str(parsed["error"])[:200])
                continue
            return parsed["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(type(exc).__name__)
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def abi_word(value: int) -> str:
    return f"{value:064x}"


def eth_call(to: str, data: str) -> str:
    return rpc("eth_call", [{"to": to, "data": data}, "latest"])


def selector(signature: str) -> str:
    return keccak(text=signature)[:4].hex()


def role_hash(name: str) -> str:
    if name == "DEFAULT_ADMIN_ROLE":
        return "0x" + "00" * 32
    return "0x" + keccak(text=name).hex()


def decode_address_word(word: str) -> str:
    return to_checksum_address("0x" + word[-40:])


def role_members(role: str) -> list[str]:
    clean_role = role.removeprefix("0x")
    count_data = "0x" + selector("getRoleMemberCount(bytes32)") + clean_role
    count = int(eth_call(DEPOSIT, count_data), 16)
    members = []
    for index in range(count):
        data = "0x" + selector("getRoleMember(bytes32,uint256)") + clean_role + abi_word(index)
        members.append(decode_address_word(eth_call(DEPOSIT, data).removeprefix("0x")[-64:]))
    return members


def code_bytes(address: str) -> int:
    return len(bytes.fromhex(rpc("eth_getCode", [address, "latest"]).removeprefix("0x")))


def tx_count(address: str) -> int:
    return int(rpc("eth_getTransactionCount", [address, "latest"]), 16)


def try_safe_owners(address: str) -> tuple[list[str], int | None]:
    try:
        raw = eth_call(address, "0x" + selector("getOwners()"))
        data = bytes.fromhex(raw.removeprefix("0x"))
        if len(data) < 64:
            return [], None
        offset = int.from_bytes(data[:32], "big")
        if offset + 32 > len(data):
            return [], None
        count = int.from_bytes(data[offset : offset + 32], "big")
        if count > 100 or offset + 32 + count * 32 > len(data):
            return [], None
        owners = [
            to_checksum_address("0x" + data[offset + 32 + i * 32 : offset + 64 + i * 32][-20:].hex())
            for i in range(count)
        ]
        threshold_raw = eth_call(address, "0x" + selector("getThreshold()"))
        threshold = int(threshold_raw, 16)
        return owners, threshold
    except Exception:
        return [], None


def clone_repo(repo: str) -> dict[str, Any]:
    target = WORK / repo.split("/", 1)[1]
    url = f"https://github.com/{repo}.git"
    started = time.monotonic()
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--filter=blob:none", "--single-branch", url, str(target)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
        check=False,
    )
    return {
        "repo": repo,
        "path": target,
        "success": proc.returncode == 0,
        "returnCode": proc.returncode,
        "elapsedSeconds": round(time.monotonic() - started, 2),
        "stderrSha256": digest(proc.stderr),
        "stderrExcerpt": proc.stderr[-500:] if proc.returncode else None,
    }


def iter_text_files(root: pathlib.Path) -> Iterable[pathlib.Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS]
        current_path = pathlib.Path(current)
        for name in files:
            path = current_path / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0 or size > MAX_SOURCE_BYTES:
                continue
            if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {"Dockerfile", "Makefile"}:
                continue
            yield path


def derive_address(candidate_hex: str) -> str | None:
    try:
        value = int(candidate_hex, 16)
        if value <= 0:
            return None
        return Account.from_key(bytes.fromhex(candidate_hex)).address
    except Exception:
        return None


def scan_repo(repo: str, root: pathlib.Path, target_addresses: set[str]) -> dict[str, Any]:
    target_lower = {value.lower() for value in target_addresses}
    candidate_hashes: set[str] = set()
    derived_addresses: set[str] = set()
    matches: list[dict[str, Any]] = []
    file_count = 0
    literal_count = 0
    for path in iter_text_files(root):
        file_count += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in HEX64_RE.finditer(line):
                literal_count += 1
                candidate = match.group(1).lower()
                candidate_hash = digest(candidate)
                if candidate_hash in candidate_hashes:
                    continue
                candidate_hashes.add(candidate_hash)
                address = derive_address(candidate)
                if not address:
                    continue
                derived_addresses.add(address.lower())
                if address.lower() in target_lower:
                    matches.append(
                        {
                            "address": to_checksum_address(address),
                            "repository": repo,
                            "path": str(path.relative_to(root)),
                            "line": line_no,
                            "publicLiteralSha256": candidate_hash,
                            "lineSha256": digest(line.strip()),
                        }
                    )
    return {
        "repository": repo,
        "filesScanned": file_count,
        "literalOccurrences": literal_count,
        "uniquePrivateKeyShapedLiterals": len(candidate_hashes),
        "uniqueDerivedAddresses": len(derived_addresses),
        "matches": matches,
    }


def mnemonic_matches(target_addresses: set[str]) -> dict[str, Any]:
    target_lower = {value.lower() for value in target_addresses}
    Account.enable_unaudited_hdwallet_features()
    derived_count = 0
    matches: list[dict[str, Any]] = []
    valid_mnemonics = 0
    for mnemonic_index, phrase in enumerate(PUBLIC_DEV_MNEMONICS):
        phrase_hash = digest(phrase)
        phrase_valid = False
        for account_index in range(100):
            path = f"m/44'/60'/0'/0/{account_index}"
            try:
                account = Account.from_mnemonic(phrase, account_path=path)
            except Exception:
                break
            phrase_valid = True
            derived_count += 1
            if account.address.lower() in target_lower:
                matches.append(
                    {
                        "address": to_checksum_address(account.address),
                        "mnemonicSha256": phrase_hash,
                        "mnemonicIndex": mnemonic_index,
                        "accountPath": path,
                    }
                )
        if phrase_valid:
            valid_mnemonics += 1
    return {
        "configuredMnemonicCount": len(PUBLIC_DEV_MNEMONICS),
        "validMnemonicCount": valid_mnemonics,
        "derivedAddressCount": derived_count,
        "matches": matches,
    }


def main() -> None:
    latest_block = int(rpc("eth_blockNumber", []), 16)
    roles: dict[str, dict[str, Any]] = {}
    privileged: set[str] = set()
    for name in ROLE_NAMES:
        role = role_hash(name)
        members = role_members(role)
        roles[name] = {"role": role, "members": members}
        privileged.update(members)

    address_meta: dict[str, dict[str, Any]] = {}
    safes: dict[str, dict[str, Any]] = {}
    for address in sorted(privileged, key=str.lower):
        code = code_bytes(address)
        meta = {"codeBytes": code, "transactionCount": tx_count(address)}
        if code:
            owners, threshold = try_safe_owners(address)
            if owners:
                safes[address] = {"owners": owners, "threshold": threshold}
                privileged.update(owners)
                meta["safeOwnerCount"] = len(owners)
                meta["safeThreshold"] = threshold
        address_meta[address] = meta

    # Record metadata for newly expanded Safe owners as well.
    for address in sorted(privileged, key=str.lower):
        if address not in address_meta:
            address_meta[address] = {"codeBytes": code_bytes(address), "transactionCount": tx_count(address)}

    clone_results = [clone_repo(repo) for repo in REPOSITORIES]
    scans = []
    for item in clone_results:
        if item["success"]:
            scans.append(scan_repo(item["repo"], item["path"], privileged))
        else:
            scans.append(
                {
                    "repository": item["repo"],
                    "filesScanned": 0,
                    "literalOccurrences": 0,
                    "uniquePrivateKeyShapedLiterals": 0,
                    "uniqueDerivedAddresses": 0,
                    "matches": [],
                    "cloneFailed": True,
                }
            )

    mnemonic = mnemonic_matches(privileged)
    repo_matches = [match for scan in scans for match in scan["matches"]]
    all_matches = repo_matches + mnemonic["matches"]

    result = {
        "safety": "Public RPC and public repository reads only; no raw candidate keys retained.",
        "snapshotBlock": latest_block,
        "deposit": DEPOSIT,
        "roles": roles,
        "safes": safes,
        "privilegedAddressCount": len(privileged),
        "privilegedAddresses": sorted(privileged, key=str.lower),
        "addressMetadata": address_meta,
        "cloneResults": [
            {key: value for key, value in item.items() if key != "path"}
            for item in clone_results
        ],
        "repositoryScans": scans,
        "commonMnemonicScan": mnemonic,
        "matchCount": len(all_matches),
        "matches": all_matches,
        "verdict": "PUBLIC_KEY_MATCH" if all_matches else "NO_PUBLIC_KEY_MATCH_IN_SCANNED_CORPUS",
        "limitations": [
            "Current default branches of the selected repositories were scanned; removed historical blobs were not exhaustively downloaded.",
            "Absence of a match does not prove that no private key has ever leaked elsewhere.",
        ],
    }
    (OUT / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                "snapshotBlock": latest_block,
                "privilegedAddressCount": len(privileged),
                "roleMemberCounts": {name: len(value["members"]) for name, value in roles.items()},
                "safeCount": len(safes),
                "repositoryScans": [
                    {
                        "repository": scan["repository"],
                        "filesScanned": scan["filesScanned"],
                        "uniquePrivateKeyShapedLiterals": scan["uniquePrivateKeyShapedLiterals"],
                        "uniqueDerivedAddresses": scan["uniqueDerivedAddresses"],
                        "matchCount": len(scan["matches"]),
                    }
                    for scan in scans
                ],
                "commonMnemonicDerivedAddressCount": mnemonic["derivedAddressCount"],
                "matchCount": len(all_matches),
                "verdict": result["verdict"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
