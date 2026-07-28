#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

OFFICIAL_RPC = "https://horizen.calderachain.xyz/http"
INDEPENDENT_RPC = "https://26514.rpc.thirdweb.com"
DEPLOYMENT_BLOCK = 21_317_418
STAKER = "0x6BF7CF29a8bcE11Aa62Cf593d165C244fA4d3E31"
TOKEN = "0x57da2D504bf8b83Ef304759d9f2648522D7a9280"
UINT256_MAX = (1 << 256) - 1
CHILD_METADATA_PREFIX = bytes.fromhex("a2646970667358221220")
SOLC_METADATA_SUFFIX = bytes.fromhex("64736f6c634300081c0033")


class GateError(RuntimeError):
    pass


def rpc(url: str, method: str, params: list[Any], timeout: int = 90) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"content-type": "application/json", "user-agent": "Horizen-surrogate-attestation/1.0"},
    )
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                obj = json.loads(response.read())
            if "error" in obj:
                raise GateError(f"{method}: {obj['error']}")
            return obj.get("result")
        except Exception as exc:
            last = exc
            time.sleep(attempt + 1)
    raise GateError(f"RPC failed {url} {method}: {last}")


def rpc_batch(url: str, calls: list[tuple[str, list[Any]]], timeout: int = 120) -> list[Any]:
    payload = [
        {"jsonrpc": "2.0", "id": i, "method": method, "params": params}
        for i, (method, params) in enumerate(calls)
    ]
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "user-agent": "Horizen-surrogate-attestation/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            parsed = json.loads(response.read())
        if not isinstance(parsed, list):
            raise GateError("batch RPC response is not a list")
        by_id = {int(item["id"]): item for item in parsed}
        out = []
        for i in range(len(calls)):
            item = by_id.get(i)
            if item is None or "error" in item:
                raise GateError(f"batch item failed: {item}")
            out.append(item.get("result"))
        return out
    except Exception:
        return [rpc(url, method, params, timeout=timeout) for method, params in calls]


def cast(*args: str, timeout: int = 90) -> str:
    proc = subprocess.run(
        ["cast", *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise GateError(f"cast {' '.join(args)} failed: {proc.stdout[-1000:]}")
    return proc.stdout.strip()


def selector(signature: str) -> str:
    return cast("sig", signature)


def normalize_hex(text: str) -> bytes:
    value = "".join(text.split())
    if value.startswith("0x"):
        value = value[2:]
    if not value:
        return b""
    return bytes.fromhex(value)


def strip_cbor(code: bytes) -> tuple[bytes, bytes]:
    if len(code) < 2:
        return code, b""
    length = int.from_bytes(code[-2:], "big")
    total = length + 2
    if total <= 2 or total > len(code):
        return code, b""
    return code[:-total], code[-total:]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def norm_addr(value: str) -> str:
    raw = value.lower().replace("0x", "")[-40:]
    return "0x" + raw.rjust(40, "0")


def word_addr(word: int) -> str:
    return norm_addr(hex(word & ((1 << 160) - 1)))


def words(raw: str) -> list[int]:
    data = normalize_hex(raw)
    if len(data) % 32:
        raise GateError(f"ABI data is not word aligned: {len(data)}")
    return [int.from_bytes(data[i:i+32], "big") for i in range(0, len(data), 32)]


def arg_word(value: int | str) -> str:
    number = int(value, 16) if isinstance(value, str) and value.startswith("0x") else int(value)
    return number.to_bytes(32, "big").hex()


def get_logs(url: str, topic0: str, latest: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    start = DEPLOYMENT_BLOCK
    chunk = 20_000
    while start <= latest:
        end = min(latest, start + chunk - 1)
        result = rpc(
            url,
            "eth_getLogs",
            [{"fromBlock": hex(start), "toBlock": hex(end), "address": STAKER, "topics": [topic0]}],
            timeout=120,
        ) or []
        out.extend(result)
        start = end + 1
    return out


def chunked_batch(url: str, calls: list[tuple[str, list[Any]]], size: int = 75) -> list[Any]:
    out: list[Any] = []
    for i in range(0, len(calls), size):
        out.extend(rpc_batch(url, calls[i:i+size]))
    return out


def embedded_child_metadata(code: bytes) -> dict[str, Any]:
    executable, parent_metadata = strip_cbor(code)
    candidates = []
    cursor = 0
    while True:
        pos = executable.find(CHILD_METADATA_PREFIX, cursor)
        if pos < 0:
            break
        hash_start = pos + len(CHILD_METADATA_PREFIX)
        hash_end = hash_start + 32
        suffix_end = hash_end + len(SOLC_METADATA_SUFFIX)
        if suffix_end <= len(executable) and executable[hash_end:suffix_end] == SOLC_METADATA_SUFFIX:
            candidates.append(
                {
                    "prefix_offset": pos,
                    "hash_offset": hash_start,
                    "ipfs_hash": executable[hash_start:hash_end].hex(),
                    "suffix_end": suffix_end,
                }
            )
        cursor = pos + 1
    return {
        "parent_executable_bytes": len(executable),
        "parent_metadata_bytes": len(parent_metadata),
        "child_metadata_candidates": candidates,
    }


def main() -> int:
    private = Path("private-evidence/surrogate-attestation")
    sanitized = Path("sanitized-surrogates")
    private.mkdir(parents=True, exist_ok=True)
    sanitized.mkdir(parents=True, exist_ok=True)

    latest_official = int(rpc(OFFICIAL_RPC, "eth_blockNumber", []), 16)
    latest_independent = int(rpc(INDEPENDENT_RPC, "eth_blockNumber", []), 16)
    snapshot = min(latest_official, latest_independent)
    block_hex = hex(snapshot)

    live_parent_official = normalize_hex(rpc(OFFICIAL_RPC, "eth_getCode", [STAKER, block_hex]))
    live_parent_independent = normalize_hex(rpc(INDEPENDENT_RPC, "eth_getCode", [STAKER, block_hex]))
    if live_parent_official != live_parent_independent:
        raise GateError("official and independent parent runtime differ")

    expected_child = normalize_hex(Path(os.environ["EXPECTED_CHILD_HEX"]).read_text())
    local_parent = normalize_hex(Path(os.environ["LOCAL_PARENT_HEX"]).read_text())
    expected_child_exec, expected_child_metadata = strip_cbor(expected_child)

    stake_topic = cast("keccak", "StakeDeposited(address,uint256,uint256,uint256,uint256)")
    logs = get_logs(OFFICIAL_RPC, stake_topic, snapshot)
    deposit_ids = sorted({int(log["topics"][2], 16) for log in logs if len(log.get("topics", [])) >= 3})

    info_sel = selector("getDepositInfo(uint256)")
    info_calls = [
        ("eth_call", [{"to": STAKER, "data": info_sel + deposit_id.to_bytes(32, "big").hex()}, block_hex])
        for deposit_id in deposit_ids
    ]
    info_results = chunked_batch(OFFICIAL_RPC, info_calls)

    deposits = []
    delegatees: set[str] = set()
    total_balance = 0
    for deposit_id, raw in zip(deposit_ids, info_results, strict=True):
        decoded = words(raw)
        if len(decoded) < 6:
            raise GateError(f"malformed deposit {deposit_id}")
        balance, owner, power, delegatee, claimer, unclaimed = decoded[:6]
        delegatee_addr = word_addr(delegatee)
        deposits.append(
            {
                "deposit_id": deposit_id,
                "balance": balance,
                "owner": word_addr(owner),
                "power": power,
                "delegatee": delegatee_addr,
                "claimer": word_addr(claimer),
                "unclaimed": unclaimed,
            }
        )
        delegatees.add(delegatee_addr)
        total_balance += balance

    surrogate_sel = selector("surrogates(address)")
    sorted_delegatees = sorted(delegatees)
    surrogate_calls = [
        (
            "eth_call",
            [{"to": STAKER, "data": surrogate_sel + int(delegatee, 16).to_bytes(32, "big").hex()}, block_hex],
        )
        for delegatee in sorted_delegatees
    ]
    surrogate_raw = chunked_batch(OFFICIAL_RPC, surrogate_calls)
    delegatee_to_surrogate = {
        delegatee: word_addr(words(raw)[0]) if words(raw) else norm_addr("0x0")
        for delegatee, raw in zip(sorted_delegatees, surrogate_raw, strict=True)
    }
    surrogates = sorted({address for address in delegatee_to_surrogate.values() if int(address, 16) != 0})

    code_calls = [("eth_getCode", [address, block_hex]) for address in surrogates]
    code_results = chunked_batch(OFFICIAL_RPC, code_calls)
    balance_sel = "0x70a08231"
    allowance_sel = "0xdd62ed3e"
    balance_calls = [
        (
            "eth_call",
            [{"to": TOKEN, "data": balance_sel + int(address, 16).to_bytes(32, "big").hex()}, block_hex],
        )
        for address in surrogates
    ]
    allowance_calls = [
        (
            "eth_call",
            [
                {
                    "to": TOKEN,
                    "data": allowance_sel
                    + int(address, 16).to_bytes(32, "big").hex()
                    + int(STAKER, 16).to_bytes(32, "big").hex(),
                },
                block_hex,
            ],
        )
        for address in surrogates
    ]
    balance_results = chunked_batch(OFFICIAL_RPC, balance_calls)
    allowance_results = chunked_batch(OFFICIAL_RPC, allowance_calls)

    rows = []
    executable_mismatches = []
    raw_hashes: set[str] = set()
    executable_hashes: set[str] = set()
    allowance_mismatches = []
    missing_code = []
    surrogate_balance_sum = 0
    for address, raw_code, raw_balance, raw_allowance in zip(
        surrogates, code_results, balance_results, allowance_results, strict=True
    ):
        code_bytes = normalize_hex(raw_code)
        executable, metadata = strip_cbor(code_bytes)
        balance = words(raw_balance)[0]
        allowance = words(raw_allowance)[0]
        raw_hash = sha(code_bytes)
        exec_hash = sha(executable)
        raw_hashes.add(raw_hash)
        executable_hashes.add(exec_hash)
        surrogate_balance_sum += balance
        if executable != expected_child_exec:
            executable_mismatches.append(address)
        if allowance != UINT256_MAX:
            allowance_mismatches.append({"address": address, "allowance": allowance})
        if not code_bytes:
            missing_code.append(address)
        rows.append(
            {
                "address": address,
                "code_bytes": len(code_bytes),
                "raw_sha256": raw_hash,
                "executable_bytes": len(executable),
                "executable_sha256": exec_hash,
                "metadata_bytes": len(metadata),
                "balance": balance,
                "allowance": allowance,
            }
        )

    nonzero_deposit_missing_surrogate = []
    for deposit in deposits:
        surrogate = delegatee_to_surrogate.get(deposit["delegatee"], norm_addr("0x0"))
        if deposit["balance"] > 0 and (int(surrogate, 16) == 0 or surrogate in missing_code):
            nonzero_deposit_missing_surrogate.append(deposit["deposit_id"])

    total_staked_raw = rpc(
        OFFICIAL_RPC,
        "eth_call",
        [{"to": STAKER, "data": selector("totalStaked()")}, block_hex],
    )
    total_staked = words(total_staked_raw)[0]

    local_child_embed = embedded_child_metadata(local_parent)
    live_child_embed = embedded_child_metadata(live_parent_official)
    local_candidates = local_child_embed["child_metadata_candidates"]
    live_candidates = live_child_embed["child_metadata_candidates"]
    embedded_layout_match = (
        len(local_candidates) == 1
        and len(live_candidates) == 1
        and local_candidates[0]["prefix_offset"] == live_candidates[0]["prefix_offset"]
        and local_candidates[0]["hash_offset"] == live_candidates[0]["hash_offset"]
        and local_candidates[0]["suffix_end"] == live_candidates[0]["suffix_end"]
    )
    embedded_hash_matches_live_child = False
    if live_candidates and rows:
        live_child_metadata_hashes = set()
        for raw_code in code_results:
            code_bytes = normalize_hex(raw_code)
            _, metadata = strip_cbor(code_bytes)
            pos = metadata.find(CHILD_METADATA_PREFIX)
            if pos >= 0 and pos + len(CHILD_METADATA_PREFIX) + 32 <= len(metadata):
                start = pos + len(CHILD_METADATA_PREFIX)
                live_child_metadata_hashes.add(metadata[start:start+32].hex())
        embedded_hash_matches_live_child = live_candidates[0]["ipfs_hash"] in live_child_metadata_hashes

    pass_gate = all(
        [
            live_parent_official == live_parent_independent,
            len(deposit_ids) > 0,
            len(surrogates) > 0,
            not executable_mismatches,
            not allowance_mismatches,
            not missing_code,
            not nonzero_deposit_missing_surrogate,
            surrogate_balance_sum == total_staked == total_balance,
            embedded_layout_match,
            embedded_hash_matches_live_child,
        ]
    )

    result = {
        "snapshot_block": snapshot,
        "deposit_count": len(deposit_ids),
        "unique_delegatees": len(delegatees),
        "unique_surrogates": len(surrogates),
        "raw_code_variant_count": len(raw_hashes),
        "executable_code_variant_count": len(executable_hashes),
        "expected_child_raw_sha256": sha(expected_child),
        "expected_child_executable_sha256": sha(expected_child_exec),
        "expected_child_metadata_bytes": len(expected_child_metadata),
        "executable_mismatches": executable_mismatches,
        "allowance_mismatches": allowance_mismatches,
        "missing_code": missing_code,
        "nonzero_deposit_missing_surrogate": nonzero_deposit_missing_surrogate,
        "deposit_balance_sum": total_balance,
        "surrogate_balance_sum": surrogate_balance_sum,
        "total_staked": total_staked,
        "parent_official_independent_equal": live_parent_official == live_parent_independent,
        "local_parent_embedded_child_metadata": local_child_embed,
        "live_parent_embedded_child_metadata": live_child_embed,
        "embedded_layout_match": embedded_layout_match,
        "embedded_hash_matches_live_child": embedded_hash_matches_live_child,
        "rows": rows,
        "pass": pass_gate,
        "security_verdict": "KILL_CANONICAL_SURROGATES" if pass_gate else "HOLD_SURROGATE_OR_CHILD_RUNTIME_DELTA",
        "public_network_writes": 0,
    }
    (private / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")

    public = {
        "snapshot_block": snapshot,
        "deposit_count": len(deposit_ids),
        "unique_delegatees": len(delegatees),
        "unique_surrogates": len(surrogates),
        "raw_code_variant_count": len(raw_hashes),
        "executable_code_variant_count": len(executable_hashes),
        "executable_mismatch_count": len(executable_mismatches),
        "allowance_mismatch_count": len(allowance_mismatches),
        "missing_code_count": len(missing_code),
        "missing_surrogate_for_nonzero_deposit_count": len(nonzero_deposit_missing_surrogate),
        "principal_balance_equality": surrogate_balance_sum == total_staked == total_balance,
        "embedded_child_metadata_layout_match": embedded_layout_match,
        "embedded_hash_matches_live_child": embedded_hash_matches_live_child,
        "pass": pass_gate,
        "security_verdict": result["security_verdict"],
        "public_network_writes": 0,
    }
    (sanitized / "RESULT.json").write_text(json.dumps(public, indent=2) + "\n")
    lines = [
        "# Horizen live surrogate and embedded-child attestation",
        "",
        f"- Snapshot block: `{snapshot}`",
        f"- Deposits / delegatees / surrogates: `{len(deposit_ids)}/{len(delegatees)}/{len(surrogates)}`",
        f"- Executable child-code variants: `{len(executable_hashes)}`",
        f"- Executable mismatches: `{len(executable_mismatches)}`",
        f"- Allowance mismatches: `{len(allowance_mismatches)}`",
        f"- Missing code: `{len(missing_code)}`",
        f"- Principal balance equality: **{surrogate_balance_sum == total_staked == total_balance}**",
        f"- Parent diff maps to embedded child metadata: **{embedded_layout_match and embedded_hash_matches_live_child}**",
        f"- Verdict: **{result['security_verdict']}**",
        "- Public-network writes: **0**",
    ]
    (sanitized / "RESULT.md").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
