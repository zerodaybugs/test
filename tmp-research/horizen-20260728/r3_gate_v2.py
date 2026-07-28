#!/usr/bin/env python3
"""Read-only Horizen Phase B production and deployment attestation.

No transaction is signed or broadcast. All chain access is eth_call / eth_getCode /
eth_getLogs / transaction, balance, and nonce reads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

MAIN_RPCS = [
    "https://horizen.calderachain.xyz/http",
    "https://26514.rpc.thirdweb.com",
]
BASE_RPCS = [
    "https://mainnet.base.org",
    "https://base-rpc.publicnode.com",
    "https://1rpc.io/base",
]
SITE = "https://staking.horizen.io/"
DEPLOYMENT_BLOCK = 21_317_418

STAKER = "0x6BF7CF29a8bcE11Aa62Cf593d165C244fA4d3E31"
ACC = "0x06f5555fee73EDdc385b6d76FE00DB2D96ccDaE8"
TOKEN = "0x57da2D504bf8b83Ef304759d9f2648522D7a9280"
CALCULATOR = "0xf518b3c7Cd5cc1595D10E7268677Da0Fe364E191"
DEPLOYER = "0x9B264B21ca7659C256aD09171f827976Acd5a1C3"
EXPECTED_SAFE = "0x1Afb144aaD0aE02f3Bb04C1eae4AC6020a727A21"
TESTNET_TOKEN = "0xb06EC4ce262D8dbDc24Fac87479A49A7DC4cFb87"
ALIAS_OFFSET = int("1111000000000000000000000000000000001111", 16)
UINT160_MOD = 1 << 160
SCALE = 10**36


class GateError(RuntimeError):
    pass


def norm_addr(value: str) -> str:
    value = value.strip().lower()
    if not value.startswith("0x"):
        value = "0x" + value
    return "0x" + value[2:].rjust(40, "0")[-40:]


def rpc(url: str, method: str, params: list[Any], timeout: int = 45) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"content-type": "application/json", "user-agent": "Horizen-R3-read-only/1.0"},
    )
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                obj = json.loads(response.read())
            if "error" in obj:
                raise GateError(f"RPC {method} error: {obj['error']}")
            return obj.get("result")
        except Exception as exc:
            last = exc
            time.sleep(1.0 + attempt)
    raise GateError(f"RPC failed {url} {method}: {last}")


def rpc_batch(url: str, calls: list[tuple[str, list[Any]]], timeout: int = 90) -> list[Any]:
    payload = [
        {"jsonrpc": "2.0", "id": i, "method": method, "params": params}
        for i, (method, params) in enumerate(calls)
    ]
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "user-agent": "Horizen-R3-read-only/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            parsed = json.loads(response.read())
        if not isinstance(parsed, list):
            raise GateError("Batch RPC did not return an array")
        by_id = {int(item["id"]): item for item in parsed}
        output: list[Any] = []
        for i in range(len(calls)):
            item = by_id.get(i)
            if item is None or "error" in item:
                raise GateError(f"Batch item {i} failed: {item}")
            output.append(item.get("result"))
        return output
    except Exception:
        return [rpc(url, method, params, timeout=timeout) for method, params in calls]


def cast(*args: str, timeout: int = 60) -> str:
    proc = subprocess.run(
        ["cast", *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise GateError(f"cast {' '.join(args)} failed ({proc.returncode}): {proc.stdout[-1000:]}")
    return proc.stdout.strip()


def selector(signature: str) -> str:
    return cast("sig", signature).strip()


def calldata(signature: str, *args: str) -> str:
    return cast("calldata", signature, *args).strip()


def eth_call(url: str, to: str, data: str, block_hex: str) -> str:
    return rpc(url, "eth_call", [{"to": to, "data": data}, block_hex])


def decode_words(raw: str) -> list[int]:
    if raw in (None, "0x", ""):
        return []
    data = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    if len(data) % 32:
        raise GateError(f"ABI output length is not word aligned: {len(data)}")
    return [int.from_bytes(data[i : i + 32], "big") for i in range(0, len(data), 32)]


def decode_address_word(word: int) -> str:
    return norm_addr(hex(word & (UINT160_MOD - 1)))


def get_word(url: str, to: str, signature: str, block_hex: str, *args: str) -> int:
    words = decode_words(eth_call(url, to, calldata(signature, *args), block_hex))
    if not words:
        raise GateError(f"Empty ABI result for {signature}")
    return words[0]


def get_address(url: str, to: str, signature: str, block_hex: str, *args: str) -> str:
    return decode_address_word(get_word(url, to, signature, block_hex, *args))


def get_bool(url: str, to: str, signature: str, block_hex: str, *args: str) -> bool:
    return bool(get_word(url, to, signature, block_hex, *args))


def get_logs(url: str, address: str, topic0: str, start: int, end: int) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    chunk = 20_000
    current = start
    while current <= end:
        upper = min(end, current + chunk - 1)
        output.extend(
            rpc(
                url,
                "eth_getLogs",
                [{"fromBlock": hex(current), "toBlock": hex(upper), "address": address, "topics": [topic0]}],
                timeout=90,
            )
            or []
        )
        current = upper + 1
    return output


def normalize_code(value: str) -> bytes:
    text = "".join(value.split()).lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text or re.fullmatch(r"[0-9a-f]+", text) is None:
        raise GateError("Invalid runtime bytecode text")
    return bytes.fromhex(text)


def abi_dynamic_address_array(raw: str, tuple_index: int = 0) -> list[str]:
    data = bytes.fromhex(raw[2:] if raw.startswith("0x") else raw)
    if len(data) < 64:
        return []
    head_pos = tuple_index * 32
    offset = int.from_bytes(data[head_pos : head_pos + 32], "big")
    if offset + 32 > len(data):
        return []
    length = int.from_bytes(data[offset : offset + 32], "big")
    result = []
    for i in range(length):
        pos = offset + 32 + i * 32
        if pos + 32 > len(data):
            raise GateError("Truncated dynamic address array")
        result.append(norm_addr("0x" + data[pos + 12 : pos + 32].hex()))
    return result


def fetch_url(url: str, timeout: int = 30) -> tuple[bytes, str]:
    req = urllib.request.Request(
        url,
        headers={
            "user-agent": "Mozilla/5.0 (compatible; Horizen-R3-read-only/1.0)",
            "accept": "text/html,application/javascript,text/javascript,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read(), response.headers.get("content-type", "")


def production_bundle_gate() -> dict[str, Any]:
    html_bytes, _ = fetch_url(SITE)
    html = html_bytes.decode("utf-8", "ignore")
    refs = set(re.findall(r'''(?:src|href)=["']([^"']+)["']''', html, flags=re.I))
    urls = []
    for ref in refs:
        absolute = urllib.parse.urljoin(SITE, ref)
        parsed = urllib.parse.urlparse(absolute)
        if parsed.netloc == urllib.parse.urlparse(SITE).netloc and (
            parsed.path.endswith((".js", ".mjs", ".json", ".html")) or "/_next/" in parsed.path
        ):
            urls.append(absolute)
    blobs = [html]
    fetched = []
    errors = []
    for url in sorted(set(urls))[:120]:
        try:
            body, _ = fetch_url(url)
            blobs.append(body.decode("utf-8", "ignore"))
            fetched.append(url)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    joined = "\n".join(blobs).lower()
    main_staker = norm_addr(STAKER)[2:] in joined or norm_addr(STAKER) in joined
    main_token = norm_addr(TOKEN)[2:] in joined or norm_addr(TOKEN) in joined
    test_token = norm_addr(TESTNET_TOKEN)[2:] in joined or norm_addr(TESTNET_TOKEN) in joined
    chain_id_present = "26514" in joined
    gate = main_staker and main_token and chain_id_present and not test_token
    return {
        "pass": gate,
        "assets_discovered": len(urls),
        "assets_fetched": len(fetched),
        "fetch_errors": errors[:20],
        "mainnet_staker_present": main_staker,
        "mainnet_token_present": main_token,
        "mainnet_chain_id_present": chain_id_present,
        "testnet_token_present": test_token,
        "fetched_urls": fetched,
    }


def safe_gate(url: str, block_hex: str, safe: str) -> dict[str, Any]:
    code = rpc(url, "eth_getCode", [safe, block_hex])
    version_raw = eth_call(url, safe, calldata("VERSION()"), block_hex)
    data = bytes.fromhex(version_raw[2:])
    version = ""
    if len(data) >= 64:
        offset = int.from_bytes(data[:32], "big")
        length = int.from_bytes(data[offset : offset + 32], "big")
        version = data[offset + 32 : offset + 32 + length].decode("utf-8", "replace")
    threshold = get_word(url, safe, "getThreshold()", block_hex)
    owners = abi_dynamic_address_array(eth_call(url, safe, calldata("getOwners()"), block_hex))
    sentinel = "0x0000000000000000000000000000000000000001"
    modules = abi_dynamic_address_array(
        eth_call(url, safe, calldata("getModulesPaginated(address,uint256)", sentinel, "100"), block_hex)
    )
    passed = code not in (None, "0x") and version == "1.4.1" and threshold == 4 and len(owners) == 7 and not modules
    return {
        "pass": passed,
        "address": norm_addr(safe),
        "code_bytes": max(0, (len(code) - 2) // 2),
        "version": version,
        "threshold": threshold,
        "owner_count": len(owners),
        "owners": owners,
        "modules": modules,
    }


def batch_eth_calls(url: str, to: str, datas: list[str], block_hex: str, chunk: int = 100) -> list[str]:
    out: list[str] = []
    for i in range(0, len(datas), chunk):
        calls = [("eth_call", [{"to": to, "data": data}, block_hex]) for data in datas[i : i + chunk]]
        out.extend(rpc_batch(url, calls, timeout=120))
    return out


def chain_census(url: str, snapshot: int) -> dict[str, Any]:
    block_hex = hex(snapshot)
    block = rpc(url, "eth_getBlockByNumber", [block_hex, False])
    timestamp = int(block["timestamp"], 16)

    admin = get_address(url, STAKER, "admin()", block_hex)
    owner = get_address(url, ACC, "owner()", block_hex)
    total_staked = get_word(url, STAKER, "totalStaked()", block_hex)
    total_power = get_word(url, STAKER, "totalEarningPower()", block_hex)
    reward_end = get_word(url, STAKER, "rewardEndTime()", block_hex)
    scaled_rate = get_word(url, STAKER, "scaledRewardRate()", block_hex)
    acc_accounted = get_word(url, ACC, "accumulatedRewards()", block_hex)
    acc_window = get_word(url, ACC, "timeWindow()", block_hex)
    acc_whitelist = get_bool(url, ACC, "whitelistEnabled()", block_hex)
    acc_staker = get_address(url, ACC, "staker()", block_hex)
    acc_token = get_address(url, ACC, "rewardToken()", block_hex)
    calculator = get_address(url, STAKER, "earningPowerCalculator()", block_hex)
    max_bump_tip = get_word(url, STAKER, "maxBumpTip()", block_hex)
    staker_balance = get_word(url, TOKEN, "balanceOf(address)", block_hex, STAKER)
    acc_balance = get_word(url, TOKEN, "balanceOf(address)", block_hex, ACC)

    stake_topic = cast("keccak", "StakeDeposited(address,uint256,uint256,uint256,uint256)")
    stake_logs = get_logs(url, STAKER, stake_topic, DEPLOYMENT_BLOCK, snapshot)
    deposit_ids = sorted({int(log["topics"][2], 16) for log in stake_logs if len(log.get("topics", [])) >= 3})

    info_sel = selector("getDepositInfo(uint256)")
    info_results = batch_eth_calls(
        url,
        STAKER,
        [info_sel + deposit_id.to_bytes(32, "big").hex() for deposit_id in deposit_ids],
        block_hex,
    )

    balance_sum = power_sum = unclaimed_sum = residual_count = residual_reward = 0
    delegatees: set[str] = set()
    owners: set[str] = set()
    for deposit_id, raw in zip(deposit_ids, info_results, strict=True):
        words = decode_words(raw)
        if len(words) < 6:
            raise GateError(f"Malformed getDepositInfo({deposit_id}) result")
        balance, owner_word, power, delegatee_word, _claimer_word, unclaimed = words[:6]
        owner_addr = decode_address_word(owner_word)
        delegatee_addr = decode_address_word(delegatee_word)
        balance_sum += balance
        power_sum += power
        unclaimed_sum += unclaimed
        owners.add(owner_addr)
        delegatees.add(delegatee_addr)
        if balance == 0 and unclaimed > 0:
            residual_count += 1
            residual_reward += unclaimed

    surrogate_sel = selector("surrogates(address)")
    surrogate_results = batch_eth_calls(
        url,
        STAKER,
        [surrogate_sel + int(addr, 16).to_bytes(32, "big").hex() for addr in sorted(delegatees)],
        block_hex,
    )
    nonzero_surrogates = [
        decode_address_word(decode_words(raw)[0])
        for raw in surrogate_results
        if decode_words(raw) and decode_words(raw)[0] != 0
    ]
    balance_sel = selector("balanceOf(address)")
    surrogate_balances_raw = batch_eth_calls(
        url,
        TOKEN,
        [balance_sel + int(addr, 16).to_bytes(32, "big").hex() for addr in nonzero_surrogates],
        block_hex,
    )
    surrogate_balance_sum = sum(decode_words(raw)[0] for raw in surrogate_balances_raw)
    surrogate_surplus = surrogate_balance_sum - total_staked

    remaining_reward = scaled_rate * max(0, reward_end - timestamp) // SCALE
    reward_surplus = staker_balance - unclaimed_sum - remaining_reward

    notifier_topic = cast("keccak", "RewardNotifierSet(address,bool)")
    notifier_logs = get_logs(url, STAKER, notifier_topic, DEPLOYMENT_BLOCK, snapshot)
    discovered_notifiers = {norm_addr(ACC), norm_addr(DEPLOYER)}
    notifier_events = []
    for log in notifier_logs:
        topics = log.get("topics", [])
        if len(topics) < 2:
            continue
        notifier = norm_addr("0x" + topics[1][-40:])
        words = decode_words(log.get("data", "0x"))
        enabled = bool(words[0]) if words else False
        discovered_notifiers.add(notifier)
        notifier_events.append(
            {"block": int(log["blockNumber"], 16), "tx": log["transactionHash"], "notifier": notifier, "enabled": enabled}
        )
    current_notifiers = {
        addr: get_bool(url, STAKER, "isRewardNotifier(address)", block_hex, addr)
        for addr in sorted(discovered_notifiers)
    }
    enabled_notifiers = sorted(addr for addr, enabled in current_notifiers.items() if enabled)

    core_pass = all(
        [
            admin == norm_addr(EXPECTED_SAFE),
            owner == norm_addr(EXPECTED_SAFE),
            acc_staker == norm_addr(STAKER),
            acc_token == norm_addr(TOKEN),
            calculator == norm_addr(CALCULATOR),
            max_bump_tip == 0,
            acc_window == 431_700,
            acc_whitelist is False,
            balance_sum == total_staked,
            power_sum == total_power,
            total_staked == total_power,
            surrogate_surplus >= 0,
            acc_balance >= acc_accounted,
            reward_surplus >= 0,
            enabled_notifiers == [norm_addr(ACC)],
        ]
    )
    return {
        "pass": core_pass,
        "snapshot_block": snapshot,
        "snapshot_timestamp": timestamp,
        "admin": admin,
        "accumulator_owner": owner,
        "accumulator_staker": acc_staker,
        "accumulator_token": acc_token,
        "accumulator_window": acc_window,
        "accumulator_whitelist_enabled": acc_whitelist,
        "calculator": calculator,
        "max_bump_tip": max_bump_tip,
        "deposit_count": len(deposit_ids),
        "unique_owner_count": len(owners),
        "unique_delegatee_count": len(delegatees),
        "deposit_balance_sum": balance_sum,
        "deposit_power_sum": power_sum,
        "total_staked": total_staked,
        "total_power": total_power,
        "surrogate_balance_sum": surrogate_balance_sum,
        "surrogate_surplus": surrogate_surplus,
        "staker_balance": staker_balance,
        "unclaimed_sum": unclaimed_sum,
        "remaining_stream_reward": remaining_reward,
        "reward_surplus": reward_surplus,
        "accumulator_balance": acc_balance,
        "accumulator_accounted": acc_accounted,
        "zero_balance_residual_count": residual_count,
        "zero_balance_residual_reward": residual_reward,
        "enabled_notifiers": enabled_notifiers,
        "notifier_states": current_notifiers,
        "notifier_events": notifier_events,
    }


def alias_gate(base_url: str, targets: dict[str, str]) -> dict[str, Any]:
    latest = int(rpc(base_url, "eth_blockNumber", []), 16)
    results = []
    active = []
    funded = []
    for name, target in targets.items():
        preimage = norm_addr(hex((int(norm_addr(target), 16) - ALIAS_OFFSET) % UINT160_MOD))
        code = rpc(base_url, "eth_getCode", [preimage, "latest"])
        nonce = int(rpc(base_url, "eth_getTransactionCount", [preimage, "latest"]), 16)
        balance = int(rpc(base_url, "eth_getBalance", [preimage, "latest"]), 16)
        row = {
            "target_name": name,
            "l3_target": norm_addr(target),
            "base_alias_preimage": preimage,
            "code_bytes": max(0, (len(code) - 2) // 2),
            "nonce": nonce,
            "balance": balance,
        }
        results.append(row)
        if row["code_bytes"] > 0 or nonce > 0:
            active.append(row)
        if balance > 0:
            funded.append(row)
    return {
        "pass": not active,
        "base_rpc": base_url,
        "base_block": latest,
        "targets": results,
        "active_preimages": active,
        "funded_preimages": funded,
    }


def runtime_gate(local_staker_path: Path, local_acc_path: Path, live_codes: dict[str, str]) -> dict[str, Any]:
    values = {
        "staker": [
            normalize_code(local_staker_path.read_text()),
            normalize_code(live_codes["official_staker"]),
            normalize_code(live_codes["independent_staker"]),
        ],
        "accumulator": [
            normalize_code(local_acc_path.read_text()),
            normalize_code(live_codes["official_acc"]),
            normalize_code(live_codes["independent_acc"]),
        ],
    }
    rows = []
    for name, triplet in values.items():
        rows.append(
            {
                "name": name,
                "sizes": [len(value) for value in triplet],
                "sha256": [hashlib.sha256(value).hexdigest() for value in triplet],
                "all_equal": triplet[0] == triplet[1] == triplet[2],
            }
        )
    return {"pass": all(row["all_equal"] for row in rows), "contracts": rows}


def audit_gate(audit_dir: Path) -> dict[str, Any]:
    pdf_texts = sorted(path for path in audit_dir.glob("*.txt") if "pdfinfo" not in path.name and "error" not in path.name)
    markdowns = sorted(audit_dir.glob("*.md"))
    files = [path for path in pdf_texts + markdowns if path.stat().st_size > 100]
    return {
        "pass": len([p for p in pdf_texts if p.stat().st_size > 100]) >= 6 and len([p for p in markdowns if p.stat().st_size > 100]) >= 1,
        "pdf_text_count": len([p for p in pdf_texts if p.stat().st_size > 100]),
        "markdown_count": len([p for p in markdowns if p.stat().st_size > 100]),
        "files": [
            {"name": path.name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in files
        ],
    }


def choose_rpc(candidates: Iterable[str], expected_chain_id: int | None = None) -> str:
    errors = []
    for url in candidates:
        try:
            chain_id = int(rpc(url, "eth_chainId", []), 16)
            if expected_chain_id is None or chain_id == expected_chain_id:
                return url
            errors.append(f"{url}: unexpected chain {chain_id}")
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    raise GateError("No usable RPC: " + " | ".join(errors))


def write_markdown(result: dict[str, Any], path: Path) -> None:
    census = result["production_census"]
    lines = [
        "# Horizen Phase B R3 final research gate",
        "",
        f"- Overall gate: **{'PASS' if result['all_required_gates_pass'] else 'HOLD'}**",
        f"- Submission verdict: **{result['submission_verdict']}**",
        "- Public-network writes: **0**",
        "",
        "## Required gates",
        "",
    ]
    for name, passed in result["gates"].items():
        lines.append(f"- `{name}`: **{'PASS' if passed else 'HOLD'}**")
    lines += [
        "",
        "## Production census",
        "",
        f"- Snapshot block: `{census.get('snapshot_block')}`",
        f"- Deposits: `{census.get('deposit_count')}`",
        f"- Unique owners: `{census.get('unique_owner_count')}`",
        f"- Total staked (wei): `{census.get('total_staked')}`",
        f"- Unclaimed reward sum (wei): `{census.get('unclaimed_sum')}`",
        f"- Remaining stream reward (wei): `{census.get('remaining_stream_reward')}`",
        f"- Reward solvency surplus (wei): `{census.get('reward_surplus')}`",
        f"- Zero-principal residual-reward deposits: `{census.get('zero_balance_residual_count')}`",
        f"- Zero-principal residual reward (wei): `{census.get('zero_balance_residual_reward')}`",
        f"- Enabled reward notifiers: `{', '.join(census.get('enabled_notifiers', []))}`",
        "",
        "## Interpretation",
        "",
        "A PASS closes the tested RewardAccumulator→ZenStaker accounting, runtime-binding, privileged-control, notifier, Base→L3 alias, live-bundle write-target, and public audit-dedup gates. It does not prove that no vulnerability exists outside the tested state space.",
        "",
        "No submission package is warranted without a new permissionless High/Critical impact and deterministic local PoC.",
    ]
    path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--local-staker-code", required=True, type=Path)
    parser.add_argument("--local-acc-code", required=True, type=Path)
    parser.add_argument("--audit-dir", required=True, type=Path)
    parser.add_argument("--handler-gate-file", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    official = choose_rpc([MAIN_RPCS[0]], expected_chain_id=26514)
    independent = choose_rpc([MAIN_RPCS[1]], expected_chain_id=26514)
    snapshot = min(int(rpc(official, "eth_blockNumber", []), 16), int(rpc(independent, "eth_blockNumber", []), 16))
    block_hex = hex(snapshot)
    live_codes = {
        "official_staker": rpc(official, "eth_getCode", [STAKER, block_hex]),
        "independent_staker": rpc(independent, "eth_getCode", [STAKER, block_hex]),
        "official_acc": rpc(official, "eth_getCode", [ACC, block_hex]),
        "independent_acc": rpc(independent, "eth_getCode", [ACC, block_hex]),
    }

    census = chain_census(official, snapshot)
    safe = safe_gate(official, block_hex, census["admin"])
    runtime = runtime_gate(args.local_staker_code, args.local_acc_code, live_codes)
    alias = alias_gate(
        choose_rpc(BASE_RPCS, expected_chain_id=8453),
        {
            "admin_safe": census["admin"],
            "staker": STAKER,
            "accumulator": ACC,
            "token": TOKEN,
            "calculator": CALCULATOR,
            "deployer": DEPLOYER,
        },
    )
    bundle = production_bundle_gate()
    audits = audit_gate(args.audit_dir)
    handler_pass = args.handler_gate_file.exists() and args.handler_gate_file.read_text().strip() == "PASS"

    gates = {
        "handler_only_stateful_invariants": handler_pass,
        "production_census": bool(census["pass"]),
        "safe_4_of_7_no_modules": bool(safe["pass"]),
        "exact_runtime_bytecode_binding": bool(runtime["pass"]),
        "only_expected_reward_notifier": census["enabled_notifiers"] == [norm_addr(ACC)],
        "base_to_l3_alias_preimages_inactive": bool(alias["pass"]),
        "production_bundle_write_targets": bool(bundle["pass"]),
        "all_seven_audit_sources_extracted": bool(audits["pass"]),
    }
    all_pass = all(gates.values())
    notes = []
    if census["zero_balance_residual_count"]:
        notes.append(
            {
                "type": "non_bounty_ui_recovery_edge",
                "count": census["zero_balance_residual_count"],
                "reward_wei": census["zero_balance_residual_reward"],
            }
        )
    result = {
        "version": "Horizen-R3-2026-07-28",
        "exact_commit": "ab92502e9da98784dfe3bd3ef933d4e9345ff628",
        "all_required_gates_pass": all_pass,
        "gates": gates,
        "submission_verdict": "NO_SUBMIT" if all_pass else "HOLD_INVESTIGATE_FAILED_GATE",
        "valid_critical_candidates": 0,
        "valid_high_candidates": 0,
        "public_network_writes": 0,
        "production_census": census,
        "safe": safe,
        "runtime_binding": runtime,
        "alias_census": alias,
        "production_bundle": bundle,
        "audit_corpus": audits,
        "notes": notes,
    }
    (args.out / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    write_markdown(result, args.out / "RESULT.md")
    return 0 if all_pass else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"R3 gate failed: {exc}", file=sys.stderr)
        raise
