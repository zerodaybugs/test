#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

OFFICIAL_RPC = "https://horizen.calderachain.xyz/http"
INDEPENDENT_RPC = "https://26514.rpc.thirdweb.com"
STAKER = "0x6BF7CF29a8bcE11Aa62Cf593d165C244fA4d3E31"
ACCUMULATOR = "0x06f5555fee73EDdc385b6d76FE00DB2D96ccDaE8"
TOKEN = "0x57da2D504bf8b83Ef304759d9f2648522D7a9280"
CALCULATOR = "0xf518b3c7Cd5cc1595D10E7268677Da0Fe364E191"
SAFE = "0x1Afb144aaD0aE02f3Bb04C1eae4AC6020a727A21"
DEPLOYER = "0x9B264B21ca7659C256aD09171f827976Acd5a1C3"
SCALE = 10**36
ZERO = "0x" + "00" * 20


class RpcError(RuntimeError):
    pass


def selector(signature: str) -> str:
    out = subprocess.check_output(["cast", "sig", signature], text=True).strip()
    if not out.startswith("0x") or len(out) != 10:
        raise RuntimeError(f"invalid selector for {signature}: {out}")
    return out.lower()


SEL = {
    name: selector(signature)
    for name, signature in {
        "getDepositInfo": "getDepositInfo(uint256)",
        "deposits": "deposits(uint256)",
        "depositorTotalStaked": "depositorTotalStaked(address)",
        "depositorTotalEarningPower": "depositorTotalEarningPower(address)",
        "surrogates": "surrogates(address)",
        "balanceOf": "balanceOf(address)",
        "totalStaked": "totalStaked()",
        "totalEarningPower": "totalEarningPower()",
        "rewardEndTime": "rewardEndTime()",
        "scaledRewardRate": "scaledRewardRate()",
        "rewardPerTokenAccumulated": "rewardPerTokenAccumulated()",
        "STAKE_TOKEN": "STAKE_TOKEN()",
        "REWARD_TOKEN": "REWARD_TOKEN()",
        "earningPowerCalculator": "earningPowerCalculator()",
        "admin": "admin()",
        "isRewardNotifier": "isRewardNotifier(address)",
        "maxBumpTip": "maxBumpTip()",
        "MAX_CLAIM_FEE": "MAX_CLAIM_FEE()",
        "claimFeeParameters": "claimFeeParameters()",
        "owner": "owner()",
        "staker": "staker()",
        "rewardToken": "rewardToken()",
        "timeWindow": "timeWindow()",
        "whitelistEnabled": "whitelistEnabled()",
        "accumulatedRewards": "accumulatedRewards()",
        "getThreshold": "getThreshold()",
        "getOwners": "getOwners()",
        "nonce": "nonce()",
        "VERSION": "VERSION()",
    }.items()
}


def enc_uint(value: int) -> str:
    if value < 0 or value >= 2**256:
        raise ValueError(value)
    return f"{value:064x}"


def enc_address(value: str) -> str:
    raw = value.lower().removeprefix("0x")
    if len(raw) != 40:
        raise ValueError(value)
    int(raw, 16)
    return raw.rjust(64, "0")


def words(data: str) -> list[int]:
    raw = data.removeprefix("0x")
    if len(raw) % 64:
        raise RpcError(f"non-word-aligned response: {data[:80]}")
    return [int(raw[i : i + 64], 16) for i in range(0, len(raw), 64)]


def as_address(word: int) -> str:
    return "0x" + f"{word:064x}"[-40:]


def as_bool(data: str) -> bool:
    parsed = words(data)
    if len(parsed) != 1 or parsed[0] not in (0, 1):
        raise RpcError(f"invalid bool: {data}")
    return bool(parsed[0])


def as_uint(data: str) -> int:
    parsed = words(data)
    if len(parsed) != 1:
        raise RpcError(f"invalid uint: {data}")
    return parsed[0]


def as_address_result(data: str) -> str:
    parsed = words(data)
    if len(parsed) != 1:
        raise RpcError(f"invalid address: {data}")
    return as_address(parsed[0])


def decode_dynamic_addresses(data: str) -> list[str]:
    w = words(data)
    if len(w) < 2 or w[0] != 32:
        raise RpcError(f"invalid dynamic address array: {data[:120]}")
    length = w[1]
    if len(w) != 2 + length:
        raise RpcError(f"invalid address-array length: expected {length}, words={len(w)}")
    return [as_address(x) for x in w[2:]]


def decode_string(data: str) -> str:
    raw = bytes.fromhex(data.removeprefix("0x"))
    if len(raw) < 64:
        raise RpcError("invalid string result")
    offset = int.from_bytes(raw[0:32], "big")
    length = int.from_bytes(raw[offset : offset + 32], "big")
    payload = raw[offset + 32 : offset + 32 + length]
    return payload.decode("utf-8")


@dataclass(frozen=True)
class Call:
    to: str
    data: str


class Rpc:
    def __init__(self, url: str, label: str):
        self.url = url
        self.label = label
        self.next_id = 1

    def _post(self, payload: Any) -> Any:
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload, separators=(",", ":")).encode(),
            headers={"content-type": "application/json", "user-agent": "horizen-readonly-census/1"},
            method="POST",
        )
        last: Exception | None = None
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    return json.loads(response.read())
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last = exc
                time.sleep(1.0 + attempt)
        raise RpcError(f"{self.label} POST failed: {last}")

    def request(self, method: str, params: list[Any]) -> Any:
        req_id = self.next_id
        self.next_id += 1
        response = self._post({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        if not isinstance(response, dict) or response.get("id") != req_id:
            raise RpcError(f"{self.label} malformed response for {method}: {response}")
        if "error" in response:
            raise RpcError(f"{self.label} {method}: {response['error']}")
        return response.get("result")

    def block_number(self) -> int:
        return int(self.request("eth_blockNumber", []), 16)

    def storage(self, address: str, slot: int, block: str) -> int:
        return int(self.request("eth_getStorageAt", [address, hex(slot), block]), 16)

    def code(self, address: str, block: str) -> bytes:
        return bytes.fromhex(self.request("eth_getCode", [address, block]).removeprefix("0x"))

    def call(self, call: Call, block: str) -> str:
        return self.request("eth_call", [{"to": call.to, "data": call.data}, block])

    def batch_calls(self, calls: list[Call], block: str, chunk: int = 80) -> list[str]:
        results: list[str] = []
        for start in range(0, len(calls), chunk):
            part = calls[start : start + chunk]
            ids = list(range(self.next_id, self.next_id + len(part)))
            self.next_id += len(part)
            payload = [
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "eth_call",
                    "params": [{"to": call.to, "data": call.data}, block],
                }
                for req_id, call in zip(ids, part)
            ]
            try:
                response = self._post(payload)
                if not isinstance(response, list):
                    raise RpcError("batch unsupported")
                by_id = {item.get("id"): item for item in response if isinstance(item, dict)}
                for req_id in ids:
                    item = by_id.get(req_id)
                    if not item or "error" in item or "result" not in item:
                        raise RpcError(f"batch item failed: {item}")
                    results.append(item["result"])
            except Exception:
                # Conservative fallback for endpoints that reject JSON-RPC batches.
                for call in part:
                    results.append(self.call(call, block))
        return results


def call0(to: str, name: str) -> Call:
    return Call(to, SEL[name])


def call_uint(to: str, name: str, value: int) -> Call:
    return Call(to, SEL[name] + enc_uint(value))


def call_address(to: str, name: str, value: str) -> Call:
    return Call(to, SEL[name] + enc_address(value))


def digest_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def scan(rpc: Rpc, block_number: int) -> dict[str, Any]:
    block = hex(block_number)
    next_deposit_id = rpc.storage(STAKER, 0, block)
    if not 0 < next_deposit_id < 10_000:
        raise RpcError(f"{rpc.label}: implausible nextDepositId={next_deposit_id}")

    global_calls = [
        call0(STAKER, "totalStaked"),
        call0(STAKER, "totalEarningPower"),
        call0(STAKER, "rewardEndTime"),
        call0(STAKER, "scaledRewardRate"),
        call0(STAKER, "rewardPerTokenAccumulated"),
        call_address(TOKEN, "balanceOf", STAKER),
        call_address(TOKEN, "balanceOf", ACCUMULATOR),
        call0(ACCUMULATOR, "accumulatedRewards"),
    ]
    (
        total_staked_raw,
        total_power_raw,
        reward_end_raw,
        scaled_rate_raw,
        current_rpt_raw,
        staker_balance_raw,
        accumulator_balance_raw,
        accumulator_accounted_raw,
    ) = rpc.batch_calls(global_calls, block)
    total_staked = as_uint(total_staked_raw)
    total_power = as_uint(total_power_raw)
    reward_end = as_uint(reward_end_raw)
    scaled_rate = as_uint(scaled_rate_raw)
    current_rpt = as_uint(current_rpt_raw)
    staker_balance = as_uint(staker_balance_raw)
    accumulator_balance = as_uint(accumulator_balance_raw)
    accumulator_accounted = as_uint(accumulator_accounted_raw)

    deposit_calls: list[Call] = []
    for deposit_id in range(next_deposit_id):
        deposit_calls.append(call_uint(STAKER, "getDepositInfo", deposit_id))
        deposit_calls.append(call_uint(STAKER, "deposits", deposit_id))
    deposit_results = rpc.batch_calls(deposit_calls, block)

    owner_balance_sum: dict[str, int] = {}
    owner_power_sum: dict[str, int] = {}
    delegatees: set[str] = set()
    deposits_digest_rows: list[list[Any]] = []
    deposit_balance_sum = 0
    deposit_power_sum = 0
    unclaimed_sum = 0
    scaled_unclaimed_sum = 0
    zero_balance_residual_count = 0
    zero_balance_residual_reward = 0
    zero_balance_residual_scaled = 0

    for deposit_id in range(next_deposit_id):
        info = words(deposit_results[deposit_id * 2])
        raw = words(deposit_results[deposit_id * 2 + 1])
        if len(info) != 6 or len(raw) != 7:
            raise RpcError(f"{rpc.label}: malformed deposit {deposit_id}")
        balance, owner_word, earning_power, delegatee_word, claimer_word, unclaimed = info
        raw_balance, raw_owner, raw_power, raw_delegatee, raw_claimer, checkpoint, scaled_checkpoint = raw
        owner = as_address(owner_word)
        delegatee = as_address(delegatee_word)
        claimer = as_address(claimer_word)
        if owner == ZERO or delegatee == ZERO:
            raise RpcError(f"{rpc.label}: zero address in allocated deposit {deposit_id}")
        if (balance, owner_word, earning_power, delegatee_word, claimer_word) != (
            raw_balance,
            raw_owner,
            raw_power,
            raw_delegatee,
            raw_claimer,
        ):
            raise RpcError(f"{rpc.label}: helper/raw mismatch for deposit {deposit_id}")
        if checkpoint > current_rpt:
            raise RpcError(f"{rpc.label}: future checkpoint in deposit {deposit_id}")
        scaled_live = scaled_checkpoint + earning_power * (current_rpt - checkpoint)
        if scaled_live // SCALE != unclaimed:
            raise RpcError(f"{rpc.label}: scaled/view reward mismatch in deposit {deposit_id}")

        deposit_balance_sum += balance
        deposit_power_sum += earning_power
        unclaimed_sum += unclaimed
        scaled_unclaimed_sum += scaled_live
        owner_balance_sum[owner] = owner_balance_sum.get(owner, 0) + balance
        owner_power_sum[owner] = owner_power_sum.get(owner, 0) + earning_power
        delegatees.add(delegatee)
        if balance == 0 and scaled_live > 0:
            zero_balance_residual_count += 1
            zero_balance_residual_reward += unclaimed
            zero_balance_residual_scaled += scaled_live
        deposits_digest_rows.append(
            [deposit_id, balance, owner, earning_power, delegatee, claimer, checkpoint, scaled_checkpoint]
        )

    future = words(rpc.call(call_uint(STAKER, "getDepositInfo", next_deposit_id), block))
    if len(future) != 6 or future[1] != 0:
        raise RpcError(f"{rpc.label}: nextDepositId slot boundary check failed")

    owners = sorted(owner_balance_sum)
    owner_calls: list[Call] = []
    for owner in owners:
        owner_calls.append(call_address(STAKER, "depositorTotalStaked", owner))
        owner_calls.append(call_address(STAKER, "depositorTotalEarningPower", owner))
    owner_results = rpc.batch_calls(owner_calls, block)
    for index, owner in enumerate(owners):
        chain_balance = as_uint(owner_results[index * 2])
        chain_power = as_uint(owner_results[index * 2 + 1])
        if chain_balance != owner_balance_sum[owner] or chain_power != owner_power_sum[owner]:
            raise RpcError(f"{rpc.label}: owner aggregate mismatch for {owner}")

    delegatee_list = sorted(delegatees)
    surrogate_results = rpc.batch_calls(
        [call_address(STAKER, "surrogates", delegatee) for delegatee in delegatee_list], block
    )
    surrogates = [as_address_result(value) for value in surrogate_results]
    if any(address == ZERO for address in surrogates):
        raise RpcError(f"{rpc.label}: missing surrogate")
    surrogate_balances = [
        as_uint(value)
        for value in rpc.batch_calls(
            [call_address(TOKEN, "balanceOf", address) for address in surrogates], block
        )
    ]
    surrogate_balance_sum = sum(surrogate_balances)
    empty_surrogates = sum(balance == 0 for balance in surrogate_balances)

    config_calls = [
        call0(STAKER, "STAKE_TOKEN"),
        call0(STAKER, "REWARD_TOKEN"),
        call0(STAKER, "earningPowerCalculator"),
        call0(STAKER, "admin"),
        call_address(STAKER, "isRewardNotifier", ACCUMULATOR),
        call_address(STAKER, "isRewardNotifier", DEPLOYER),
        call0(STAKER, "maxBumpTip"),
        call0(STAKER, "MAX_CLAIM_FEE"),
        call0(STAKER, "claimFeeParameters"),
        call0(ACCUMULATOR, "owner"),
        call0(ACCUMULATOR, "staker"),
        call0(ACCUMULATOR, "rewardToken"),
        call0(ACCUMULATOR, "timeWindow"),
        call0(ACCUMULATOR, "whitelistEnabled"),
        call0(SAFE, "getThreshold"),
        call0(SAFE, "getOwners"),
        call0(SAFE, "nonce"),
        call0(SAFE, "VERSION"),
    ]
    config = rpc.batch_calls(config_calls, block)
    fee_words = words(config[8])
    if len(fee_words) != 2:
        raise RpcError(f"{rpc.label}: malformed fee tuple")
    safe_owners = decode_dynamic_addresses(config[15])
    safe_threshold = as_uint(config[14])
    safe_nonce = as_uint(config[16])
    safe_version = decode_string(config[17])

    expected_addresses = {
        "stake_token": TOKEN.lower(),
        "reward_token": TOKEN.lower(),
        "calculator": CALCULATOR.lower(),
        "admin": SAFE.lower(),
        "acc_owner": SAFE.lower(),
        "acc_staker": STAKER.lower(),
        "acc_token": TOKEN.lower(),
    }
    actual_addresses = {
        "stake_token": as_address_result(config[0]),
        "reward_token": as_address_result(config[1]),
        "calculator": as_address_result(config[2]),
        "admin": as_address_result(config[3]),
        "acc_owner": as_address_result(config[9]),
        "acc_staker": as_address_result(config[10]),
        "acc_token": as_address_result(config[11]),
    }
    for key, expected in expected_addresses.items():
        if actual_addresses[key] != expected:
            raise RpcError(f"{rpc.label}: {key}={actual_addresses[key]}, expected={expected}")

    if not as_bool(config[4]) or as_bool(config[5]):
        raise RpcError(f"{rpc.label}: notifier configuration mismatch")
    if as_uint(config[6]) != 0 or as_uint(config[7]) != 0:
        raise RpcError(f"{rpc.label}: Phase-1 fee/bump configuration mismatch")
    if fee_words != [0, 0]:
        raise RpcError(f"{rpc.label}: nonzero claim fee tuple")
    if as_uint(config[12]) != 431_700 or as_bool(config[13]):
        raise RpcError(f"{rpc.label}: accumulator timing/whitelist mismatch")
    if safe_threshold == 0 or safe_threshold > len(safe_owners):
        raise RpcError(f"{rpc.label}: invalid Safe threshold")
    if ZERO in safe_owners or len(set(safe_owners)) != len(safe_owners):
        raise RpcError(f"{rpc.label}: invalid Safe owner list")

    if deposit_balance_sum != total_staked:
        raise RpcError(f"{rpc.label}: deposit/global principal mismatch")
    if deposit_power_sum != total_power or total_staked != total_power:
        raise RpcError(f"{rpc.label}: earning-power mismatch")
    if surrogate_balance_sum < total_staked:
        raise RpcError(f"{rpc.label}: surrogate undercollateralization")
    if accumulator_balance < accumulator_accounted:
        raise RpcError(f"{rpc.label}: accumulator undercollateralization")

    block_data = rpc.request("eth_getBlockByNumber", [block, False])
    timestamp = int(block_data["timestamp"], 16)
    remaining_scaled = scaled_rate * max(0, reward_end - timestamp)
    total_scaled_obligations = scaled_unclaimed_sum + remaining_scaled
    reward_balance_scaled = staker_balance * SCALE
    if total_scaled_obligations > reward_balance_scaled:
        raise RpcError(
            f"{rpc.label}: reward insolvency by {total_scaled_obligations - reward_balance_scaled} scaled units"
        )

    staker_code = rpc.code(STAKER, block)
    accumulator_code = rpc.code(ACCUMULATOR, block)
    safe_code = rpc.code(SAFE, block)
    if not staker_code or not accumulator_code or not safe_code:
        raise RpcError(f"{rpc.label}: missing runtime code")

    return {
        "label": rpc.label,
        "block": block_number,
        "timestamp": timestamp,
        "next_deposit_id": next_deposit_id,
        "unique_owners": len(owners),
        "unique_delegatees": len(delegatee_list),
        "total_staked": total_staked,
        "total_power": total_power,
        "surrogate_balance_sum": surrogate_balance_sum,
        "surrogate_surplus": surrogate_balance_sum - total_staked,
        "empty_surrogates": empty_surrogates,
        "unclaimed_sum": unclaimed_sum,
        "scaled_unclaimed_sum": scaled_unclaimed_sum,
        "remaining_scaled": remaining_scaled,
        "total_scaled_obligations": total_scaled_obligations,
        "staker_balance": staker_balance,
        "reward_surplus_scaled": reward_balance_scaled - total_scaled_obligations,
        "accumulator_balance": accumulator_balance,
        "accumulator_accounted": accumulator_accounted,
        "zero_balance_residual_count": zero_balance_residual_count,
        "zero_balance_residual_reward": zero_balance_residual_reward,
        "zero_balance_residual_scaled": zero_balance_residual_scaled,
        "safe_version": safe_version,
        "safe_threshold": safe_threshold,
        "safe_owner_count": len(safe_owners),
        "safe_owners": safe_owners,
        "safe_nonce": safe_nonce,
        "staker_code_size": len(staker_code),
        "staker_code_sha256": hashlib.sha256(staker_code).hexdigest(),
        "accumulator_code_size": len(accumulator_code),
        "accumulator_code_sha256": hashlib.sha256(accumulator_code).hexdigest(),
        "safe_code_size": len(safe_code),
        "safe_code_sha256": hashlib.sha256(safe_code).hexdigest(),
        "deposits_digest": digest_json(deposits_digest_rows),
    }


def comparable(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if key != "label"}


def main() -> int:
    official_rpc = Rpc(OFFICIAL_RPC, "official")
    independent_rpc = Rpc(INDEPENDENT_RPC, "independent")
    latest = official_rpc.block_number()
    pinned = latest - 8
    if pinned <= 0:
        raise RpcError("invalid pinned block")

    official = scan(official_rpc, pinned)
    independent = scan(independent_rpc, pinned)
    if comparable(official) != comparable(independent):
        differing = {
            key: [official.get(key), independent.get(key)]
            for key in sorted(set(official) | set(independent))
            if key != "label" and official.get(key) != independent.get(key)
        }
        raise RpcError("RPC consensus mismatch: " + json.dumps(differing, sort_keys=True))

    output = {
        "target_commit": "ab92502e9da98784dfe3bd3ef933d4e9345ff628",
        "public_network_writes": 0,
        "rpc_consensus": True,
        "result": official,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"CENSUS_ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
