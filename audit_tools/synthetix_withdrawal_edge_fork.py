#!/usr/bin/env python3
"""Adaptive local-fork edge-case probe for the current Synthetix Deposit proxy.

The script runs only against a local Anvil fork. It impersonates the currently configured live role
members on the fork, never signs with a real key, and never broadcasts to a public network. It tests
empty, zero-amount, duplicate-token, array-length, and destination-lock withdrawal entries.
"""
from __future__ import annotations

import json
import os
import pathlib
import time
import urllib.request
from typing import Any

from web3 import Web3
from web3.exceptions import ContractLogicError

OUT = pathlib.Path("synthetix_withdrawal_edge_fork")
OUT.mkdir(parents=True, exist_ok=True)
RPC = os.environ.get("ANVIL_RPC", "http://127.0.0.1:8545")
PROXY = Web3.to_checksum_address("0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B")
IMPLEMENTATION = Web3.to_checksum_address("0xff6611190b48Cc920EF3c5DCbD356bF2C20D731F")
USDT = Web3.to_checksum_address("0xdAC17F958D2ee523a2206206994597C13D831ec7")
DEST_A = Web3.to_checksum_address("0x1000000000000000000000000000000000000001")
DEST_B = Web3.to_checksum_address("0x1000000000000000000000000000000000000002")
DEST_C = Web3.to_checksum_address("0x1000000000000000000000000000000000000003")


def fetch_abi() -> list[dict[str, Any]]:
    urls = [
        f"https://repo.sourcify.dev/contracts/full_match/1/{IMPLEMENTATION}/metadata.json",
        f"https://repo.sourcify.dev/contracts/partial_match/1/{IMPLEMENTATION}/metadata.json",
    ]
    errors = []
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                metadata = json.load(response)
            abi = metadata.get("output", {}).get("abi")
            if isinstance(abi, list):
                return abi
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{type(exc).__name__}: {exc}")
    raise RuntimeError(f"unable to fetch ABI: {errors}")


def fn_abis(abi: list[dict[str, Any]], predicate) -> list[dict[str, Any]]:
    return [item for item in abi if item.get("type") == "function" and predicate(item)]


def function_signature(item: dict[str, Any]) -> str:
    return f"{item.get('name')}({','.join(x.get('type','') for x in item.get('inputs',[]))})"


def rpc(w3: Web3, method: str, params: list[Any]) -> Any:
    response = w3.provider.make_request(method, params)
    if "error" in response:
        raise RuntimeError(f"{method}: {response['error']}")
    return response.get("result")


def impersonate(w3: Web3, address: str) -> None:
    rpc(w3, "anvil_impersonateAccount", [address])
    rpc(w3, "anvil_setBalance", [address, hex(10**20)])


def snapshot(w3: Web3) -> str:
    return rpc(w3, "evm_snapshot", [])


def revert(w3: Web3, snap: str) -> None:
    rpc(w3, "evm_revert", [snap])


def transact(fn, sender: str, gas: int = 8_000_000) -> dict[str, Any]:
    tx_hash = fn.transact({"from": sender, "gas": gas})
    receipt = fn.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    if receipt.status != 1:
        raise RuntimeError("transaction reverted")
    return dict(receipt)


def normalize_role_member(contract, role_name: str) -> str:
    role_fn = getattr(contract.functions, role_name)
    role = role_fn().call()
    count = contract.functions.getRoleMemberCount(role).call()
    if count < 1:
        raise RuntimeError(f"{role_name} has no member")
    return Web3.to_checksum_address(contract.functions.getRoleMember(role, 0).call())


def locate_abi(abi: list[dict[str, Any]]) -> dict[str, Any]:
    create = fn_abis(abi, lambda x: "create" in x.get("name", "").lower() and "withdraw" in x.get("name", "").lower() and any(i.get("type", "").startswith("tuple") for i in x.get("inputs", [])))
    vote = fn_abis(abi, lambda x: ("vote" in x.get("name", "").lower() or "validate" in x.get("name", "").lower()) and "withdraw" in x.get("name", "").lower())
    disburse = fn_abis(abi, lambda x: any(k in x.get("name", "").lower() for k in ("disburse", "finalize")) and "withdraw" in x.get("name", "").lower())
    active = fn_abis(abi, lambda x: x.get("stateMutability") in ("view", "pure") and "active" in x.get("name", "").lower() and "withdraw" in x.get("name", "").lower() and len(x.get("inputs", [])) == 1 and x["inputs"][0].get("type") == "address")
    if not create:
        raise RuntimeError("create-withdrawal tuple function not found")
    return {
        "create": create[0],
        "vote": vote[0] if vote else None,
        "disburse": disburse[0] if disburse else None,
        "active": active[0] if active else None,
        "candidates": {
            "create": [function_signature(x) for x in create],
            "vote": [function_signature(x) for x in vote],
            "disburse": [function_signature(x) for x in disburse],
            "active": [function_signature(x) for x in active],
        },
    }


def tuple_components(create_abi: dict[str, Any]) -> list[dict[str, Any]]:
    tuple_input = next(i for i in create_abi["inputs"] if i.get("type", "").startswith("tuple"))
    return tuple_input.get("components", [])


def build_entry(components: list[dict[str, Any]], tokens: list[str], amounts: list[int], beneficiary: str):
    values = []
    for component in components:
        name = component.get("name", "").lower()
        typ = component.get("type", "")
        if "token" in name or typ == "address[]":
            values.append(tokens)
        elif "amount" in name or typ.startswith("uint") and typ.endswith("[]"):
            values.append(amounts)
        elif "beneficiary" in name or (typ == "address" and "user" in name):
            values.append(beneficiary)
        elif typ == "address":
            values.append(beneficiary)
        elif typ.endswith("[]"):
            values.append([])
        elif typ.startswith("uint"):
            values.append(0)
        elif typ == "bool":
            values.append(False)
        else:
            raise RuntimeError(f"unsupported tuple component: {component}")
    return tuple(values)


def call_create(contract, create_abi: dict[str, Any], sender: str, entries: list[tuple]) -> dict[str, Any]:
    fn = contract.get_function_by_signature(function_signature(create_abi))
    inputs = create_abi.get("inputs", [])
    args = []
    for item in inputs:
        typ = item.get("type", "")
        name = item.get("name", "").lower()
        if typ.startswith("tuple"):
            args.append(entries)
        elif typ.startswith("uint"):
            args.append(0)
        elif typ == "address":
            args.append(sender)
        elif typ == "bool":
            args.append(True)
        else:
            raise RuntimeError(f"unsupported create input: {item}")
    return transact(fn(*args), sender)


def active_id(contract, active_abi: dict[str, Any] | None, beneficiary: str) -> Any:
    if not active_abi:
        return None
    fn = contract.get_function_by_signature(function_signature(active_abi))
    try:
        return fn(beneficiary).call()
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"[:300]


def run_case(w3: Web3, contract, located: dict[str, Any], relayer: str, label: str, raw_entries: list[tuple[list[str], list[int], str]]) -> dict[str, Any]:
    snap = snapshot(w3)
    components = tuple_components(located["create"])
    entries = [build_entry(components, tokens, amounts, beneficiary) for tokens, amounts, beneficiary in raw_entries]
    before = {dest: active_id(contract, located["active"], dest) for _, _, dest in raw_entries}
    result: dict[str, Any] = {"label": label, "beforeActive": before, "accepted": False}
    try:
        receipt = call_create(contract, located["create"], relayer, entries)
        result["accepted"] = True
        result["gasUsed"] = receipt.get("gasUsed")
        result["logCount"] = len(receipt.get("logs", []))
        result["afterActive"] = {dest: active_id(contract, located["active"], dest) for _, _, dest in raw_entries}
        # Try a second zero-value request to the first destination to determine whether a lock was created.
        first_dest = raw_entries[0][2]
        second = build_entry(components, [USDT], [0], first_dest)
        try:
            call_create(contract, located["create"], relayer, [second])
            result["secondSameDestinationAccepted"] = True
        except Exception as exc:  # noqa: BLE001
            result["secondSameDestinationAccepted"] = False
            result["secondSameDestinationError"] = f"{type(exc).__name__}: {exc}"[:500]
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"{type(exc).__name__}: {exc}"[:1000]
    finally:
        revert(w3, snap)
    return result


def main() -> None:
    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 60}))
    if not w3.is_connected():
        raise RuntimeError("Anvil is not reachable")
    abi = fetch_abi()
    contract = w3.eth.contract(address=PROXY, abi=abi)
    located = locate_abi(abi)
    relayer = normalize_role_member(contract, "RELAYER_ROLE")
    watcher = normalize_role_member(contract, "WATCHER_ROLE")
    teller = normalize_role_member(contract, "TELLER_ROLE")
    for address in {relayer, watcher, teller}:
        impersonate(w3, address)

    token = w3.eth.contract(address=USDT, abi=[{
        "type":"function","name":"balanceOf","stateMutability":"view",
        "inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}]
    }])
    physical = int(token.functions.balanceOf(PROXY).call())
    cases = [
        ("empty_entry", [([], [], DEST_A)]),
        ("zero_amount", [([USDT], [0], DEST_A)]),
        ("duplicate_token_single_entry", [([USDT, USDT], [1_000_000, 1_000_000], DEST_A)]),
        ("mismatch_more_tokens", [([USDT, USDT], [1_000_000], DEST_A)]),
        ("mismatch_more_amounts", [([USDT], [1_000_000, 1_000_000], DEST_A)]),
        ("duplicate_entries_same_destination", [([USDT], [1_000_000], DEST_A), ([USDT], [1_000_000], DEST_A)]),
        ("duplicate_entries_distinct_destinations", [([USDT], [1_000_000], DEST_A), ([USDT], [1_000_000], DEST_B)]),
        ("three_zero_distinct_destinations", [([USDT], [0], DEST_A), ([USDT], [0], DEST_B), ([USDT], [0], DEST_C)]),
        ("sum_exceeds_physical_but_each_below", [([USDT], [physical * 3 // 5], DEST_A), ([USDT], [physical * 3 // 5], DEST_B)]),
    ]
    results = [run_case(w3, contract, located, relayer, label, entries) for label, entries in cases]
    output = {
        "safety": "Local Anvil fork only; live role addresses impersonated locally; no public transaction or real key.",
        "proxy": PROXY,
        "implementation": IMPLEMENTATION,
        "abiFunctions": located["candidates"],
        "roleAddressHashes": {
            "relayer": Web3.keccak(text=relayer).hex(),
            "watcher": Web3.keccak(text=watcher).hex(),
            "teller": Web3.keccak(text=teller).hex(),
        },
        "physicalUSDT": physical,
        "results": results,
        "acceptedCases": [item["label"] for item in results if item.get("accepted")],
        "zeroCostLockCandidates": [item["label"] for item in results if item.get("accepted") and item.get("secondSameDestinationAccepted") is False and item["label"] in {"empty_entry", "zero_amount", "three_zero_distinct_destinations"}],
        "verdict": "CONTRACT_EDGE_CASES_REQUIRE_BACKEND_REACHABILITY_REVIEW",
    }
    (OUT / "summary.json").write_text(json.dumps(output, indent=2, sort_keys=True, default=str), encoding="utf-8")
    print(json.dumps({
        "acceptedCases": output["acceptedCases"],
        "zeroCostLockCandidates": output["zeroCostLockCandidates"],
        "verdict": output["verdict"],
    }, indent=2))


if __name__ == "__main__":
    main()
