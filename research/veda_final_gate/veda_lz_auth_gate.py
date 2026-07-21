#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Any

from Crypto.Hash import keccak

RANDOM_EOA = "0x000000000000000000000000000000000000dEaD"
TELLER = "0x9AA79C84b79816ab920bBcE20f8f74557B514734"

CHAINS = [
    {
        "name": "ethereum",
        "chain_id": 1,
        "peer_eid": 30214,
        "rpcs": [
            "https://ethereum-rpc.publicnode.com",
            "https://eth.llamarpc.com",
            "https://eth.drpc.org",
        ],
    },
    {
        "name": "scroll",
        "chain_id": 534352,
        "peer_eid": 30101,
        "rpcs": [
            "https://rpc.scroll.io",
            "https://scroll-rpc.publicnode.com",
            "https://scroll.drpc.org",
        ],
    },
]

ADMIN_FUNCTIONS = [
    ("addChain", "addChain(uint32,bool,bool,address,uint128)", ["uint32", "bool", "bool", "address", "uint128"]),
    ("removeChain", "removeChain(uint32)", ["uint32"]),
    ("allowMessagesFromChain", "allowMessagesFromChain(uint32,address)", ["uint32", "address"]),
    ("allowMessagesToChain", "allowMessagesToChain(uint32,address,uint128)", ["uint32", "address", "uint128"]),
    ("stopMessagesFromChain", "stopMessagesFromChain(uint32)", ["uint32"]),
    ("stopMessagesToChain", "stopMessagesToChain(uint32)", ["uint32"]),
    ("setChainGasLimit", "setChainGasLimit(uint32,uint128)", ["uint32", "uint128"]),
    ("setPeer", "setPeer(uint32,bytes32)", ["uint32", "bytes32"]),
    ("setDelegate", "setDelegate(address)", ["address"]),
    ("setAuthority", "setAuthority(address)", ["address"]),
    ("transferOwnership", "transferOwnership(address)", ["address"]),
    ("setInboundRateLimits", "setInboundRateLimits((uint32,uint256,uint256)[])", ["empty_tuple_array"]),
    ("setOutboundRateLimits", "setOutboundRateLimits((uint32,uint256,uint256)[])", ["empty_tuple_array"]),
]


def selector(signature: str) -> str:
    h = keccak.new(digest_bits=256)
    h.update(signature.encode())
    return "0x" + h.hexdigest()[:8]


def word_uint(value: int) -> str:
    return hex(value)[2:].rjust(64, "0")


def word_bool(value: bool) -> str:
    return word_uint(1 if value else 0)


def word_address(value: str) -> str:
    return value.lower().removeprefix("0x").rjust(64, "0")


def word_bytes32(value: str) -> str:
    raw = value.lower().removeprefix("0x")
    return raw.rjust(64, "0")


def encode_static(signature: str, types: list[str], values: list[Any]) -> str:
    data = selector(signature).removeprefix("0x")
    for typ, value in zip(types, values):
        if typ in {"uint32", "uint128", "uint256"}:
            data += word_uint(int(value))
        elif typ == "bool":
            data += word_bool(bool(value))
        elif typ == "address":
            data += word_address(str(value))
        elif typ == "bytes32":
            data += word_bytes32(str(value))
        elif typ == "empty_tuple_array":
            # one dynamic argument: offset=32, then array length=0
            data += word_uint(32) + word_uint(0)
        else:
            raise ValueError(typ)
    return "0x" + data


def rpc_request(url: str, method: str, params: list[Any], retries: int = 3) -> dict[str, Any]:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = ""
    for attempt in range(retries):
        request = urllib.request.Request(
            url,
            data=body,
            headers={"content-type": "application/json", "user-agent": "veda-final-gate/1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                payload = json.loads(response.read().decode())
            if payload.get("error") is not None:
                return {"ok": False, "rpc_error": payload["error"]}
            return {"ok": True, "result": payload.get("result")}
        except Exception as exc:
            last = f"{type(exc).__name__}: {exc}"
            if attempt + 1 < retries:
                time.sleep(1.5 ** attempt)
    return {"ok": False, "transport_error": last}


class Client:
    def __init__(self, urls: list[str], expected_chain_id: int):
        self.urls = urls
        self.expected_chain_id = expected_chain_id
        self.url = self._select_url()

    def _select_url(self) -> str:
        errors = []
        for url in self.urls:
            rec = rpc_request(url, "eth_chainId", [])
            if rec.get("ok") and int(rec["result"], 16) == self.expected_chain_id:
                return url
            errors.append({"url_host": url.split("/")[2], "result": rec})
        raise RuntimeError(f"no healthy RPC for chain {self.expected_chain_id}: {errors}")

    def call(self, method: str, params: list[Any]) -> dict[str, Any]:
        return rpc_request(self.url, method, params)

    def eth_call(self, to: str, data: str, block: int, sender: str | None = None) -> dict[str, Any]:
        tx = {"to": to, "data": data}
        if sender:
            tx["from"] = sender
        rec = self.call("eth_call", [tx, hex(block)])
        return rec


def parse_address_word(value: str) -> str:
    if not isinstance(value, str) or len(value) < 66:
        raise ValueError(f"bad address word {value!r}")
    return "0x" + value[-40:]


def parse_bool_word(value: str) -> bool:
    return int(value, 16) != 0


def parse_uint_word(value: str) -> int:
    return int(value, 16)


def encode_can_call(caller: str, target: str, fn_selector: str) -> str:
    return (
        selector("canCall(address,address,bytes4)")
        + word_address(caller)
        + word_address(target)
        + fn_selector.removeprefix("0x").ljust(64, "0")
    )


def encode_public(target: str, fn_selector: str) -> str:
    return (
        selector("isCapabilityPublic(address,bytes4)")
        + word_address(target)
        + fn_selector.removeprefix("0x").ljust(64, "0")
    )


def encode_roles(target: str, fn_selector: str) -> str:
    return (
        selector("getRolesWithCapability(address,bytes4)")
        + word_address(target)
        + fn_selector.removeprefix("0x").ljust(64, "0")
    )


def direct_admin_calldata(name: str, sig: str, types: list[str], peer_eid: int) -> str:
    if name == "addChain":
        values = [peer_eid, True, True, RANDOM_EOA, 1]
    elif name in {"removeChain", "stopMessagesFromChain", "stopMessagesToChain"}:
        values = [peer_eid]
    elif name == "allowMessagesFromChain":
        values = [peer_eid, RANDOM_EOA]
    elif name == "allowMessagesToChain":
        values = [peer_eid, RANDOM_EOA, 1]
    elif name == "setChainGasLimit":
        values = [peer_eid, 1]
    elif name == "setPeer":
        values = [peer_eid, RANDOM_EOA]
    elif name in {"setDelegate", "setAuthority", "transferOwnership"}:
        values = [RANDOM_EOA]
    elif name in {"setInboundRateLimits", "setOutboundRateLimits"}:
        values = [None]
    else:
        raise ValueError(name)
    return encode_static(sig, types, values)


def run_chain(config: dict[str, Any]) -> dict[str, Any]:
    client = Client(config["rpcs"], config["chain_id"])
    block_number_rec = client.call("eth_blockNumber", [])
    if not block_number_rec.get("ok"):
        raise RuntimeError(block_number_rec)
    block = int(block_number_rec["result"], 16)
    block_rec = client.call("eth_getBlockByNumber", [hex(block), False])
    if not block_rec.get("ok") or not isinstance(block_rec.get("result"), dict):
        raise RuntimeError(block_rec)

    result: dict[str, Any] = {
        "chain": config["name"],
        "chain_id": config["chain_id"],
        "rpc_host": client.url.split("/")[2],
        "pinned_block": block,
        "pinned_block_hash": block_rec["result"]["hash"],
        "teller": TELLER,
        "peer_eid": config["peer_eid"],
        "reads": {},
        "admin_matrix": [],
        "errors": [],
    }

    for label, signature in [
        ("authority", "authority()"),
        ("owner", "owner()"),
        ("vault", "vault()"),
        ("accountant", "accountant()"),
        ("endpoint", "endpoint()"),
    ]:
        rec = client.eth_call(TELLER, selector(signature), block)
        result["reads"][label] = rec
        if rec.get("ok"):
            result[label] = parse_address_word(rec["result"])
        else:
            result["errors"].append({"read": label, "result": rec})

    authority = result.get("authority")
    if not authority:
        return result

    for address_label, address in [("teller", TELLER), ("authority", authority), ("vault", result.get("vault"))]:
        if not address:
            continue
        code_rec = client.call("eth_getCode", [address, hex(block)])
        result["reads"][f"code_{address_label}"] = code_rec
        if not code_rec.get("ok") or code_rec.get("result") in {None, "0x"}:
            result["errors"].append({"read": f"code_{address_label}", "result": code_rec})

    # Current peer and rate-limit state.
    peer_call = encode_static("peers(uint32)", ["uint32"], [config["peer_eid"]])
    result["reads"]["peer"] = client.eth_call(TELLER, peer_call, block)
    chain_call = encode_static("idToChains(uint32)", ["uint32"], [config["peer_eid"]])
    result["reads"]["chain_config"] = client.eth_call(TELLER, chain_call, block)
    inbound_call = encode_static("getAmountCanBeReceived(uint32)", ["uint32"], [config["peer_eid"]])
    result["reads"]["amount_can_be_received"] = client.eth_call(TELLER, inbound_call, block)

    for name, sig, types in ADMIN_FUNCTIONS:
        fn_sel = selector(sig)
        can_rec = client.eth_call(authority, encode_can_call(RANDOM_EOA, TELLER, fn_sel), block)
        public_rec = client.eth_call(authority, encode_public(TELLER, fn_sel), block)
        roles_rec = client.eth_call(authority, encode_roles(TELLER, fn_sel), block)
        direct_data = direct_admin_calldata(name, sig, types, config["peer_eid"])
        direct_rec = client.eth_call(TELLER, direct_data, block, RANDOM_EOA)

        row: dict[str, Any] = {
            "name": name,
            "signature": sig,
            "selector": fn_sel,
            "can_call_raw": can_rec,
            "public_raw": public_rec,
            "roles_raw": roles_rec,
            "direct_random_eoa_eth_call": direct_rec,
        }
        try:
            row["random_eoa_can_call"] = can_rec.get("ok") and parse_bool_word(can_rec["result"])
            row["is_public"] = public_rec.get("ok") and parse_bool_word(public_rec["result"])
            row["roles_bitmap"] = hex(parse_uint_word(roles_rec["result"])) if roles_rec.get("ok") else None
            row["direct_call_succeeded"] = bool(direct_rec.get("ok"))
        except Exception as exc:
            row["parse_error"] = f"{type(exc).__name__}: {exc}"
            result["errors"].append({"admin": name, "error": row["parse_error"]})
        result["admin_matrix"].append(row)

    return result


def main() -> int:
    output: dict[str, Any] = {
        "schema_version": 1,
        "safety": {
            "read_only": True,
            "private_key": False,
            "state_changing_transaction": False,
            "all_admin_invocations": "eth_call simulation only",
        },
        "random_eoa": RANDOM_EOA,
        "teller": TELLER,
        "chains": [],
        "errors": [],
    }

    for chain in CHAINS:
        try:
            output["chains"].append(run_chain(chain))
        except Exception as exc:
            output["errors"].append({"chain": chain["name"], "error": f"{type(exc).__name__}: {exc}"})

    rows = [row for chain in output["chains"] for row in chain.get("admin_matrix", [])]
    critical = [row for row in rows if row.get("random_eoa_can_call") or row.get("is_public") or row.get("direct_call_succeeded")]
    incomplete = bool(output["errors"]) or any(chain.get("errors") for chain in output["chains"]) or len(output["chains"]) != len(CHAINS)

    if critical:
        verdict = "MATERIAL_LIVE_PRECONDITION"
    elif incomplete:
        verdict = "EVIDENCE_INCOMPLETE"
    else:
        verdict = "KILL_PERMISSIONLESS_LZ_ADMIN_ABSENT"

    output["critical_rows"] = critical
    output["overall_verdict"] = verdict
    Path("results").mkdir(exist_ok=True)
    Path("results/veda_lz_auth_gate.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")

    lines = [
        "# Veda LayerZero live authorization gate",
        "",
        f"Overall verdict: `{verdict}`",
        "",
    ]
    for chain in output["chains"]:
        lines += [
            f"## {chain['chain']}",
            "",
            f"- pinned block: `{chain['pinned_block']}`",
            f"- block hash: `{chain['pinned_block_hash']}`",
            f"- authority: `{chain.get('authority')}`",
            f"- owner: `{chain.get('owner')}`",
            f"- vault: `{chain.get('vault')}`",
            "",
            "| selector | canCall(dead) | public | direct eth_call succeeds | roles |",
            "|---|---:|---:|---:|---|",
        ]
        for row in chain.get("admin_matrix", []):
            lines.append(
                f"| `{row['signature']}` | `{row.get('random_eoa_can_call')}` | `{row.get('is_public')}` | "
                f"`{row.get('direct_call_succeeded')}` | `{row.get('roles_bitmap')}` |"
            )
        if chain.get("errors"):
            lines += ["", "Errors:", "```json", json.dumps(chain["errors"], indent=2), "```"]
    if output["errors"]:
        lines += ["", "Top-level errors:", "```json", json.dumps(output["errors"], indent=2), "```"]
    Path("results/SUMMARY.md").write_text("\n".join(lines) + "\n")

    print(json.dumps({"verdict": verdict, "critical_rows": len(critical), "incomplete": incomplete}, indent=2))
    return 2 if critical else 3 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
