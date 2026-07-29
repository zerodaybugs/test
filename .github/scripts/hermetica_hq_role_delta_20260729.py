#!/usr/bin/env python3
"""Public read-only Hermetica HQ role delta and authority-relay census.

Pins calls to one Stacks tip, refreshes all six role maps, inventories successful
HQ transactions, discovers newly mentioned principals, and inspects source for
active contract principals. It never constructs, signs, or broadcasts a tx.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HIRO = "https://api.hiro.so"
DEPLOYER = "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D"
HQ_NAME = "hq-v1"
HQ = f"{DEPLOYER}.{HQ_NAME}"
OUT = Path(os.environ.get("SCAN_OUT", "hermetica-hq-role-delta-output"))
UA = "authorized-read-only-hermetica-role-delta/1.0"
C32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
BASELINE_MAX_SUCCESS_HEIGHT = 8_370_264
BASELINE_SUCCESS_TXIDS = {
    "0x80e04aa5719611edecfcc61ba184fbf04d195c36c4bf7b5ec3a85a3772ccec46",
    "0x624aeee9fff17a0bd817dea5bbcc48c6420200f16c0f281e413de5290a22239e",
    "0x7ea2b82c30f06be6ef5548c2165bb8a5d24f45f518afcc744d48992c47274c11",
}
ROLES = ["guardian", "trader", "rewarder", "manager", "fee-setter", "protocol"]
BASELINE_CANDIDATES = [
    "SM1QXYXZG78DCWJZJKY0901KTK3350071W9YYRPMT",
    "SP1C72K3FP2VCMW6814TGPG2Q07A54597WW6HB1YR",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.airdrop-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.blacklist-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.controller-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.fee-collector-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.granite-interface-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.hermetica-interface-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.hq-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.reserve-fund-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.reserve-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.state-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.token-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.trading-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.vault-hbtc-v1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.vault-hbtc-v1-1",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.vault-hbtc-v1-2",
    "SP1S1HSFH0SQQGWKB69EYFNY0B1MHRMGXR3J1FH4D.zest-interface-hbtc-v1",
    "SP20V8SG811G6CT2QMZQNX6XCN20YAX36DYD1BAE0",
    "SP292YFARYZZ46EJY8GYRPN94Q1Q7DEBJ2QF7AA6F",
    "SP2AS467J369H67HK3TS2TDH1YB0XNN7YZ8M7FM1B",
    "SP2WS9QFNR8VMJZY6VWWFZNPKN7ZTVP746BMXJF7A",
    "SP334EHW3XT01N9K2K163XRJT0KVTGY92C9P12EHP",
    "SP36VR1J6EXNXTP02K0AQD4BNQ63F30R1P5W6C93C",
    "SP6XGBDAD800GGY6XF48AC27467W9PEHA6EPBGKJ",
]
BASELINE_ACTIVE = {
    "SM1QXYXZG78DCWJZJKY0901KTK3350071W9YYRPMT": ["trader", "rewarder", "manager"],
    "SP1C72K3FP2VCMW6814TGPG2Q07A54597WW6HB1YR": ["trader", "rewarder", "manager"],
    f"{DEPLOYER}.controller-hbtc-v1": ["protocol"],
    f"{DEPLOYER}.fee-collector-hbtc-v1": ["protocol"],
    f"{DEPLOYER}.hermetica-interface-hbtc-v1": ["protocol"],
    f"{DEPLOYER}.reserve-fund-hbtc-v1": ["protocol"],
    f"{DEPLOYER}.reserve-hbtc-v1": ["protocol"],
    f"{DEPLOYER}.state-hbtc-v1": ["protocol"],
    f"{DEPLOYER}.trading-hbtc-v1": ["trader", "manager"],
    f"{DEPLOYER}.vault-hbtc-v1-2": ["protocol"],
    f"{DEPLOYER}.zest-interface-hbtc-v1": ["protocol"],
    "SP2WS9QFNR8VMJZY6VWWFZNPKN7ZTVP746BMXJF7A": ["trader", "manager"],
    "SP334EHW3XT01N9K2K163XRJT0KVTGY92C9P12EHP": ["trader", "manager"],
    "SP36VR1J6EXNXTP02K0AQD4BNQ63F30R1P5W6C93C": ["trader", "manager"],
}


def fetch_json(url: str, body: dict[str, Any] | None = None, retries: int = 16) -> Any:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
            with urllib.request.urlopen(req, timeout=40) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code in (400, 404):
                try:
                    detail = exc.read().decode("utf-8", "replace")
                except Exception:
                    detail = ""
                raise RuntimeError(f"HTTP {exc.code} {url}: {detail[:500]}") from exc
            time.sleep(min(15.0, 0.75 * (2 ** min(attempt, 5))))
    raise RuntimeError(f"request failed after retries: {url}: {last}")


def c32encode(input_hex: str) -> str:
    if len(input_hex) % 2:
        input_hex = "0" + input_hex
    input_hex = input_hex.lower()
    hexchars = "0123456789abcdef"
    result: list[str] = []
    carry = 0
    for index in range(len(input_hex) - 1, -1, -1):
        if carry < 4:
            current = hexchars.index(input_hex[index]) >> carry
            following = hexchars.index(input_hex[index - 1]) if index else 0
            bits = carry + 1
            result.insert(0, C32[current + ((following % (1 << bits)) << (5 - bits))])
            carry = bits
        else:
            carry = 0
    while result and result[0] == "0":
        result.pop(0)
    zero_bytes = 0
    for byte in bytes.fromhex(input_hex):
        if byte:
            break
        zero_bytes += 1
    return "0" * zero_bytes + "".join(result)


def c32decode(value: str) -> str:
    value = value.upper().replace("O", "0").replace("L", "1").replace("I", "1")
    if any(ch not in C32 for ch in value):
        raise ValueError("invalid c32")
    zero_bytes = len(value) - len(value.lstrip("0"))
    hexchars = "0123456789abcdef"
    result: list[str] = []
    carry = 0
    carry_bits = 0
    for ch in reversed(value):
        if carry_bits == 4:
            result.insert(0, hexchars[carry])
            carry_bits = 0
            carry = 0
        code = C32.index(ch) << carry_bits
        current = code + carry
        result.insert(0, hexchars[current % 16])
        carry_bits += 1
        carry = current >> 4
    result.insert(0, hexchars[carry])
    if len(result) % 2:
        result.insert(0, "0")
    leading = 0
    while leading < len(result) and result[leading] == "0":
        leading += 1
    result = result[leading - (leading % 2):]
    return "00" * zero_bytes + "".join(result)


def decode_address(address: str) -> tuple[int, bytes]:
    payload = address[1:].upper().replace("O", "0").replace("L", "1").replace("I", "1")
    version = C32.index(payload[0])
    decoded = c32decode(payload[1:])
    body, checksum = decoded[:-8], decoded[-8:]
    expected = hashlib.sha256(hashlib.sha256(bytes.fromhex(f"{version:02x}" + body)).digest()).digest()[:4].hex()
    if checksum != expected:
        raise ValueError(f"checksum mismatch: {address}")
    return version, bytes.fromhex(body)


def encode_principal(principal: str) -> str:
    address, dot, contract = principal.partition(".")
    version, hash160 = decode_address(address)
    output = bytes([0x06 if dot else 0x05, version]) + hash160
    if dot:
        encoded = contract.encode("ascii")
        output += bytes([len(encoded)]) + encoded
    return "0x" + output.hex()


def c32address(version: int, hash160: bytes) -> str:
    payload = f"{version:02x}" + hash160.hex()
    checksum = hashlib.sha256(hashlib.sha256(bytes.fromhex(payload)).digest()).digest()[:4]
    return "S" + C32[version] + c32encode(hash160.hex() + checksum.hex())


@dataclass
class CVReader:
    data: bytes
    pos: int = 0

    def take(self, size: int) -> bytes:
        result = self.data[self.pos:self.pos + size]
        if len(result) != size:
            raise ValueError("truncated clarity value")
        self.pos += size
        return result

    def value(self) -> Any:
        kind = self.take(1)[0]
        if kind == 0x00:
            return int.from_bytes(self.take(16), "big", signed=True)
        if kind == 0x01:
            return int.from_bytes(self.take(16), "big")
        if kind == 0x02:
            return {"buffer_hex": self.take(int.from_bytes(self.take(4), "big")).hex()}
        if kind == 0x03:
            return True
        if kind == 0x04:
            return False
        if kind in (0x05, 0x06):
            principal = c32address(self.take(1)[0], self.take(20))
            if kind == 0x06:
                principal += "." + self.take(self.take(1)[0]).decode("ascii")
            return principal
        if kind == 0x07:
            return {"response": "ok", "value": self.value()}
        if kind == 0x08:
            return {"response": "err", "value": self.value()}
        if kind == 0x09:
            return None
        if kind == 0x0A:
            return self.value()
        if kind == 0x0B:
            return [self.value() for _ in range(int.from_bytes(self.take(4), "big"))]
        if kind == 0x0C:
            output: dict[str, Any] = {}
            for _ in range(int.from_bytes(self.take(4), "big")):
                key = self.take(self.take(1)[0]).decode("ascii")
                output[key] = self.value()
            return output
        if kind in (0x0D, 0x0E):
            return self.take(int.from_bytes(self.take(4), "big")).decode("ascii" if kind == 0x0D else "utf-8")
        raise ValueError(f"unsupported clarity value type {kind:#x}")


def decode_cv(value: str) -> Any:
    reader = CVReader(bytes.fromhex(value.removeprefix("0x")))
    decoded = reader.value()
    if reader.pos != len(reader.data):
        raise ValueError("trailing clarity bytes")
    return decoded


def call_read(function: str, tip: str, arguments: list[str] | None = None) -> dict[str, Any]:
    url = f"{HIRO}/v2/contracts/call-read/{DEPLOYER}/{HQ_NAME}/{function}?tip={urllib.parse.quote(tip, safe='')}"
    raw = fetch_json(url, {"sender": DEPLOYER, "arguments": arguments or []})
    return {"url": url, "raw": raw, "decoded": decode_cv(raw["result"]) if raw.get("okay") else None}


def pinned_tip() -> tuple[dict[str, Any], dict[str, Any], int, str]:
    info = fetch_json(f"{HIRO}/v2/info")
    height = int(info["stacks_tip_height"])
    for candidate_height in (height, height - 1):
        block = fetch_json(f"{HIRO}/extended/v2/blocks/{candidate_height}")
        candidates: list[str] = []
        for raw in (info.get("stacks_tip") if candidate_height == height else None, block.get("index_block_hash"), block.get("hash"), block.get("block_hash")):
            if raw:
                candidate = raw if str(raw).startswith("0x") else "0x" + str(raw)
                if candidate not in candidates:
                    candidates.append(candidate)
        for tip in candidates:
            try:
                call_read("get-protocol-enabled", tip)
                return info, block, candidate_height, tip
            except RuntimeError as exc:
                if "HTTP 404" not in str(exc):
                    raise
    raise RuntimeError("no usable pinned tip")


def normalize_history() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    all_rows: list[dict[str, Any]] = []
    offset = 0
    total = None
    raw_pages: list[dict[str, Any]] = []
    while total is None or offset < total:
        url = f"{HIRO}/extended/v1/address/{HQ}/transactions?limit=50&offset={offset}"
        page = fetch_json(url)
        raw_pages.append({"url": url, "payload": page})
        rows = page.get("results", [])
        total = int(page.get("total", len(rows)))
        all_rows.extend(rows)
        if not rows:
            break
        offset += len(rows)
    direct: list[dict[str, Any]] = []
    for tx in all_rows:
        call = tx.get("contract_call") or {}
        if call.get("contract_id") != HQ:
            continue
        args = call.get("function_args") or []
        direct.append({
            "tx_id": tx.get("tx_id"),
            "status": tx.get("tx_status"),
            "block_height": int(tx.get("block_height") or 0),
            "burn_block_time_iso": tx.get("burn_block_time_iso"),
            "sender_address": tx.get("sender_address"),
            "function_name": call.get("function_name"),
            "args": [{"name": arg.get("name"), "repr": arg.get("repr"), "type": arg.get("type")} for arg in args],
            "result": (tx.get("tx_result") or {}).get("repr"),
        })
    direct.sort(key=lambda row: (row["block_height"], row["tx_id"] or ""), reverse=True)
    return direct, {"pages": raw_pages, "address_history_count": len(all_rows), "reported_total": total}


def extract_principals(rows: list[dict[str, Any]]) -> set[str]:
    result: set[str] = set()
    pattern = re.compile(r"'(S[PMTN][0-9A-HJKMNP-TV-Z]+(?:\.[a-zA-Z0-9_-]+)?)")
    for row in rows:
        for arg in row.get("args", []):
            value = arg.get("repr") or ""
            match = pattern.search(value)
            if match:
                result.add(match.group(1))
    return result


def source_state(principal: str) -> dict[str, Any]:
    if "." not in principal:
        return {"is_contract": False}
    address, contract = principal.split(".", 1)
    url = f"{HIRO}/v2/contracts/source/{address}/{contract}?proof=0"
    try:
        raw = fetch_json(url)
    except RuntimeError as exc:
        if "HTTP 404" in str(exc):
            return {"is_contract": True, "exists": False, "url": url}
        raise
    source = raw.get("source", "") if isinstance(raw, dict) else ""
    public_functions = re.findall(r"\(define-public\s+\(([a-zA-Z0-9_-]+)", source)
    role_checks = sorted(set(re.findall(r"check-is-(guardian|trader|rewarder|manager|fee-setter|protocol)", source)))
    return {
        "is_contract": True,
        "exists": bool(source),
        "url": url,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "source_bytes": len(source.encode()),
        "public_functions": public_functions,
        "direct_role_checks": role_checks,
        "tx_sender_refs": source.count("tx-sender"),
        "contract_caller_refs": source.count("contract-caller"),
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    info, block, height, tip = pinned_tip()
    direct, history_raw = normalize_history()
    successful = [row for row in direct if row["status"] == "success"]
    discovered = extract_principals(direct)
    candidates = sorted(set(BASELINE_CANDIDATES) | discovered)

    globals_state = {name: call_read(name, tip) for name in ["get-protocol-enabled", "get-owner", "get-next-owner", "get-timelock", "get-next-timelock"]}
    role_calls: dict[str, Any] = {}
    active_roles: dict[str, list[str]] = {}
    for principal in candidates:
        argument = encode_principal(principal)
        role_calls[principal] = {}
        enabled: list[str] = []
        for role in ROLES:
            call = call_read(f"get-{role}", tip, [argument])
            role_calls[principal][role] = call
            if call["decoded"] is True:
                enabled.append(role)
            time.sleep(0.015)
        if enabled:
            active_roles[principal] = enabled

    baseline_norm = {principal: sorted(roles) for principal, roles in BASELINE_ACTIVE.items()}
    current_norm = {principal: sorted(roles) for principal, roles in active_roles.items()}
    all_principals = sorted(set(baseline_norm) | set(current_norm))
    role_delta = {
        principal: {"baseline": baseline_norm.get(principal, []), "current": current_norm.get(principal, [])}
        for principal in all_principals
        if baseline_norm.get(principal, []) != current_norm.get(principal, [])
    }

    new_successful = [row for row in successful if row["block_height"] > BASELINE_MAX_SUCCESS_HEIGHT or row["tx_id"] not in BASELINE_SUCCESS_TXIDS and row["block_height"] > BASELINE_MAX_SUCCESS_HEIGHT]
    newly_discovered = sorted(discovered - set(BASELINE_CANDIDATES))
    active_contracts = sorted(principal for principal in active_roles if "." in principal)
    source_states = {principal: source_state(principal) for principal in active_contracts}
    new_active_contracts = sorted(principal for principal in active_contracts if principal not in BASELINE_ACTIVE)
    public_new_authority = [
        principal for principal in new_active_contracts
        if source_states.get(principal, {}).get("exists") and source_states.get(principal, {}).get("public_functions")
    ]

    invariant = {
        "role_matrix_matches_baseline": not role_delta,
        "no_successful_hq_call_after_baseline": not new_successful,
        "no_newly_discovered_principal": not newly_discovered,
        "no_new_active_contract_role": not new_active_contracts,
        "no_public_new_authority_contract": not public_new_authority,
    }
    review_required = not all(invariant.values())
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "public read-only",
        "chain_writes": 0,
        "anchor": {
            "height": height,
            "tip": tip,
            "block_time": int(block.get("block_time", 0)),
            "block_time_utc": datetime.fromtimestamp(int(block.get("block_time", 0)), timezone.utc).isoformat(),
            "index_block_hash": block.get("index_block_hash"),
        },
        "history": {
            "address_history_count": history_raw["address_history_count"],
            "reported_total": history_raw["reported_total"],
            "direct_hq_call_count": len(direct),
            "successful_direct_hq_call_count": len(successful),
            "max_successful_height": max((row["block_height"] for row in successful), default=0),
            "latest_successful_call": successful[0] if successful else None,
            "new_successful_calls_after_baseline": new_successful,
        },
        "candidates": candidates,
        "newly_discovered_principals": newly_discovered,
        "active_roles": active_roles,
        "role_delta": role_delta,
        "active_contract_sources": source_states,
        "new_active_contracts": new_active_contracts,
        "public_new_authority_contracts": public_new_authority,
        "globals": {name: call["decoded"] for name, call in globals_state.items()},
        "invariants": invariant,
        "decision": "AUTHORITY_RELAY_REVIEW_REQUIRED" if review_required else "NO_HQ_ROLE_OR_AUTHORITY_DELTA",
    }

    payloads = {
        "SUMMARY.json": summary,
        "role_calls.json": role_calls,
        "globals_calls.json": globals_state,
        "hq_direct_calls.json": direct,
        "hq_history_raw.json": history_raw,
        "active_contract_sources.json": source_states,
        "anchor.json": {"info": info, "block": block},
    }
    for name, payload in payloads.items():
        (OUT / name).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    manifest = []
    for path in sorted(OUT.glob("*.json")):
        manifest.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (OUT / "SHA256SUMS.txt").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
