#!/usr/bin/env python3
"""Public read-only Hermetica auxiliary authority scan.

Refreshes the independent Blacklist blacklister map and Airdrop whitelist from
complete contract histories, pins all reads to one Stacks tip, inspects active
contract principals for public relay surfaces, and inventories airdrop-held
fungible-token balances. It never constructs, signs, or broadcasts a tx.
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
BLACKLIST_NAME = "blacklist"
AIRDROP_NAME = "airdrop-v1"
BLACKLIST = f"{DEPLOYER}.{BLACKLIST_NAME}"
AIRDROP = f"{DEPLOYER}.{AIRDROP_NAME}"
OUT = Path(os.environ.get("SCAN_OUT", "hermetica-aux-authority-output"))
UA = "authorized-read-only-hermetica-aux-authority/1.0"
C32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PRINCIPAL_RE = re.compile(r"'(S[PMTN][0-9A-HJKMNP-TV-Z]+(?:\.[a-zA-Z0-9_-]+)?)")
BASELINE = {
    "SM1QXYXZG78DCWJZJKY0901KTK3350071W9YYRPMT",
    "SP1C72K3FP2VCMW6814TGPG2Q07A54597WW6HB1YR",
    "SP20V8SG811G6CT2QMZQNX6XCN20YAX36DYD1BAE0",
    "SP292YFARYZZ46EJY8GYRPN94Q1Q7DEBJ2QF7AA6F",
    "SP2AS467J369H67HK3TS2TDH1YB0XNN7YZ8M7FM1B",
    "SP2WS9QFNR8VMJZY6VWWFZNPKN7ZTVP746BMXJF7A",
    "SP334EHW3XT01N9K2K163XRJT0KVTGY92C9P12EHP",
    "SP36VR1J6EXNXTP02K0AQD4BNQ63F30R1P5W6C93C",
    DEPLOYER,
}


def fetch_json(url: str, body: dict[str, Any] | None = None, retries: int = 16) -> Any:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
            with urllib.request.urlopen(request, timeout=40) as response:
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


def call_read(contract: str, function: str, tip: str, arguments: list[str] | None = None) -> dict[str, Any]:
    url = f"{HIRO}/v2/contracts/call-read/{DEPLOYER}/{contract}/{function}?tip={urllib.parse.quote(tip, safe='')}"
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
                call_read(BLACKLIST_NAME, "get-soft-blacklist-enabled", tip)
                call_read(AIRDROP_NAME, "get-next-airdrop-id", tip)
                return info, block, candidate_height, tip
            except RuntimeError as exc:
                if "HTTP 404" not in str(exc):
                    raise
    raise RuntimeError("no usable pinned tip")


def contract_history(principal: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    offset = 0
    total = None
    all_rows: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    while total is None or offset < total:
        url = f"{HIRO}/extended/v1/address/{principal}/transactions?limit=50&offset={offset}"
        page = fetch_json(url)
        pages.append({"url": url, "payload": page})
        rows = page.get("results", [])
        total = int(page.get("total", len(rows)))
        all_rows.extend(rows)
        if not rows:
            break
        offset += len(rows)
    direct: list[dict[str, Any]] = []
    for tx in all_rows:
        call = tx.get("contract_call") or {}
        if call.get("contract_id") != principal:
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
    return direct, {"pages": pages, "reported_total": total, "address_history_count": len(all_rows)}


def principals_from_history(rows: list[dict[str, Any]]) -> set[str]:
    output: set[str] = set()
    for row in rows:
        for argument in row.get("args", []):
            output.update(PRINCIPAL_RE.findall(argument.get("repr") or ""))
    return output


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
    return {
        "is_contract": True,
        "exists": bool(source),
        "url": url,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "source_bytes": len(source.encode()),
        "public_functions": re.findall(r"\(define-public\s+\(([a-zA-Z0-9_-]+)", source),
        "owner_checks": len(re.findall(r"check-is-owner", source)),
        "blacklister_checks": len(re.findall(r"check-is-blacklister", source)),
        "whitelist_checks": len(re.findall(r"get-whitelist|ERR_NOT_WHITELISTED", source)),
        "tx_sender_refs": source.count("tx-sender"),
        "contract_caller_refs": source.count("contract-caller"),
        "source": source,
    }


def simplify_fungible_tokens(payload: dict[str, Any]) -> dict[str, int]:
    return {asset_id: int(entry.get("balance", 0)) for asset_id, entry in payload.get("fungible_tokens", {}).items() if int(entry.get("balance", 0)) != 0}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    info, block, height, tip = pinned_tip()
    blacklist_calls, blacklist_history_raw = contract_history(BLACKLIST)
    airdrop_calls, airdrop_history_raw = contract_history(AIRDROP)
    successful_blacklist = [row for row in blacklist_calls if row["status"] == "success"]
    successful_airdrop = [row for row in airdrop_calls if row["status"] == "success"]

    blacklist_discovered = principals_from_history(blacklist_calls)
    airdrop_discovered = principals_from_history(airdrop_calls)
    candidates = sorted(BASELINE | blacklist_discovered | airdrop_discovered)

    blacklister_calls: dict[str, Any] = {}
    whitelist_calls: dict[str, Any] = {}
    blacklist_state_calls: dict[str, Any] = {}
    active_blacklisters: list[str] = []
    active_whitelist: list[str] = []
    soft_blacklisted: list[str] = []
    full_blacklisted: list[str] = []
    for principal in candidates:
        argument = encode_principal(principal)
        blacklister = call_read(BLACKLIST_NAME, "get-blacklister", tip, [argument])
        whitelist = call_read(AIRDROP_NAME, "get-whitelist", tip, [argument])
        soft = call_read(BLACKLIST_NAME, "get-soft-blacklist", tip, [argument])
        full = call_read(BLACKLIST_NAME, "get-full-blacklist", tip, [argument])
        blacklister_calls[principal] = blacklister
        whitelist_calls[principal] = whitelist
        blacklist_state_calls[principal] = {"soft": soft, "full": full}
        if blacklister["decoded"] is True:
            active_blacklisters.append(principal)
        whitelist_value = whitelist["decoded"] or {}
        if isinstance(whitelist_value, dict) and whitelist_value.get("active") is True:
            active_whitelist.append(principal)
        if soft["decoded"] is True:
            soft_blacklisted.append(principal)
        if full["decoded"] is True:
            full_blacklisted.append(principal)
        time.sleep(0.02)

    blacklist_globals = {
        "soft_enabled": call_read(BLACKLIST_NAME, "get-soft-blacklist-enabled", tip),
        "full_enabled": call_read(BLACKLIST_NAME, "get-full-blacklist-enabled", tip),
    }
    airdrop_globals = {"next_airdrop_id": call_read(AIRDROP_NAME, "get-next-airdrop-id", tip)}

    active_contract_principals = sorted({p for p in active_blacklisters + active_whitelist if "." in p})
    active_sources = {principal: source_state(principal) for principal in active_contract_principals}
    blacklister_contracts = [p for p in active_blacklisters if "." in p]
    whitelist_contracts = [p for p in active_whitelist if "." in p]
    public_blacklister_contracts = [p for p in blacklister_contracts if active_sources.get(p, {}).get("public_functions")]
    public_whitelist_contracts = [p for p in whitelist_contracts if active_sources.get(p, {}).get("public_functions")]

    airdrop_balance_url = f"{HIRO}/extended/v1/address/{AIRDROP}/balances?until_block={height}"
    airdrop_balance_raw = fetch_json(airdrop_balance_url)
    airdrop_ft_balances = simplify_fungible_tokens(airdrop_balance_raw)
    blacklist_source = source_state(BLACKLIST)
    airdrop_source = source_state(AIRDROP)

    soft_enabled = bool(blacklist_globals["soft_enabled"]["decoded"])
    full_enabled = bool(blacklist_globals["full_enabled"]["decoded"])
    blacklister_relay_risk = bool(public_blacklister_contracts)
    airdrop_relay_risk = bool(public_whitelist_contracts and airdrop_ft_balances)
    decision = "AUX_AUTHORITY_RELAY_REVIEW_REQUIRED" if blacklister_relay_risk or airdrop_relay_risk else "NO_AUXILIARY_AUTHORITY_RELAY"

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
        "blacklist": {
            "history_count": blacklist_history_raw["address_history_count"],
            "direct_call_count": len(blacklist_calls),
            "successful_direct_call_count": len(successful_blacklist),
            "latest_successful_call": successful_blacklist[0] if successful_blacklist else None,
            "soft_blacklist_enabled": soft_enabled,
            "full_blacklist_enabled": full_enabled,
            "active_blacklisters": active_blacklisters,
            "active_blacklister_contracts": blacklister_contracts,
            "public_blacklister_contracts": public_blacklister_contracts,
            "soft_blacklisted": soft_blacklisted,
            "full_blacklisted": full_blacklisted,
            "source": {k: v for k, v in blacklist_source.items() if k != "source"},
        },
        "airdrop": {
            "history_count": airdrop_history_raw["address_history_count"],
            "direct_call_count": len(airdrop_calls),
            "successful_direct_call_count": len(successful_airdrop),
            "latest_successful_call": successful_airdrop[0] if successful_airdrop else None,
            "next_airdrop_id": airdrop_globals["next_airdrop_id"]["decoded"],
            "active_whitelist": active_whitelist,
            "active_whitelist_contracts": whitelist_contracts,
            "public_whitelist_contracts": public_whitelist_contracts,
            "fungible_token_balances": airdrop_ft_balances,
            "source": {k: v for k, v in airdrop_source.items() if k != "source"},
        },
        "active_contract_sources": {principal: {k: v for k, v in state.items() if k != "source"} for principal, state in active_sources.items()},
        "invariants": {
            "no_public_blacklister_contract": not public_blacklister_contracts,
            "no_funded_public_airdrop_relay": not airdrop_relay_risk,
            "blacklist_contract_source_present": blacklist_source.get("exists") is True,
            "airdrop_contract_source_present": airdrop_source.get("exists") is True,
        },
        "decision": decision,
    }

    payloads = {
        "SUMMARY.json": summary,
        "blacklist_direct_calls.json": blacklist_calls,
        "blacklist_history_raw.json": blacklist_history_raw,
        "airdrop_direct_calls.json": airdrop_calls,
        "airdrop_history_raw.json": airdrop_history_raw,
        "blacklister_calls.json": blacklister_calls,
        "airdrop_whitelist_calls.json": whitelist_calls,
        "blacklist_state_calls.json": blacklist_state_calls,
        "global_calls.json": {"blacklist": blacklist_globals, "airdrop": airdrop_globals},
        "active_contract_sources.json": active_sources,
        "core_sources.json": {"blacklist": blacklist_source, "airdrop": airdrop_source},
        "airdrop_balance.json": {"url": airdrop_balance_url, "raw": airdrop_balance_raw},
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
