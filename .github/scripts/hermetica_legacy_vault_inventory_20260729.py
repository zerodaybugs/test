#!/usr/bin/env python3
"""Public read-only Hermetica legacy-vault claim/liability inventory.

The scanner pins every contract call to one Stacks tip, enumerates every claim ID
across Vault v1, v1.1, and v1.2, reconciles escrowed hBTC and funded sBTC
liabilities, and records the current HQ protocol-role/recovery state.
It never constructs, signs, or broadcasts a transaction.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
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
STATE = "state-hbtc-v1"
HQ = "hq-v1"
TOKEN = "token-hbtc"
SBTC_DEPLOYER = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4"
SBTC_TOKEN = "sbtc-token"
VAULTS = ["vault-hbtc-v1", "vault-hbtc-v1-1", "vault-hbtc-v1-2"]
OUT = Path(os.environ.get("SCAN_OUT", "hermetica-legacy-vault-inventory-output"))
UA = "authorized-read-only-hermetica-legacy-inventory/1.0"
C32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SHARE_BASE = 100_000_000
BPS_BASE = 10_000
PROTOCOL_ROLE = b"\x06"


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


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
                    payload = exc.read().decode("utf-8", "replace")
                except Exception:
                    payload = ""
                raise RuntimeError(f"HTTP {exc.code} {url}: {payload[:600]}") from exc
            time.sleep(min(15.0, 0.75 * (2**min(attempt, 5))))
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
    raw = bytes([0x06 if dot else 0x05, version]) + hash160
    if dot:
        name = contract.encode("ascii")
        raw += bytes([len(name)]) + name
    return "0x" + raw.hex()


def encode_uint(value: int) -> str:
    return "0x01" + value.to_bytes(16, "big").hex()


def encode_buffer(value: bytes) -> str:
    return "0x02" + len(value).to_bytes(4, "big").hex() + value.hex()


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
        raise ValueError(f"unsupported Clarity value type {kind:#x}")


def decode_cv(value: str) -> Any:
    reader = CVReader(bytes.fromhex(value.removeprefix("0x")))
    decoded = reader.value()
    if reader.pos != len(reader.data):
        raise ValueError("trailing Clarity bytes")
    return decoded


def call_read(address: str, contract: str, function: str, tip: str, arguments: list[str] | None = None) -> dict[str, Any]:
    url = f"{HIRO}/v2/contracts/call-read/{address}/{contract}/{function}?tip={urllib.parse.quote(tip, safe='')}"
    raw = fetch_json(url, {"sender": DEPLOYER, "arguments": arguments or []})
    return {"url": url, "raw": raw, "decoded": decode_cv(raw["result"]) if raw.get("okay") else None}


def unwrap_ok(value: Any) -> Any:
    if not isinstance(value, dict) or value.get("response") != "ok":
        raise ValueError(value)
    return value["value"]


def get_ft_balance(payload: dict[str, Any], prefix: str) -> tuple[int, str | None]:
    for asset_id, entry in payload.get("fungible_tokens", {}).items():
        if asset_id.startswith(prefix):
            return int(entry.get("balance", 0)), asset_id
    return 0, None


def pinned_tip() -> tuple[dict[str, Any], dict[str, Any], int, str]:
    info = fetch_json(f"{HIRO}/v2/info")
    height = int(info["stacks_tip_height"])
    for candidate_height in (height, height - 1):
        block = fetch_json(f"{HIRO}/extended/v2/blocks/{candidate_height}")
        candidates: list[str] = []
        for raw in (info.get("stacks_tip") if candidate_height == height else None, block.get("index_block_hash"), block.get("hash"), block.get("block_hash")):
            if raw:
                value = raw if str(raw).startswith("0x") else "0x" + str(raw)
                if value not in candidates:
                    candidates.append(value)
        for tip in candidates:
            try:
                call_read(DEPLOYER, STATE, "get-claim-id", tip)
                return info, block, candidate_height, tip
            except RuntimeError as exc:
                if "HTTP 404" not in str(exc):
                    raise
    raise RuntimeError("no usable pinned tip")


def source_snapshot(contract: str) -> dict[str, Any]:
    url = f"{HIRO}/v2/contracts/source/{DEPLOYER}/{contract}?proof=0"
    raw = fetch_json(url)
    source = raw.get("source", "") if isinstance(raw, dict) else ""
    return {"url": url, "raw": raw, "source_sha256": hashlib.sha256(source.encode()).hexdigest(), "source_bytes": len(source.encode())}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    info, block, height, tip = pinned_tip()
    block_time = int(block.get("block_time", block.get("burn_block_time", 0)))

    state_names = [
        "get-claim-id", "get-share-price", "get-total-assets", "get-net-assets",
        "get-pending-fees", "get-pending-rf", "get-redeem-enabled",
        "get-request-redeem-enabled", "get-vault-enabled",
    ]
    state_calls = {name: call_read(DEPLOYER, STATE, name, tip) for name in state_names}
    protocol_enabled_call = call_read(DEPLOYER, HQ, "get-protocol-enabled", tip)
    timelock_call = call_read(DEPLOYER, HQ, "get-timelock", tip)
    claim_id = int(state_calls["get-claim-id"]["decoded"])
    share_price = int(state_calls["get-share-price"]["decoded"])
    if claim_id > 10_000:
        raise RuntimeError(f"unexpected claim-id {claim_id}")

    all_calls: dict[str, Any] = {}
    indexed_balances: dict[str, Any] = {}
    pinned_balances: dict[str, Any] = {}
    sources: dict[str, Any] = {}
    vault_results: list[dict[str, Any]] = []

    for vault in VAULTS:
        principal = f"{DEPLOYER}.{vault}"
        protocol_call = call_read(DEPLOYER, HQ, "get-protocol", tip, [encode_principal(principal)])
        pending_role_call = call_read(DEPLOYER, HQ, "get-update-request", tip, [encode_buffer(PROTOCOL_ROLE), encode_principal(principal)])
        protocol_active = bool(protocol_call["decoded"])

        claims: list[dict[str, Any]] = []
        for claim_number in range(1, claim_id + 1):
            response = call_read(DEPLOYER, vault, "get-claim", tip, [encode_uint(claim_number)])
            decoded = response.get("decoded")
            row: dict[str, Any] = {"claim_id": claim_number, "raw": response["raw"], "decoded": decoded, "exists": False}
            if isinstance(decoded, dict) and decoded.get("response") == "ok":
                row.update({"exists": True, **decoded["value"]})
            claims.append(row)
            time.sleep(0.025)
        all_calls[vault] = claims
        active_raw = [claim for claim in claims if claim["exists"]]

        sbtc_call = call_read(SBTC_DEPLOYER, SBTC_TOKEN, "get-balance", tip, [encode_principal(principal)])
        hbtc_call = call_read(DEPLOYER, TOKEN, "get-balance", tip, [encode_principal(principal)])
        sbtc_balance = int(unwrap_ok(sbtc_call["decoded"]))
        hbtc_balance = int(unwrap_ok(hbtc_call["decoded"]))
        pinned_balances[vault] = {"sbtc": sbtc_call, "hbtc": hbtc_call}

        indexed_url = f"{HIRO}/extended/v1/address/{principal}/balances?until_block={height}"
        indexed_raw = fetch_json(indexed_url)
        indexed_sbtc, sbtc_asset_id = get_ft_balance(indexed_raw, f"{SBTC_DEPLOYER}.{SBTC_TOKEN}::")
        indexed_hbtc, hbtc_asset_id = get_ft_balance(indexed_raw, f"{DEPLOYER}.{TOKEN}::")
        indexed_balances[vault] = {"url": indexed_url, "raw": indexed_raw}

        active: list[dict[str, Any]] = []
        for claim in active_raw:
            shares = int(claim["shares"])
            assets = claim.get("assets")
            fee = claim.get("fee")
            fee_bps = int(claim["fee-bps"])
            maturity = int(claim["ts"])
            gross = int(assets) if assets is not None else shares * share_price // SHARE_BASE
            active.append({
                "claim_id": claim["claim_id"],
                "user": claim["user"],
                "shares": shares,
                "share_price": claim.get("share-price"),
                "assets": assets,
                "fee": fee,
                "fee_bps": fee_bps,
                "is_express": bool(claim["is-express"]),
                "maturity_unix": maturity,
                "maturity_utc": iso(maturity),
                "mature_at_anchor": block_time >= maturity,
                "funded": assets is not None,
                "current_gross_assets_if_funded": gross,
                "current_fee_if_funded": int(fee or 0) if assets is not None else gross * fee_bps // BPS_BASE,
            })

        funded = [claim for claim in active if claim["funded"]]
        unfunded = [claim for claim in active if not claim["funded"]]
        mature_unfunded = [claim for claim in unfunded if claim["mature_at_anchor"]]
        unfunded_express = [claim for claim in unfunded if claim["is_express"]]
        mature_unfunded_express = [claim for claim in mature_unfunded if claim["is_express"]]
        funded_gross = sum(int(claim["assets"]) for claim in funded)
        funded_fees = sum(int(claim["fee"] or 0) for claim in funded)
        unfunded_shares = sum(int(claim["shares"]) for claim in unfunded)

        escrow_exact = unfunded_shares == hbtc_balance
        funded_exact = funded_gross == sbtc_balance
        funded_covered = funded_gross <= sbtc_balance
        admin_recovery_available = True
        inactive_unfunded_express = (not protocol_active) and bool(unfunded_express)
        current_permanent_freeze = inactive_unfunded_express and not admin_recovery_available
        temporary_freeze_review = inactive_unfunded_express and admin_recovery_available
        deficit = funded_gross > sbtc_balance

        vault_results.append({
            "vault": vault,
            "principal": principal,
            "protocol_active": protocol_active,
            "pending_protocol_update": pending_role_call["decoded"],
            "active_claim_count": len(active),
            "funded_claim_count": len(funded),
            "unfunded_claim_count": len(unfunded),
            "mature_unfunded_claim_count": len(mature_unfunded),
            "unfunded_express_claim_count": len(unfunded_express),
            "mature_unfunded_express_claim_count": len(mature_unfunded_express),
            "active_claims": active,
            "balances": {
                "vault_sbtc": sbtc_balance,
                "vault_hbtc": hbtc_balance,
                "indexed_sbtc": indexed_sbtc,
                "indexed_hbtc": indexed_hbtc,
                "indexed_matches_pinned": indexed_sbtc == sbtc_balance and indexed_hbtc == hbtc_balance,
                "asset_ids": {"sbtc": sbtc_asset_id, "hbtc": hbtc_asset_id},
            },
            "invariants": {
                "unfunded_claim_shares": unfunded_shares,
                "vault_hbtc_equals_unfunded_shares": escrow_exact,
                "escrow_share_delta": hbtc_balance - unfunded_shares,
                "funded_gross_liability": funded_gross,
                "funded_fee_liability": funded_fees,
                "funded_net_user_liability": funded_gross - funded_fees,
                "vault_sbtc_covers_funded_gross": funded_covered,
                "vault_sbtc_equals_funded_gross": funded_exact,
                "vault_sbtc_minus_funded_gross": sbtc_balance - funded_gross,
            },
            "reachability": {
                "fund_claim_currently_authorized": protocol_active,
                "standard_unfunded_user_can_cancel": True,
                "express_unfunded_user_can_cancel": False,
                "owner_can_reactivate_after_timelock": admin_recovery_available,
                "minimum_reactivation_delay_seconds": int(timelock_call["decoded"]),
                "current_permanent_freeze_candidate": current_permanent_freeze,
                "temporary_freeze_review_required": temporary_freeze_review,
                "funded_liability_deficit": deficit,
            },
        })
        sources[vault] = source_snapshot(vault)

    critical = any(result["reachability"]["funded_liability_deficit"] or result["reachability"]["current_permanent_freeze_candidate"] for result in vault_results)
    high = any(result["reachability"]["temporary_freeze_review_required"] for result in vault_results)
    invariant_failure = any(
        not result["invariants"]["vault_hbtc_equals_unfunded_shares"]
        or not result["invariants"]["vault_sbtc_covers_funded_gross"]
        or not result["balances"]["indexed_matches_pinned"]
        for result in vault_results
    )
    if critical or invariant_failure:
        decision = "CRITICAL_CANDIDATE_REVIEW_REQUIRED"
    elif high:
        decision = "HIGH_TEMPORARY_FREEZE_REVIEW_REQUIRED"
    else:
        decision = "NO_LEGACY_CLAIM_DIVERGENCE"

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "public read-only",
        "chain_writes": 0,
        "anchor": {
            "stacks_height": height,
            "tip": tip,
            "block_time": block_time,
            "block_time_utc": iso(block_time),
            "index_block_hash": block.get("index_block_hash"),
        },
        "global_claim_id": claim_id,
        "global_share_price": share_price,
        "protocol_enabled": protocol_enabled_call["decoded"],
        "hq_timelock_seconds": int(timelock_call["decoded"]),
        "global_flags": {
            "vault_enabled": state_calls["get-vault-enabled"]["decoded"],
            "redeem_enabled": state_calls["get-redeem-enabled"]["decoded"],
            "request_redeem_enabled": state_calls["get-request-redeem-enabled"]["decoded"],
        },
        "vaults": vault_results,
        "decision": decision,
    }

    payloads = {
        "SUMMARY.json": summary,
        "all_claim_calls.json": all_calls,
        "state_calls.json": state_calls,
        "pinned_balance_calls.json": pinned_balances,
        "indexed_balances.json": indexed_balances,
        "sources.json": sources,
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
