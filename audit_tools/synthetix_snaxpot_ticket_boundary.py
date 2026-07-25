#!/usr/bin/env python3
"""Low-noise EIP-712/wire-field differential for Synthetix Snaxpot ticket saving.

Safety constraints:
- deterministic synthetic EOA only;
- preflight confirms the EOA owns/manages/delegates zero Synthetix accounts;
- deliberately nonexistent valid-range subaccount ID;
- plausible but synthetic ticket entries only;
- no real account, ticket, credential, balance, order, or position is used;
- no request can mutate state because the signer has no Synthetix account;
- output retains only redacted errors, schemas, hashes, and recovered-address comparisons.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.request
from copy import deepcopy
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

OUT = pathlib.Path("snaxpot_ticket_boundary")
OUT.mkdir(parents=True, exist_ok=True)

PAPI_INFO = "https://papi.synthetix.io/v1/info"
PAPI_TRADE = "https://papi.synthetix.io/v1/trade"
PRIVATE_KEY = "0x" + "88" * 32
ACCOUNT = Account.from_key(PRIVATE_KEY)
SUBACCOUNT_ID = 8_000_000_000_000_001
UA = "Mozilla/5.0 (compatible; authorized-controlled-security-review/1.0)"
MAX_BODY = 2 * 1024 * 1024

DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
DOMAIN = {
    "name": "Synthetix",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x0000000000000000000000000000000000000000",
}
TYPES = {
    "EIP712Domain": DOMAIN_FIELDS,
    "SnaxpotTicket": [
        {"name": "ball1", "type": "uint256"},
        {"name": "ball2", "type": "uint256"},
        {"name": "ball3", "type": "uint256"},
        {"name": "ball4", "type": "uint256"},
        {"name": "ball5", "type": "uint256"},
        {"name": "snaxBall", "type": "uint256"},
        {"name": "ticketSerial", "type": "uint256"},
    ],
    "SaveSnaxpotTickets": [
        {"name": "subAccountId", "type": "uint256"},
        {"name": "entries", "type": "SnaxpotTicket[]"},
        {"name": "nonce", "type": "uint256"},
        {"name": "expiresAfter", "type": "uint256"},
    ],
}
ENTRY_A = {
    "ball1": 1,
    "ball2": 2,
    "ball3": 3,
    "ball4": 4,
    "ball5": 5,
    "snaxBall": 1,
    "ticketSerial": 1,
}
ENTRY_B = {
    "ball1": 6,
    "ball2": 7,
    "ball3": 8,
    "ball4": 9,
    "ball5": 10,
    "snaxBall": 2,
    "ticketSerial": 2,
}
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def digest(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = ADDRESS_RE.sub("<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{12,}\b", "<large-number>", text)
    return text[:800]


def post_bytes(url: str, body: bytes, timeout: int = 45) -> tuple[int, bytes, dict[str, str], float]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read(MAX_BODY + 1)
            if len(response_body) > MAX_BODY:
                raise ValueError("response too large")
            return response.status, response_body, dict(response.headers.items()), time.monotonic() - started
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read(MAX_BODY + 1),
            dict(exc.headers.items()) if exc.headers else {},
            time.monotonic() - started,
        )


def post_json(url: str, payload: dict[str, Any]) -> tuple[int, bytes, dict[str, str], float]:
    return post_bytes(url, json.dumps(payload, separators=(",", ":")).encode())


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body)
    except Exception:
        return None


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(item, depth + 1) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return {"type": "list", "count": len(value), "sample": schema(value[0], depth + 1) if value else None}
    return type(value).__name__


def account_count(response: Any) -> int | None:
    if isinstance(response, list):
        return len(response)
    if isinstance(response, dict):
        recognized = False
        total = 0
        for key in ("subAccountIds", "delegatedSubAccountIds", "managedSubAccountIds"):
            values = response.get(key)
            if isinstance(values, list):
                recognized = True
                total += len(values)
        return total if recognized else None
    return None


def normalize_entry(entry: dict[str, Any]) -> dict[str, int]:
    return {
        "ball1": int(entry["ball1"]),
        "ball2": int(entry["ball2"]),
        "ball3": int(entry["ball3"]),
        "ball4": int(entry["ball4"]),
        "ball5": int(entry["ball5"]),
        "snaxBall": int(entry["snaxBall"]),
        "ticketSerial": int(entry["ticketSerial"]),
    }


def format_signature(signed: Any) -> dict[str, Any]:
    return {
        "v": signed.v,
        "r": "0x" + format(signed.r, "064x"),
        "s": "0x" + format(signed.s, "064x"),
    }


def sign(entries: list[dict[str, Any]], nonce: int, expires_after: int, *, subaccount_id: int = SUBACCOUNT_ID) -> dict[str, Any]:
    encoded = encode_typed_data(
        full_message={
            "types": TYPES,
            "primaryType": "SaveSnaxpotTickets",
            "domain": DOMAIN,
            "message": {
                "subAccountId": subaccount_id,
                "entries": [normalize_entry(entry) for entry in entries],
                "nonce": nonce,
                "expiresAfter": expires_after,
            },
        }
    )
    return format_signature(ACCOUNT.sign_message(encoded))


def corrupt(signature: dict[str, Any]) -> dict[str, Any]:
    value = int(signature["s"], 16) ^ 1
    return {"v": signature["v"], "r": signature["r"], "s": "0x" + format(value, "064x")}


def envelope(
    *,
    signed_entries: list[dict[str, Any]],
    wire_entries: list[dict[str, Any]],
    signed_subaccount_id: int = SUBACCOUNT_ID,
    wire_subaccount_id: Any = SUBACCOUNT_ID,
    action: str = "saveSnaxpotTickets",
    corrupt_signature: bool = False,
    extra_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign(signed_entries, nonce, expires_after, subaccount_id=signed_subaccount_id)
    if corrupt_signature:
        signature = corrupt(signature)
    params: dict[str, Any] = {
        "action": action,
        "subAccountId": wire_subaccount_id,
        "entries": wire_entries,
    }
    if extra_params:
        params.update(extra_params)
    return {
        "params": params,
        "signature": signature,
        "nonce": nonce,
        "expiresAfter": expires_after,
    }


def duplicate_ticket_serial_body(*, signed_entries: list[dict[str, Any]], first: int, second: int) -> bytes:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = sign(signed_entries, nonce, expires_after)
    entry = ENTRY_A
    return (
        "{"
        '"params":{'
        '"action":"saveSnaxpotTickets",'
        f'"subAccountId":"{SUBACCOUNT_ID}",'
        '"entries":[{'
        f'"ball1":{entry["ball1"]},"ball2":{entry["ball2"]},"ball3":{entry["ball3"]},'
        f'"ball4":{entry["ball4"]},"ball5":{entry["ball5"]},"snaxBall":{entry["snaxBall"]},'
        f'"ticketSerial":{first},"ticketSerial":{second}'
        "}]},"
        f'nonce":{nonce},'
        '"signature":' + json.dumps(signature, separators=(",", ":")) + ","
        f'"expiresAfter":{expires_after}'
        "}"
    ).encode()


def summarize(name: str, status: int, body: bytes, headers: dict[str, str], elapsed: float) -> dict[str, Any]:
    parsed = parse_json(body)
    error = parsed.get("error") if isinstance(parsed, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    response = parsed.get("response") if isinstance(parsed, dict) else None
    raw_message = str(error_message) if error_message is not None else ""
    addresses = [address.lower() for address in ADDRESS_RE.findall(raw_message)]
    return {
        "name": name,
        "httpStatus": status,
        "elapsedMs": round(elapsed * 1000, 2),
        "apiStatus": parsed.get("status") if isinstance(parsed, dict) else None,
        "errorCode": error_code,
        "errorMessageRedacted": redact(error_message),
        "errorMessageSha256": digest(raw_message) if raw_message else None,
        "errorAddressCount": len(addresses),
        "errorMentionsSyntheticSigner": ACCOUNT.address.lower() in addresses,
        "errorAddressSha256": sorted(digest(address) for address in addresses),
        "responseSchema": schema(response),
        "bodySha256": digest(body),
        "bodyBytes": len(body),
        "requestId": (
            parsed.get("request_id") if isinstance(parsed, dict) else None
        ) or headers.get("X-Request-Id") or headers.get("x-request-id"),
    }


def mutate(entry: dict[str, Any], **changes: Any) -> dict[str, Any]:
    result = deepcopy(entry)
    result.update(changes)
    return result


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": (
            "Deterministic zero-account EOA and deliberately nonexistent valid-range subaccount ID only. "
            "No real ticket/account exists and no save can execute."
        ),
        "syntheticAddress": ACCOUNT.address,
        "targetSubaccountIdSha256": digest(str(SUBACCOUNT_ID)),
        "tests": [],
    }

    status, body, headers, elapsed = post_json(
        PAPI_INFO,
        {
            "params": {
                "action": "getSubAccountIds",
                "walletAddress": ACCOUNT.address,
                "includeDelegations": True,
            }
        },
    )
    preflight = summarize("synthetic_account_preflight", status, body, headers, elapsed)
    parsed = parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    count = account_count(response)
    preflight["accountCount"] = count
    evidence["tests"].append(preflight)

    if count != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic EOA was not confirmed to own/manage/delegate zero accounts."
    else:
        a = deepcopy(ENTRY_A)
        b = deepcopy(ENTRY_B)
        cases: list[tuple[str, dict[str, Any] | bytes]] = [
            ("corrupted_signature_control", envelope(signed_entries=[a], wire_entries=[a], corrupt_signature=True)),
            ("correct_single_entry", envelope(signed_entries=[a], wire_entries=[a])),
            ("signed_ball1_mismatch", envelope(signed_entries=[a], wire_entries=[mutate(a, ball1=11)])),
            ("signed_snax_ball_mismatch", envelope(signed_entries=[a], wire_entries=[mutate(a, snaxBall=3)])),
            ("signed_ticket_serial_mismatch", envelope(signed_entries=[a], wire_entries=[mutate(a, ticketSerial=2)])),
            ("entry_order_reversed", envelope(signed_entries=[a, b], wire_entries=[b, a])),
            ("extra_wire_entry_appended", envelope(signed_entries=[a], wire_entries=[a, b])),
            ("signed_second_entry_omitted", envelope(signed_entries=[a, b], wire_entries=[a])),
            ("duplicate_ticket_serial_array", envelope(signed_entries=[a, b], wire_entries=[a, mutate(b, ticketSerial=1)])),
            (
                "numeric_string_normalization",
                envelope(
                    signed_entries=[a],
                    wire_entries=[{key: str(value) for key, value in a.items()}],
                    wire_subaccount_id=str(SUBACCOUNT_ID),
                ),
            ),
            (
                "signed_source_account_mismatch",
                envelope(
                    signed_entries=[a],
                    wire_entries=[a],
                    signed_subaccount_id=SUBACCOUNT_ID + 2,
                    wire_subaccount_id=str(SUBACCOUNT_ID),
                ),
            ),
            (
                "lowercase_source_alias_only",
                envelope(
                    signed_entries=[a],
                    wire_entries=[a],
                    wire_subaccount_id=None,
                    extra_params={"subaccountId": str(SUBACCOUNT_ID)},
                ),
            ),
            (
                "wrong_wire_action_preference",
                envelope(
                    signed_entries=[a],
                    wire_entries=[a],
                    action="setSnaxpotPreference",
                    extra_params={"snaxBall": 1, "scope": "current"},
                ),
            ),
            (
                "unsigned_epoch_and_owner_fields",
                envelope(
                    signed_entries=[a],
                    wire_entries=[a],
                    extra_params={"epochId": 999_999, "walletAddress": ACCOUNT.address},
                ),
            ),
            ("duplicate_ticket_serial_json_key", duplicate_ticket_serial_body(signed_entries=[a], first=1, second=2)),
        ]

        for index, (name, payload) in enumerate(cases):
            if isinstance(payload, bytes):
                status, body, headers, elapsed = post_bytes(PAPI_TRADE, payload)
            else:
                status, body, headers, elapsed = post_json(PAPI_TRADE, payload)
            evidence["tests"].append(summarize(name, status, body, headers, elapsed))
            if index + 1 < len(cases):
                time.sleep(0.55)

    tests = evidence["tests"]
    evidence["summary"] = {
        "testCount": len(tests),
        "probeAborted": bool(evidence.get("probeAborted")),
        "casesMentioningSyntheticSigner": [
            test.get("name") for test in tests if test.get("errorMentionsSyntheticSigner")
        ],
        "caseMatrix": [
            {
                "name": test.get("name"),
                "httpStatus": test.get("httpStatus"),
                "apiStatus": test.get("apiStatus"),
                "errorCode": test.get("errorCode"),
                "errorMentionsSyntheticSigner": test.get("errorMentionsSyntheticSigner"),
                "errorMessageSha256": test.get("errorMessageSha256"),
                "bodySha256": test.get("bodySha256"),
            }
            for test in tests
        ],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(evidence["summary"], indent=2), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__":
    main()
