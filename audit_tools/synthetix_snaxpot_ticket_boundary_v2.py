#!/usr/bin/env python3
"""Corrected Snaxpot ticket-binding differential using production wire types."""
from __future__ import annotations

import json
import time
from copy import deepcopy
from typing import Any

import synthetix_snaxpot_ticket_boundary as base

OUT = base.pathlib.Path("snaxpot_ticket_boundary_v2")
OUT.mkdir(parents=True, exist_ok=True)
ENTRY_A = {"ball1": 1, "ball2": 2, "ball3": 3, "ball4": 4, "ball5": 5, "snaxBall": 1, "ticketSerial": "1"}
ENTRY_B = {"ball1": 6, "ball2": 7, "ball3": 8, "ball4": 9, "ball5": 10, "snaxBall": 2, "ticketSerial": "2"}


def envelope(
    *,
    signed_entries: list[dict[str, Any]],
    wire_entries: list[dict[str, Any]],
    signed_subaccount_id: int = base.SUBACCOUNT_ID,
    wire_subaccount_id: str = str(base.SUBACCOUNT_ID),
    action: str = "saveSnaxpotTickets",
    corrupt_signature: bool = False,
    extra_params: dict[str, Any] | None = None,
    source_key: str = "subAccountId",
) -> dict[str, Any]:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = base.sign(signed_entries, nonce, expires_after, subaccount_id=signed_subaccount_id)
    if corrupt_signature:
        signature = base.corrupt(signature)
    params: dict[str, Any] = {"action": action, source_key: wire_subaccount_id, "entries": wire_entries}
    if extra_params:
        params.update(extra_params)
    return {"params": params, "signature": signature, "nonce": nonce, "expiresAfter": expires_after}


def duplicate_ticket_serial_body(first: str, second: str) -> bytes:
    nonce = int(time.time() * 1000)
    expires_after = nonce + 120_000
    signature = base.sign([ENTRY_A], nonce, expires_after)
    e = ENTRY_A
    return (
        "{"
        '"params":{'
        '"action":"saveSnaxpotTickets",'
        f'"subAccountId":"{base.SUBACCOUNT_ID}",'
        '"entries":[{'
        f'"ball1":{e["ball1"]},"ball2":{e["ball2"]},"ball3":{e["ball3"]},'
        f'"ball4":{e["ball4"]},"ball5":{e["ball5"]},"snaxBall":{e["snaxBall"]},'
        f'"ticketSerial":"{first}","ticketSerial":"{second}"'
        "}]},"
        f'"nonce":{nonce},'
        '"signature":' + json.dumps(signature, separators=(",", ":")) + ","
        f'"expiresAfter":{expires_after}'
        "}"
    ).encode()


def mutate(entry: dict[str, Any], **changes: Any) -> dict[str, Any]:
    result = deepcopy(entry)
    result.update(changes)
    return result


def main() -> None:
    evidence: dict[str, Any] = {
        "safety": "Synthetic zero-account EOA and nonexistent valid-range account only; no ticket mutation can execute.",
        "syntheticAddress": base.ACCOUNT.address,
        "targetSubaccountIdSha256": base.digest(str(base.SUBACCOUNT_ID)),
        "tests": [],
    }
    status, body, headers, elapsed = base.post_json(
        base.PAPI_INFO,
        {"params": {"action": "getSubAccountIds", "walletAddress": base.ACCOUNT.address, "includeDelegations": True}},
    )
    preflight = base.summarize("synthetic_account_preflight", status, body, headers, elapsed)
    parsed = base.parse_json(body)
    response = parsed.get("response") if isinstance(parsed, dict) else None
    count = base.account_count(response)
    preflight["accountCount"] = count
    evidence["tests"].append(preflight)
    if count != 0:
        evidence["probeAborted"] = True
        evidence["abortReason"] = "Synthetic EOA was not confirmed to own/manage/delegate zero accounts."
    else:
        a, b = deepcopy(ENTRY_A), deepcopy(ENTRY_B)
        cases: list[tuple[str, dict[str, Any] | bytes]] = [
            ("corrupted_signature_control", envelope(signed_entries=[a], wire_entries=[a], corrupt_signature=True)),
            ("correct_single_entry", envelope(signed_entries=[a], wire_entries=[a])),
            ("signed_ball1_mismatch", envelope(signed_entries=[a], wire_entries=[mutate(a, ball1=11)])),
            ("signed_snax_ball_mismatch", envelope(signed_entries=[a], wire_entries=[mutate(a, snaxBall=3)])),
            ("signed_ticket_serial_mismatch", envelope(signed_entries=[a], wire_entries=[mutate(a, ticketSerial="2")])),
            ("entry_order_reversed", envelope(signed_entries=[a, b], wire_entries=[b, a])),
            ("extra_wire_entry_appended", envelope(signed_entries=[a], wire_entries=[a, b])),
            ("signed_second_entry_omitted", envelope(signed_entries=[a, b], wire_entries=[a])),
            ("duplicate_ticket_serial_array", envelope(signed_entries=[a, b], wire_entries=[a, mutate(b, ticketSerial="1")])),
            ("ball_numeric_string_normalization", envelope(signed_entries=[a], wire_entries=[{k: str(v) for k, v in a.items()}])),
            ("signed_source_account_mismatch", envelope(signed_entries=[a], wire_entries=[a], signed_subaccount_id=base.SUBACCOUNT_ID + 2)),
            ("lowercase_source_alias_only", envelope(signed_entries=[a], wire_entries=[a], source_key="subaccountId")),
            ("wrong_wire_action_preference", envelope(signed_entries=[a], wire_entries=[a], action="setSnaxpotPreference", extra_params={"snaxBall": 1, "scope": "current"})),
            ("unsigned_epoch_and_owner_fields", envelope(signed_entries=[a], wire_entries=[a], extra_params={"epochId": 999999, "walletAddress": base.ACCOUNT.address})),
            ("duplicate_ticket_serial_json_key", duplicate_ticket_serial_body("1", "2")),
        ]
        for index, (name, payload) in enumerate(cases):
            if isinstance(payload, bytes):
                status, body, headers, elapsed = base.post_bytes(base.PAPI_TRADE, payload)
            else:
                status, body, headers, elapsed = base.post_json(base.PAPI_TRADE, payload)
            evidence["tests"].append(base.summarize(name, status, body, headers, elapsed))
            if index + 1 < len(cases):
                time.sleep(0.55)
    evidence["summary"] = {
        "testCount": len(evidence["tests"]),
        "probeAborted": bool(evidence.get("probeAborted")),
        "casesMentioningSyntheticSigner": [t["name"] for t in evidence["tests"] if t.get("errorMentionsSyntheticSigner")],
        "caseMatrix": [
            {k: t.get(k) for k in ("name", "httpStatus", "apiStatus", "errorCode", "errorMentionsSyntheticSigner", "errorMessageSha256", "bodySha256")}
            for t in evidence["tests"]
        ],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(evidence["summary"], indent=2), encoding="utf-8")
    print(json.dumps(evidence["summary"], indent=2))


if __name__ == "__main__":
    main()
