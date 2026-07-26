#!/usr/bin/env python3
"""Final corrected launcher for the generic-to-write boundary matrix.

The production parser permits ModifyOrder requests with only a changed quantity and
requires cancelAllOrders to contain at least one symbol. This launcher keeps the
controlled matrix unchanged while replacing those two synthetic baseline payloads
with parser-valid forms.
"""
from __future__ import annotations

import synthetix_generic_write_boundary_v2 as corrected

base = corrected.base

replacements = {
    "modifyOrder": base.ActionCase(
        "modifyOrder",
        "ModifyOrder",
        lambda nonce, expiry: {
            "subAccountId": base.SOURCE_ID,
            "orderId": 1,
            "price": "",
            "quantity": "0.001",
            "triggerPrice": "",
            "nonce": nonce,
            "expiresAfter": expiry,
        },
        lambda now: {
            "action": "modifyOrder",
            "subAccountId": str(base.SOURCE_ID),
            "orderId": "1",
            "quantity": "0.001",
        },
    ),
    "cancelAllOrders": base.ActionCase(
        "cancelAllOrders",
        "CancelAllOrders",
        lambda nonce, expiry: {
            "subAccountId": base.SOURCE_ID,
            "symbols": ["BTC-USDT"],
            "nonce": nonce,
            "expiresAfter": expiry,
        },
        lambda now: {
            "action": "cancelAllOrders",
            "subAccountId": str(base.SOURCE_ID),
            "symbols": ["BTC-USDT"],
        },
    ),
}

base.ACTIONS = [replacements.get(action.wire_action, action) for action in base.ACTIONS]

if __name__ == "__main__":
    base.main()
