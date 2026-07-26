#!/usr/bin/env python3
"""Corrected launcher for the generic-to-write boundary matrix.

eth-account requires each typed-data graph to expose exactly one root primary type.
The production frontend stores PlaceOrders, ModifyOrder, and CancelOrders in one
constant, so this launcher filters that constant to the exact graph used by each
request before executing the unchanged controlled probe.
"""
from __future__ import annotations

from typing import Any

import synthetix_generic_write_boundary as base


def typed_types(primary_type: str) -> dict[str, Any]:
    if primary_type == "PlaceOrders":
        return {
            "EIP712Domain": base.DOMAIN_FIELDS,
            "Order": base.ORDER_TYPES["Order"],
            "PlaceOrders": base.ORDER_TYPES["PlaceOrders"],
        }
    if primary_type in {"ModifyOrder", "CancelOrders"}:
        return {
            "EIP712Domain": base.DOMAIN_FIELDS,
            primary_type: base.ORDER_TYPES[primary_type],
        }
    return {
        "EIP712Domain": base.DOMAIN_FIELDS,
        primary_type: base.SIMPLE_TYPES[primary_type],
    }


base.typed_types = typed_types

if __name__ == "__main__":
    base.main()
