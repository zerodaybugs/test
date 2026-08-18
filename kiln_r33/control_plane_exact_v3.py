#!/usr/bin/env python3
"""Canonical-slot wrapper for the R33 v2 control-plane gate."""
from web3 import Web3
import control_plane_exact_v2 as gate


def slot(label: str) -> int:
    return int.from_bytes(bytes(Web3.keccak(text=label)), "big") - 1


gate.IMPLEMENTATION_SLOT = slot("eip1967.proxy.implementation")
gate.ADMIN_SLOT = slot("eip1967.proxy.admin")
gate.ADMIN_SLOT_CANON = gate.ADMIN_SLOT
gate.BEACON_SLOT = slot("eip1967.proxy.beacon")
gate.SENSITIVE_SLOTS = {
    "eip1967_implementation": gate.IMPLEMENTATION_SLOT,
    "eip1967_admin": gate.ADMIN_SLOT,
    "eip1967_beacon": gate.BEACON_SLOT,
}

if __name__ == "__main__":
    raise SystemExit(gate.main())
