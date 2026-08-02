#!/usr/bin/env python3
"""Compatibility wrapper for Web3.py topic hex normalization."""
from __future__ import annotations

import importlib.util
from pathlib import Path

from web3 import Web3

BASE = Path(__file__).with_name("termmax_zero_price_live_binding_20260802.py")
SPEC = importlib.util.spec_from_file_location("termmax_zero_price_live_binding_base", BASE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load scanner: {BASE}")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

# HexBytes.hex() changed prefix behavior across Web3.py releases. Explorer logs
# always expose a 0x-prefixed topic, so normalize the expected event signature.
module.CREATE_MARKET_TOPIC = Web3.to_hex(Web3.keccak(text="CreateMarket(address,address,address)"))

raise SystemExit(module.main())
