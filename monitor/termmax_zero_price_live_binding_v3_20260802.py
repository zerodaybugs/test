#!/usr/bin/env python3
"""Compatibility wrapper for canonical TermMax V2 MarketCreated events."""
from __future__ import annotations

import importlib.util
from pathlib import Path

from web3 import Web3

BASE = Path(__file__).with_name("termmax_zero_price_live_binding_20260802.py")
SPEC = importlib.util.spec_from_file_location("termmax_zero_price_live_binding_base_v3", BASE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load scanner: {BASE}")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

module.CREATE_MARKET_TOPIC = Web3.to_hex(Web3.keccak(text=(
    "MarketCreated(address,address,address,"
    "(address,address,address,address,"
    "(address,uint64,(uint32,uint32,uint32,uint32,uint32,uint32)),"
    "(address,uint32,uint32,bool),bytes,string,string))"
)))

raise SystemExit(module.main())
