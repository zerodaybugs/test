#!/usr/bin/env python3
"""Retrieve one missing public Pyth BTC/USD historical minute."""
import pyth_market_window_scan as scan

scan.WINDOWS = [
    ("oct10_2116", "2025-10-10T21:16:00Z", "2025-10-10T21:16:59Z"),
]
scan.MAX_PAIR_SECONDS = 60

if __name__ == "__main__":
    raise SystemExit(scan.main())
