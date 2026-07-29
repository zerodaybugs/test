#!/usr/bin/env python3
"""Focused public read-only scan of documented BTC dislocation minutes."""
import pyth_market_window_scan as scan

scan.WINDOWS = [
    ("oct10_start", "2025-10-10T20:48:00Z", "2025-10-10T20:55:00Z"),
    ("oct10_peak", "2025-10-10T21:10:00Z", "2025-10-10T21:20:00Z"),
    ("dec05_flash", "2024-12-05T10:22:00Z", "2024-12-05T10:29:00Z"),
    ("feb03_low", "2025-02-03T01:55:00Z", "2025-02-03T02:05:00Z"),
]
scan.MAX_PAIR_SECONDS = 600

if __name__ == "__main__":
    raise SystemExit(scan.main())
