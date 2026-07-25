#!/usr/bin/env python3
"""Run the corrected transfer alias differential with valid signed-64-bit IDs."""

from __future__ import annotations

import pathlib

import synthetix_transfer_alias_boundary_v2 as probe

probe.OUT = pathlib.Path("transfer_alias_boundary_v3")
probe.OUT.mkdir(parents=True, exist_ok=True)
probe.SOURCE = 8_832_451_907_612_340_731
probe.DEST_A = 8_832_451_907_612_340_737
probe.DEST_B = 8_832_451_907_612_340_739

if __name__ == "__main__":
    probe.main()
