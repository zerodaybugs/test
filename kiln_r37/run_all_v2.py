#!/usr/bin/env python3
from pathlib import Path

import run_all as base

base.ROOT = Path("r37d_persisted/LATEST")
base.SCRIPT = Path("kiln_r37/fee_invariant_census_v2.py")

if __name__ == "__main__":
    raise SystemExit(base.main())
