#!/usr/bin/env python3
"""Read-only historical Stacks four-block timing probe."""
import json
from datetime import datetime, timezone
from pathlib import Path
import pyth_market_window_scan as scan

OUT = Path("pyth-scan-output")
OUT.mkdir(parents=True, exist_ok=True)
blocks = scan.Blocks()

pairs = [
    {
        "name": "first_material_pair",
        "high_time": scan.unix("2025-10-10T21:15:31Z"),
        "low_time": scan.unix("2025-10-10T21:19:31Z"),
        "drop_bps": "540.282839509026",
    },
    {
        "name": "best_180_second_pair",
        "high_time": scan.unix("2025-10-10T21:15:31Z"),
        "low_time": scan.unix("2025-10-10T21:17:50Z"),
        "drop_bps": "422.478489497916",
    },
]

results = []
for pair in pairs:
    start_h = blocks.before(pair["low_time"])
    end_h = blocks.before(pair["low_time"] + 60)
    observations = []
    for height in range(start_h, end_h + 1):
        current = blocks.at(height)
        prior = blocks.at(height - 4)
        observations.append({
            "height": height,
            "block_time": current["time"],
            "block_utc": current["utc"],
            "height_minus_4": height - 4,
            "height_minus_4_time": prior["time"],
            "height_minus_4_utc": prior["utc"],
            "four_block_seconds": current["time"] - prior["time"],
            "high_payload_fresh": pair["high_time"] > prior["time"],
        })
    results.append(pair | {
        "high_utc": scan.iso(pair["high_time"]),
        "low_utc": scan.iso(pair["low_time"]),
        "start_height": start_h,
        "end_height": end_h,
        "passes_at_any_height_in_first_60_seconds": any(x["high_payload_fresh"] for x in observations),
        "observations": observations,
    })

summary = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "tip_height": blocks.tip,
    "results": results,
    "decision": "FOUR_BLOCK_GATE_PASS" if any(x["passes_at_any_height_in_first_60_seconds"] and float(x["drop_bps"]) > 500 for x in results) else "FOUR_BLOCK_GATE_FAIL",
}
(OUT / "SUMMARY.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
(OUT / "block_cache.json").write_text(json.dumps(blocks.cache, indent=2), encoding="utf-8")
(OUT / "SHA256SUMS.txt").write_text("generated in isolated read-only workflow\n", encoding="utf-8")
print(json.dumps(summary, indent=2))
