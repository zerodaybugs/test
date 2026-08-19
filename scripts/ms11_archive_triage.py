#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("security-research/ms11-archive-boundary")
RESULTS = {
    "net10": ROOT / "evidence/net10/RESULT.json",
    "net8": ROOT / "evidence/net8/RESULT.json",
}


def load(path: Path):
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def row_map(data):
    return {row["Name"]: row for row in data.get("rows", [])}


def outside(data, name):
    row = row_map(data).get(name)
    return bool(row and row.get("OutsideCreated"))


def main():
    loaded = {name: load(path) for name, path in RESULTS.items()}
    complete = all(loaded.values())
    direct_names = ["tar-archive-symlink-dir", "tar-dotdot", "tar-absolute"]
    preexisting_names = [
        "tar-preexisting-symlink-dir", "tar-preexisting-symlink-file",
        "zip-preexisting-symlink-dir", "zip-preexisting-symlink-file",
    ]

    direct_both = [
        name for name in direct_names
        if complete and all(outside(loaded[label], name) for label in loaded)
    ]
    preexisting_both = [
        name for name in preexisting_names
        if complete and all(outside(loaded[label], name) for label in loaded)
    ]
    controls = bool(complete and all(d.get("controlPass") for d in loaded.values()))
    harness_clean = bool(complete and all(d.get("counts", {}).get("failed") == 0 for d in loaded.values()))

    if not complete:
        verdict = "PENDING_MATRIX"
        promotion = False
        reason = "Both supported-runtime result objects are required."
    elif direct_both and controls:
        verdict = "PROMOTE_DIRECT_ARCHIVE_CONTROLLED_ESCAPE"
        promotion = True
        reason = "Archive-contained metadata alone produced an outside write on both runtime lines."
    elif preexisting_both and controls:
        verdict = "HOLD_PREEXISTING_SYMLINK_DESTINATION_ONLY"
        promotion = False
        reason = "Only a preexisting attacker-controlled extraction destination produced an outside write; design and privilege preconditions dominate."
    elif harness_clean:
        verdict = "KILL_NO_ARCHIVE_BOUNDARY_ESCAPE"
        promotion = False
        reason = "All malicious archive rows remained within the extraction boundary."
    else:
        verdict = "HOLD_HARNESS_OR_CONTROL_FAILURE"
        promotion = False
        reason = "One or more controls or matrix rows failed independently of a security boundary escape."

    result = {
        "schema": "ms11_archive_boundary_triage/v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "complete": complete,
        "controls_pass": controls,
        "harness_clean": harness_clean,
        "direct_escape_rows_both_runtimes": direct_both,
        "preexisting_symlink_rows_both_runtimes": preexisting_both,
        "verdict": verdict,
        "promote_to_focused_gate": promotion,
        "reason": reason,
        "submission_ready": False,
    }
    (ROOT / "TRIAGE.json").write_text(json.dumps(result, indent=2) + "\n")
    (ROOT / "TRIAGE.md").write_text(
        "# MS11 archive boundary triage\n\n"
        f"- Verdict: `{verdict}`\n"
        f"- Promote: `{promotion}`\n"
        f"- Direct archive rows: `{direct_both}`\n"
        f"- Preexisting destination rows: `{preexisting_both}`\n"
        f"- Reason: {reason}\n\n"
        "This is a research triage artifact, not an MSRC submission.\n"
    )


if __name__ == "__main__":
    main()
