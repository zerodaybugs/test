#!/usr/bin/env python3
"""Compare normalized Geth/Besu EIP-2537 results without leaking candidate rows."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def read_results(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if not line:
            continue
        fields = line.split("\t", 2)
        if len(fields) != 3:
            raise ValueError(f"invalid result row in {path.name}")
        case_id, operation, result = fields
        key = f"{case_id}\t{operation}"
        if key in rows:
            raise ValueError(f"duplicate result row in {path.name}")
        rows[key] = result
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--geth", type=Path, required=True)
    parser.add_argument("--besu", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--decision", type=Path, required=True)
    args = parser.parse_args()

    geth = read_results(args.geth)
    besu = read_results(args.besu)
    if geth.keys() != besu.keys():
        missing_geth = sorted(besu.keys() - geth.keys())
        missing_besu = sorted(geth.keys() - besu.keys())
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(
            "RESULT_SET_MISMATCH\n"
            + f"missing_geth={missing_geth[:10]}\n"
            + f"missing_besu={missing_besu[:10]}\n",
            encoding="ascii",
        )
        args.decision.write_text("INCONCLUSIVE_RESULT_SET_MISMATCH\n", encoding="ascii")
        print("BLS2537_RESULT_SET_MISMATCH")
        raise SystemExit(2)

    corpus_rows: dict[str, str] = {}
    for line in args.corpus.read_text(encoding="ascii").splitlines():
        fields = line.split("\t", 2)
        if len(fields) != 3:
            raise ValueError("invalid corpus row")
        corpus_rows[f"{fields[0]}\t{fields[1]}"] = fields[2]

    mismatches: list[tuple[str, str, str, str]] = []
    for key in geth:
        if geth[key] != besu[key]:
            mismatches.append((key, corpus_rows[key], geth[key], besu[key]))

    args.decision.parent.mkdir(parents=True, exist_ok=True)
    if mismatches:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        with args.evidence.open("w", encoding="ascii", newline="\n") as evidence:
            evidence.write(f"mismatch_count={len(mismatches)}\n")
            for key, input_hex, geth_result, besu_result in mismatches[:100]:
                evidence.write(f"case={key}\n")
                evidence.write(f"input={input_hex}\n")
                evidence.write(f"geth={geth_result}\n")
                evidence.write(f"besu={besu_result}\n\n")
        args.decision.write_text("CANDIDATE_BLS2537_CONSENSUS_DIFFERENTIAL\n", encoding="ascii")
        print(f"BLS2537_CONSENSUS_DIFFERENTIAL_CANDIDATE count={len(mismatches)}")
        raise SystemExit(1)

    digest = hashlib.sha256(args.geth.read_bytes()).hexdigest()
    args.decision.write_text("NO_DIFFERENTIAL_OBSERVED\n", encoding="ascii")
    print(f"BLS2537_NO_DIFFERENTIAL cases={len(geth)} result_sha256={digest}")


if __name__ == "__main__":
    main()
