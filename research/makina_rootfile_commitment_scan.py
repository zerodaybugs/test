#!/usr/bin/env python3
"""Scan public Makina rootfiles for state-commitment/dataflow anomalies.

This is a non-invasive offline scanner. It parses generated TOML rootfiles and
checks the exact Weiroll command encoding used by Makina v1.2.0:

* use of IDX_USE_STATE (0xfe) as an argument or raw-call return destination;
* state vectors longer than the uint128 commitment bitmap;
* state reads that are neither committed, declared runtime inputs, nor written
  by an earlier command;
* input-slot indexes outside the addressable 0..127 Weiroll range;
* malformed command words and bitmap bits outside the state vector.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib
from dataclasses import asdict, dataclass
from typing import Any, Iterable

IDX_VARIABLE_LENGTH = 0x80
IDX_VALUE_MASK = 0x7F
IDX_DYNAMIC_END = 0xFB
IDX_TUPLE_START = 0xFC
IDX_ARRAY_START = 0xFD
IDX_USE_STATE = 0xFE
IDX_END_OF_ARGS = 0xFF
FLAG_EXTENDED_COMMAND = 0x40

MARKERS = {
    IDX_DYNAMIC_END,
    IDX_TUPLE_START,
    IDX_ARRAY_START,
    IDX_USE_STATE,
    IDX_END_OF_ARGS,
}


@dataclass(frozen=True)
class Hit:
    file: str
    instruction: str
    kind: str
    detail: str


def walk_instruction_tables(node: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(node, dict):
        if "commands" in node and "state" in node and "bitmap" in node:
            yield path, node
            return
        for key, value in node.items():
            yield from walk_instruction_tables(value, path + (str(key),))


def decode_word(raw: str) -> bytes:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ValueError(f"not a 0x-prefixed command word: {raw!r}")
    data = bytes.fromhex(raw[2:])
    if len(data) != 32:
        raise ValueError(f"command word has {len(data)} bytes, expected 32")
    return data


def parse_arg_indexes(encoded: bytes) -> tuple[set[int], bool]:
    refs: set[int] = set()
    use_state = False
    for value in encoded:
        if value == IDX_END_OF_ARGS:
            break
        if value == IDX_USE_STATE:
            use_state = True
            continue
        if value in (IDX_DYNAMIC_END, IDX_TUPLE_START, IDX_ARRAY_START):
            continue
        refs.add(value & IDX_VALUE_MASK)
    return refs, use_state


def bitmap_committed(bitmap: int, index: int) -> bool:
    if not 0 <= index < 128:
        return False
    return bool(bitmap & (1 << (127 - index)))


def analyze_instruction(file: pathlib.Path, name: str, inst: dict[str, Any]) -> tuple[list[Hit], dict[str, Any]]:
    hits: list[Hit] = []
    commands_raw = inst.get("commands", [])
    state = inst.get("state", [])
    bitmap = int(inst.get("bitmap", 0))
    input_slots_raw = inst.get("inputs_slots", [])

    input_slots: set[int] = set()
    for slot in input_slots_raw:
        try:
            index = int(slot["index"])
        except (KeyError, TypeError, ValueError):
            hits.append(Hit(str(file), name, "MALFORMED_INPUT_SLOT", repr(slot)))
            continue
        input_slots.add(index)
        if index >= 128:
            hits.append(Hit(str(file), name, "INPUT_SLOT_OUT_OF_RANGE", f"index={index}"))

    if len(state) > 128:
        hits.append(Hit(str(file), name, "STATE_OVER_128", f"len={len(state)}"))

    for bit_index in range(128):
        if bitmap_committed(bitmap, bit_index) and bit_index >= len(state):
            hits.append(
                Hit(str(file), name, "BITMAP_BIT_OUTSIDE_STATE", f"index={bit_index}, state_len={len(state)}")
            )

    words: list[bytes] = []
    for raw in commands_raw:
        try:
            words.append(decode_word(raw))
        except (TypeError, ValueError) as exc:
            hits.append(Hit(str(file), name, "MALFORMED_COMMAND", str(exc)))

    written: set[int] = set()
    referenced: set[int] = set()
    unbound_reads: set[int] = set()
    use_state_commands: list[int] = []
    raw_state_returns: list[int] = []

    i = 0
    logical_command = 0
    while i < len(words):
        word = words[i]
        flags = word[4]
        ret = word[11]

        if flags & FLAG_EXTENDED_COMMAND:
            if i + 1 >= len(words):
                hits.append(Hit(str(file), name, "TRUNCATED_EXTENDED_COMMAND", f"word={i}"))
                break
            arg_bytes = words[i + 1]
            i += 2
        else:
            arg_bytes = word[5:11]
            i += 1

        refs, use_state = parse_arg_indexes(arg_bytes)
        referenced.update(refs)
        if use_state:
            use_state_commands.append(logical_command)
            hits.append(Hit(str(file), name, "IDX_USE_STATE_ARGUMENT", f"command={logical_command}"))

        for index in refs:
            if index >= len(state):
                hits.append(
                    Hit(str(file), name, "READ_OUTSIDE_STATE", f"command={logical_command}, index={index}, state_len={len(state)}")
                )
            elif not bitmap_committed(bitmap, index) and index not in input_slots and index not in written:
                unbound_reads.add(index)

        if ret == IDX_USE_STATE:
            raw_state_returns.append(logical_command)
            hits.append(Hit(str(file), name, "IDX_USE_STATE_RETURN", f"command={logical_command}"))
        elif ret != IDX_END_OF_ARGS:
            out_index = ret & IDX_VALUE_MASK
            if out_index >= 128:
                hits.append(Hit(str(file), name, "RETURN_SLOT_OUT_OF_RANGE", f"command={logical_command}, index={out_index}"))
            written.add(out_index)

        logical_command += 1

    for index in sorted(unbound_reads):
        value = state[index] if index < len(state) else None
        hits.append(
            Hit(
                str(file),
                name,
                "UNBOUND_STATE_READ",
                f"index={index}, value={value!r}, committed=false, input=false, prior_write=false",
            )
        )

    summary = {
        "instruction": name,
        "state_len": len(state),
        "bitmap_popcount": bitmap.bit_count(),
        "input_slots": sorted(input_slots),
        "referenced_slots": sorted(referenced),
        "written_slots": sorted(written),
        "unbound_read_slots": sorted(unbound_reads),
        "idx_use_state_args": use_state_commands,
        "idx_use_state_returns": raw_state_returns,
    }
    return hits, summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=pathlib.Path, help="makina-integrations checkout")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    rootfiles = sorted(args.root.glob("machines/**/rootfiles/*.toml"))
    hits: list[Hit] = []
    summaries: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []

    max_state_len = 0
    instruction_count = 0

    for file in rootfiles:
        try:
            with file.open("rb") as handle:
                doc = tomllib.load(handle)
        except Exception as exc:  # report and continue across the public corpus
            parse_errors.append({"file": str(file), "error": f"{type(exc).__name__}: {exc}"})
            continue

        for path, inst in walk_instruction_tables(doc.get("instructions", {})):
            instruction_count += 1
            name = ".".join(path)
            inst_hits, summary = analyze_instruction(file, name, inst)
            max_state_len = max(max_state_len, summary["state_len"])
            hits.extend(inst_hits)
            summaries.append({"file": str(file), **summary})

    by_kind: dict[str, int] = {}
    for hit in hits:
        by_kind[hit.kind] = by_kind.get(hit.kind, 0) + 1

    report = {
        "rootfiles": len(rootfiles),
        "instructions": instruction_count,
        "max_state_len": max_state_len,
        "parse_errors": parse_errors,
        "hits_by_kind": dict(sorted(by_kind.items())),
        "hits": [asdict(hit) for hit in hits],
    }

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "rootfile_commitment_scan.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out / "rootfile_instruction_summaries.json").write_text(
        json.dumps(summaries, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [
        f"rootfiles={len(rootfiles)}",
        f"instructions={instruction_count}",
        f"max_state_len={max_state_len}",
        f"parse_errors={len(parse_errors)}",
    ]
    lines.extend(f"{kind}={count}" for kind, count in sorted(by_kind.items()))
    (args.out / "rootfile_commitment_scan.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))

    # The scanner itself succeeds even when it finds anomalies; the evidence
    # report is the decision input and must be reviewed before any submission.
    return 0


if __name__ == "__main__":
    sys.exit(main())
