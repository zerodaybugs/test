#!/usr/bin/env python3
"""Generate a deterministic, parser-heavy EIP-2537 differential corpus."""

from __future__ import annotations

import argparse
import hashlib
import random
from pathlib import Path
from typing import Iterable

from py_ecc.optimized_bls12_381 import (
    G1,
    G2,
    Z1,
    Z2,
    curve_order,
    field_modulus,
    multiply,
    neg,
    normalize,
)

P = int(field_modulus)
Q = int(curve_order)
TWO_256 = 1 << 256
TWO_384 = 1 << 384


def fp(value: int) -> bytes:
    if value < 0 or value >= 1 << 512:
        raise ValueError(f"field container overflow: {value}")
    return value.to_bytes(64, "big")


def scalar(value: int) -> bytes:
    return (value % TWO_256).to_bytes(32, "big")


def g1_bytes(point: object) -> bytes:
    if point == Z1:
        return bytes(128)
    x, y = normalize(point)  # type: ignore[arg-type]
    return fp(int(x)) + fp(int(y))


def g2_bytes(point: object) -> bytes:
    if point == Z2:
        return bytes(256)
    x, y = normalize(point)  # type: ignore[arg-type]
    return (
        fp(int(x.coeffs[0]))
        + fp(int(x.coeffs[1]))
        + fp(int(y.coeffs[0]))
        + fp(int(y.coeffs[1]))
    )


def replace_component(data: bytes, component: int, value: int) -> bytes:
    start = component * 64
    end = start + 64
    if end > len(data):
        raise ValueError("component outside input")
    return data[:start] + fp(value) + data[end:]


def component(data: bytes, component_index: int) -> int:
    start = component_index * 64
    return int.from_bytes(data[start : start + 64], "big")


def deterministic_bytes(label: str, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(f"{label}:{counter}".encode()).digest())
        counter += 1
    return bytes(out[:length])


def lines() -> Iterable[tuple[str, str, bytes]]:
    case_number = 0

    def emit(op: str, label: str, data: bytes):
        nonlocal case_number
        case_number += 1
        return f"c{case_number:06d}-{label}", op, data

    # Fixed-length malformed input gates.
    malformed_lengths = {
        "G1ADD": [0, 1, 127, 128, 255, 257, 512],
        "G2ADD": [0, 1, 255, 256, 511, 513, 1024],
        "G1MSM": [0, 1, 128, 159, 161, 319, 321],
        "G2MSM": [0, 1, 256, 287, 289, 575, 577],
        "PAIRING": [0, 1, 127, 383, 385, 767, 769],
        "MAP_FP_G1": [0, 1, 63, 65, 128],
        "MAP_FP2_G2": [0, 1, 64, 127, 129, 256],
    }
    for op, lengths in malformed_lengths.items():
        for length in lengths:
            yield emit(op, f"malformed-len-{length}", deterministic_bytes(f"{op}-{length}", length))

    # Field-map boundaries and canonical/non-canonical random values.
    field_boundaries = [0, 1, 2, P - 2, P - 1, P, P + 1, 2 * P - 1, TWO_384 - 1]
    for value in field_boundaries:
        yield emit("MAP_FP_G1", f"fp-boundary-{value:x}", fp(value))
    for left in field_boundaries:
        for right in (0, 1, P - 1, P, P + 1):
            yield emit("MAP_FP2_G2", f"fp2-boundary-{left:x}-{right:x}", fp(left) + fp(right))
    for index in range(768):
        canonical = int.from_bytes(deterministic_bytes(f"map-fp-{index}", 48), "big") % P
        yield emit("MAP_FP_G1", f"fp-canonical-{index}", fp(canonical))
        yield emit("MAP_FP_G1", f"fp-plus-p-{index}", fp(canonical + P))
        second = int.from_bytes(deterministic_bytes(f"map-fp2-{index}", 48), "big") % P
        yield emit("MAP_FP2_G2", f"fp2-canonical-{index}", fp(canonical) + fp(second))
        yield emit("MAP_FP2_G2", f"fp2-left-plus-p-{index}", fp(canonical + P) + fp(second))
        yield emit("MAP_FP2_G2", f"fp2-right-plus-p-{index}", fp(canonical) + fp(second + P))

    # G1 add and MSM: valid points, infinities, cancellation, canonicality and subgroup boundaries.
    scalar_values = [0, 1, 2, Q - 1, Q, Q + 1, TWO_256 - 1]
    for seed in range(1, 257):
        p1 = multiply(G1, seed)
        p2 = multiply(G1, seed * 17 + 3)
        encoded1 = g1_bytes(p1)
        encoded2 = g1_bytes(p2)
        valid_add = encoded1 + encoded2
        yield emit("G1ADD", f"g1-valid-{seed}", valid_add)
        yield emit("G1ADD", f"g1-left-infinity-{seed}", bytes(128) + encoded2)
        yield emit("G1ADD", f"g1-right-infinity-{seed}", encoded1 + bytes(128))
        yield emit("G1ADD", f"g1-cancel-{seed}", encoded1 + g1_bytes(neg(p1)))
        yield emit("G1ADD", f"g1-nonsubgroup-{seed}", fp(0) + fp(2) + encoded2)

        for coordinate in range(4):
            value = component(valid_add, coordinate)
            yield emit(
                "G1ADD",
                f"g1-plus-p-{seed}-{coordinate}",
                replace_component(valid_add, coordinate, value + P),
            )
            yield emit(
                "G1ADD",
                f"g1-exact-p-{seed}-{coordinate}",
                replace_component(valid_add, coordinate, P),
            )
        top_pad = bytearray(valid_add)
        top_pad[(seed % 4) * 64] = 1
        yield emit("G1ADD", f"g1-top-pad-{seed}", bytes(top_pad))

        for s in scalar_values:
            yield emit("G1MSM", f"g1-msm-{seed}-scalar-{s:x}", encoded1 + scalar(s))
        two_pair = encoded1 + scalar(seed) + encoded2 + scalar(seed * 3 + 1)
        yield emit("G1MSM", f"g1-msm-two-pair-{seed}", two_pair)
        yield emit(
            "G1MSM",
            f"g1-msm-plus-p-{seed}",
            replace_component(encoded1 + scalar(1), seed % 2, component(encoded1, seed % 2) + P),
        )
        yield emit("G1MSM", f"g1-msm-nonsubgroup-{seed}", fp(0) + fp(2) + scalar(1))

    # G2 add and MSM.
    for seed in range(1, 129):
        p1 = multiply(G2, seed)
        p2 = multiply(G2, seed * 13 + 5)
        encoded1 = g2_bytes(p1)
        encoded2 = g2_bytes(p2)
        valid_add = encoded1 + encoded2
        yield emit("G2ADD", f"g2-valid-{seed}", valid_add)
        yield emit("G2ADD", f"g2-left-infinity-{seed}", bytes(256) + encoded2)
        yield emit("G2ADD", f"g2-right-infinity-{seed}", encoded1 + bytes(256))
        yield emit("G2ADD", f"g2-cancel-{seed}", encoded1 + g2_bytes(neg(p1)))
        for coordinate in range(8):
            value = component(valid_add, coordinate)
            yield emit(
                "G2ADD",
                f"g2-plus-p-{seed}-{coordinate}",
                replace_component(valid_add, coordinate, value + P),
            )
            yield emit(
                "G2ADD",
                f"g2-exact-p-{seed}-{coordinate}",
                replace_component(valid_add, coordinate, P),
            )
        top_pad = bytearray(valid_add)
        top_pad[(seed % 8) * 64] = 1
        yield emit("G2ADD", f"g2-top-pad-{seed}", bytes(top_pad))

        for s in scalar_values:
            yield emit("G2MSM", f"g2-msm-{seed}-scalar-{s:x}", encoded1 + scalar(s))
        two_pair = encoded1 + scalar(seed) + encoded2 + scalar(seed * 5 + 1)
        yield emit("G2MSM", f"g2-msm-two-pair-{seed}", two_pair)
        coord = seed % 4
        yield emit(
            "G2MSM",
            f"g2-msm-plus-p-{seed}",
            replace_component(encoded1 + scalar(1), coord, component(encoded1, coord) + P),
        )

    # Pairing identity and parser boundaries.
    for seed in range(1, 65):
        p1 = multiply(G1, seed)
        p2 = multiply(G2, seed * 7 + 1)
        g1 = g1_bytes(p1)
        g2 = g2_bytes(p2)
        one_pair = g1 + g2
        identity = one_pair + g1_bytes(neg(p1)) + g2
        yield emit("PAIRING", f"pair-single-{seed}", one_pair)
        yield emit("PAIRING", f"pair-identity-{seed}", identity)
        for coordinate in range(6):
            value = component(one_pair, coordinate)
            yield emit(
                "PAIRING",
                f"pair-plus-p-{seed}-{coordinate}",
                replace_component(one_pair, coordinate, value + P),
            )

    # Deterministic raw corpora. Most reject at parsing; any cross-client acceptance/output
    # discrepancy is retained by the private comparer.
    raw_plan = {
        "G1ADD": (256, 4_000),
        "G2ADD": (512, 2_000),
        "G1MSM": (160, 1_500),
        "G2MSM": (288, 750),
        "PAIRING": (384, 750),
        "MAP_FP_G1": (64, 1_500),
        "MAP_FP2_G2": (128, 1_000),
    }
    randomizer = random.Random(0x2537_2026_0810)
    for op, (length, count) in raw_plan.items():
        for index in range(count):
            data = randomizer.randbytes(length)
            yield emit(op, f"raw-{op.lower()}-{index}", data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with args.output.open("w", encoding="ascii", newline="\n") as output:
        for case_id, op, data in lines():
            output.write(f"{case_id}\t{op}\t{data.hex()}\n")
            count += 1

    print(f"BLS2537_CORPUS_READY cases={count} sha256={hashlib.sha256(args.output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
