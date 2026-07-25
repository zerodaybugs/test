#!/usr/bin/env python3
"""Run manager-revocation correlation with checksummed PAPI wallet addresses."""

from __future__ import annotations

import json
import pathlib

from eth_utils import to_checksum_address

import synthetix_manager_revocation_history as probe

OUT = pathlib.Path("manager_revocation_history_v3")
OUT.mkdir(parents=True, exist_ok=True)
probe.OUT = OUT

_original_discovery = probe.account_discovery


def checksummed_discovery(manager: str):
    return _original_discovery(to_checksum_address(manager))


probe.account_discovery = checksummed_discovery


def has_code(block_number: int) -> bool:
    code = probe.rpc("eth_getCode", [probe.REGISTRY, hex(block_number)])
    return isinstance(code, str) and code not in ("0x", "0x0", "")


def find_creation_block(latest: int) -> int:
    if not has_code(latest):
        raise RuntimeError("PermissionsRegistry has no bytecode at latest block")
    low, high = 0, latest
    while low < high:
        middle = (low + high) // 2
        if has_code(middle):
            high = middle
        else:
            low = middle + 1
    return low


if __name__ == "__main__":
    latest_block = int(probe.rpc("eth_blockNumber", []), 16)
    deployment_block = find_creation_block(latest_block)
    probe.START_BLOCK = deployment_block
    (OUT / "deployment.json").write_text(
        json.dumps(
            {
                "registry": probe.REGISTRY,
                "deploymentBlock": deployment_block,
                "latestBlock": latest_block,
                "papiWalletEncoding": "EIP-55 checksum",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    probe.main()
