#!/usr/bin/env python3
"""Read-only TMX cross-chain deployment and OFT-interface gate.

No signer, transaction construction, broadcast, impersonation, or state mutation.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

TMX = Web3.to_checksum_address("0x9daf7A876366c1f1195FE3072262FDE900000000")
EXPECTED_ADMIN = Web3.to_checksum_address("0x81f314f70702Bbe89FEd0F2cFe6841950275E0b7")
CHAINS = {
    "ethereum": {
        "chainId": 1,
        "ownEid": 30101,
        "remoteEid": 30102,
        "rpcs": [
            "https://ethereum-rpc.publicnode.com",
            "https://eth.drpc.org",
            "https://1rpc.io/eth",
        ],
    },
    "bnb": {
        "chainId": 56,
        "ownEid": 30102,
        "remoteEid": 30101,
        "rpcs": [
            "https://bsc-rpc.publicnode.com",
            "https://bsc-dataseed.binance.org",
            "https://bsc.drpc.org",
        ],
    },
}

TMX_ABI = [
    {"type":"function","name":"name","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"symbol","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]},
    {"type":"function","name":"decimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"totalSupply","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"owner","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"endpoint","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"peers","stateMutability":"view","inputs":[{"type":"uint32"}],"outputs":[{"type":"bytes32"}]},
    {"type":"function","name":"msgInspector","stateMutability":"view","inputs":[],"outputs":[{"type":"address"}]},
    {"type":"function","name":"sharedDecimals","stateMutability":"view","inputs":[],"outputs":[{"type":"uint8"}]},
    {"type":"function","name":"decimalConversionRate","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
    {"type":"function","name":"oAppVersion","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"},{"type":"uint64"}]},
]
ENDPOINT_ABI = [
    {"type":"function","name":"eid","stateMutability":"view","inputs":[],"outputs":[{"type":"uint32"}]},
    {"type":"function","name":"delegates","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"address"}]},
]


def connect(cfg: dict[str, Any]) -> tuple[Web3, str, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    for url in cfg["rpcs"]:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
            if cfg["chainId"] == 56:
                w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            chain_id = w3.eth.chain_id
            block = w3.eth.get_block("latest")
            if chain_id != cfg["chainId"]:
                raise RuntimeError(f"unexpected chain id {chain_id}")
            attempts.append({"url": url, "ok": True, "block": block.number})
            return w3, url, attempts
        except Exception as exc:  # noqa: BLE001
            attempts.append({"url": url, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    raise RuntimeError(json.dumps(attempts))


def safe(fn, *args, **kwargs) -> dict[str, Any]:
    try:
        value = fn(*args, **kwargs)
        if isinstance(value, bytes):
            value = Web3.to_hex(value)
        elif isinstance(value, tuple):
            value = list(value)
        return {"ok": True, "value": value}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    chain = os.environ["CHAIN"].strip().lower()
    cfg = CHAINS[chain]
    out = Path(os.environ.get("OUT_DIR", "evidence"))
    out.mkdir(parents=True, exist_ok=True)

    w3, rpc, attempts = connect(cfg)
    block = w3.eth.get_block("latest")
    token = w3.eth.contract(address=TMX, abi=TMX_ABI)
    code = w3.eth.get_code(TMX, block_identifier=block.number)
    endpoint_r = safe(token.functions.endpoint().call, block_identifier=block.number)
    endpoint = Web3.to_checksum_address(endpoint_r["value"]) if endpoint_r.get("ok") else None
    endpoint_contract = w3.eth.contract(address=endpoint, abi=ENDPOINT_ABI) if endpoint else None

    own_peer = safe(token.functions.peers(cfg["ownEid"]).call, block_identifier=block.number)
    remote_peer = safe(token.functions.peers(cfg["remoteEid"]).call, block_identifier=block.number)
    expected_peer = Web3.to_hex(Web3.to_bytes(hexstr=TMX).rjust(32, b"\x00"))
    owner = safe(token.functions.owner().call, block_identifier=block.number)
    total_supply = safe(token.functions.totalSupply().call, block_identifier=block.number)
    decimals = safe(token.functions.decimals().call, block_identifier=block.number)
    endpoint_eid = (
        safe(endpoint_contract.functions.eid().call, block_identifier=block.number)
        if endpoint_contract else {"ok": False, "error": "endpoint unavailable"}
    )
    delegate = (
        safe(endpoint_contract.functions.delegates(TMX).call, block_identifier=block.number)
        if endpoint_contract else {"ok": False, "error": "endpoint unavailable"}
    )

    oft_calls = {
        "owner": owner,
        "endpoint": endpoint_r,
        "endpointEid": endpoint_eid,
        "endpointDelegate": delegate,
        "msgInspector": safe(token.functions.msgInspector().call, block_identifier=block.number),
        "sharedDecimals": safe(token.functions.sharedDecimals().call, block_identifier=block.number),
        "decimalConversionRate": safe(token.functions.decimalConversionRate().call, block_identifier=block.number),
        "oAppVersion": safe(token.functions.oAppVersion().call, block_identifier=block.number),
        "ownPeer": own_peer,
        "remotePeer": remote_peer,
    }
    oft_interface_present = any(row.get("ok") for row in oft_calls.values())

    result = {
        "schema": "termmax-tmx-crosschain-live-gate/v2",
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(),
        "safety": {"privateKeys": 0, "signedTransactions": 0, "broadcastTransactions": 0, "stateChanges": 0},
        "chain": chain,
        "chainId": cfg["chainId"],
        "rpc": rpc,
        "rpcAttempts": attempts,
        "block": {
            "number": block.number,
            "hash": block.hash.hex(),
            "timestamp": block.timestamp,
            "timestampUtc": datetime.fromtimestamp(block.timestamp, tz=timezone.utc).isoformat(),
        },
        "tmx": TMX,
        "tmxCodeBytes": len(code),
        "tmxCodeHash": Web3.keccak(code).hex(),
        "name": safe(token.functions.name().call, block_identifier=block.number),
        "symbol": safe(token.functions.symbol().call, block_identifier=block.number),
        "decimals": decimals,
        "totalSupply": total_supply,
        "expectedAdmin": EXPECTED_ADMIN,
        "oftInterfaceCalls": oft_calls,
        "ownEid": cfg["ownEid"],
        "remoteEid": cfg["remoteEid"],
        "expectedRemotePeer": expected_peer,
    }
    result["verdict"] = {
        "contractDeployed": len(code) > 0,
        "oftInterfacePresent": oft_interface_present,
        "ownerMatchesExpectedAdmin": bool(owner.get("ok") and owner.get("value", "").lower() == EXPECTED_ADMIN.lower()),
        "endpointEidMatchesChain": bool(endpoint_eid.get("ok") and endpoint_eid.get("value") == cfg["ownEid"]),
        "remotePeerMatchesTMX": bool(remote_peer.get("ok") and str(remote_peer.get("value")).lower() == expected_peer.lower()),
        "ownPeerIsZero": bool(own_peer.get("ok") and int(str(own_peer.get("value")), 16) == 0),
        "delegateMatchesExpectedAdmin": bool(delegate.get("ok") and delegate.get("value", "").lower() == EXPECTED_ADMIN.lower()),
    }
    (out / "TMX_CROSSCHAIN_LIVE_GATE.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "VERDICT.json").write_text(json.dumps(result["verdict"], indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
