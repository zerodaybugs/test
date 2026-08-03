#!/usr/bin/env python3
"""Fast read-only V1/V2 renounceRole behavior probe for one TermMax chain."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

ATTACKER = Web3.to_checksum_address("0x1000000000000000000000000000000000000001")
TARGET = Web3.to_checksum_address("0x8409a9C1A911CED491892c5694E43994c9d47E8f")
PAUSER_ROLE = Web3.keccak(text="PAUSER_ROLE")
IMPL_SLOT = int("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16)

CHAINS = {
    "ethereum": (1, "0xDA4aAF85Bb924B53DCc2DFFa9e1A9C2Ef97aCFDF", ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://1rpc.io/eth"]),
    "arbitrum": (42161, "0xFaD175CAf9B0Ac0EBca3B1816ec799884EB04B9c", ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc", "https://arbitrum.drpc.org"]),
    "bnb": (56, "0x9498764f0c62257B83A04e2A757De30908EC793d", ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.binance.org", "https://bsc.drpc.org"]),
    "base": (8453, "0x90C72fa3b55E4Bd00afc0a6c4419E2DF99f6D95a", ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://base.drpc.org"]),
    "berachain": (80094, "0x9498764f0c62257B83A04e2A757De30908EC793d", ["https://berachain-rpc.publicnode.com", "https://rpc.berachain.com"]),
    "hyperevm": (999, "0x9498764f0c62257B83A04e2A757De30908EC793d", ["https://rpc.hyperliquid.xyz/evm", "https://hyperliquid.drpc.org"]),
    "xlayer": (196, "0x9498764f0c62257B83A04e2A757De30908EC793d", ["https://rpc.xlayer.tech", "https://xlayerrpc.okx.com"]),
}

ABI = [
    {"type":"function","name":"renounceRole","stateMutability":"nonpayable","inputs":[{"type":"bytes32"},{"type":"address"}],"outputs":[]},
    {"type":"function","name":"getVersion","stateMutability":"pure","inputs":[],"outputs":[{"type":"string"}]},
]

def main() -> int:
    chain = os.environ["CHAIN"].lower()
    expected_id, raw_access, rpcs = CHAINS[chain]
    access = Web3.to_checksum_address(raw_access)
    attempts = []
    w3 = None
    block = None
    rpc = None
    for url in rpcs:
        try:
            candidate = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout":30}))
            if chain == "bnb":
                candidate.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            if candidate.eth.chain_id != expected_id:
                raise RuntimeError(f"unexpected chain id {candidate.eth.chain_id}")
            block = candidate.eth.get_block("latest")
            w3, rpc = candidate, url
            attempts.append({"url":url,"ok":True,"block":block.number})
            break
        except Exception as exc:
            attempts.append({"url":url,"ok":False,"error":f"{type(exc).__name__}: {exc}"})
    if w3 is None or block is None:
        raise SystemExit(json.dumps(attempts, indent=2))
    contract = w3.eth.contract(address=access, abi=ABI)
    impl_raw = w3.eth.get_storage_at(access, IMPL_SLOT, block_identifier=block.number)
    implementation = Web3.to_checksum_address("0x" + impl_raw[-20:].hex())
    call = {"from":ATTACKER,"to":access,"data":contract.encode_abi("renounceRole", args=[PAUSER_ROLE, TARGET])}
    try:
        returned = w3.eth.call(call, block_identifier=block.number)
        probe = {"ok":True,"returnData":Web3.to_hex(returned)}
    except Exception as exc:
        probe = {"ok":False,"error":f"{type(exc).__name__}: {exc}"}
    try:
        version = {"ok":True,"value":contract.functions.getVersion().call(block_identifier=block.number)}
    except Exception as exc:
        version = {"ok":False,"error":f"{type(exc).__name__}: {exc}"}
    result = {
        "schema":"termmax-accessmanager-fast-renounce-probe/v2",
        "generatedAtUtc":datetime.now(timezone.utc).isoformat(),
        "safety":{"privateKeys":0,"signedTransactions":0,"broadcastTransactions":0,"stateChanges":0},
        "chain":chain,"chainId":expected_id,"rpc":rpc,"rpcAttempts":attempts,
        "block":{"number":block.number,"hash":block.hash.hex(),"timestamp":block.timestamp},
        "accessManager":access,"implementation":implementation,
        "implementationCodeBytes":len(w3.eth.get_code(implementation, block_identifier=block.number)),
        "version":version,"arbitraryAttackerRenounceRoleEthCall":probe,
        "verdict":{"v1LikeUnrestrictedRenounce":bool(probe.get("ok")),"v2LikeRenounceBlocked":not bool(probe.get("ok"))},
    }
    out = Path(os.environ.get("OUT_DIR", "evidence")); out.mkdir(parents=True, exist_ok=True)
    (out / "ACCESSMANAGER_FAST_PROBE.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
