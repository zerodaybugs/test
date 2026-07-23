#!/usr/bin/env python3
"""Minimal read-only Synthetix state snapshot without historical log scans."""

from __future__ import annotations

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import synthetix_state_read as s  # noqa: E402

out = pathlib.Path("out")
out.mkdir(parents=True, exist_ok=True)
state: dict[str, object] = {"proxy": s.PROXY, "rpc_endpoints": s.RPC_URLS}

latest = int(s.rpc("eth_blockNumber", []), 16)
receipt = s.rpc("eth_getTransactionReceipt", [s.PROXY_CREATION_TX])
creation_block = int(receipt["blockNumber"], 16)
state.update(latest_block=latest, proxy_creation_block=creation_block, proxy_creation_receipt=receipt)

implementations = {
    "deposit_proxy_impl": s.implementation_of(s.PROXY),
    "lens_impl": s.implementation_of(s.LENS),
    "permissions_registry_impl": s.implementation_of(s.REGISTRY_PROXY),
}
state["implementations"] = implementations

scalar_decoders = {
    "slpVault": s.decode_address,
    "getSLPVaultAllowance": s.decode_uint,
    "watcherQuorum": s.decode_uint,
    "withdrawalExpiryTimeout": s.decode_uint,
    "depositsGloballyPaused": s.decode_bool,
    "withdrawalsGloballyPaused": s.decode_bool,
    "slippageToleranceBps": s.decode_uint,
    "maxOracleStaleTimeout": s.decode_uint,
    "getWithdrawalRequestCounter": s.decode_uint,
    "USDT": s.decode_address,
}
scalar_state: dict[str, object] = {}
for name, decoder in scalar_decoders.items():
    scalar_state[name] = decoder(s.call(s.PROXY, s.SELECTORS[name]))
state["deposit_state"] = scalar_state

roles: dict[str, object] = {}
for role_name in [
    "OWNER_ROLE",
    "MANAGER_ROLE",
    "RELAYER_ROLE",
    "WATCHER_ROLE",
    "TELLER_ROLE",
    "GUARDIAN_ROLE",
    "AUTHORIZED_TRADER_ROLE",
]:
    role = s.call(s.PROXY, s.SELECTORS[role_name])
    count = s.decode_uint(s.call(s.PROXY, s.GET_ROLE_MEMBER_COUNT + s.word(role)))
    members = [
        s.decode_address(s.call(s.PROXY, s.GET_ROLE_MEMBER + s.word(role) + s.word(i)))
        for i in range(count)
    ]
    roles[role_name] = {"role": role, "count": count, "members": members}
state["roles"] = roles

usdt = str(scalar_state["USDT"])
slp_vault = str(scalar_state["slpVault"])
state["usdt_balance"] = s.decode_uint(s.call(usdt, s.BALANCE_OF + s.word(s.PROXY)))
state["usdt_allowance_to_slp_vault_direct"] = s.decode_uint(
    s.call(usdt, s.ALLOWANCE + s.word(s.PROXY) + s.word(slp_vault))
)

(out / "state_snapshot.json").write_text(json.dumps(state, indent=2), encoding="utf-8")

fetch_targets = {
    "deposit_current_impl": s.CURRENT_IMPL,
    "deposit_previous_impl": s.PREVIOUS_IMPL,
    "lens_impl": implementations["lens_impl"],
    "permissions_registry_impl": implementations["permissions_registry_impl"],
    "slp_vault": slp_vault,
}
manifest: list[dict[str, object]] = []
for name, address_obj in fetch_targets.items():
    address = str(address_obj)
    if address.lower() == "0x" + "0" * 40:
        continue
    for kind, url, suffix in [
        ("sourcify_v2", f"https://sourcify.dev/server/v2/contract/1/{address}?fields=all", "json"),
        ("etherscan_html", f"https://etherscan.io/address/{address}#code", "html"),
    ]:
        path = out / f"{name}__{kind}.{suffix}"
        record: dict[str, object] = {"name": name, "address": address, "kind": kind}
        record.update(s.fetch_url(url, path))
        manifest.append(record)
        time.sleep(0.1)

(out / "manifest_quick.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
print(json.dumps({"state": state, "manifest": manifest}, indent=2))
