#!/usr/bin/env python3
"""Read-only Synthetix scope snapshot and verified-source fetcher.

This script performs only public JSON-RPC reads and public source downloads.
It does not submit transactions or mutate target state.
"""

from __future__ import annotations

import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

OUT = pathlib.Path("out")
OUT.mkdir(parents=True, exist_ok=True)

RPC_URLS = [
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
]

PROXY = "0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B"
LENS = "0x99E61877aF9Bc6805BCc3813F655D94Ed5f3782A"
REGISTRY_PROXY = "0x45F91031b33Da2585932c8f1cdFF0faa6cD329ae"
CURRENT_IMPL = "0xff6611190b48Cc920EF3c5DCbD356bF2C20D731F"
PREVIOUS_IMPL = "0x985814a3057Cc631e145199db599ADde77A7cA4B"
PROXY_CREATION_TX = "0xbdccb92258f17e478722a0d37cccc059cb6e2c67be7e80396d87c5a099cbd74a"
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

SELECTORS = {
    "slpVault": "0x7aa4f99d",
    "getSLPVaultAllowance": "0x68d9416f",
    "watcherQuorum": "0x552ab542",
    "withdrawalExpiryTimeout": "0x5d2ed68b",
    "depositsGloballyPaused": "0x82ad920c",
    "withdrawalsGloballyPaused": "0x163f5bdf",
    "slippageToleranceBps": "0x070cc3f0",
    "maxOracleStaleTimeout": "0x90769891",
    "getWithdrawalRequestCounter": "0x482d2bc5",
    "OWNER_ROLE": "0xe58378bb",
    "MANAGER_ROLE": "0xec87621c",
    "RELAYER_ROLE": "0x926d7d7f",
    "WATCHER_ROLE": "0xf1ba83a1",
    "TELLER_ROLE": "0x268a24dc",
    "GUARDIAN_ROLE": "0x24ea54f4",
    "AUTHORIZED_TRADER_ROLE": "0x1c019657",
    "USDT": "0xc54e44eb",
}

GET_ROLE_MEMBER_COUNT = "0xca15c873"
GET_ROLE_MEMBER = "0x9010d07c"
BALANCE_OF = "0x70a08231"
ALLOWANCE = "0xdd62ed3e"

EVENT_TOPICS = [
    "0x7db05e63d635a68c62fd7fd8f3107ae8ab584a383e102d1bd8a40f4c977e465f",  # CollateralAdded
    "0x44a6d536bc4529db8fc60021a86c8798e6021db2809290a01da3a18661f61142",  # CollateralConfigUpdated
    "0xd89d2ee68ab04dca0193f48a4aff55e20fa5ec0429a8a8c1c51b8dad6178a593",  # CollateralRemoved
    "0xa647f206c32bd71818165f5af85332f8fd468913d5d05a2ed8a62798b3344ff4",  # SLPVaultSet
    "0x1c9623c8f330b351eec87393dbdba4ee26bcf2da85a96ad62d8aba9f5c84a18c",  # SLPVaultApproved
    "0x411a0ea7df204b05858fde699d8392524be79c2c6ab5db2a8aa6e51012b397fc",  # CowVaultRelayerApproved
    "0x39a36a524c2beffaa94a07e00bc40880be8ecc6a1f1cce2c0953e222c79f784e",  # CowApprovalRevoked
    "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d",  # RoleGranted
    "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b",  # RoleRevoked
    "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",  # Upgraded
    "0xd2d8394cf7549a5ddbc2ba3dd7b2de8d53c891472d1f2907008ed6a10045fdae",  # PriceFeedSet
    "0x064474326de671030c7e3ae6568f3c68138b1e5d3de0590b0b7188eb2dd9febd",  # WatcherQuorumSet
    "0x5977f897a5332cc3a8a05df19fefa3ccac8541f93e752cd3488a84e160066032",  # WithdrawalExpiryTimeoutSet
]


def request_json(url: str, payload: dict[str, Any] | None = None, timeout: int = 45) -> Any:
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"User-Agent": "Mozilla/5.0 source-audit/1.0", "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read())


def rpc(method: str, params: list[Any]) -> Any:
    errors: list[str] = []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    for url in RPC_URLS:
        try:
            response = request_json(url, payload)
            if "error" in response:
                errors.append(f"{url}: {response['error']}")
                continue
            return response["result"]
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {exc!r}")
    raise RuntimeError(f"RPC {method} failed: {' | '.join(errors)}")


def call(to: str, data: str) -> str:
    return rpc("eth_call", [{"to": to, "data": data}, "latest"])


def word(value: int | str) -> str:
    if isinstance(value, str):
        raw = value[2:] if value.startswith("0x") else value
        return raw.rjust(64, "0")
    return hex(value)[2:].rjust(64, "0")


def decode_uint(raw: str) -> int:
    return int(raw, 16)


def decode_bool(raw: str) -> bool:
    return bool(int(raw, 16))


def decode_address(raw: str) -> str:
    return "0x" + raw[-40:]


def implementation_of(address: str) -> str:
    return decode_address(rpc("eth_getStorageAt", [address, EIP1967_IMPL_SLOT, "latest"]))


def fetch_logs_split(address: str, start: int, end: int) -> list[dict[str, Any]]:
    params = [{"address": address, "fromBlock": hex(start), "toBlock": hex(end), "topics": [EVENT_TOPICS]}]
    try:
        return rpc("eth_getLogs", params)
    except Exception:
        if start >= end:
            raise
        middle = (start + end) // 2
        return fetch_logs_split(address, start, middle) + fetch_logs_split(address, middle + 1, end)


def fetch_url(url: str, path: pathlib.Path) -> dict[str, Any]:
    record: dict[str, Any] = {"url": url, "path": str(path)}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 source-audit/1.0"})
        with urllib.request.urlopen(req, timeout=45) as response:
            body = response.read()
            path.write_bytes(body)
            record.update(status=response.status, bytes=len(body), content_type=response.headers.get("content-type"))
    except urllib.error.HTTPError as exc:
        body = exc.read()
        path.write_bytes(body)
        record.update(status=exc.code, bytes=len(body), error=str(exc))
    except Exception as exc:  # noqa: BLE001
        path.write_text(repr(exc), encoding="utf-8")
        record.update(status=None, bytes=path.stat().st_size, error=repr(exc))
    return record


def main() -> None:
    state: dict[str, Any] = {"proxy": PROXY, "rpc_endpoints": RPC_URLS}
    latest = int(rpc("eth_blockNumber", []), 16)
    receipt = rpc("eth_getTransactionReceipt", [PROXY_CREATION_TX])
    creation_block = int(receipt["blockNumber"], 16)
    state.update(latest_block=latest, proxy_creation_block=creation_block, proxy_creation_receipt=receipt)

    implementations = {
        "deposit_proxy_impl": implementation_of(PROXY),
        "lens_impl": implementation_of(LENS),
        "permissions_registry_impl": implementation_of(REGISTRY_PROXY),
    }
    state["implementations"] = implementations

    scalar_decoders = {
        "slpVault": decode_address,
        "getSLPVaultAllowance": decode_uint,
        "watcherQuorum": decode_uint,
        "withdrawalExpiryTimeout": decode_uint,
        "depositsGloballyPaused": decode_bool,
        "withdrawalsGloballyPaused": decode_bool,
        "slippageToleranceBps": decode_uint,
        "maxOracleStaleTimeout": decode_uint,
        "getWithdrawalRequestCounter": decode_uint,
        "USDT": decode_address,
    }
    scalar_state: dict[str, Any] = {}
    for name, decoder in scalar_decoders.items():
        scalar_state[name] = decoder(call(PROXY, SELECTORS[name]))
    state["deposit_state"] = scalar_state

    roles: dict[str, Any] = {}
    for role_name in [
        "OWNER_ROLE",
        "MANAGER_ROLE",
        "RELAYER_ROLE",
        "WATCHER_ROLE",
        "TELLER_ROLE",
        "GUARDIAN_ROLE",
        "AUTHORIZED_TRADER_ROLE",
    ]:
        role = call(PROXY, SELECTORS[role_name])
        count = decode_uint(call(PROXY, GET_ROLE_MEMBER_COUNT + word(role)))
        members = [decode_address(call(PROXY, GET_ROLE_MEMBER + word(role) + word(i))) for i in range(count)]
        roles[role_name] = {"role": role, "count": count, "members": members}
    state["roles"] = roles

    usdt = scalar_state["USDT"]
    slp_vault = scalar_state["slpVault"]
    state["usdt_balance"] = decode_uint(call(usdt, BALANCE_OF + word(PROXY)))
    state["usdt_allowance_to_slp_vault_direct"] = decode_uint(call(usdt, ALLOWANCE + word(PROXY) + word(slp_vault)))

    logs: list[dict[str, Any]] = []
    chunk = 100_000
    for start in range(creation_block, latest + 1, chunk):
        end = min(start + chunk - 1, latest)
        logs.extend(fetch_logs_split(PROXY, start, end))
    logs.sort(key=lambda x: (int(x["blockNumber"], 16), int(x["logIndex"], 16)))

    (OUT / "state_snapshot.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    (OUT / "governance_events.json").write_text(json.dumps(logs, indent=2), encoding="utf-8")

    targets = {
        "deposit_proxy": PROXY,
        "deposit_current_impl": CURRENT_IMPL,
        "deposit_previous_impl": PREVIOUS_IMPL,
        "lens": LENS,
        "lens_impl": implementations["lens_impl"],
        "permissions_registry_proxy": REGISTRY_PROXY,
        "permissions_registry_impl": implementations["permissions_registry_impl"],
        "slp_vault": slp_vault,
    }
    manifest: list[dict[str, Any]] = []
    for name, address in targets.items():
        if address.lower() == "0x" + "0" * 40:
            continue
        endpoints = {
            "sourcify_v2": f"https://sourcify.dev/server/v2/contract/1/{address}?fields=all",
            "etherscan_html": f"https://etherscan.io/address/{address}#code",
        }
        for kind, url in endpoints.items():
            suffix = "json" if kind == "sourcify_v2" else "html"
            path = OUT / f"{name}__{kind}.{suffix}"
            record = {"name": name, "address": address, "kind": kind}
            record.update(fetch_url(url, path))
            manifest.append(record)
            time.sleep(0.1)

    (OUT / "manifest_v2.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"state": state, "events": len(logs), "manifest": manifest}, indent=2))


if __name__ == "__main__":
    main()
