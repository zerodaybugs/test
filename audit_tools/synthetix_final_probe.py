#!/usr/bin/env python3
"""Focused read-only state probe for the in-scope Synthetix contracts."""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import synthetix_state_read as s  # noqa: E402

OUT = pathlib.Path("out")
OUT.mkdir(parents=True, exist_ok=True)

WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
USDT = s.SELECTORS["USDT"]  # selector only; actual address is queried below
COW_VAULT_RELAYER = "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110"
ROLE_ACCOUNTS = {
    "owner_manager": "0xeb3107117fead7de89cd14d463d340a2e6917769",
    "relayer_watcher_teller": "0xe6ac604d479450a501c9162ff5a87026d097232b",
    "watcher": "0x41b8737908061237bfc648515a0c87390d9af10e",
    "teller": "0xecf6ef0aaac4b4fd01f557e96855183465c22ceb",
    "guardian_snax": "0x1c8236b406911a376369e33d39189f1b4b39f27d",
    "guardian_2": "0x46f5aee4af7c36d7ff7215bf3e8a74f1a00a5ff9",
}

SELECTORS = {
    "getCollateralConfig": "0xf6a44b38",
    "getCowAllowance": "0x515871c3",
    "getTotalDeposited": "0x0c9c31bd",
    "priceFeedsUSD": "0xad4e2690",
    "isCollateralSupported": "0xfa6bd2ee",
    "permissionsOwner": "0x8da5cb5b",
    "permissionsPaused": "0x5c975abb",
}


def split_words(raw: str) -> list[int]:
    body = raw[2:] if raw.startswith("0x") else raw
    if len(body) % 64 != 0:
        raise ValueError(f"unexpected ABI word length: {len(body)}")
    return [int(body[i : i + 64], 16) for i in range(0, len(body), 64)]


def code_info(address: str) -> dict[str, object]:
    code = s.rpc("eth_getCode", [address, "latest"])
    body = code[2:] if code.startswith("0x") else code
    return {"address": address, "code_bytes": len(body) // 2, "is_contract": len(body) > 0}


def token_state(token: str) -> dict[str, object]:
    cfg = split_words(s.call(s.PROXY, SELECTORS["getCollateralConfig"] + s.word(token)))
    if len(cfg) != 5:
        raise ValueError(f"unexpected collateral tuple for {token}: {cfg}")
    return {
        "token": token,
        "supported": s.decode_bool(s.call(s.PROXY, SELECTORS["isCollateralSupported"] + s.word(token))),
        "config": {
            "enabled": bool(cfg[0]),
            "globalMaximum": cfg[1],
            "userMinimum": cfg[2],
            "userMaximum": cfg[3],
            "withdrawalMinimum": cfg[4],
        },
        "contract_balance": s.decode_uint(s.call(token, s.BALANCE_OF + s.word(s.PROXY))),
        "tracked_total_deposited": s.decode_uint(s.call(s.PROXY, SELECTORS["getTotalDeposited"] + s.word(token))),
        "cow_allowance_via_contract": s.decode_uint(s.call(s.PROXY, SELECTORS["getCowAllowance"] + s.word(token))),
        "cow_allowance_direct": s.decode_uint(
            s.call(token, s.ALLOWANCE + s.word(s.PROXY) + s.word(COW_VAULT_RELAYER))
        ),
        "price_feed": s.decode_address(s.call(s.PROXY, SELECTORS["priceFeedsUSD"] + s.word(token))),
    }


def main() -> None:
    usdt = s.decode_address(s.call(s.PROXY, s.SELECTORS["USDT"]))
    registry_owner = s.decode_address(s.call(s.REGISTRY_PROXY, SELECTORS["permissionsOwner"]))
    result = {
        "latest_block": int(s.rpc("eth_blockNumber", []), 16),
        "code": {
            name: code_info(address)
            for name, address in {
                **ROLE_ACCOUNTS,
                "deposit_proxy": s.PROXY,
                "deposit_impl": s.CURRENT_IMPL,
                "lens": s.LENS,
                "permissions_registry_proxy": s.REGISTRY_PROXY,
                "permissions_registry_impl": s.implementation_of(s.REGISTRY_PROXY),
                "permissions_registry_owner": registry_owner,
                "cow_vault_relayer": COW_VAULT_RELAYER,
            }.items()
        },
        "permissions_registry": {
            "implementation": s.implementation_of(s.REGISTRY_PROXY),
            "owner": registry_owner,
            "paused": s.decode_bool(s.call(s.REGISTRY_PROXY, SELECTORS["permissionsPaused"])),
        },
        "tokens": {
            "USDT": token_state(usdt),
            "WETH": token_state(WETH),
        },
    }
    (OUT / "focused_probe.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
