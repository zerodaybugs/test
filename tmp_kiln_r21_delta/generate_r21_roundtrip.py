#!/usr/bin/env python3
"""Generate a fixed-block local-fork round-trip test for one chain.

All state changes happen only inside Foundry's ephemeral fork. No transaction is
signed or broadcast to a public network.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from web3 import Web3

chain = int(os.environ["R21_CHAIN_ID"])
rows = json.loads(Path("r21_delta_results/SCOPE_RESOLVED.json").read_text())
vaults = []
seen = set()
for row in rows:
    if int(row.get("chain_id", -1)) != chain:
        continue
    try:
        addr = Web3.to_checksum_address(row["vault"])
    except Exception:
        continue
    if addr.lower() in seen:
        continue
    seen.add(addr.lower())
    vaults.append(addr)

pushes = "\n".join(f"        vaults.push({a});" for a in vaults)

source = f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {{Test, console2}} from "forge-std/Test.sol";

interface IR21Vault {{
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function maxDeposit(address) external view returns (uint256);
    function deposit(uint256,address) external returns (uint256);
    function redeem(uint256,address,address) external returns (uint256);
    function balanceOf(address) external view returns (uint256);
}}

contract KilnR21CurrentScopeRoundTrip is Test {{
    address constant ATTACKER = address(0xA77121);
    address[] vaults;

    function setUp() public {{
{pushes}
    }}

    function test_current_scope_roundtrips() external {{
        console2.log("R21_CHAIN_ID", block.chainid);
        console2.log("R21_FIXED_BLOCK", block.number);
        console2.log("R21_VAULT_COUNT", vaults.length);
        uint256 candidates;
        for (uint256 i; i < vaults.length; ++i) {{
            candidates += _scan(vaults[i]);
        }}
        console2.log("R21_ROUNDTRIP_CANDIDATE_COUNT", candidates);
    }}

    function _scan(address vaultAddr) internal returns (uint256 candidates) {{
        if (vaultAddr.code.length == 0) return 0;
        IR21Vault vault = IR21Vault(vaultAddr);
        address asset;
        uint256 total;
        uint256 maxDep;
        try vault.asset() returns (address a) {{ asset = a; }} catch {{ return 0; }}
        if (asset == address(0) || asset.code.length == 0) return 0;
        try vault.totalAssets() returns (uint256 x) {{ total = x; }} catch {{ return 0; }}
        try vault.maxDeposit(ATTACKER) returns (uint256 x) {{ maxDep = x; }} catch {{ return 0; }}
        if (maxDep == 0) return 0;
        uint8 dec = _decimals(asset);
        if (dec > 30) return 0;
        uint256 unit = 10 ** dec;
        uint256[4] memory amounts;
        amounts[0] = unit;
        amounts[1] = _max(unit, total / 10_000);
        amounts[2] = _max(unit, total / 1_000);
        amounts[3] = _max(unit, total / 100);
        for (uint256 j; j < amounts.length; ++j) {{
            uint256 amount = amounts[j];
            if (maxDep != type(uint256).max && amount > maxDep) amount = maxDep;
            if (amount == 0) continue;
            uint256 snap = vm.snapshotState();
            bool candidate = _roundTrip(vaultAddr, asset, amount, unit);
            if (candidate) ++candidates;
            require(vm.revertToState(snap), "snapshot restore failed");
        }}
    }}

    function _roundTrip(address vaultAddr, address asset, uint256 amount, uint256 unit)
        internal returns (bool candidate)
    {{
        deal(asset, ATTACKER, amount, true);
        uint256 beforeAsset = _balance(asset, ATTACKER);
        vm.startPrank(ATTACKER);
        if (!_approve(asset, vaultAddr, type(uint256).max)) {{ vm.stopPrank(); return false; }}
        (bool okDep, bytes memory depRet) = vaultAddr.call(
            abi.encodeWithSignature("deposit(uint256,address)", amount, ATTACKER)
        );
        if (!okDep || depRet.length < 32) {{ vm.stopPrank(); return false; }}
        uint256 shares = abi.decode(depRet, (uint256));
        if (shares == 0) {{ vm.stopPrank(); return false; }}
        (bool okRed,) = vaultAddr.call(
            abi.encodeWithSignature("redeem(uint256,address,address)", shares, ATTACKER, ATTACKER)
        );
        vm.stopPrank();
        if (!okRed) return false;
        uint256 remaining = _balance(vaultAddr, ATTACKER);
        uint256 afterAsset = _balance(asset, ATTACKER);
        if (remaining != 0 || afterAsset <= beforeAsset) return false;
        uint256 profit = afterAsset - beforeAsset;
        uint256 threshold = _max(1, unit / 1_000);
        if (profit > threshold) {{
            console2.log("R21_PROFIT_CANDIDATE_VAULT", vaultAddr);
            console2.log("R21_PROFIT_CANDIDATE_AMOUNT", amount);
            console2.log("R21_PROFIT_CANDIDATE_PROFIT", profit);
            return true;
        }}
        return false;
    }}

    function _approve(address token, address spender, uint256 value) internal returns (bool) {{
        (bool ok, bytes memory ret) = token.call(
            abi.encodeWithSelector(bytes4(0x095ea7b3), spender, value)
        );
        return ok && (ret.length == 0 || (ret.length >= 32 && abi.decode(ret, (bool))));
    }}

    function _balance(address token, address who) internal view returns (uint256 value) {{
        (bool ok, bytes memory ret) = token.staticcall(
            abi.encodeWithSelector(bytes4(0x70a08231), who)
        );
        if (!ok || ret.length < 32) return 0;
        value = abi.decode(ret, (uint256));
    }}

    function _decimals(address token) internal view returns (uint8 value) {{
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(bytes4(0x313ce567)));
        if (!ok || ret.length < 32) return 18;
        value = abi.decode(ret, (uint8));
    }}

    function _max(uint256 a, uint256 b) internal pure returns (uint256) {{ return a > b ? a : b; }}
}}
'''

out = Path("test/KilnR21CurrentScopeRoundTrip.t.sol")
out.parent.mkdir(exist_ok=True)
out.write_text(source)
Path("r21_delta_results/R21_ROUNDTRIP_INPUT.json").write_text(json.dumps({
    "chain_id": chain,
    "vault_count": len(vaults),
    "vaults": vaults,
}, indent=2, sort_keys=True))
print(json.dumps({"chain_id": chain, "vault_count": len(vaults)}))
