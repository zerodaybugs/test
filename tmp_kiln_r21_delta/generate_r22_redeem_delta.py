#!/usr/bin/env python3
"""Generate a fixed-block local-fork ERC-4626 redeem-delta invariant test.

The test checks whether Kiln reports/previews more underlying than the receiver
actually obtains, whether a full redeem leaves residual shares, and whether a
redeem reverts despite maxRedeem/maxWithdraw advertising full liquidity.
All mutations are confined to the ephemeral local fork.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from web3 import Web3

chain = int(os.environ["R22_CHAIN_ID"])
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

interface IR22Vault {{
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function maxDeposit(address) external view returns (uint256);
    function maxRedeem(address) external view returns (uint256);
    function maxWithdraw(address) external view returns (uint256);
    function previewRedeem(uint256) external view returns (uint256);
    function deposit(uint256,address) external returns (uint256);
    function redeem(uint256,address,address) external returns (uint256);
    function balanceOf(address) external view returns (uint256);
}}

contract KilnR22RedeemDeltaInvariant is Test {{
    address constant USER = address(0xA77222);
    address[] vaults;

    function setUp() public {{
{pushes}
    }}

    function test_redeem_delta_invariant() external {{
        console2.log("R22_CHAIN_ID", block.chainid);
        console2.log("R22_FIXED_BLOCK", block.number);
        console2.log("R22_VAULT_COUNT", vaults.length);
        uint256 candidates;
        for (uint256 i; i < vaults.length; ++i) {{
            candidates += _scan(vaults[i]);
        }}
        console2.log("R22_CANDIDATE_COUNT", candidates);
    }}

    function _scan(address vaultAddr) internal returns (uint256 candidates) {{
        if (vaultAddr.code.length == 0) return 0;
        IR22Vault vault = IR22Vault(vaultAddr);
        address asset;
        uint256 total;
        uint256 maxDep;
        try vault.asset() returns (address a) {{ asset = a; }} catch {{ return 0; }}
        if (asset == address(0) || asset.code.length == 0) return 0;
        try vault.totalAssets() returns (uint256 x) {{ total = x; }} catch {{ return 0; }}
        try vault.maxDeposit(USER) returns (uint256 x) {{ maxDep = x; }} catch {{ return 0; }}
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
            candidates += _roundTrip(vaultAddr, asset, amount, unit);
            require(vm.revertToState(snap), "snapshot restore failed");
        }}
    }}

    function _roundTrip(address vaultAddr, address asset, uint256 amount, uint256 unit)
        internal returns (uint256 candidates)
    {{
        IR22Vault vault = IR22Vault(vaultAddr);
        deal(asset, USER, amount, true);
        vm.startPrank(USER);
        if (!_approve(asset, vaultAddr, type(uint256).max)) {{ vm.stopPrank(); return 0; }}
        (bool okDep, bytes memory depRet) = vaultAddr.call(
            abi.encodeWithSignature("deposit(uint256,address)", amount, USER)
        );
        if (!okDep || depRet.length < 32) {{ vm.stopPrank(); return 0; }}
        uint256 shares = abi.decode(depRet, (uint256));
        if (shares == 0) {{ vm.stopPrank(); return 0; }}

        uint256 preview;
        uint256 maxRedeemable;
        uint256 maxWithdrawable;
        try vault.previewRedeem(shares) returns (uint256 x) {{ preview = x; }} catch {{ vm.stopPrank(); return 0; }}
        try vault.maxRedeem(USER) returns (uint256 x) {{ maxRedeemable = x; }} catch {{}}
        try vault.maxWithdraw(USER) returns (uint256 x) {{ maxWithdrawable = x; }} catch {{}}
        uint256 beforeAsset = _balance(asset, USER);
        (bool okRed, bytes memory redRet) = vaultAddr.call(
            abi.encodeWithSignature("redeem(uint256,address,address)", shares, USER, USER)
        );
        uint256 afterAsset = _balance(asset, USER);
        uint256 residual = _balance(vaultAddr, USER);
        vm.stopPrank();

        uint256 tolerance = _max(1, unit / 1_000_000);
        if (!okRed) {{
            if (maxRedeemable >= shares && maxWithdrawable + tolerance >= preview && preview >= unit) {{
                console2.log("R22_REDEEM_REVERT_WITH_ADVERTISED_LIQUIDITY", vaultAddr);
                console2.log("R22_AMOUNT", amount);
                console2.log("R22_PREVIEW", preview);
                console2.log("R22_MAX_REDEEM", maxRedeemable);
                console2.log("R22_MAX_WITHDRAW", maxWithdrawable);
                return 1;
            }}
            return 0;
        }}

        uint256 reported = redRet.length >= 32 ? abi.decode(redRet, (uint256)) : 0;
        uint256 received = afterAsset >= beforeAsset ? afterAsset - beforeAsset : 0;
        if (reported > received + tolerance && reported >= unit) {{
            console2.log("R22_REPORTED_RECEIVED_MISMATCH", vaultAddr);
            console2.log("R22_AMOUNT", amount);
            console2.log("R22_REPORTED", reported);
            console2.log("R22_RECEIVED", received);
            ++candidates;
        }}
        if (preview > received + tolerance && preview >= unit) {{
            console2.log("R22_PREVIEW_RECEIVED_MISMATCH", vaultAddr);
            console2.log("R22_AMOUNT", amount);
            console2.log("R22_PREVIEW", preview);
            console2.log("R22_RECEIVED", received);
            ++candidates;
        }}
        if (residual != 0) {{
            console2.log("R22_RESIDUAL_SHARES_AFTER_FULL_REDEEM", vaultAddr);
            console2.log("R22_RESIDUAL", residual);
            ++candidates;
        }}
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

out = Path("test/KilnR22RedeemDeltaInvariant.t.sol")
out.parent.mkdir(exist_ok=True)
out.write_text(source)
Path("r21_delta_results/R22_INPUT.json").write_text(json.dumps({
    "chain_id": chain,
    "vault_count": len(vaults),
    "vaults": vaults,
}, indent=2, sort_keys=True))
print(json.dumps({"chain_id": chain, "vault_count": len(vaults)}))
