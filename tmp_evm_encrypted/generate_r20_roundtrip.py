#!/usr/bin/env python3
"""Generate one-chain fixed-block local-fork ERC-4626 round-trip tests.

The generated Foundry test mutates only local fork state through cheatcodes. It
never signs or broadcasts a transaction to a public network.
"""
from __future__ import annotations

import os
from pathlib import Path

import requests
from web3 import Web3

SCOPE_URL = (
    "https://raw.githubusercontent.com/zerodaybugs/test/"
    "agent/kiln-omnivault-r11-readonly/"
    "r13_persisted_results/31910466827/r13_generation/SCOPE.json"
)

CHAIN_ID = int(os.environ["R20_CHAIN_ID"])
CHAIN_NAME = os.environ["R20_CHAIN_NAME"]
OUT = Path("test/KilnR20RoundTrip.t.sol")

scope = requests.get(
    SCOPE_URL,
    headers={"User-Agent": "Kiln-R20-LocalFork/1.0"},
    timeout=45,
).json()
rows = [row for row in scope if int(row["chain_id"]) == CHAIN_ID]
if not rows:
    raise SystemExit(f"no vaults for {CHAIN_ID}")

pushes = "\n".join(
    f"        vaults.push({Web3.to_checksum_address(row['vault'])});"
    for row in rows
)

source = f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {{Test, console2}} from "forge-std/Test.sol";

interface IR20Vault {{
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function maxDeposit(address owner) external view returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function balanceOf(address owner) external view returns (uint256);
}}

interface IR20Token {{
    function balanceOf(address owner) external view returns (uint256);
    function decimals() external view returns (uint8);
    function approve(address spender, uint256 value) external returns (bool);
}}

contract KilnR20RoundTrip is Test {{
    address internal constant ATTACKER = address(0xA771);
    address[] internal vaults;

    struct Result {{
        bool depositOk;
        bool redeemOk;
        uint256 amount;
        uint256 mintedShares;
        uint256 remainingShares;
        uint256 beforeBalance;
        uint256 afterBalance;
        uint256 totalAssetsBefore;
        uint256 totalAssetsAfter;
        bytes4 depositError;
        bytes4 redeemError;
    }}

    function setUp() public {{
{pushes}
    }}

    function test_fixedBlockRoundTrip() external {{
        string memory rpc = vm.envString("R20_RPC_URL");
        vm.createSelectFork(rpc);
        uint256 fixedBlock = block.number;
        console2.log("R20_CHAIN_ID", uint256({CHAIN_ID}));
        console2.log("R20_CHAIN_NAME {CHAIN_NAME}");
        console2.log("R20_FIXED_BLOCK", fixedBlock);
        console2.log("R20_VAULT_COUNT", vaults.length);

        for (uint256 i; i < vaults.length; ++i) {{
            _scanVault(rpc, fixedBlock, vaults[i]);
        }}
    }}

    function _scanVault(string memory rpc, uint256 fixedBlock, address vaultAddr) internal {{
        vm.createSelectFork(rpc, fixedBlock);
        IR20Vault vault = IR20Vault(vaultAddr);

        address asset;
        uint256 totalAssetsBefore;
        uint256 totalSupplyBefore;
        uint256 maxDeposit;
        uint8 assetDecimals;

        try vault.asset() returns (address value) {{ asset = value; }}
        catch {{
            _logBindingFailure(vaultAddr, bytes4(keccak256("asset()")));
            return;
        }}
        try vault.totalAssets() returns (uint256 value) {{ totalAssetsBefore = value; }}
        catch {{
            _logBindingFailure(vaultAddr, bytes4(keccak256("totalAssets()")));
            return;
        }}
        try vault.totalSupply() returns (uint256 value) {{ totalSupplyBefore = value; }}
        catch {{
            _logBindingFailure(vaultAddr, bytes4(keccak256("totalSupply()")));
            return;
        }}
        try vault.maxDeposit(ATTACKER) returns (uint256 value) {{ maxDeposit = value; }}
        catch {{
            _logBindingFailure(vaultAddr, bytes4(keccak256("maxDeposit(address)")));
            return;
        }}
        try IR20Token(asset).decimals() returns (uint8 value) {{ assetDecimals = value; }}
        catch {{
            _logBindingFailure(vaultAddr, bytes4(keccak256("decimals()")));
            return;
        }}

        uint256 unit = 10 ** assetDecimals;
        uint256 small = unit;
        uint256 material;
        if (totalSupplyBefore == 0) {{
            material = _boundedMul(unit, 1_000);
        }} else {{
            uint256 proportional = totalAssetsBefore / 1_000;
            material = _max(unit, _min(proportional, _boundedMul(unit, 10_000)));
        }}

        small = _capToMax(small, maxDeposit);
        material = _capToMax(material, maxDeposit);

        if (small > 0) {{
            Result memory smallResult = _attempt(rpc, fixedBlock, vaultAddr, asset, small, totalAssetsBefore);
            _logResult(vaultAddr, 1, smallResult);
        }} else {{
            _logSkipped(vaultAddr, 1, maxDeposit);
        }}

        if (material > 0 && material != small) {{
            Result memory materialResult = _attempt(rpc, fixedBlock, vaultAddr, asset, material, totalAssetsBefore);
            _logResult(vaultAddr, 2, materialResult);
        }} else if (material == 0) {{
            _logSkipped(vaultAddr, 2, maxDeposit);
        }}
    }}

    function _attempt(
        string memory rpc,
        uint256 fixedBlock,
        address vaultAddr,
        address asset,
        uint256 amount,
        uint256 totalAssetsBefore
    ) internal returns (Result memory result) {{
        vm.createSelectFork(rpc, fixedBlock);
        IR20Vault vault = IR20Vault(vaultAddr);
        IR20Token token = IR20Token(asset);
        result.amount = amount;
        result.totalAssetsBefore = totalAssetsBefore;

        deal(asset, ATTACKER, amount, true);
        result.beforeBalance = token.balanceOf(ATTACKER);

        vm.startPrank(ATTACKER);
        (bool approved, bytes memory approvalData) =
            asset.call(abi.encodeWithSelector(IR20Token.approve.selector, vaultAddr, type(uint256).max));
        if (!approved || (approvalData.length != 0 && !abi.decode(approvalData, (bool)))) {{
            vm.stopPrank();
            result.depositError = bytes4(keccak256("APPROVE_FAILED"));
            return result;
        }}

        try vault.deposit(amount, ATTACKER) returns (uint256 shares) {{
            result.depositOk = true;
            result.mintedShares = shares;
        }} catch (bytes memory reason) {{
            result.depositError = _errorSelector(reason);
            vm.stopPrank();
            result.afterBalance = token.balanceOf(ATTACKER);
            return result;
        }}

        try vault.redeem(result.mintedShares, ATTACKER, ATTACKER) returns (uint256) {{
            result.redeemOk = true;
        }} catch (bytes memory reason) {{
            result.redeemError = _errorSelector(reason);
        }}
        vm.stopPrank();

        result.afterBalance = token.balanceOf(ATTACKER);
        result.remainingShares = vault.balanceOf(ATTACKER);
        try vault.totalAssets() returns (uint256 value) {{ result.totalAssetsAfter = value; }}
        catch {{ result.totalAssetsAfter = type(uint256).max; }}
    }}

    function _logResult(address vaultAddr, uint256 arm, Result memory r) internal view {{
        console2.log("R20_CASE_BEGIN");
        console2.log("R20_VAULT", vaultAddr);
        console2.log("R20_ARM", arm);
        console2.log("R20_AMOUNT", r.amount);
        console2.log("R20_DEPOSIT_OK", r.depositOk);
        console2.log("R20_REDEEM_OK", r.redeemOk);
        console2.log("R20_MINTED_SHARES", r.mintedShares);
        console2.log("R20_REMAINING_SHARES", r.remainingShares);
        console2.log("R20_BEFORE_BALANCE", r.beforeBalance);
        console2.log("R20_AFTER_BALANCE", r.afterBalance);
        console2.log("R20_PROFIT_SIGNED");
        console2.logInt(int256(r.afterBalance) - int256(r.beforeBalance));
        console2.log("R20_TOTAL_ASSETS_BEFORE", r.totalAssetsBefore);
        console2.log("R20_TOTAL_ASSETS_AFTER", r.totalAssetsAfter);
        console2.logBytes4(r.depositError);
        console2.logBytes4(r.redeemError);
        console2.log("R20_CASE_END");
    }}

    function _logBindingFailure(address vaultAddr, bytes4 selector_) internal pure {{
        console2.log("R20_BINDING_FAILURE", vaultAddr);
        console2.logBytes4(selector_);
    }}

    function _logSkipped(address vaultAddr, uint256 arm, uint256 maxDeposit) internal pure {{
        console2.log("R20_SKIPPED", vaultAddr);
        console2.log("R20_ARM", arm);
        console2.log("R20_MAX_DEPOSIT", maxDeposit);
    }}

    function _errorSelector(bytes memory reason) internal pure returns (bytes4 out) {{
        if (reason.length >= 4) {{
            assembly {{ out := mload(add(reason, 32)) }}
        }}
    }}

    function _capToMax(uint256 value, uint256 maximum) internal pure returns (uint256) {{
        if (maximum == type(uint256).max) return value;
        return _min(value, maximum);
    }}

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {{ return a < b ? a : b; }}
    function _max(uint256 a, uint256 b) internal pure returns (uint256) {{ return a > b ? a : b; }}
    function _boundedMul(uint256 a, uint256 b) internal pure returns (uint256) {{
        return a > type(uint256).max / b ? type(uint256).max : a * b;
    }}
}}
'''

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(source)
print(f"generated {OUT} for {CHAIN_NAME} with {len(rows)} vaults")
