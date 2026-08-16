#!/usr/bin/env python3
"""Generate an isolated local-fork control for zero-supply Fluid vaults.

The test is selected from the public scope by connector family and chain. No
public transaction is signed or broadcast.
"""
from pathlib import Path
import requests
from web3 import Web3

SCOPE_URL=(
 "https://raw.githubusercontent.com/zerodaybugs/test/"
 "agent/kiln-omnivault-r11-readonly/"
 "r13_persisted_results/31910466827/r13_generation/SCOPE.json"
)
scope=requests.get(SCOPE_URL,headers={'User-Agent':'Kiln-R21-LocalFork/1.0'},timeout=45).json()
rows=[r for r in scope if int(r['chain_id'])==1 and r.get('connector')=='FLUID']
if not rows: raise SystemExit('no Ethereum FLUID vaults')
pushes='\n'.join(f"        vaults.push({Web3.to_checksum_address(r['vault'])});" for r in rows)

source=f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {{Test, console2}} from "forge-std/Test.sol";

interface IR21Vault {{
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function maxRedeem(address owner) external view returns (uint256);
    function previewRedeem(uint256 shares) external view returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function balanceOf(address owner) external view returns (uint256);
}}
interface IR21Token {{
    function balanceOf(address owner) external view returns (uint256);
    function decimals() external view returns (uint8);
    function approve(address spender,uint256 value) external returns (bool);
}}

contract KilnR21FluidDust is Test {{
    address constant ATTACKER=address(0xA771);
    address[] vaults;

    struct Arm {{
        uint256 amount;
        uint256 minted;
        uint256 totalAssetsAfterDeposit;
        uint256 totalSupplyAfterDeposit;
        uint256 maxRedeemAfterDeposit;
        uint256 previewFull;
        uint256 previewMax;
        bool fullRedeemOk;
        bytes4 fullRedeemError;
        bool maxRedeemOk;
        bytes4 maxRedeemError;
        uint256 maxRedeemReceived;
        uint256 attackerAssetAfterMax;
        uint256 remainingShares;
        uint256 remainingMaxRedeem;
        uint256 remainingPreviewRedeem;
        uint256 totalAssetsAfterMax;
        uint256 totalSupplyAfterMax;
        bool secondRedeemOk;
        bytes4 secondRedeemError;
    }}

    function setUp() public {{
{pushes}
    }}

    function test_zeroSupplyFluidFullVsMaxRedeem() external {{
        vm.createSelectFork(vm.envString("R21_RPC_URL"));
        console2.log("R21_FIXED_BLOCK",block.number);
        console2.log("R21_VAULT_COUNT",vaults.length);
        for(uint256 i;i<vaults.length;++i) _scan(vaults[i]);
    }}

    function _scan(address vaultAddr) internal {{
        IR21Vault v=IR21Vault(vaultAddr);
        address asset=v.asset();
        uint8 decimals=IR21Token(asset).decimals();
        uint256 supply=v.totalSupply();
        uint256 assets=v.totalAssets();
        console2.log("R21_VAULT_BEGIN");
        console2.log("R21_VAULT",vaultAddr);
        console2.log("R21_ASSET",asset);
        console2.log("R21_INITIAL_SUPPLY",supply);
        console2.log("R21_INITIAL_ASSETS",assets);
        if(supply!=0 || assets!=0) {{
            console2.log("R21_SKIP_NONEMPTY",true);
            console2.log("R21_VAULT_END");
            return;
        }}
        uint256 unit=10**decimals;
        _run(vaultAddr,asset,unit,1);
        _run(vaultAddr,asset,unit*1000,2);
        console2.log("R21_VAULT_END");
    }}

    function _run(address vaultAddr,address asset,uint256 amount,uint256 armId) internal {{
        Arm memory a;
        a.amount=amount;
        uint256 snapshot=vm.snapshotState();
        _fundApprove(asset,vaultAddr,amount);
        IR21Vault v=IR21Vault(vaultAddr);
        vm.prank(ATTACKER);
        a.minted=v.deposit(amount,ATTACKER);
        a.totalAssetsAfterDeposit=v.totalAssets();
        a.totalSupplyAfterDeposit=v.totalSupply();
        a.maxRedeemAfterDeposit=v.maxRedeem(ATTACKER);
        a.previewFull=v.previewRedeem(a.minted);
        a.previewMax=v.previewRedeem(a.maxRedeemAfterDeposit);
        vm.prank(ATTACKER);
        try v.redeem(a.minted,ATTACKER,ATTACKER) returns(uint256) {{ a.fullRedeemOk=true; }}
        catch(bytes memory reason) {{ a.fullRedeemError=_sel(reason); }}
        require(vm.revertToState(snapshot),"restore full arm");

        snapshot=vm.snapshotState();
        _fundApprove(asset,vaultAddr,amount);
        vm.prank(ATTACKER);
        a.minted=v.deposit(amount,ATTACKER);
        a.maxRedeemAfterDeposit=v.maxRedeem(ATTACKER);
        vm.prank(ATTACKER);
        try v.redeem(a.maxRedeemAfterDeposit,ATTACKER,ATTACKER) returns(uint256 received) {{
            a.maxRedeemOk=true;
            a.maxRedeemReceived=received;
        }} catch(bytes memory reason) {{ a.maxRedeemError=_sel(reason); }}
        a.attackerAssetAfterMax=IR21Token(asset).balanceOf(ATTACKER);
        a.remainingShares=v.balanceOf(ATTACKER);
        a.remainingMaxRedeem=v.maxRedeem(ATTACKER);
        a.remainingPreviewRedeem=v.previewRedeem(a.remainingShares);
        a.totalAssetsAfterMax=v.totalAssets();
        a.totalSupplyAfterMax=v.totalSupply();
        if(a.remainingShares>0) {{
            vm.prank(ATTACKER);
            try v.redeem(a.remainingShares,ATTACKER,ATTACKER) returns(uint256) {{ a.secondRedeemOk=true; }}
            catch(bytes memory reason) {{ a.secondRedeemError=_sel(reason); }}
        }}
        _log(vaultAddr,armId,a);
        require(vm.revertToState(snapshot),"restore max arm");
    }}

    function _fundApprove(address asset,address vaultAddr,uint256 amount) internal {{
        deal(asset,ATTACKER,amount,false);
        vm.prank(ATTACKER);
        bool ok=IR21Token(asset).approve(vaultAddr,type(uint256).max);
        require(ok,"approve");
    }}

    function _log(address vaultAddr,uint256 armId,Arm memory a) internal view {{
        console2.log("R21_ARM_BEGIN");
        console2.log("R21_VAULT",vaultAddr);
        console2.log("R21_ARM",armId);
        console2.log("R21_AMOUNT",a.amount);
        console2.log("R21_MINTED",a.minted);
        console2.log("R21_TOTAL_ASSETS_AFTER_DEPOSIT",a.totalAssetsAfterDeposit);
        console2.log("R21_TOTAL_SUPPLY_AFTER_DEPOSIT",a.totalSupplyAfterDeposit);
        console2.log("R21_MAX_REDEEM_AFTER_DEPOSIT",a.maxRedeemAfterDeposit);
        console2.log("R21_PREVIEW_FULL",a.previewFull);
        console2.log("R21_PREVIEW_MAX",a.previewMax);
        console2.log("R21_FULL_REDEEM_OK",a.fullRedeemOk);
        console2.logBytes4(a.fullRedeemError);
        console2.log("R21_MAX_REDEEM_OK",a.maxRedeemOk);
        console2.logBytes4(a.maxRedeemError);
        console2.log("R21_MAX_REDEEM_RECEIVED",a.maxRedeemReceived);
        console2.log("R21_ATTACKER_ASSET_AFTER_MAX",a.attackerAssetAfterMax);
        console2.log("R21_ASSET_LOSS_RAW",a.amount-a.attackerAssetAfterMax);
        console2.log("R21_REMAINING_SHARES",a.remainingShares);
        console2.log("R21_REMAINING_MAX_REDEEM",a.remainingMaxRedeem);
        console2.log("R21_REMAINING_PREVIEW_REDEEM",a.remainingPreviewRedeem);
        console2.log("R21_TOTAL_ASSETS_AFTER_MAX",a.totalAssetsAfterMax);
        console2.log("R21_TOTAL_SUPPLY_AFTER_MAX",a.totalSupplyAfterMax);
        console2.log("R21_SECOND_REDEEM_OK",a.secondRedeemOk);
        console2.logBytes4(a.secondRedeemError);
        console2.log("R21_ARM_END");
    }}

    function _sel(bytes memory reason) internal pure returns(bytes4 out) {{
        if(reason.length>=4) assembly {{ out:=mload(add(reason,32)) }}
    }}
}}
'''
Path('test/KilnR21FluidDust.t.sol').write_text(source)
print(f'generated {{len(rows)}} Fluid vaults')
