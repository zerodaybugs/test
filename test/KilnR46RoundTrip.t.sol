// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";

contract KilnR46RoundTrip is Test {
    address internal constant ATTACKER = address(0xA11CE);

    function _staticUint(address target, bytes memory data) internal view returns (bool ok, uint256 value) {
        bytes memory out;
        (ok, out) = target.staticcall(data);
        if (ok && out.length >= 32) value = abi.decode(out, (uint256));
    }

    function _staticAddress(address target, bytes memory data) internal view returns (bool ok, address value) {
        bytes memory out;
        (ok, out) = target.staticcall(data);
        if (ok && out.length >= 32) value = abi.decode(out, (address));
    }

    function _balance(address token, address who) internal view returns (bool ok, uint256 value) {
        return _staticUint(token, abi.encodeWithSignature("balanceOf(address)", who));
    }

    function _approve(address token, address spender) internal returns (bool ok) {
        vm.prank(ATTACKER);
        bytes memory out;
        (ok, out) = token.call(abi.encodeWithSignature("approve(address,uint256)", spender, type(uint256).max));
        if (ok && out.length >= 32) ok = abi.decode(out, (bool));
    }

    function _fund(address token, uint256 amount) internal returns (bool ok) {
        try this.externalDeal(token, ATTACKER, amount) {
            ok = true;
        } catch {
            ok = false;
        }
    }

    function externalDeal(address token, address who, uint256 amount) external {
        require(msg.sender == address(this), "self only");
        deal(token, who, amount, true);
    }

    function _runDepositRedeem(address vault, address asset, uint256 amount)
        internal
        returns (string memory json)
    {
        (bool ta0ok, uint256 ta0) = _staticUint(vault, abi.encodeWithSignature("totalAssets()"));
        (bool ts0ok, uint256 ts0) = _staticUint(vault, abi.encodeWithSignature("totalSupply()"));
        (bool pDok, uint256 previewDeposit) = _staticUint(vault, abi.encodeWithSignature("previewDeposit(uint256)", amount));
        bool funded = _fund(asset, amount * 4 + 1);
        bool approved = funded && _approve(asset, vault);
        (, uint256 initialBalance) = _balance(asset, ATTACKER);

        bool depositOk;
        uint256 depositReturn;
        if (approved) {
            vm.prank(ATTACKER);
            bytes memory out;
            (depositOk, out) = vault.call(abi.encodeWithSignature("deposit(uint256,address)", amount, ATTACKER));
            if (depositOk && out.length >= 32) depositReturn = abi.decode(out, (uint256));
        }
        (, uint256 sharesAfterDeposit) = _balance(vault, ATTACKER);
        (, uint256 afterDepositBalance) = _balance(asset, ATTACKER);
        uint256 spent = initialBalance > afterDepositBalance ? initialBalance - afterDepositBalance : 0;

        bool redeemOk;
        uint256 redeemReturn;
        if (depositOk && sharesAfterDeposit > 0) {
            vm.prank(ATTACKER);
            bytes memory out;
            (redeemOk, out) = vault.call(
                abi.encodeWithSignature("redeem(uint256,address,address)", sharesAfterDeposit, ATTACKER, ATTACKER)
            );
            if (redeemOk && out.length >= 32) redeemReturn = abi.decode(out, (uint256));
        }
        (, uint256 finalBalance) = _balance(asset, ATTACKER);
        (bool ta1ok, uint256 ta1) = _staticUint(vault, abi.encodeWithSignature("totalAssets()"));
        (bool ts1ok, uint256 ts1) = _staticUint(vault, abi.encodeWithSignature("totalSupply()"));
        (, uint256 residualShares) = _balance(vault, ATTACKER);

        uint256 attackerProfit = finalBalance > initialBalance ? finalBalance - initialBalance : 0;
        uint256 attackerLoss = initialBalance > finalBalance ? initialBalance - finalBalance : 0;
        uint256 holderLoss = ta0ok && ta1ok && ta0 > ta1 ? ta0 - ta1 : 0;

        string memory obj = "deposit";
        vm.serializeBool(obj, "funded", funded);
        vm.serializeBool(obj, "approved", approved);
        vm.serializeBool(obj, "deposit_ok", depositOk);
        vm.serializeBool(obj, "redeem_ok", redeemOk);
        vm.serializeBool(obj, "total_assets_before_ok", ta0ok);
        vm.serializeBool(obj, "total_assets_after_ok", ta1ok);
        vm.serializeBool(obj, "total_supply_before_ok", ts0ok);
        vm.serializeBool(obj, "total_supply_after_ok", ts1ok);
        vm.serializeBool(obj, "preview_deposit_ok", pDok);
        vm.serializeUint(obj, "amount", amount);
        vm.serializeUint(obj, "preview_deposit", previewDeposit);
        vm.serializeUint(obj, "deposit_return", depositReturn);
        vm.serializeUint(obj, "shares_after_deposit", sharesAfterDeposit);
        vm.serializeUint(obj, "spent", spent);
        vm.serializeUint(obj, "redeem_return", redeemReturn);
        vm.serializeUint(obj, "initial_balance", initialBalance);
        vm.serializeUint(obj, "final_balance", finalBalance);
        vm.serializeUint(obj, "attacker_profit", attackerProfit);
        vm.serializeUint(obj, "attacker_loss", attackerLoss);
        vm.serializeUint(obj, "total_assets_before", ta0);
        vm.serializeUint(obj, "total_assets_after", ta1);
        vm.serializeUint(obj, "total_supply_before", ts0);
        vm.serializeUint(obj, "total_supply_after", ts1);
        vm.serializeUint(obj, "holder_loss", holderLoss);
        json = vm.serializeUint(obj, "residual_shares", residualShares);
    }

    function _runMintRedeem(address vault, address asset, uint256 baseAmount)
        internal
        returns (string memory json)
    {
        (bool pDok, uint256 targetShares) = _staticUint(
            vault, abi.encodeWithSignature("previewDeposit(uint256)", baseAmount)
        );
        if (!pDok || targetShares == 0) targetShares = 1;
        (bool pMok, uint256 quotedAssets) = _staticUint(
            vault, abi.encodeWithSignature("previewMint(uint256)", targetShares)
        );
        uint256 funding = (quotedAssets > baseAmount ? quotedAssets : baseAmount) * 4 + 10;
        bool funded = _fund(asset, funding);
        bool approved = funded && _approve(asset, vault);
        (, uint256 initialBalance) = _balance(asset, ATTACKER);
        (bool ta0ok, uint256 ta0) = _staticUint(vault, abi.encodeWithSignature("totalAssets()"));

        bool mintOk;
        uint256 mintReturn;
        if (approved) {
            vm.prank(ATTACKER);
            bytes memory out;
            (mintOk, out) = vault.call(abi.encodeWithSignature("mint(uint256,address)", targetShares, ATTACKER));
            if (mintOk && out.length >= 32) mintReturn = abi.decode(out, (uint256));
        }
        (, uint256 shares) = _balance(vault, ATTACKER);
        (, uint256 afterMintBalance) = _balance(asset, ATTACKER);
        uint256 spent = initialBalance > afterMintBalance ? initialBalance - afterMintBalance : 0;

        bool redeemOk;
        if (mintOk && shares > 0) {
            vm.prank(ATTACKER);
            (redeemOk,) = vault.call(
                abi.encodeWithSignature("redeem(uint256,address,address)", shares, ATTACKER, ATTACKER)
            );
        }
        (, uint256 finalBalance) = _balance(asset, ATTACKER);
        (bool ta1ok, uint256 ta1) = _staticUint(vault, abi.encodeWithSignature("totalAssets()"));
        (, uint256 residualShares) = _balance(vault, ATTACKER);
        uint256 attackerProfit = finalBalance > initialBalance ? finalBalance - initialBalance : 0;
        uint256 holderLoss = ta0ok && ta1ok && ta0 > ta1 ? ta0 - ta1 : 0;

        string memory obj = "mint";
        vm.serializeBool(obj, "funded", funded);
        vm.serializeBool(obj, "approved", approved);
        vm.serializeBool(obj, "preview_mint_ok", pMok);
        vm.serializeBool(obj, "mint_ok", mintOk);
        vm.serializeBool(obj, "redeem_ok", redeemOk);
        vm.serializeUint(obj, "target_shares", targetShares);
        vm.serializeUint(obj, "quoted_assets", quotedAssets);
        vm.serializeUint(obj, "mint_return", mintReturn);
        vm.serializeUint(obj, "actual_spent", spent);
        vm.serializeUint(obj, "attacker_profit", attackerProfit);
        vm.serializeUint(obj, "holder_loss", holderLoss);
        vm.serializeUint(obj, "total_assets_before", ta0);
        vm.serializeUint(obj, "total_assets_after", ta1);
        json = vm.serializeUint(obj, "residual_shares", residualShares);
    }

    function _runWithdraw(address vault, address asset, uint256 amount)
        internal
        returns (string memory json)
    {
        bool funded = _fund(asset, amount * 4 + 1);
        bool approved = funded && _approve(asset, vault);
        (, uint256 initialBalance) = _balance(asset, ATTACKER);
        bool depositOk;
        if (approved) {
            vm.prank(ATTACKER);
            (depositOk,) = vault.call(abi.encodeWithSignature("deposit(uint256,address)", amount, ATTACKER));
        }
        (, uint256 sharesBefore) = _balance(vault, ATTACKER);
        (bool maxOk, uint256 maxWithdraw) = _staticUint(
            vault, abi.encodeWithSignature("maxWithdraw(address)", ATTACKER)
        );
        uint256 requested = maxWithdraw > 1 ? maxWithdraw / 2 : maxWithdraw;
        (bool pWok, uint256 previewShares) = _staticUint(
            vault, abi.encodeWithSignature("previewWithdraw(uint256)", requested)
        );
        bool withdrawOk;
        uint256 withdrawReturn;
        if (depositOk && requested > 0) {
            vm.prank(ATTACKER);
            bytes memory out;
            (withdrawOk, out) = vault.call(
                abi.encodeWithSignature("withdraw(uint256,address,address)", requested, ATTACKER, ATTACKER)
            );
            if (withdrawOk && out.length >= 32) withdrawReturn = abi.decode(out, (uint256));
        }
        (, uint256 sharesAfterWithdraw) = _balance(vault, ATTACKER);
        bool redeemOk;
        if (sharesAfterWithdraw > 0) {
            vm.prank(ATTACKER);
            (redeemOk,) = vault.call(
                abi.encodeWithSignature("redeem(uint256,address,address)", sharesAfterWithdraw, ATTACKER, ATTACKER)
            );
        }
        (, uint256 finalBalance) = _balance(asset, ATTACKER);
        (, uint256 residualShares) = _balance(vault, ATTACKER);
        uint256 attackerProfit = finalBalance > initialBalance ? finalBalance - initialBalance : 0;
        uint256 burned = sharesBefore > sharesAfterWithdraw ? sharesBefore - sharesAfterWithdraw : 0;

        string memory obj = "withdraw";
        vm.serializeBool(obj, "funded", funded);
        vm.serializeBool(obj, "approved", approved);
        vm.serializeBool(obj, "deposit_ok", depositOk);
        vm.serializeBool(obj, "max_withdraw_ok", maxOk);
        vm.serializeBool(obj, "preview_withdraw_ok", pWok);
        vm.serializeBool(obj, "withdraw_ok", withdrawOk);
        vm.serializeBool(obj, "redeem_ok", redeemOk);
        vm.serializeUint(obj, "max_withdraw", maxWithdraw);
        vm.serializeUint(obj, "requested", requested);
        vm.serializeUint(obj, "preview_shares", previewShares);
        vm.serializeUint(obj, "withdraw_return", withdrawReturn);
        vm.serializeUint(obj, "actual_burned_shares", burned);
        vm.serializeUint(obj, "attacker_profit", attackerProfit);
        json = vm.serializeUint(obj, "residual_shares", residualShares);
    }

    function testR46() public {
        string memory rpcUrl = vm.envString("R46_RPC_URL");
        uint256 forkBlock = vm.envUint("R46_FORK_BLOCK");
        address vault = vm.envAddress("R46_VAULT");
        uint256 amount = vm.envUint("R46_AMOUNT");
        string memory resultPath = vm.envString("R46_RESULT_PATH");

        uint256 fork1 = vm.createFork(rpcUrl, forkBlock);
        vm.selectFork(fork1);
        (bool assetOk, address asset) = _staticAddress(vault, abi.encodeWithSignature("asset()"));
        require(assetOk && asset != address(0), "asset unavailable");
        string memory depositJson = _runDepositRedeem(vault, asset, amount);

        uint256 fork2 = vm.createFork(rpcUrl, forkBlock);
        vm.selectFork(fork2);
        string memory mintJson = _runMintRedeem(vault, asset, amount);

        uint256 fork3 = vm.createFork(rpcUrl, forkBlock);
        vm.selectFork(fork3);
        string memory withdrawJson = _runWithdraw(vault, asset, amount);

        string memory root = "root";
        vm.serializeAddress(root, "vault", vault);
        vm.serializeAddress(root, "asset", asset);
        vm.serializeUint(root, "fork_block", forkBlock);
        vm.serializeJson(root, "deposit_redeem", depositJson);
        vm.serializeJson(root, "mint_redeem", mintJson);
        string memory finalJson = vm.serializeJson(root, "withdraw", withdrawJson);
        vm.writeJson(finalJson, resultPath);
    }
}
