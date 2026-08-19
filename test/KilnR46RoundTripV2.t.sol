// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import {Test} from "forge-std/Test.sol";

contract KilnR46RoundTripV2 is Test {
    address internal constant ATTACKER = address(0xA11CE);

    struct Scenario {
        bool funded;
        bool approved;
        bool actionOk;
        bool exitOk;
        bool totalAssetsBeforeOk;
        bool totalAssetsAfterOk;
        uint256 requested;
        uint256 preview;
        uint256 actionReturn;
        uint256 initialBalance;
        uint256 postActionBalance;
        uint256 finalBalance;
        uint256 sharesAfterAction;
        uint256 residualShares;
        uint256 totalAssetsBefore;
        uint256 totalAssetsAfter;
        uint256 totalSupplyBefore;
        uint256 totalSupplyAfter;
        uint256 attackerProfit;
        uint256 attackerLoss;
        uint256 holderLoss;
    }

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

    function _balance(address token, address who) internal view returns (uint256 value) {
        (bool ok, uint256 out) = _staticUint(token, abi.encodeWithSignature("balanceOf(address)", who));
        if (ok) value = out;
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

    function _snapshot(address vault) internal view returns (bool taOk, uint256 ta, uint256 ts) {
        (taOk, ta) = _staticUint(vault, abi.encodeWithSignature("totalAssets()"));
        (, ts) = _staticUint(vault, abi.encodeWithSignature("totalSupply()"));
    }

    function _finalize(address vault, address asset, Scenario memory s) internal view returns (Scenario memory) {
        s.finalBalance = _balance(asset, ATTACKER);
        s.residualShares = _balance(vault, ATTACKER);
        (s.totalAssetsAfterOk, s.totalAssetsAfter, s.totalSupplyAfter) = _snapshot(vault);
        if (s.finalBalance > s.initialBalance) s.attackerProfit = s.finalBalance - s.initialBalance;
        if (s.initialBalance > s.finalBalance) s.attackerLoss = s.initialBalance - s.finalBalance;
        if (s.totalAssetsBeforeOk && s.totalAssetsAfterOk && s.totalAssetsBefore > s.totalAssetsAfter) {
            s.holderLoss = s.totalAssetsBefore - s.totalAssetsAfter;
        }
        return s;
    }

    function _depositRedeem(address vault, address asset, uint256 amount) internal returns (Scenario memory s) {
        (s.totalAssetsBeforeOk, s.totalAssetsBefore, s.totalSupplyBefore) = _snapshot(vault);
        (, s.preview) = _staticUint(vault, abi.encodeWithSignature("previewDeposit(uint256)", amount));
        s.requested = amount;
        s.funded = _fund(asset, amount * 8 + 100);
        s.approved = s.funded && _approve(asset, vault);
        s.initialBalance = _balance(asset, ATTACKER);
        if (s.approved) {
            vm.prank(ATTACKER);
            bytes memory out;
            (s.actionOk, out) = vault.call(abi.encodeWithSignature("deposit(uint256,address)", amount, ATTACKER));
            if (s.actionOk && out.length >= 32) s.actionReturn = abi.decode(out, (uint256));
        }
        s.sharesAfterAction = _balance(vault, ATTACKER);
        s.postActionBalance = _balance(asset, ATTACKER);
        if (s.actionOk && s.sharesAfterAction > 0) {
            vm.prank(ATTACKER);
            (s.exitOk,) = vault.call(
                abi.encodeWithSignature("redeem(uint256,address,address)", s.sharesAfterAction, ATTACKER, ATTACKER)
            );
        }
        return _finalize(vault, asset, s);
    }

    function _mintRedeem(address vault, address asset, uint256 baseAmount) internal returns (Scenario memory s) {
        (s.totalAssetsBeforeOk, s.totalAssetsBefore, s.totalSupplyBefore) = _snapshot(vault);
        (, uint256 targetShares) = _staticUint(vault, abi.encodeWithSignature("previewDeposit(uint256)", baseAmount));
        if (targetShares == 0) targetShares = 1;
        (bool previewOk, uint256 quotedAssets) = _staticUint(
            vault, abi.encodeWithSignature("previewMint(uint256)", targetShares)
        );
        s.requested = targetShares;
        if (previewOk) s.preview = quotedAssets;
        uint256 funding = (quotedAssets > baseAmount ? quotedAssets : baseAmount) * 8 + 100;
        s.funded = _fund(asset, funding);
        s.approved = s.funded && _approve(asset, vault);
        s.initialBalance = _balance(asset, ATTACKER);
        if (s.approved) {
            vm.prank(ATTACKER);
            bytes memory out;
            (s.actionOk, out) = vault.call(abi.encodeWithSignature("mint(uint256,address)", targetShares, ATTACKER));
            if (s.actionOk && out.length >= 32) s.actionReturn = abi.decode(out, (uint256));
        }
        s.sharesAfterAction = _balance(vault, ATTACKER);
        s.postActionBalance = _balance(asset, ATTACKER);
        if (s.actionOk && s.sharesAfterAction > 0) {
            vm.prank(ATTACKER);
            (s.exitOk,) = vault.call(
                abi.encodeWithSignature("redeem(uint256,address,address)", s.sharesAfterAction, ATTACKER, ATTACKER)
            );
        }
        return _finalize(vault, asset, s);
    }

    function _withdrawRedeem(address vault, address asset, uint256 amount) internal returns (Scenario memory s) {
        (s.totalAssetsBeforeOk, s.totalAssetsBefore, s.totalSupplyBefore) = _snapshot(vault);
        s.funded = _fund(asset, amount * 8 + 100);
        s.approved = s.funded && _approve(asset, vault);
        s.initialBalance = _balance(asset, ATTACKER);
        bool depositOk;
        if (s.approved) {
            vm.prank(ATTACKER);
            (depositOk,) = vault.call(abi.encodeWithSignature("deposit(uint256,address)", amount, ATTACKER));
        }
        s.sharesAfterAction = _balance(vault, ATTACKER);
        (bool maxOk, uint256 maxWithdraw) = _staticUint(vault, abi.encodeWithSignature("maxWithdraw(address)", ATTACKER));
        uint256 requestedAssets = maxOk && maxWithdraw > 1 ? maxWithdraw / 2 : maxWithdraw;
        s.requested = requestedAssets;
        (, s.preview) = _staticUint(vault, abi.encodeWithSignature("previewWithdraw(uint256)", requestedAssets));
        if (depositOk && requestedAssets > 0) {
            vm.prank(ATTACKER);
            bytes memory out;
            (s.actionOk, out) = vault.call(
                abi.encodeWithSignature("withdraw(uint256,address,address)", requestedAssets, ATTACKER, ATTACKER)
            );
            if (s.actionOk && out.length >= 32) s.actionReturn = abi.decode(out, (uint256));
        }
        s.postActionBalance = _balance(asset, ATTACKER);
        uint256 remainingShares = _balance(vault, ATTACKER);
        if (remainingShares > 0) {
            vm.prank(ATTACKER);
            (s.exitOk,) = vault.call(
                abi.encodeWithSignature("redeem(uint256,address,address)", remainingShares, ATTACKER, ATTACKER)
            );
        } else {
            s.exitOk = depositOk;
        }
        return _finalize(vault, asset, s);
    }

    function _writeScenario(string memory objectKey, string memory prefix, Scenario memory s) internal returns (string memory) {
        vm.serializeBool(objectKey, string.concat(prefix, "_funded"), s.funded);
        vm.serializeBool(objectKey, string.concat(prefix, "_approved"), s.approved);
        vm.serializeBool(objectKey, string.concat(prefix, "_action_ok"), s.actionOk);
        vm.serializeBool(objectKey, string.concat(prefix, "_exit_ok"), s.exitOk);
        vm.serializeBool(objectKey, string.concat(prefix, "_total_assets_before_ok"), s.totalAssetsBeforeOk);
        vm.serializeBool(objectKey, string.concat(prefix, "_total_assets_after_ok"), s.totalAssetsAfterOk);
        vm.serializeUint(objectKey, string.concat(prefix, "_requested"), s.requested);
        vm.serializeUint(objectKey, string.concat(prefix, "_preview"), s.preview);
        vm.serializeUint(objectKey, string.concat(prefix, "_action_return"), s.actionReturn);
        vm.serializeUint(objectKey, string.concat(prefix, "_initial_balance"), s.initialBalance);
        vm.serializeUint(objectKey, string.concat(prefix, "_post_action_balance"), s.postActionBalance);
        vm.serializeUint(objectKey, string.concat(prefix, "_final_balance"), s.finalBalance);
        vm.serializeUint(objectKey, string.concat(prefix, "_shares_after_action"), s.sharesAfterAction);
        vm.serializeUint(objectKey, string.concat(prefix, "_residual_shares"), s.residualShares);
        vm.serializeUint(objectKey, string.concat(prefix, "_total_assets_before"), s.totalAssetsBefore);
        vm.serializeUint(objectKey, string.concat(prefix, "_total_assets_after"), s.totalAssetsAfter);
        vm.serializeUint(objectKey, string.concat(prefix, "_total_supply_before"), s.totalSupplyBefore);
        vm.serializeUint(objectKey, string.concat(prefix, "_total_supply_after"), s.totalSupplyAfter);
        vm.serializeUint(objectKey, string.concat(prefix, "_attacker_profit"), s.attackerProfit);
        vm.serializeUint(objectKey, string.concat(prefix, "_attacker_loss"), s.attackerLoss);
        return vm.serializeUint(objectKey, string.concat(prefix, "_holder_loss"), s.holderLoss);
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
        Scenario memory depositScenario = _depositRedeem(vault, asset, amount);

        uint256 fork2 = vm.createFork(rpcUrl, forkBlock);
        vm.selectFork(fork2);
        Scenario memory mintScenario = _mintRedeem(vault, asset, amount);

        uint256 fork3 = vm.createFork(rpcUrl, forkBlock);
        vm.selectFork(fork3);
        Scenario memory withdrawScenario = _withdrawRedeem(vault, asset, amount);

        string memory objectKey = "r46";
        vm.serializeAddress(objectKey, "vault", vault);
        vm.serializeAddress(objectKey, "asset", asset);
        vm.serializeUint(objectKey, "fork_block", forkBlock);
        _writeScenario(objectKey, "deposit", depositScenario);
        _writeScenario(objectKey, "mint", mintScenario);
        string memory finalJson = _writeScenario(objectKey, "withdraw", withdrawScenario);
        vm.writeJson(finalJson, resultPath);
    }
}
