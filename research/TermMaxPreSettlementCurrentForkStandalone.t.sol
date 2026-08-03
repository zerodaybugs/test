// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

interface VmPSX1 {
    function createSelectFork(string calldata urlOrAlias, uint256 blockNumber) external returns (uint256 forkId);
    function envString(string calldata name) external view returns (string memory value);
    function snapshotState() external returns (uint256 snapshotId);
    function revertToState(uint256 snapshotId) external returns (bool success);
    function prank(address msgSender) external;
}

interface IERC20MinimalPSX1 {
    function balanceOf(address account) external view returns (uint256);
}

interface IERC4626PoolPSX1 {
    function balanceOf(address account) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
}

interface ITermMaxVaultPSX1 {
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function pool() external view returns (address);
    function balanceOf(address account) external view returns (uint256);
    function maxWithdraw(address owner) external view returns (uint256);
    function previewWithdraw(uint256 assets) external view returns (uint256);
    function previewRedeem(uint256 shares) external view returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function redeemOrder(address order) external returns (uint256 badDebt, uint256 deliveryCollateral);
    function badDebtMapping(address collateral) external view returns (uint256);
    function orderMaturity(address order) external view returns (uint256);
}

interface IGearingTokenValuePSX1 {
    function getCollateralValue(bytes calldata collateralData) external view returns (uint256 collateralValue1e8);
}

interface IOracleValuePSX1 {
    function getPrice(address token) external view returns (uint256 price, uint8 decimals);
}

contract TermMaxPreSettlementCurrentForkStandalonePoC {
    VmPSX1 internal constant vm = VmPSX1(address(uint160(uint256(keccak256("hevm cheat code")))));

    event log_named_uint(string key, uint256 value);
    event log_named_address(string key, address value);

    uint256 internal constant PINNED_BLOCK = 25_677_087;

    address internal constant VAULT = 0xF488ccdf04079cC03183cDB6A147d12Cf97F9317;
    address internal constant ORDER = 0x93257038eCc1337D296eC61B2629704fe89acfa5;
    address internal constant CURATOR = 0x008c7DC790fA31E6CA19D8Cb6d11C53f6A88DF6c;
    address internal constant HOLDER = 0xB355F88FB60E3fca64dD94E0932144069f2671a9;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant COLLATERAL = 0x29fD7180E5cCEd14Ad148c7997e6B6857a8BE86e;
    address internal constant GT = 0xbEabD241853B217660788694125e1809465d6393;
    address internal constant ORACLE = 0xE3a31690392E8E18DC3d862651C079339E2c1ADE;

    error AssertionFailed(string reason, uint256 actual, uint256 expected);
    error BooleanAssertionFailed(string reason);

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), PINNED_BLOCK);
        _assertEq(block.number, PINNED_BLOCK, "wrong fork block");
    }

    function test_CurrentProductionPreSettlementExitRemovesLiquidPrincipalAtPar() public {
        ITermMaxVaultPSX1 vault = ITermMaxVaultPSX1(VAULT);
        IERC20MinimalPSX1 usdc = IERC20MinimalPSX1(USDC);

        _assertEq(vault.badDebtMapping(COLLATERAL), 0, "target already settled");
        _assertGt(vault.orderMaturity(ORDER), 0, "target order no longer active in vault");

        uint256 bookBefore = vault.totalAssets();
        uint256 supplyBefore = vault.totalSupply();
        uint256 holderShares = vault.balanceOf(HOLDER);
        uint256 holderMaxWithdraw = vault.maxWithdraw(HOLDER);
        _assertGt(holderShares, 0, "production holder has no shares");

        uint256 snapshotId = vm.snapshotState();
        vm.prank(CURATOR);
        (uint256 expectedBadDebt, uint256 expectedDelivery) = vault.redeemOrder(ORDER);
        (uint256 debtPrice, uint8 debtPriceDecimals) = IOracleValuePSX1(ORACLE).getPrice(USDC);
        uint256 badDebtValue1e8 = expectedBadDebt * debtPrice * 1e8 / (1e6 * (10 ** debtPriceDecimals));
        uint256 deliveryValue1e8 = IGearingTokenValuePSX1(GT).getCollateralValue(abi.encode(expectedDelivery));
        _assertGt(badDebtValue1e8, deliveryValue1e8, "settlement is not loss-making");
        uint256 economicLoss1e8 = badDebtValue1e8 - deliveryValue1e8;
        uint256 economicLossUsdc =
            economicLoss1e8 * 1e6 * (10 ** debtPriceDecimals) / (debtPrice * 1e8);
        _assertGt(economicLossUsdc, 4_500e6, "unexpectedly small live loss");
        _assertTrue(vm.revertToState(snapshotId), "snapshot restore failed");

        address poolAddress = vault.pool();
        _assertTrue(poolAddress != address(0), "vault has no liquid pool");
        IERC4626PoolPSX1 pool = IERC4626PoolPSX1(poolAddress);
        uint256 poolShares = pool.balanceOf(VAULT);
        uint256 poolAssets = pool.convertToAssets(poolShares);
        uint256 withdrawableAssets = holderMaxWithdraw < poolAssets ? holderMaxWithdraw : poolAssets;
        _assertGt(withdrawableAssets, 2_700_000e6, "insufficient current liquid principal");

        uint256 sharesToRedeem = vault.previewWithdraw(withdrawableAssets);
        if (sharesToRedeem > holderShares) sharesToRedeem = holderShares;
        uint256 staleQuote = vault.previewRedeem(sharesToRedeem);
        uint256 fairQuote = sharesToRedeem * (bookBefore - economicLossUsdc) / supplyBefore;
        _assertGt(staleQuote, fairQuote, "no pre-settlement value transfer");
        uint256 valueShift = staleQuote - fairQuote;
        _assertGt(valueShift, 3_600e6, "current value shift below proof threshold");

        uint256 holderUsdcBefore = usdc.balanceOf(HOLDER);
        vm.prank(HOLDER);
        uint256 assetsOut = vault.redeem(sharesToRedeem, HOLDER, HOLDER);
        uint256 holderReceived = usdc.balanceOf(HOLDER) - holderUsdcBefore;

        _assertEq(assetsOut, holderReceived, "redeem return/balance mismatch");
        _assertEq(assetsOut, staleQuote, "holder did not receive stale par NAV");
        _assertGt(assetsOut, fairQuote, "holder did not externalize loss");
        _assertEq(vault.badDebtMapping(COLLATERAL), 0, "exit recognized or consumed bad debt");
        _assertGt(vault.orderMaturity(ORDER), 0, "exit settled target order");

        vm.prank(CURATOR);
        (uint256 badDebtAfterExit, uint256 deliveryAfterExit) = vault.redeemOrder(ORDER);
        _assertEq(badDebtAfterExit, expectedBadDebt, "exit changed bad debt");
        _assertEq(deliveryAfterExit, expectedDelivery, "exit changed collateral delivery");
        _assertEq(vault.badDebtMapping(COLLATERAL), expectedBadDebt, "loss not left for remaining LPs");

        emit log_named_uint("pinnedBlock", PINNED_BLOCK);
        emit log_named_uint("bookBeforeUSDC", bookBefore);
        emit log_named_uint("poolAssetsUSDC", poolAssets);
        emit log_named_uint("holderMaxWithdrawUSDC", holderMaxWithdraw);
        emit log_named_uint("sharesRedeemed", sharesToRedeem);
        emit log_named_uint("staleQuoteUSDC", staleQuote);
        emit log_named_uint("fairQuoteUSDC", fairQuote);
        emit log_named_uint("preSettlementValueShiftUSDC", valueShift);
        emit log_named_uint("economicLossUSDC", economicLossUsdc);
        emit log_named_uint("badDebtAfterExitUSDC", badDebtAfterExit);
        emit log_named_uint("holderReceivedUSDC", holderReceived);
        emit log_named_address("pool", poolAddress);
    }

    function _assertTrue(bool condition, string memory reason) internal pure {
        if (!condition) revert BooleanAssertionFailed(reason);
    }

    function _assertEq(uint256 actual, uint256 expected, string memory reason) internal pure {
        if (actual != expected) revert AssertionFailed(reason, actual, expected);
    }

    function _assertGt(uint256 actual, uint256 threshold, string memory reason) internal pure {
        if (actual <= threshold) revert AssertionFailed(reason, actual, threshold);
    }
}
