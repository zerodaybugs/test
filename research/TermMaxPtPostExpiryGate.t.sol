// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import {Test} from "forge-std/Test.sol";

interface IAggregatorLike {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

interface ITermMaxPTFeed is IAggregatorLike {
    function MARKET() external view returns (address);
    function PRICE_FEED() external view returns (address);
    function DURATION() external view returns (uint32);
    function asset() external view returns (address);
}

interface IPendleMarketExpiry {
    function expiry() external view returns (uint256);
}

interface IPendlePT {
    function YT() external view returns (address);
    function expiry() external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IPendleYT {
    function SY() external view returns (address);
    function expiry() external view returns (uint256);
    function redeemPY(address receiver) external returns (uint256 amountSyOut);
}

interface IERC20Like {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface ITermMaxOracle {
    function getPrice(address asset) external view returns (uint256 price, uint8 decimals);
}

interface ITermMaxGt {
    function loanInfo(uint256 id) external view returns (address owner, uint128 debtAmt, bytes memory collateralData);
    function getLiquidationInfo(uint256 id)
        external
        view
        returns (bool isLiquidable, uint128 ltv, uint128 maxRepayAmt);
    function repay(uint256 id, uint128 repayAmt, bool byDebtToken) external;
    function liquidate(uint256 id, uint128 repayAmt, bool byDebtToken) external;
}

contract TermMaxPtPostExpiryGate is Test {
    address internal constant TERM_MAX_MARKET = 0xf61d02aE5D19fA11fC825dc565cFaf264720F6C4;
    address internal constant PENDLE_MARKET = 0x4237a8acBD0B5a2DEc4aa83B1fd83F20162d02B8;
    address internal constant GT = 0xD58Dd7Cd72AeA98FdAafBc4a965F4fCC49C68859;
    address internal constant PT = 0x2D433b943FB8c015AE409444B7F960ED288082b4;
    address internal constant FEED = 0x762CAacE43CD1a5a57761fFc2744be6235544f1e;
    address internal constant ORACLE = 0x16110F65047a46D39FFEB3dadd61ed33ec9FaBC2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address internal constant USDC_FEED = 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6;

    uint256 internal constant TERM_MATURITY = 1_788_055_200;
    uint256 internal constant TARGET_ID = 2;

    uint256 internal forkBlock;

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        forkBlock = block.number;
        assertLt(block.timestamp, TERM_MATURITY, "production state already passed TermMax maturity");
    }

    function test_PostPtExpiryOracleRepayLiquidationAndRedemptionRemainOperational() public {
        uint256 initialSnapshot = vm.snapshotState();
        ITermMaxPTFeed feed = ITermMaxPTFeed(FEED);
        ITermMaxGt gt = ITermMaxGt(GT);

        assertEq(feed.asset(), PT, "wrong feed asset");
        assertEq(feed.MARKET(), PENDLE_MARKET, "wrong Pendle market");

        uint256 pendleExpiry = IPendleMarketExpiry(PENDLE_MARKET).expiry();
        assertEq(IPendlePT(PT).expiry(), pendleExpiry, "PT/market expiry mismatch");
        assertLt(block.timestamp, pendleExpiry, "production state already passed PT expiry");
        assertLt(pendleExpiry, TERM_MATURITY, "no PT/TermMax maturity gap");

        address underlyingFeed = feed.PRICE_FEED();
        (uint80 uRound, int256 uAnswer, uint256 uStarted,, uint80 uAnsweredInRound) =
            IAggregatorLike(underlyingFeed).latestRoundData();
        (uint80 dRound, int256 dAnswer, uint256 dStarted,, uint80 dAnsweredInRound) =
            IAggregatorLike(USDC_FEED).latestRoundData();
        assertGt(uint256(uAnswer), 0, "underlying answer not positive");
        assertGt(uint256(dAnswer), 0, "USDC answer not positive");

        // First day after Pendle PT expiry, while the TermMax market is still live.
        vm.warp(pendleExpiry + 1 days);
        assertLt(block.timestamp, TERM_MATURITY, "warp crossed TermMax maturity");
        _mockFreshRound(underlyingFeed, uRound, uAnswer, uStarted, uAnsweredInRound);
        _mockFreshRound(USDC_FEED, dRound, dAnswer, dStarted, dAnsweredInRound);

        (, int256 rawPostExpiryAnswer,, uint256 rawUpdatedAt,) = feed.latestRoundData();
        assertGt(uint256(rawPostExpiryAnswer), 0, "PT feed failed after PT expiry");
        assertEq(rawUpdatedAt, block.timestamp, "fresh timestamp not propagated");

        (uint256 oraclePrice, uint8 oracleDecimals) = ITermMaxOracle(ORACLE).getPrice(PT);
        assertGt(oraclePrice, 0, "TermMax oracle failed after PT expiry");
        assertEq(oracleDecimals, 8, "unexpected oracle decimals");

        // Ordinary debt-token repayment remains possible throughout the three-day maturity gap.
        (, uint128 debtBefore,) = gt.loanInfo(TARGET_ID);
        uint128 repayAmount = 1e6;
        deal(USDC, address(this), repayAmount);
        IERC20Like(USDC).approve(GT, repayAmount);
        gt.repay(TARGET_ID, repayAmount, true);
        (, uint128 debtAfter,) = gt.loanInfo(TARGET_ID);
        assertEq(debtAfter, debtBefore - repayAmount, "repay failed in PT/TermMax maturity gap");

        // Restore the exact current production state, then cross TermMax maturity locally.
        assertTrue(vm.revertToState(initialSnapshot), "snapshot restore failed");
        vm.clearMockedCalls();
        feed = ITermMaxPTFeed(FEED);
        gt = ITermMaxGt(GT);
        underlyingFeed = feed.PRICE_FEED();
        (uRound, uAnswer, uStarted,, uAnsweredInRound) = IAggregatorLike(underlyingFeed).latestRoundData();
        (dRound, dAnswer, dStarted,, dAnsweredInRound) = IAggregatorLike(USDC_FEED).latestRoundData();
        vm.warp(TERM_MATURITY + 1);
        _mockFreshRound(underlyingFeed, uRound, uAnswer, uStarted, uAnsweredInRound);
        _mockFreshRound(USDC_FEED, dRound, dAnswer, dStarted, dAnsweredInRound);

        (bool liquidatable,, uint128 maxRepayAmt) = gt.getLiquidationInfo(TARGET_ID);
        assertTrue(liquidatable, "GT not liquidatable in maturity window");
        assertGt(maxRepayAmt, 0, "zero liquidation capacity");

        deal(USDC, address(this), maxRepayAmt);
        IERC20Like(USDC).approve(GT, maxRepayAmt);
        uint256 ptBefore = IPendlePT(PT).balanceOf(address(this));
        gt.liquidate(TARGET_ID, maxRepayAmt, true);
        uint256 ptReceived = IPendlePT(PT).balanceOf(address(this)) - ptBefore;
        assertGt(ptReceived, 0, "liquidation did not transfer PT collateral");

        // Post-expiry PT is independently redeemable through its YT contract.
        address yt = IPendlePT(PT).YT();
        address sy = IPendleYT(yt).SY();
        assertEq(IPendleYT(yt).expiry(), pendleExpiry, "YT expiry mismatch");
        uint256 syBefore = IERC20Like(sy).balanceOf(address(this));
        IPendlePT(PT).transfer(yt, ptReceived);
        uint256 syOut = IPendleYT(yt).redeemPY(address(this));
        uint256 syReceived = IERC20Like(sy).balanceOf(address(this)) - syBefore;
        assertEq(syReceived, syOut, "YT redeem return/balance mismatch");
        assertGt(syReceived, 0, "post-expiry PT redemption failed");

        emit log_named_address("termMaxMarket", TERM_MAX_MARKET);
        emit log_named_address("pendleMarket", PENDLE_MARKET);
        emit log_named_uint("currentForkBlock", forkBlock);
        emit log_named_uint("pendleExpiry", pendleExpiry);
        emit log_named_uint("termMaxMaturity", TERM_MATURITY);
        emit log_named_uint("postExpiryOraclePrice", oraclePrice);
        emit log_named_uint("repayAmount", repayAmount);
        emit log_named_uint("liquidationRepayAmount", maxRepayAmt);
        emit log_named_uint("ptReceived", ptReceived);
        emit log_named_uint("syRedeemed", syReceived);
    }

    function _mockFreshRound(
        address aggregator,
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint80 answeredInRound
    ) internal {
        vm.mockCall(
            aggregator,
            abi.encodeWithSelector(IAggregatorLike.latestRoundData.selector),
            abi.encode(roundId, answer, startedAt, block.timestamp, answeredInRound)
        );
    }
}
