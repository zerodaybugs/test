// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

interface VmPTExpiry {
    function createSelectFork(string calldata urlOrAlias, uint256 blockNumber) external returns (uint256 forkId);
    function envString(string calldata name) external view returns (string memory value);
    function warp(uint256 newTimestamp) external;
}

interface ITermMaxMarketPTExpiry {
    struct FeeConfig {
        uint32 lendTakerFeeRatio;
        uint32 lendMakerFeeRatio;
        uint32 borrowTakerFeeRatio;
        uint32 borrowMakerFeeRatio;
        uint32 mintGtFeeRatio;
        uint32 mintGtFeeRef;
    }
    struct MarketConfig {
        address treasurer;
        uint64 maturity;
        FeeConfig feeConfig;
    }
    function tokens() external view returns (address ft, address xt, address gt, address collateral, address debtToken);
    function config() external view returns (MarketConfig memory);
}

interface IGearingTokenPTExpiry {
    struct LoanConfig {
        address oracle;
        uint32 liquidationLtv;
        uint32 maxLtv;
        bool liquidatable;
    }
    struct GtConfig {
        address collateral;
        address debtToken;
        address ft;
        address treasurer;
        uint64 maturity;
        LoanConfig loanConfig;
    }
    function getGtConfig() external view returns (GtConfig memory);
    function loanInfo(uint256 gtId) external view returns (address owner, uint128 debt, bytes memory collateralData);
}

interface IOraclePTExpiry {
    function getPrice(address token) external view returns (uint256 price, uint8 decimals);
    function oracles(address token)
        external
        view
        returns (
            address aggregator,
            address backupAggregator,
            int256 maxPrice,
            int256 minPrice,
            uint32 heartbeat,
            uint32 backupHeartbeat
        );
}

interface IAggregatorPTExpiry {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
    function market() external view returns (address);
}

contract TermMaxPtPostExpiryStandaloneTest {
    VmPTExpiry internal constant vm = VmPTExpiry(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant PINNED_BLOCK = 25_677_087;
    address internal constant MARKET = 0xf61d02aE5D19fA11fC825dc565cFaf264720F6C4;
    address internal constant GT = 0xD58Dd7Cd72AeA98FdAafBc4a965F4fCC49C68859;
    uint256 internal constant GT_ID = 2;

    event log_named_uint(string key, uint256 value);
    event log_named_int(string key, int256 value);
    event log_named_address(string key, address value);
    event log_named_bytes(string key, bytes value);

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), PINNED_BLOCK);
        require(block.number == PINNED_BLOCK, "WRONG_FORK_BLOCK");
    }

    function test_PostPtExpiryBeforeTermMaxMaturity_RemainsOperational() public {
        ITermMaxMarketPTExpiry market = ITermMaxMarketPTExpiry(MARKET);
        (,, address gtAddress, address collateral, address debtToken) = market.tokens();
        require(gtAddress == GT, "GT_BINDING_MISMATCH");

        ITermMaxMarketPTExpiry.MarketConfig memory marketConfig = market.config();
        IGearingTokenPTExpiry.GtConfig memory gtConfig = IGearingTokenPTExpiry(GT).getGtConfig();
        require(gtConfig.collateral == collateral, "COLLATERAL_BINDING_MISMATCH");
        require(gtConfig.debtToken == debtToken, "DEBT_BINDING_MISMATCH");
        require(gtConfig.maturity == marketConfig.maturity, "MATURITY_BINDING_MISMATCH");

        IOraclePTExpiry oracle = IOraclePTExpiry(gtConfig.loanConfig.oracle);
        (address aggregator,,,,,) = oracle.oracles(collateral);
        require(aggregator != address(0), "NO_COLLATERAL_AGGREGATOR");

        uint256 ptExpiry = _discoverExpiry(collateral, aggregator);
        require(ptExpiry > block.timestamp, "PT_ALREADY_EXPIRED_AT_PIN");
        require(ptExpiry < marketConfig.maturity, "NO_PT_TERM_MATURITY_GAP");
        uint256 gap = uint256(marketConfig.maturity) - ptExpiry;
        require(gap >= 1 days, "MATURITY_GAP_TOO_SMALL");

        (uint256 prePrice, uint8 preDecimals) = oracle.getPrice(collateral);
        require(prePrice > 0, "PRE_EXPIRY_ZERO_PRICE");
        (,,,, uint256 preUpdatedAt,) = _latestRoundData(aggregator);

        uint256 postTimestamp = ptExpiry + 1 hours;
        require(postTimestamp < marketConfig.maturity, "POST_TIMESTAMP_AFTER_TERM_MATURITY");
        vm.warp(postTimestamp);

        (bool oracleOk, bytes memory oracleData) = address(oracle).staticcall(
            abi.encodeWithSelector(IOraclePTExpiry.getPrice.selector, collateral)
        );
        require(oracleOk, "POST_EXPIRY_ORACLE_REVERT");
        require(oracleData.length >= 64, "POST_EXPIRY_ORACLE_MALFORMED");
        (uint256 postPrice, uint8 postDecimals) = abi.decode(oracleData, (uint256, uint8));
        require(postPrice > 0, "POST_EXPIRY_ZERO_PRICE");

        (bool feedOk, bytes memory feedData) = aggregator.staticcall(
            abi.encodeWithSelector(IAggregatorPTExpiry.latestRoundData.selector)
        );
        require(feedOk, "POST_EXPIRY_FEED_REVERT");
        require(feedData.length >= 160, "POST_EXPIRY_FEED_MALFORMED");
        (, int256 postAnswer,, uint256 postUpdatedAt,) = abi.decode(feedData, (uint80, int256, uint256, uint256, uint80));
        require(postAnswer > 0, "POST_EXPIRY_FEED_NONPOSITIVE");

        (bool liquidationOk, bytes memory liquidationData) = GT.staticcall(
            abi.encodeWithSignature("getLiquidationInfo(uint256)", GT_ID)
        );
        require(liquidationOk, "POST_EXPIRY_LIQUIDATION_INFO_REVERT");
        require(liquidationData.length != 0, "POST_EXPIRY_LIQUIDATION_INFO_EMPTY");

        (address owner, uint128 debt, bytes memory collateralData) = IGearingTokenPTExpiry(GT).loanInfo(GT_ID);
        require(owner != address(0), "GT_OWNER_ZERO");
        require(debt > 0, "GT_DEBT_ZERO");
        require(collateralData.length != 0, "GT_COLLATERAL_EMPTY");

        emit log_named_uint("pinnedBlock", PINNED_BLOCK);
        emit log_named_uint("pinnedTimestamp", block.timestamp);
        emit log_named_uint("ptExpiry", ptExpiry);
        emit log_named_uint("termMaxMaturity", marketConfig.maturity);
        emit log_named_uint("postExpiryPreMarketGapSeconds", gap);
        emit log_named_uint("prePrice", prePrice);
        emit log_named_uint("prePriceDecimals", preDecimals);
        emit log_named_uint("preUpdatedAt", preUpdatedAt);
        emit log_named_uint("postTimestamp", postTimestamp);
        emit log_named_uint("postPrice", postPrice);
        emit log_named_uint("postPriceDecimals", postDecimals);
        emit log_named_int("postFeedAnswer", postAnswer);
        emit log_named_uint("postUpdatedAt", postUpdatedAt);
        emit log_named_address("collateral", collateral);
        emit log_named_address("debtToken", debtToken);
        emit log_named_address("oracle", address(oracle));
        emit log_named_address("aggregator", aggregator);
        emit log_named_address("gtOwner", owner);
        emit log_named_uint("gtDebt", debt);
        emit log_named_bytes("liquidationInfoRaw", liquidationData);
    }

    function _discoverExpiry(address collateral, address aggregator) internal view returns (uint256 expiry) {
        expiry = _readUint(collateral, bytes4(keccak256("expiry()")));
        if (expiry != 0) return expiry;

        address yt = _readAddress(collateral, bytes4(keccak256("YT()")));
        if (yt != address(0)) {
            expiry = _readUint(yt, bytes4(keccak256("expiry()")));
            if (expiry != 0) return expiry;
        }

        address pendleMarket = _readAddress(aggregator, bytes4(keccak256("market()")));
        if (pendleMarket != address(0)) {
            expiry = _readUint(pendleMarket, bytes4(keccak256("expiry()")));
            if (expiry != 0) return expiry;
        }

        revert("PT_EXPIRY_NOT_DISCOVERED");
    }

    function _readUint(address target, bytes4 selector) internal view returns (uint256 value) {
        (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSelector(selector));
        if (ok && data.length >= 32) value = abi.decode(data, (uint256));
    }

    function _readAddress(address target, bytes4 selector) internal view returns (address value) {
        (bool ok, bytes memory data) = target.staticcall(abi.encodeWithSelector(selector));
        if (ok && data.length >= 32) value = abi.decode(data, (address));
    }

    function _latestRoundData(address aggregator)
        internal
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        return IAggregatorPTExpiry(aggregator).latestRoundData();
    }
}
