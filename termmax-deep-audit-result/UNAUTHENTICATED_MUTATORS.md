# Unauthenticated mutator candidates

Count: 98

## contracts/v1/TermMaxMarket.sol:74 `initialize`

`external override initializer`

```solidity
function initialize(MarketInitialParams memory params) external override initializer {
        __Ownable_init(params.admin);
        __ReentrancyGuard_init();
        if (params.collateral == address(params.debtToken)) revert CollateralCanNotEqualUnderlyinng();
        MarketConfig memory config_ = params.marketConfig;
        if (config_.maturity <= block.timestamp) revert InvalidMaturity();
        _checkFee(config_.feeConfig);

        debtToken = params.debtToken;
        collateral = params.collateral;
        _config = config_;

        (ft, xt, gt) = _deployTokens(params);

        emit MarketInitialized(params.collateral, params.debtToken, _config.maturity, ft, xt, gt);
    }
```

## contracts/v1/TermMaxMarket.sol:171 `mint`

`external override nonReentrant isOpen`

```solidity
function mint(address recipient, uint256 debtTokenAmt) external override nonReentrant isOpen {
        _mint(msg.sender, recipient, debtTokenAmt);
    }
```

## contracts/v1/TermMaxMarket.sol:184 `burn`

`external override nonReentrant isOpen`

```solidity
function burn(address recipient, uint256 debtTokenAmt) external override nonReentrant isOpen {
        _burn(msg.sender, recipient, debtTokenAmt);
    }
```

## contracts/v1/TermMaxOrder.sol:321 `swapExactTokenToToken`

`external override nonReentrant isOpen returns (uint256 netTokenOut)`

```solidity
function swapExactTokenToToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        uint128 tokenAmtIn,
        uint128 minTokenOut,
        uint256 deadline
    ) external override nonReentrant isOpen returns (uint256 netTokenOut) {
        if (block.timestamp > deadline) revert DeadlineExpired();
        if (tokenIn == tokenOut) revert CantSwapSameToken();
        OrderConfig memory config = _orderConfig;
        uint256 feeAmt;
        if (tokenAmtIn != 0) {
            // Store ft and xt reserve before swap
            setInitialFtReserve(ft.balanceOf(address(this)));
            setInitialXtReserve(xt.balanceOf(address(this)));
            if (tokenIn == ft && tokenOut == debtToken) {
                (netTokenOut, feeAmt) = _sellFt(tokenAmtIn, minTokenOut, msg.sender, recipient, config);
            } else if (tokenIn == xt && tokenOut == debtToken) {
                (netTokenOut, feeAmt) = _sellXt(tokenAmtIn, minTokenOut, msg.sender, recipient, config);
            } else if (tokenIn == debtToken && tokenOut == ft) {
                (netTokenOut, feeAmt) = _buyFt(tokenAmtIn, minTokenOut, msg.sender, recipient, config);
            } else if (tokenIn == debtToken && tokenOut == xt) {
                (netTokenOut, feeAmt) = _buyXt(tokenAmtIn, minTokenOut, msg.sender, recipient, config);
            } else {
                revert CantNotSwapToken(tokenIn, tokenOut);
            }
            // transfer fee to treasurer
            ft.safeTransfer(market.config().treasurer, feeAmt);
            /// @dev callback the changes of ft and xt reserve to trigger
            if (address(_orderConfig.swapTrigger) != address(0)) {
                uint256 ftReserve = ft.balanceOf(address(this));
                uint256 xtReserve = xt.balanceOf(address(this));
                int256 deltaFt = ftReserve.toInt256() - getInitialFtReserve().toInt256();
                int256 deltaXt = xtReserve.toInt256() - getInitialXtReserve().toInt256();
                _orderConfig.swapTrigger.afterSwap(ftReserve, xtReserve, deltaFt, deltaXt);
            }
        } else {
            if (address(_orderConfig.swapTrigger) != address(0)) {
               
```

## contracts/v1/TermMaxOrder.sol:531 `swapTokenToExactToken`

`external override nonReentrant isOpen returns (uint256 netTokenIn)`

```solidity
function swapTokenToExactToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        uint128 tokenAmtOut,
        uint128 maxTokenIn,
        uint256 deadline
    ) external override nonReentrant isOpen returns (uint256 netTokenIn) {
        if (block.timestamp > deadline) revert DeadlineExpired();
        if (tokenIn == tokenOut) revert CantSwapSameToken();
        OrderConfig memory config = _orderConfig;
        uint256 feeAmt;
        if (tokenAmtOut != 0 && maxTokenIn != 0) {
            // Storage current ft and xt reserve
            setInitialFtReserve(ft.balanceOf(address(this)));
            setInitialXtReserve(xt.balanceOf(address(this)));

            if (tokenIn == debtToken && tokenOut == ft) {
                (netTokenIn, feeAmt) = _buyExactFt(tokenAmtOut, maxTokenIn, msg.sender, recipient, config);
            } else if (tokenIn == debtToken && tokenOut == xt) {
                (netTokenIn, feeAmt) = _buyExactXt(tokenAmtOut, maxTokenIn, msg.sender, recipient, config);
            } else if (tokenIn == ft && tokenOut == debtToken) {
                (netTokenIn, feeAmt) = _sellFtForExactToken(tokenAmtOut, maxTokenIn, msg.sender, recipient, config);
            } else if (tokenIn == xt && tokenOut == debtToken) {
                (netTokenIn, feeAmt) = _sellXtForExactToken(tokenAmtOut, maxTokenIn, msg.sender, recipient, config);
            } else {
                revert CantNotSwapToken(tokenIn, tokenOut);
            }
            // transfer fee to treasurer
            ft.safeTransfer(market.config().treasurer, feeAmt);

            /// @dev callback the changes of ft and xt reserve to trigger
            if (address(_orderConfig.swapTrigger) != address(0)) {
                uint256 ftReserve = ft.balanceOf(address(this));
                uint256 xtReserve = xt.balanceOf(address(this));
                int256 deltaFt = ftReserve.toInt256() - getInitialFtReserve().toInt256();
                int256 deltaXt = xtReserve.toInt256() - getInitialXtReserve().toInt256();
                _orderConfig.swapTrigger.afterSwap(ftReserve, xtReserve, deltaFt, deltaXt);
            }
        } else {
            if (address(_orderC
```

## contracts/mocks/MockVToken.sol:30 `setDecimals`

`external`

```solidity
function setDecimals(uint8 decimals_) external {
        _decimals = decimals_;
    }
```

## contracts/mocks/MockVToken.sol:44 `transferFrom`

`public override(ERC20, IVToken) returns (bool)`

```solidity
function transferFrom(address from, address to, uint256 value) public override(ERC20, IVToken) returns (bool) {
        return super.transferFrom(from, to, value);
    }
```

## contracts/mocks/MockVToken.sol:74 `mint`

`public virtual override returns (uint256)`

```solidity
function mint(uint256 mintAmount) public virtual override returns (uint256) {
        IERC20(_underlying).transferFrom(msg.sender, address(this), mintAmount);
        // mintTokens = mintAmount / exchangeRate
        uint256 vTokenAmount = (mintAmount * 1e18) / exchangeRateMock;
        _mint(msg.sender, vTokenAmount);
        cashMock += mintAmount;
        return 0; // Success
    }
```

## contracts/mocks/MockVToken.sol:83 `mintBehalf`

`external override returns (uint256)`

```solidity
function mintBehalf(address minter, uint256 mintAmount) external override returns (uint256) {
        IERC20(_underlying).transferFrom(msg.sender, address(this), mintAmount);
        uint256 vTokenAmount = (mintAmount * 1e18) / exchangeRateMock;
        _mint(minter, vTokenAmount);
        cashMock += mintAmount;
        return 0;
    }
```

## contracts/mocks/MockVToken.sol:91 `redeem`

`external override returns (uint256)`

```solidity
function redeem(uint256 redeemTokens) external override returns (uint256) {
        uint256 redeemAmount = (redeemTokens * exchangeRateMock) / 1e18;
        _burn(msg.sender, redeemTokens);
        IERC20(_underlying).transfer(msg.sender, redeemAmount);
        if (cashMock >= redeemAmount) cashMock -= redeemAmount;
        return 0;
    }
```

## contracts/mocks/MockVToken.sol:99 `redeemBehalf`

`external override returns (uint256)`

```solidity
function redeemBehalf(address redeemer, uint256 redeemTokens) external override returns (uint256) {
        // NOTE: Mock assumes caller has permission or logic is simplified for testing
        uint256 redeemAmount = (redeemTokens * exchangeRateMock) / 1e18;
        _burn(redeemer, redeemTokens);
        IERC20(_underlying).transfer(redeemer, redeemAmount);
        if (cashMock >= redeemAmount) cashMock -= redeemAmount;
        return 0;
    }
```

## contracts/mocks/MockVToken.sol:108 `redeemUnderlying`

`public virtual override returns (uint256)`

```solidity
function redeemUnderlying(uint256 redeemAmount) public virtual override returns (uint256) {
        uint256 redeemTokens = (redeemAmount * 1e18) / exchangeRateMock;
        _burn(msg.sender, redeemTokens);
        IERC20(_underlying).transfer(msg.sender, redeemAmount);
        if (cashMock >= redeemAmount) cashMock -= redeemAmount;
        return 0;
    }
```

## contracts/mocks/MockVToken.sol:116 `redeemUnderlyingBehalf`

`external override returns (uint256)`

```solidity
function redeemUnderlyingBehalf(address redeemer, uint256 redeemAmount) external override returns (uint256) {
        uint256 redeemTokens = (redeemAmount * 1e18) / exchangeRateMock;
        _burn(redeemer, redeemTokens);
        IERC20(_underlying).transfer(redeemer, redeemAmount);
        if (cashMock >= redeemAmount) cashMock -= redeemAmount;
        return 0;
    }
```

## contracts/mocks/MockVToken.sol:140 `repayBorrow`

`external override returns (uint256)`

```solidity
function repayBorrow(uint256 repayAmount) external override returns (uint256) {
        IERC20(_underlying).transferFrom(msg.sender, address(this), repayAmount);
        if (borrowBalancesMock[msg.sender] >= repayAmount) borrowBalancesMock[msg.sender] -= repayAmount;
        else borrowBalancesMock[msg.sender] = 0;

        if (totalBorrowsMock >= repayAmount) totalBorrowsMock -= repayAmount;
        else totalBorrowsMock = 0;

        cashMock += repayAmount;
        return 0;
    }
```

## contracts/mocks/MockVToken.sol:152 `repayBorrowBehalf`

`external override returns (uint256)`

```solidity
function repayBorrowBehalf(address borrower, uint256 repayAmount) external override returns (uint256) {
        IERC20(_underlying).transferFrom(msg.sender, address(this), repayAmount);
        if (borrowBalancesMock[borrower] >= repayAmount) borrowBalancesMock[borrower] -= repayAmount;
        else borrowBalancesMock[borrower] = 0;

        if (totalBorrowsMock >= repayAmount) totalBorrowsMock -= repayAmount;
        else totalBorrowsMock = 0;

        cashMock += repayAmount;
        return 0;
    }
```

## contracts/mocks/MockVToken.sol:164 `liquidateBorrow`

`external override returns (uint256)`

```solidity
function liquidateBorrow(address borrower, uint256 repayAmount, address vTokenCollateral)
        external
        override
        returns (uint256)
    {
        // Mock liquidation logic
        IERC20(_underlying).transferFrom(msg.sender, address(this), repayAmount);

        if (borrowBalancesMock[borrower] >= repayAmount) borrowBalancesMock[borrower] -= repayAmount;
        else borrowBalancesMock[borrower] = 0;

        if (totalBorrowsMock >= repayAmount) totalBorrowsMock -= repayAmount;
        else totalBorrowsMock = 0;

        cashMock += repayAmount;

        // Seize collateral - simplified
        if (vTokenCollateral == address(this)) {
            uint256 seizeTokens = (repayAmount * 1e18) / exchangeRateMock;
            _transfer(borrower, msg.sender, seizeTokens);
        } else {
            // If cross-market, need to call seize
            try IVToken(vTokenCollateral).seize(msg.sender, borrower, (repayAmount * 1e18) / 1e18) {} catch {}
        }
        return 0;
    }
```

## contracts/mocks/MockVToken.sol:229 `addReserves`

`external override`

```solidity
function addReserves(uint256 addAmount) external override {
        IERC20(_underlying).transferFrom(msg.sender, address(this), addAmount);
        totalReservesMock += addAmount;
        cashMock += addAmount;
    }
```

## contracts/v2/TermMaxMarketV2.sol:92 `initialize`

`external virtual override initializer`

```solidity
function initialize(MarketInitialParams memory params) external virtual override initializer {
        __Ownable_init_unchained(params.admin);
        __ReentrancyGuard_init_unchained();
        if (params.collateral == address(params.debtToken)) revert CollateralCanNotEqualUnderlyinng();
        MarketConfig memory config_ = params.marketConfig;
        if (config_.maturity <= block.timestamp) revert InvalidMaturity();
        _checkFee(config_.feeConfig);

        debtToken = params.debtToken;
        collateral = params.collateral;
        _config = config_;

        (ft, xt, gt) = _deployTokens(params);
        name = StringUtil.contact(MarketConstantsV2.PREFIX_MARKET, params.tokenName);
        emit MarketInitialized(params.collateral, params.debtToken, _config.maturity, ft, xt, gt);
    }
```

## contracts/v2/TermMaxMarketV2.sol:191 `mint`

`external virtual override nonReentrant isOpen`

```solidity
function mint(address recipient, uint256 debtTokenAmt) external virtual override nonReentrant isOpen {
        _mint(msg.sender, recipient, debtTokenAmt);
    }
```

## contracts/v2/TermMaxMarketV2.sol:207 `burn`

`external virtual override nonReentrant isOpen`

```solidity
function burn(address recipient, uint256 debtTokenAmt) external virtual override nonReentrant isOpen {
        _burn(msg.sender, msg.sender, recipient, debtTokenAmt);
    }
```

## contracts/v2/TermMaxMarketV2.sol:214 `burn`

`external virtual override nonReentrant isOpen`

```solidity
function burn(address owner, address recipient, uint256 debtTokenAmt)
        external
        virtual
        override
        nonReentrant
        isOpen
    {
        _burn(owner, msg.sender, recipient, debtTokenAmt);
    }
```

## contracts/v2/TermMaxOrderV2.sol:142 `initialize`

`external virtual override initializer`

```solidity
function initialize(OrderInitialParams memory params) external virtual override initializer {
        __Ownable_init_unchained(params.maker);
        __ReentrancyGuard_init_unchained();
        __Pausable_init_unchained();
        address _market = _msgSender();
        market = ITermMaxMarket(_market);
        ft = params.ft;
        xt = params.xt;
        debtToken = params.debtToken;
        gt = params.gt;
        _setPool(params.pool);
        _setCurveAndPrice(params.virtualXtReserve, params.orderConfig.maxXtReserve, params.orderConfig.curveCuts);
        _updateGeneralConfig(params.orderConfig.gtId, params.orderConfig.swapTrigger);
        _setExpiryTimestamp(params.maturity);
        emit OrderEventsV2.OrderInitialized(params.maker, _market);
    }
```

## contracts/v2/TermMaxOrderV2.sol:666 `swapExactTokenToToken`

`external virtual override nonReentrant onlyOpen returns (uint256 netTokenOut)`

```solidity
function swapExactTokenToToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        uint128 tokenAmtIn,
        uint128 minTokenOut,
        uint256 deadline
    ) external virtual override nonReentrant onlyOpen returns (uint256 netTokenOut) {
        if (block.timestamp > deadline) revert DeadlineExpired();
        if (tokenIn == tokenOut) revert CantSwapSameToken();
        uint256 feeAmt;
        if (tokenAmtIn != 0) {
            IERC20 _debtToken = debtToken;
            IERC20 _ft = ft;
            IERC20 _xt = xt;
            OrderConfig memory orderConfig_ = _orderConfig;
            orderConfig_.feeConfig = _getMarketConfigAndCache().feeConfig;
            int256 deltaFt;
            int256 deltaXt;
            if (tokenIn == _ft && tokenOut == _debtToken) {
                (netTokenOut, feeAmt, deltaFt, deltaXt) =
                    _swapAndUpdateReserves(tokenAmtIn, minTokenOut, orderConfig_, _sellFt);
            } else if (tokenIn == _xt && tokenOut == _debtToken) {
                (netTokenOut, feeAmt, deltaFt, deltaXt) =
                    _swapAndUpdateReserves(tokenAmtIn, minTokenOut, orderConfig_, _sellXt);
            } else if (tokenIn == _debtToken && tokenOut == _ft) {
                (netTokenOut, feeAmt, deltaFt, deltaXt) =
                    _swapAndUpdateReserves(tokenAmtIn, minTokenOut, orderConfig_, _buyFt);
            } else if (tokenIn == _debtToken && tokenOut == _xt) {
                (netTokenOut, feeAmt, deltaFt, deltaXt) =
                    _swapAndUpdateReserves(tokenAmtIn, minTokenOut, orderConfig_, _buyXt);
            } else {
                revert CantNotSwapToken(tokenIn, tokenOut);
            }

            uint256 ftBalance = ft.balanceOf(address(this));
            uint256 xtBalance = xt.balanceOf(address(this));
            if (orderConfig_.swapTrigger != ISwapCallback(address(0))) {
                orderConfig_.swapTrigger.afterSwap(ftBalance, xtBalance, deltaFt, deltaXt);
            }

            // transfer token in
            tokenIn.safeTransferFrom(msg.sender, address(this), tokenAmtIn);

            _rebalance(
                _ft, _xt, _debtToken, tokenAmtIn, tokenOut
```

## contracts/v2/TermMaxOrderV2.sol:734 `swapTokenToExactToken`

`external virtual override nonReentrant onlyOpen returns (uint256 netTokenIn)`

```solidity
function swapTokenToExactToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        uint128 tokenAmtOut,
        uint128 maxTokenIn,
        uint256 deadline
    ) external virtual override nonReentrant onlyOpen returns (uint256 netTokenIn) {
        if (block.timestamp > deadline) revert DeadlineExpired();
        if (tokenIn == tokenOut) revert CantSwapSameToken();
        uint256 feeAmt;
        if (tokenAmtOut != 0 && maxTokenIn != 0) {
            IERC20 _debtToken = debtToken;
            IERC20 _ft = ft;
            IERC20 _xt = xt;
            int256 deltaFt;
            int256 deltaXt;
            OrderConfig memory orderConfig_ = _orderConfig;
            orderConfig_.feeConfig = _getMarketConfigAndCache().feeConfig;
            if (tokenIn == _debtToken && tokenOut == _ft) {
                (netTokenIn, feeAmt, deltaFt, deltaXt) =
                    _swapAndUpdateReserves(tokenAmtOut, maxTokenIn, orderConfig_, _buyExactFt);
            } else if (tokenIn == _debtToken && tokenOut == _xt) {
                (netTokenIn, feeAmt, deltaFt, deltaXt) =
                    _swapAndUpdateReserves(tokenAmtOut, maxTokenIn, orderConfig_, _buyExactXt);
            } else if (tokenIn == _ft && tokenOut == _debtToken) {
                (netTokenIn, feeAmt, deltaFt, deltaXt) =
                    _swapAndUpdateReserves(tokenAmtOut, maxTokenIn, orderConfig_, _sellFtForExactToken);
            } else if (tokenIn == _xt && tokenOut == _debtToken) {
                (netTokenIn, feeAmt, deltaFt, deltaXt) =
                    _swapAndUpdateReserves(tokenAmtOut, maxTokenIn, orderConfig_, _sellXtForExactToken);
            } else {
                revert CantNotSwapToken(tokenIn, tokenOut);
            }
            // trigger call back function
            if (orderConfig_.swapTrigger != ISwapCallback(address(0))) {
                orderConfig_.swapTrigger.afterSwap(
                    ft.balanceOf(address(this)), xt.balanceOf(address(this)), deltaFt, deltaXt
                );
            }

            // transfer token in
            tokenIn.safeTransferFrom(msg.sender, address(this), netTokenIn);
            _rebalance(
               
```

## contracts/v1/vault/OrderManager.sol:150 `depositAssets`

`external override onlyProxy`

```solidity
function depositAssets(IERC20 asset, uint256 amount) external override onlyProxy {
        _accruedInterest();
        uint256 amountLeft = amount;
        for (uint256 i = 0; i < _supplyQueue.length; ++i) {
            address order = _supplyQueue[i];

            //check maturity
            OrderInfo memory orderInfo = _orderMapping[order];
            if (block.timestamp > orderInfo.maturity) continue;

            //check supply
            uint256 xtReserve = orderInfo.xt.balanceOf(order);
            if (xtReserve >= orderInfo.maxSupply) continue;

            uint256 depositAmt = (orderInfo.maxSupply - xtReserve).min(amountLeft);

            asset.safeIncreaseAllowance(address(orderInfo.market), depositAmt);
            orderInfo.market.mint(order, depositAmt);
            amountLeft -= depositAmt;
            if (amountLeft == 0) break;
        }
        // deposit to lpers
        uint256 amplifiedAmt = amount * Constants.DECIMAL_BASE_SQ;
        _totalFt += amplifiedAmt;
        _accretingPrincipal += amplifiedAmt;
    }
```

## contracts/v1/vault/OrderManager.sol:180 `withdrawAssets`

`external override onlyProxy`

```solidity
function withdrawAssets(IERC20 asset, address recipient, uint256 amount) external override onlyProxy {
        _accruedInterest();
        uint256 amountLeft = amount;
        uint256 assetBalance = asset.balanceOf(address(this));
        if (assetBalance >= amount) {
            asset.safeTransfer(recipient, amount);
        } else {
            amountLeft -= assetBalance;
            uint256 length = _withdrawQueue.length;
            // withdraw from orders
            uint256 i;
            while (length > 0 && i < length) {
                address order = _withdrawQueue[i];
                OrderInfo memory orderInfo = _orderMapping[order];
                if (block.timestamp >= orderInfo.maturity + Constants.LIQUIDATION_WINDOW) {
                    // redeem assets from expired order
                    uint256 totalRedeem = _redeemFromMarket(order, orderInfo);
                    length--;
                    if (totalRedeem < amountLeft) {
                        amountLeft -= totalRedeem;
                        continue;
                    } else {
                        // transfer all assets to recipient
                        asset.safeTransfer(recipient, amount);
                        amountLeft = 0;
                        break;
                    }
                } else if (block.timestamp < orderInfo.maturity) {
                    // withdraw ft and xt from order to burn
                    uint256 maxWithdraw = orderInfo.xt.balanceOf(order).min(orderInfo.ft.balanceOf(order));

                    if (maxWithdraw < amountLeft) {
                        amountLeft -= maxWithdraw;
                        _burnFromOrder(ITermMaxOrder(order), orderInfo, maxWithdraw);
                        ++i;
                    } else {
                        _burnFromOrder(ITermMaxOrder(order), orderInfo, amountLeft);
                        // transfer all assets to recipient
                        asset.safeTransfer(recipient, amount);
                        amountLeft = 0;
                        break;
                    }
                } else {
                    // ignore orders that are in liquidation window
                    ++i;
     
```

## contracts/v1/vault/OrderManager.sol:252 `dealBadDebt`

`external onlyProxy returns (uint256 collateralOut)`

```solidity
function dealBadDebt(address recipient, address collateral, uint256 amount)
        external
        onlyProxy
        returns (uint256 collateralOut)
    {
        _accruedInterest();
        uint256 badDebtAmt = _badDebtMapping[collateral];
        if (badDebtAmt == 0) revert NoBadDebt(collateral);
        if (amount > badDebtAmt) revert InsufficientFunds(badDebtAmt, amount);
        uint256 collateralBalance = IERC20(collateral).balanceOf(address(this));
        collateralOut = (amount * collateralBalance) / badDebtAmt;
        IERC20(collateral).safeTransfer(recipient, collateralOut);

        _badDebtMapping[collateral] -= amount;
        uint256 amplifiedAmt = amount * Constants.DECIMAL_BASE_SQ;
        _accretingPrincipal -= amplifiedAmt;
        _totalFt -= amplifiedAmt;
    }
```

## contracts/v1/vault/OrderManager.sol:356 `afterSwap`

`external onlyProxy`

```solidity
function afterSwap(uint256 ftReserve, uint256 xtReserve, int256 deltaFt) external onlyProxy {
        if (ftReserve < xtReserve) {
            revert OrderHasNegativeInterest();
        }
        address orderAddress = msg.sender;
        /// @dev Check if the order is valid
        _checkOrder(orderAddress);
        uint64 maturity = _orderMapping[orderAddress].maturity;
        /// @dev Calculate interest from last update time to now
        _accruedInterest();

        /// @dev If ft increases, interest increases, and if ft decreases,
        ///  interest decreases. Update the expected annualized return based on the change
        uint256 ftChanges;

        if (deltaFt > 0) {
            ftChanges = uint256(deltaFt) * Constants.DECIMAL_BASE_SQ;
            _totalFt += ftChanges;
            uint256 deltaAnnualizedInterest = ftChanges * 365 days / uint256(maturity - block.timestamp);

            _maturityToInterest[maturity] += deltaAnnualizedInterest;

            _annualizedInterest += deltaAnnualizedInterest;
        } else {
            ftChanges = uint256(-deltaFt) * Constants.DECIMAL_BASE_SQ;
            _totalFt -= ftChanges;
            uint256 deltaAnnualizedInterest = (ftChanges * 365 days) / uint256(maturity - block.timestamp);
            if (
                _maturityToInterest[maturity] < deltaAnnualizedInterest || _annualizedInterest < deltaAnnualizedInterest
            ) {
                revert LockedFtGreaterThanTotalFt();
            }
            _maturityToInterest[maturity] -= deltaAnnualizedInterest;
            _annualizedInterest -= deltaAnnualizedInterest;
        }
        /// @dev Ensure that the total assets after the transaction are
        ///greater than or equal to the principal and the allocated interest
        _checkLockedFt();
    }
```

## contracts/v1/vault/TermMaxVault.sol:94 `initialize`

`external initializer`

```solidity
function initialize(VaultInitialParams memory params) external initializer {
        __ERC20_init(params.name, params.symbol);
        __Ownable_init(params.admin);
        __ERC4626_init(params.asset);
        __ReentrancyGuard_init();
        __Pausable_init();

        _setPerformanceFeeRate(params.performanceFeeRate);
        _checkTimelockBounds(params.timelock);
        _timelock = params.timelock;
        _maxCapacity = params.maxCapacity;
        _curator = params.curator;
    }
```

## contracts/v1/vault/TermMaxVault.sol:246 `apr`

`external view returns (uint256)`

```solidity
function apr() external view returns (uint256) {
        if (_accretingPrincipal == 0) return 0;
        return (_annualizedInterest * (Constants.DECIMAL_BASE - _performanceFeeRate)) / (_accretingPrincipal);
    }
```

## contracts/v1/vault/TermMaxVault.sol:396 `dealBadDebt`

`external nonReentrant returns (uint256 shares, uint256 collateralOut)`

```solidity
function dealBadDebt(address collateral, uint256 badDebtAmt, address recipient, address owner)
        external
        nonReentrant
        returns (uint256 shares, uint256 collateralOut)
    {
        address caller = msg.sender;
        shares = previewWithdraw(badDebtAmt);
        uint256 maxShares = maxRedeem(owner);
        if (shares > maxShares) {
            revert ERC4626ExceededMaxMint(recipient, shares, maxShares);
        }

        if (caller != owner) {
            _spendAllowance(owner, caller, shares);
        }

        _burn(owner, shares);

        collateralOut = abi.decode(
            _delegateCall(abi.encodeCall(IOrderManager.dealBadDebt, (recipient, collateral, badDebtAmt))), (uint256)
        );

        emit DealBadDebt(caller, recipient, collateral, badDebtAmt, shares, collateralOut);
    }
```

## contracts/v1/vault/TermMaxVault.sol:451 `setCapacity`

`external onlyCuratorRole`

```solidity
function setCapacity(uint256 newCapacity) external onlyCuratorRole {
        if (newCapacity == _maxCapacity) revert AlreadySet();
        _maxCapacity = newCapacity;
        emit SetCapacity(_msgSender(), newCapacity);
    }
```

## contracts/v1/vault/TermMaxVault.sol:745 `afterSwap`

`external override`

```solidity
function afterSwap(uint256 ftReserve, uint256 xtReserve, int256 deltaFt, int256) external override {
        _delegateCall(abi.encodeCall(IOrderManager.afterSwap, (ftReserve, xtReserve, deltaFt)));
    }
```

## contracts/v1/test/MockFlashLoanReceiver.sol:19 `executeOperation`

`external override returns (bytes memory collateralData)`

```solidity
function executeOperation(address gtReceiver, IERC20 asset, uint256 amount, bytes calldata data)
        external
        override
        returns (bytes memory collateralData)
    {
        (address caller, uint256 collateralAmt) = abi.decode(data, (address, uint256));
        IERC20(collateral).approve(address(gt), collateralAmt);

        assert(gtReceiver == caller);
        assert(asset == underlying);
        assert(asset.balanceOf(address(this)) == amount);

        collateralData = abi.encode(collateralAmt);
    }
```

## contracts/v1/test/MockFlashLoanReceiver.sol:34 `leverageByXt`

`external returns (uint256 gtId)`

```solidity
function leverageByXt(uint128 xtAmt, bytes calldata callbackData) external returns (uint256 gtId) {
        xt.transferFrom(msg.sender, address(this), xtAmt);
        xt.approve(address(market), xtAmt);
        gtId = market.leverageByXt(msg.sender, xtAmt, callbackData);
    }
```

## contracts/v1/test/MockOrder.sol:224 `swapExactTokenToToken`

`external override nonReentrant isOpen returns (uint256 netTokenOut)`

```solidity
function swapExactTokenToToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        uint128 tokenAmtIn,
        uint128 minTokenOut,
        uint256
    ) external override nonReentrant isOpen returns (uint256 netTokenOut) {
        if (tokenIn == tokenOut) revert CantSwapSameToken();
        uint256 feeAmt = 0;
        uint256 ftBlanceBefore = ft.balanceOf(address(this));
        uint256 xtBlanceBefore = xt.balanceOf(address(this));

        tokenIn.safeTransferFrom(msg.sender, address(this), tokenAmtIn);
        if (tokenIn == debtToken) {
            tokenIn.safeIncreaseAllowance(address(market), tokenAmtIn);
            market.mint(address(this), tokenAmtIn);
        }
        if (tokenOut == debtToken) {
            ft.safeIncreaseAllowance(address(market), minTokenOut);
            xt.safeIncreaseAllowance(address(market), minTokenOut);
            market.burn(recipient, minTokenOut);
        } else {
            tokenOut.safeTransfer(recipient, minTokenOut);
        }

        netTokenOut = minTokenOut;

        if (address(_orderConfig.swapTrigger) != address(0)) {
            uint256 ftReserve = ft.balanceOf(address(this));
            uint256 xtReserve = xt.balanceOf(address(this));
            int256 deltaFt = ftReserve.toInt256() - ftBlanceBefore.toInt256();
            int256 deltaXt = xtReserve.toInt256() - xtBlanceBefore.toInt256();
            _orderConfig.swapTrigger.afterSwap(ftReserve, xtReserve, deltaFt, deltaXt);
        }
        emit SwapExactTokenToToken(
            tokenIn, tokenOut, msg.sender, recipient, tokenAmtIn, netTokenOut.toUint128(), feeAmt.toUint128()
        );
    }
```

## contracts/v1/test/MockOrder.sol:264 `swapTokenToExactToken`

`external nonReentrant isOpen returns (uint256 netTokenIn)`

```solidity
function swapTokenToExactToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        uint128 tokenAmtOut,
        uint128 maxTokenIn,
        uint256
    ) external nonReentrant isOpen returns (uint256 netTokenIn) {
        if (tokenIn == tokenOut) revert CantSwapSameToken();
        uint256 feeAmt = 0;
        uint256 ftBlanceBefore = ft.balanceOf(address(this));
        uint256 xtBlanceBefore = xt.balanceOf(address(this));

        tokenIn.safeTransferFrom(msg.sender, address(this), maxTokenIn);
        if (tokenIn == debtToken) {
            tokenIn.safeIncreaseAllowance(address(market), maxTokenIn);
            market.mint(address(this), maxTokenIn);
        }
        if (tokenOut == debtToken) {
            ft.safeIncreaseAllowance(address(market), tokenAmtOut);
            xt.safeIncreaseAllowance(address(market), tokenAmtOut);
            market.burn(recipient, tokenAmtOut);
        } else {
            tokenOut.safeTransfer(recipient, tokenAmtOut);
        }
        netTokenIn = maxTokenIn;

        if (address(_orderConfig.swapTrigger) != address(0)) {
            uint256 ftReserve = ft.balanceOf(address(this));
            uint256 xtReserve = xt.balanceOf(address(this));
            int256 deltaFt = ftReserve.toInt256() - ftBlanceBefore.toInt256();
            int256 deltaXt = xtReserve.toInt256() - xtBlanceBefore.toInt256();
            _orderConfig.swapTrigger.afterSwap(ftReserve, xtReserve, deltaFt, deltaXt);
        }
        emit SwapTokenToExactToken(
            tokenIn, tokenOut, msg.sender, recipient, tokenAmtOut, netTokenIn.toUint128(), feeAmt.toUint128()
        );
    }
```

## contracts/v1/test/MockERC20.sol:17 `mint`

`external`

```solidity
function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
```

## contracts/v1/test/MockFlashRepayer.sol:14 `flashRepay`

`external`

```solidity
function flashRepay(uint256 id, bool byUnderlying) external {
        gt.safeTransferFrom(msg.sender, address(this), id, "");
        gt.flashRepay(id, byUnderlying, abi.encode(msg.sender));
    }
```

## contracts/v1/test/MockFlashRepayer.sol:19 `executeOperation`

`external override`

```solidity
function executeOperation(IERC20 repayToken, uint128 debtAmt, address, bytes memory, bytes calldata)
        external
        override
    {
        repayToken.approve(address(gt), debtAmt);
    }
```

## contracts/v1/router/TermMaxRouter.sol:99 `swapExactTokenToToken`

`external whenNotPaused returns (uint256 netTokenOut)`

```solidity
function swapExactTokenToToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        ITermMaxOrder[] memory orders,
        uint128[] memory tradingAmts,
        uint128 minTokenOut,
        uint256 deadline
    ) external whenNotPaused returns (uint256 netTokenOut) {
        uint256 totalAmtIn = sum(tradingAmts);
        tokenIn.safeTransferFrom(msg.sender, address(this), totalAmtIn);
        netTokenOut = _swapExactTokenToToken(tokenIn, tokenOut, recipient, orders, tradingAmts, minTokenOut, deadline);
        emit SwapExactTokenToToken(tokenIn, tokenOut, msg.sender, recipient, orders, tradingAmts, netTokenOut);
    }
```

## contracts/v1/router/TermMaxRouter.sol:132 `swapTokenToExactToken`

`external whenNotPaused returns (uint256 netTokenIn)`

```solidity
function swapTokenToExactToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        ITermMaxOrder[] memory orders,
        uint128[] memory tradingAmts,
        uint128 maxTokenIn,
        uint256 deadline
    ) external whenNotPaused returns (uint256 netTokenIn) {
        tokenIn.safeTransferFrom(msg.sender, address(this), maxTokenIn);
        netTokenIn = _swapTokenToExactToken(tokenIn, tokenOut, recipient, orders, tradingAmts, maxTokenIn, deadline);
        tokenIn.safeTransfer(msg.sender, maxTokenIn - netTokenIn);
        emit SwapTokenToExactToken(tokenIn, tokenOut, msg.sender, recipient, orders, tradingAmts, netTokenIn);
    }
```

## contracts/v1/router/TermMaxRouter.sol:172 `sellTokens`

`external whenNotPaused returns (uint256 netTokenOut)`

```solidity
function sellTokens(
        address recipient,
        ITermMaxMarket market,
        uint128 ftInAmt,
        uint128 xtInAmt,
        ITermMaxOrder[] memory orders,
        uint128[] memory amtsToSellTokens,
        uint128 minTokenOut,
        uint256 deadline
    ) external whenNotPaused returns (uint256 netTokenOut) {
        (IERC20 ft, IERC20 xt,,, IERC20 debtToken) = market.tokens();
        (uint256 maxBurn, IERC20 toenToSell) = ftInAmt > xtInAmt ? (xtInAmt, ft) : (ftInAmt, xt);

        ft.safeTransferFrom(msg.sender, address(this), ftInAmt);
        ft.safeIncreaseAllowance(address(market), maxBurn);
        xt.safeTransferFrom(msg.sender, address(this), xtInAmt);
        xt.safeIncreaseAllowance(address(market), maxBurn);
        market.burn(recipient, maxBurn);
        netTokenOut = _swapExactTokenToToken(toenToSell, debtToken, recipient, orders, amtsToSellTokens, 0, deadline);
        netTokenOut += maxBurn;
        if (netTokenOut < minTokenOut) revert InsufficientTokenOut(address(debtToken), netTokenOut, minTokenOut);
        emit SellTokens(market, msg.sender, recipient, ftInAmt, xtInAmt, orders, amtsToSellTokens, netTokenOut);
    }
```

## contracts/v1/router/TermMaxRouter.sol:196 `leverageFromToken`

`external whenNotPaused returns (uint256 gtId, uint256 netXtOut)`

```solidity
function leverageFromToken(
        address recipient,
        ITermMaxMarket market,
        ITermMaxOrder[] memory orders,
        uint128[] memory amtsToBuyXt,
        uint128 minXtOut,
        uint128 tokenToSwap,
        uint128 maxLtv,
        SwapUnit[] memory units,
        uint256 deadline
    ) external whenNotPaused returns (uint256 gtId, uint256 netXtOut) {
        (, IERC20 xt, IGearingToken gt,, IERC20 debtToken) = market.tokens();
        uint256 totalAmtToBuyXt = sum(amtsToBuyXt);
        debtToken.safeTransferFrom(msg.sender, address(this), tokenToSwap + totalAmtToBuyXt);
        netXtOut = _swapExactTokenToToken(debtToken, xt, address(this), orders, amtsToBuyXt, minXtOut, deadline);

        bytes memory callbackData = abi.encode(address(gt), tokenToSwap, units, FlashLoanType.DEBT);
        xt.safeIncreaseAllowance(address(market), netXtOut);

        gtId = market.leverageByXt(recipient, netXtOut.toUint128(), callbackData);
        (,, bytes memory collateralData) = gt.loanInfo(gtId);
        (, uint128 ltv,) = gt.getLiquidationInfo(gtId);
        if (ltv > maxLtv) {
            revert LtvBiggerThanExpected(maxLtv, ltv);
        }
        emit IssueGt(market, gtId, msg.sender, recipient, tokenToSwap, netXtOut.toUint128(), ltv, collateralData);
    }
```

## contracts/v1/router/TermMaxRouter.sol:227 `leverageFromXt`

`external whenNotPaused returns (uint256 gtId)`

```solidity
function leverageFromXt(
        address recipient,
        ITermMaxMarket market,
        uint128 xtInAmt,
        uint128 tokenInAmt,
        uint128 maxLtv,
        SwapUnit[] memory units
    ) external whenNotPaused returns (uint256 gtId) {
        (, IERC20 xt, IGearingToken gt,, IERC20 debtToken) = market.tokens();
        xt.safeTransferFrom(msg.sender, address(this), xtInAmt);
        xt.safeIncreaseAllowance(address(market), xtInAmt);

        debtToken.safeTransferFrom(msg.sender, address(this), tokenInAmt);

        bytes memory callbackData = abi.encode(address(gt), tokenInAmt, units, FlashLoanType.DEBT);
        gtId = market.leverageByXt(recipient, xtInAmt.toUint128(), callbackData);

        (,, bytes memory collateralData) = gt.loanInfo(gtId);
        (, uint128 ltv,) = gt.getLiquidationInfo(gtId);
        if (ltv > maxLtv) {
            revert LtvBiggerThanExpected(maxLtv, ltv);
        }
        emit IssueGt(market, gtId, msg.sender, recipient, tokenInAmt, xtInAmt, ltv, collateralData);
    }
```

## contracts/v1/router/TermMaxRouter.sol:255 `leverageFromXtAndCollateral`

`external whenNotPaused returns (uint256 gtId)`

```solidity
function leverageFromXtAndCollateral(
        address recipient,
        ITermMaxMarket market,
        uint128 xtInAmt,
        uint128 collateralInAmt,
        uint128 maxLtv,
        SwapUnit[] memory units
    ) external whenNotPaused returns (uint256 gtId) {
        (, IERC20 xt, IGearingToken gt, address collAddr,) = market.tokens();
        IERC20 collateral = IERC20(collAddr);
        xt.safeTransferFrom(msg.sender, address(this), xtInAmt);
        xt.safeIncreaseAllowance(address(market), xtInAmt);

        collateral.safeTransferFrom(msg.sender, address(this), collateralInAmt);

        bytes memory callbackData = abi.encode(address(gt), 0, units, FlashLoanType.COLLATERAL);
        gtId = market.leverageByXt(recipient, xtInAmt.toUint128(), callbackData);

        (,, bytes memory collateralData) = gt.loanInfo(gtId);
        (, uint128 ltv,) = gt.getLiquidationInfo(gtId);
        if (ltv > maxLtv) {
            revert LtvBiggerThanExpected(maxLtv, ltv);
        }
        emit IssueGt(market, gtId, msg.sender, recipient, 0, xtInAmt, ltv, collateralData);
    }
```

## contracts/v1/router/TermMaxRouter.sol:284 `borrowTokenFromCollateral`

`external whenNotPaused returns (uint256)`

```solidity
function borrowTokenFromCollateral(
        address recipient,
        ITermMaxMarket market,
        uint256 collInAmt,
        ITermMaxOrder[] memory orders,
        uint128[] memory tokenAmtsWantBuy,
        uint128 maxDebtAmt,
        uint256 deadline
    ) external whenNotPaused returns (uint256) {
        (IERC20 ft,, IGearingToken gt, address collateralAddr, IERC20 debtToken) = market.tokens();
        IERC20(collateralAddr).safeTransferFrom(msg.sender, address(this), collInAmt);
        IERC20(collateralAddr).safeIncreaseAllowance(address(gt), collInAmt);

        (uint256 gtId, uint128 ftOutAmt) = market.issueFt(address(this), maxDebtAmt, _encodeAmount(collInAmt));
        uint256 netTokenIn =
            _swapTokenToExactToken(ft, debtToken, recipient, orders, tokenAmtsWantBuy, ftOutAmt, deadline);
        uint256 repayAmt = ftOutAmt - netTokenIn;
        if (repayAmt > 0) {
            ft.safeIncreaseAllowance(address(gt), repayAmt);
            gt.repay(gtId, repayAmt.toUint128(), false);
        }

        gt.safeTransferFrom(address(this), recipient, gtId);
        emit Borrow(market, gtId, msg.sender, recipient, collInAmt, ftOutAmt, netTokenIn.toUint128());
        return gtId;
    }
```

## contracts/v1/router/TermMaxRouter.sol:311 `borrowTokenFromCollateral`

`external whenNotPaused returns (uint256)`

```solidity
function borrowTokenFromCollateral(address recipient, ITermMaxMarket market, uint256 collInAmt, uint256 borrowAmt)
        external
        whenNotPaused
        returns (uint256)
    {
        (IERC20 ft, IERC20 xt, IGearingToken gt, address collateralAddr,) = market.tokens();

        IERC20(collateralAddr).safeTransferFrom(msg.sender, address(this), collInAmt);
        IERC20(collateralAddr).safeIncreaseAllowance(address(gt), collInAmt);

        uint256 mintGtFeeRatio = market.mintGtFeeRatio();
        uint128 debtAmt = ((borrowAmt * Constants.DECIMAL_BASE) / (Constants.DECIMAL_BASE - mintGtFeeRatio)).toUint128();

        (uint256 gtId, uint128 ftOutAmt) = market.issueFt(address(this), debtAmt, _encodeAmount(collInAmt));
        borrowAmt = borrowAmt.min(ftOutAmt);
        xt.safeTransferFrom(msg.sender, address(this), borrowAmt);

        ft.safeIncreaseAllowance(address(market), borrowAmt);
        xt.safeIncreaseAllowance(address(market), borrowAmt);

        market.burn(recipient, borrowAmt);

        gt.safeTransferFrom(address(this), recipient, gtId);
        emit Borrow(market, gtId, msg.sender, recipient, collInAmt, debtAmt, borrowAmt.toUint128());
        return gtId;
    }
```

## contracts/v1/router/TermMaxRouter.sol:365 `flashRepayFromColl`

`external whenNotPaused returns (uint256 netTokenOut)`

```solidity
function flashRepayFromColl(
        address recipient,
        ITermMaxMarket market,
        uint256 gtId,
        ITermMaxOrder[] memory orders,
        uint128[] memory amtsToBuyFt,
        bool byDebtToken,
        SwapUnit[] memory units,
        uint256 deadline
    ) external whenNotPaused returns (uint256 netTokenOut) {
        (IERC20 ft,, IGearingToken gt,, IERC20 debtToken) = market.tokens();
        gt.safeTransferFrom(msg.sender, address(this), gtId, "");
        gt.flashRepay(gtId, byDebtToken, abi.encode(orders, amtsToBuyFt, ft, units, deadline));
        netTokenOut = debtToken.balanceOf(address(this));
        debtToken.safeTransfer(recipient, netTokenOut);
    }
```

## contracts/v1/router/TermMaxRouter.sol:385 `repayByTokenThroughFt`

`external whenNotPaused returns (uint256 returnAmt)`

```solidity
function repayByTokenThroughFt(
        address recipient,
        ITermMaxMarket market,
        uint256 gtId,
        ITermMaxOrder[] memory orders,
        uint128[] memory ftAmtsWantBuy,
        uint128 maxTokenIn,
        uint256 deadline
    ) external whenNotPaused returns (uint256 returnAmt) {
        (IERC20 ft,, IGearingToken gt,, IERC20 debtToken) = market.tokens();

        debtToken.safeTransferFrom(msg.sender, address(this), maxTokenIn);
        uint256 netCost =
            _swapTokenToExactToken(debtToken, ft, address(this), orders, ftAmtsWantBuy, maxTokenIn, deadline);
        uint256 totalFtAmt = sum(ftAmtsWantBuy);
        (, uint128 repayAmt,) = gt.loanInfo(gtId);

        if (totalFtAmt < repayAmt) {
            repayAmt = totalFtAmt.toUint128();
        }
        ft.safeIncreaseAllowance(address(gt), repayAmt);
        gt.repay(gtId, repayAmt, false);

        returnAmt = maxTokenIn - netCost;
        debtToken.safeTransfer(recipient, returnAmt);
        if (totalFtAmt > repayAmt) {
            ft.safeTransfer(recipient, totalFtAmt - repayAmt);
        }

        emit RepayByTokenThroughFt(market, gtId, msg.sender, recipient, repayAmt, returnAmt);
    }
```

## contracts/v1/router/TermMaxRouter.sol:417 `redeemAndSwap`

`external whenNotPaused returns (uint256)`

```solidity
function redeemAndSwap(
        address recipient,
        ITermMaxMarket market,
        uint256 ftAmount,
        SwapUnit[] memory units,
        uint256 minTokenOut
    ) external whenNotPaused returns (uint256) {
        (IERC20 ft,,, address collateralAddr, IERC20 debtToken) = market.tokens();
        ft.safeTransferFrom(msg.sender, address(this), ftAmount);
        ft.safeIncreaseAllowance(address(market), ftAmount);
        (uint256 redeemedAmt, bytes memory collateralData) = market.redeem(ftAmount, address(this));
        redeemedAmt += _decodeAmount(_doSwap(collateralData, units));
        if (redeemedAmt < minTokenOut) {
            revert InsufficientTokenOut(address(debtToken), redeemedAmt, minTokenOut);
        }
        debtToken.safeTransfer(recipient, redeemedAmt);
        emit RedeemAndSwap(market, ftAmount, msg.sender, recipient, redeemedAmt);
        return redeemedAmt;
    }
```

## contracts/v1/router/TermMaxRouter.sol:437 `createOrderAndDeposit`

`external whenNotPaused returns (ITermMaxOrder order)`

```solidity
function createOrderAndDeposit(
        ITermMaxMarket market,
        address maker,
        uint256 maxXtReserve,
        ISwapCallback swapTrigger,
        uint256 debtTokenToDeposit,
        uint128 ftToDeposit,
        uint128 xtToDeposit,
        CurveCuts memory curveCuts
    ) external whenNotPaused returns (ITermMaxOrder order) {
        (IERC20 ft, IERC20 xt,,, IERC20 debtToken) = market.tokens();
        order = market.createOrder(maker, maxXtReserve, swapTrigger, curveCuts);
        if (debtTokenToDeposit > 0) {
            debtToken.safeTransferFrom(msg.sender, address(this), debtTokenToDeposit);
            debtToken.safeIncreaseAllowance(address(market), debtTokenToDeposit);
            market.mint(address(order), debtTokenToDeposit);
        }
        if (ftToDeposit > 0) {
            ft.safeTransferFrom(msg.sender, address(order), ftToDeposit);
        }
        if (xtToDeposit > 0) {
            xt.safeTransferFrom(msg.sender, address(order), xtToDeposit);
        }

        emit CreateOrderAndDeposit(market, order, maker, debtTokenToDeposit, ftToDeposit, xtToDeposit, curveCuts);
    }
```

## contracts/v1/router/TermMaxRouter.sol:465 `executeOperation`

`external returns (bytes memory collateralData)`

```solidity
function executeOperation(address, IERC20, uint256 amount, bytes memory data)
        external
        returns (bytes memory collateralData)
    {
        (address gt, uint256 tokenInAmt, SwapUnit[] memory units, FlashLoanType flashLoanType) =
            abi.decode(data, (address, uint256, SwapUnit[], FlashLoanType));
        uint256 totalAmount = amount + tokenInAmt;
        collateralData = _doSwap(abi.encode(totalAmount), units);
        SwapUnit memory lastUnit = units[units.length - 1];
        if (!adapterWhitelist[lastUnit.adapter]) {
            revert AdapterNotWhitelisted(lastUnit.adapter);
        }

        if (flashLoanType == FlashLoanType.COLLATERAL) {
            IERC20 collateral = IERC20(lastUnit.tokenOut);
            uint256 collateralBalance = collateral.balanceOf(address(this));
            collateralData = _encodeAmount(collateralBalance);
            // approve all collateral if fashloan type is collateral
            collateral.safeIncreaseAllowance(gt, collateralBalance);
        } else if (flashLoanType == FlashLoanType.DEBT) {
            bytes memory approvalData =
                abi.encodeCall(ISwapAdapter.approveOutputToken, (lastUnit.tokenOut, gt, collateralData));
            (bool success, bytes memory returnData) = lastUnit.adapter.delegatecall(approvalData);
            if (!success) {
                revert ApproveTokenFailWhenSwap(lastUnit.tokenOut, returnData);
            }
        }
    }
```

## contracts/v1/router/TermMaxRouter.sol:507 `executeOperation`

`external override`

```solidity
function executeOperation(
        IERC20 repayToken,
        uint128 debtAmt,
        address,
        bytes memory collateralData,
        bytes memory callbackData
    ) external override {
        (
            ITermMaxOrder[] memory orders,
            uint128[] memory amtsToBuyFt,
            IERC20 ft,
            SwapUnit[] memory units,
            uint256 deadline
        ) = abi.decode(callbackData, (ITermMaxOrder[], uint128[], IERC20, SwapUnit[], uint256));
        bytes memory outData = _doSwap(collateralData, units);

        if (address(repayToken) == address(ft)) {
            IERC20 debtToken = IERC20(units[units.length - 1].tokenOut);
            uint256 amount = abi.decode(outData, (uint256));
            _swapTokenToExactToken(debtToken, ft, address(this), orders, amtsToBuyFt, amount.toUint128(), deadline);
        }
        repayToken.safeIncreaseAllowance(msg.sender, debtAmt);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:119 `swapExactTokenToToken`

`external nonReentrant whenNotPaused returns (uint256 netTokenOut)`

```solidity
function swapExactTokenToToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        ITermMaxOrder[] memory orders,
        uint128[] memory tradingAmts,
        uint128 minTokenOut,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256 netTokenOut) {
        uint256 totalAmtIn = sum(tradingAmts);
        tokenIn.safeTransferFrom(msg.sender, address(this), totalAmtIn);
        netTokenOut = _swapExactTokenToToken(tokenIn, tokenOut, recipient, orders, tradingAmts, minTokenOut, deadline);
        emit SwapExactTokenToToken(tokenIn, tokenOut, msg.sender, recipient, orders, tradingAmts, netTokenOut);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:152 `swapTokenToExactToken`

`external nonReentrant whenNotPaused returns (uint256 netTokenIn)`

```solidity
function swapTokenToExactToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        ITermMaxOrder[] memory orders,
        uint128[] memory tradingAmts,
        uint128 maxTokenIn,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256 netTokenIn) {
        tokenIn.safeTransferFrom(msg.sender, address(this), maxTokenIn);
        netTokenIn = _swapTokenToExactToken(tokenIn, tokenOut, recipient, orders, tradingAmts, maxTokenIn, deadline);
        tokenIn.safeTransfer(msg.sender, maxTokenIn - netTokenIn);
        emit SwapTokenToExactToken(tokenIn, tokenOut, msg.sender, recipient, orders, tradingAmts, netTokenIn);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:192 `sellTokens`

`external nonReentrant whenNotPaused returns (uint256 netTokenOut)`

```solidity
function sellTokens(
        address recipient,
        ITermMaxMarket market,
        uint128 ftInAmt,
        uint128 xtInAmt,
        ITermMaxOrder[] memory orders,
        uint128[] memory amtsToSellTokens,
        uint128 minTokenOut,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256 netTokenOut) {
        (IERC20 ft, IERC20 xt,,, IERC20 debtToken) = market.tokens();
        (uint256 maxBurn, IERC20 toenToSell) = ftInAmt > xtInAmt ? (xtInAmt, ft) : (ftInAmt, xt);

        ft.safeTransferFrom(msg.sender, address(this), ftInAmt);
        ft.safeIncreaseAllowance(address(market), maxBurn);
        xt.safeTransferFrom(msg.sender, address(this), xtInAmt);
        xt.safeIncreaseAllowance(address(market), maxBurn);
        market.burn(recipient, maxBurn);
        netTokenOut = _swapExactTokenToToken(toenToSell, debtToken, recipient, orders, amtsToSellTokens, 0, deadline);
        netTokenOut += maxBurn;
        if (netTokenOut < minTokenOut) revert InsufficientTokenOut(address(debtToken), netTokenOut, minTokenOut);
        emit SellTokens(market, msg.sender, recipient, ftInAmt, xtInAmt, orders, amtsToSellTokens, netTokenOut);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:216 `leverageFromToken`

`external nonReentrant whenNotPaused returns (uint256 gtId, uint256 netXtOut)`

```solidity
function leverageFromToken(
        address recipient,
        ITermMaxMarket market,
        ITermMaxOrder[] memory orders,
        uint128[] memory amtsToBuyXt,
        uint128 minXtOut,
        uint128 tokenToSwap,
        uint128 maxLtv,
        SwapUnit[] memory units,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256 gtId, uint256 netXtOut) {
        assembly {
            tstore(T_CALLBACK_ADDRESS_STORE, market) // set callback address
        }
        (, IERC20 xt, IGearingToken gt,, IERC20 debtToken) = market.tokens();
        uint256 totalAmtToBuyXt = sum(amtsToBuyXt);
        debtToken.safeTransferFrom(msg.sender, address(this), tokenToSwap + totalAmtToBuyXt);
        netXtOut = _swapExactTokenToToken(debtToken, xt, address(this), orders, amtsToBuyXt, minXtOut, deadline);

        bytes memory callbackData = abi.encode(address(gt), tokenToSwap, units, FlashLoanType.DEBT);
        xt.safeIncreaseAllowance(address(market), netXtOut);

        gtId = market.leverageByXt(recipient, netXtOut.toUint128(), callbackData);
        (,, bytes memory collateralData) = gt.loanInfo(gtId);
        (, uint128 ltv,) = gt.getLiquidationInfo(gtId);
        if (ltv > maxLtv) {
            revert LtvBiggerThanExpected(maxLtv, ltv);
        }
        emit IssueGt(market, gtId, msg.sender, recipient, tokenToSwap, netXtOut.toUint128(), ltv, collateralData);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:250 `leverageFromXt`

`external nonReentrant whenNotPaused returns (uint256 gtId)`

```solidity
function leverageFromXt(
        address recipient,
        ITermMaxMarket market,
        uint128 xtInAmt,
        uint128 tokenInAmt,
        uint128 maxLtv,
        SwapUnit[] memory units
    ) external nonReentrant whenNotPaused returns (uint256 gtId) {
        assembly {
            tstore(T_CALLBACK_ADDRESS_STORE, market) // set callback address
        }
        (, IERC20 xt, IGearingToken gt,, IERC20 debtToken) = market.tokens();
        xt.safeTransferFrom(msg.sender, address(this), xtInAmt);
        xt.safeIncreaseAllowance(address(market), xtInAmt);

        debtToken.safeTransferFrom(msg.sender, address(this), tokenInAmt);

        bytes memory callbackData = abi.encode(address(gt), tokenInAmt, units, FlashLoanType.DEBT);
        gtId = market.leverageByXt(recipient, xtInAmt.toUint128(), callbackData);

        (,, bytes memory collateralData) = gt.loanInfo(gtId);
        (, uint128 ltv,) = gt.getLiquidationInfo(gtId);
        if (ltv > maxLtv) {
            revert LtvBiggerThanExpected(maxLtv, ltv);
        }
        emit IssueGt(market, gtId, msg.sender, recipient, tokenInAmt, xtInAmt, ltv, collateralData);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:281 `leverageFromXtAndCollateral`

`external nonReentrant whenNotPaused returns (uint256 gtId)`

```solidity
function leverageFromXtAndCollateral(
        address recipient,
        ITermMaxMarket market,
        uint128 xtInAmt,
        uint128 collateralInAmt,
        uint128 maxLtv,
        SwapUnit[] memory units
    ) external nonReentrant whenNotPaused returns (uint256 gtId) {
        assembly {
            tstore(T_CALLBACK_ADDRESS_STORE, market) // set callback address
        }
        (, IERC20 xt, IGearingToken gt, address collAddr,) = market.tokens();
        IERC20 collateral = IERC20(collAddr);
        xt.safeTransferFrom(msg.sender, address(this), xtInAmt);
        xt.safeIncreaseAllowance(address(market), xtInAmt);

        collateral.safeTransferFrom(msg.sender, address(this), collateralInAmt);

        bytes memory callbackData = abi.encode(address(gt), 0, units, FlashLoanType.COLLATERAL);
        gtId = market.leverageByXt(recipient, xtInAmt.toUint128(), callbackData);

        (,, bytes memory collateralData) = gt.loanInfo(gtId);
        (, uint128 ltv,) = gt.getLiquidationInfo(gtId);
        if (ltv > maxLtv) {
            revert LtvBiggerThanExpected(maxLtv, ltv);
        }
        emit IssueGt(market, gtId, msg.sender, recipient, 0, xtInAmt, ltv, collateralData);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:313 `borrowTokenFromCollateral`

`external nonReentrant whenNotPaused returns (uint256)`

```solidity
function borrowTokenFromCollateral(
        address recipient,
        ITermMaxMarket market,
        uint256 collInAmt,
        ITermMaxOrder[] memory orders,
        uint128[] memory tokenAmtsWantBuy,
        uint128 maxDebtAmt,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256) {
        (IERC20 ft,, IGearingToken gt, address collateralAddr, IERC20 debtToken) = market.tokens();
        IERC20(collateralAddr).safeTransferFrom(msg.sender, address(this), collInAmt);
        IERC20(collateralAddr).safeIncreaseAllowance(address(gt), collInAmt);

        (uint256 gtId, uint128 ftOutAmt) = market.issueFt(address(this), maxDebtAmt, _encodeAmount(collInAmt));
        gt.safeTransferFrom(address(this), recipient, gtId);
        uint256 netTokenIn =
            _swapTokenToExactToken(ft, debtToken, recipient, orders, tokenAmtsWantBuy, ftOutAmt, deadline);
        uint256 repayAmt = ftOutAmt - netTokenIn;
        if (repayAmt > 0) {
            ft.safeIncreaseAllowance(address(gt), repayAmt);
            gt.repay(gtId, repayAmt.toUint128(), false);
        }

        emit Borrow(market, gtId, msg.sender, recipient, collInAmt, ftOutAmt, netTokenIn.toUint128());
        return gtId;
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:340 `borrowTokenFromCollateral`

`external nonReentrant whenNotPaused returns (uint256)`

```solidity
function borrowTokenFromCollateral(address recipient, ITermMaxMarket market, uint256 collInAmt, uint256 borrowAmt)
        external
        nonReentrant
        whenNotPaused
        returns (uint256)
    {
        (IERC20 ft, IERC20 xt, IGearingToken gt, address collateralAddr,) = market.tokens();

        IERC20(collateralAddr).safeTransferFrom(msg.sender, address(this), collInAmt);
        IERC20(collateralAddr).safeIncreaseAllowance(address(gt), collInAmt);

        uint256 mintGtFeeRatio = market.mintGtFeeRatio();
        uint128 debtAmt = ((borrowAmt * Constants.DECIMAL_BASE) / (Constants.DECIMAL_BASE - mintGtFeeRatio)).toUint128();

        (uint256 gtId, uint128 ftOutAmt) = market.issueFt(address(this), debtAmt, _encodeAmount(collInAmt));
        gt.safeTransferFrom(address(this), recipient, gtId);
        borrowAmt = borrowAmt.min(ftOutAmt);
        xt.safeTransferFrom(msg.sender, address(this), borrowAmt);

        ft.safeIncreaseAllowance(address(market), borrowAmt);
        xt.safeIncreaseAllowance(address(market), borrowAmt);

        market.burn(recipient, borrowAmt);

        emit Borrow(market, gtId, msg.sender, recipient, collInAmt, debtAmt, borrowAmt.toUint128());
        return gtId;
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:396 `flashRepayFromColl`

`external nonReentrant whenNotPaused returns (uint256 netTokenOut)`

```solidity
function flashRepayFromColl(
        address recipient,
        ITermMaxMarket market,
        uint256 gtId,
        ITermMaxOrder[] memory orders,
        uint128[] memory amtsToBuyFt,
        bool byDebtToken,
        SwapUnit[] memory units,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256 netTokenOut) {
        (IERC20 ft,, IGearingToken gtToken,, IERC20 debtToken) = market.tokens();
        assembly {
            // set callback address
            tstore(T_CALLBACK_ADDRESS_STORE, gtToken)
        }
        gtToken.safeTransferFrom(msg.sender, address(this), gtId, "");
        gtToken.flashRepay(gtId, byDebtToken, abi.encode(orders, amtsToBuyFt, ft, units, deadline));
        netTokenOut = debtToken.balanceOf(address(this));
        debtToken.safeTransfer(recipient, netTokenOut);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:420 `repayByTokenThroughFt`

`external nonReentrant whenNotPaused returns (uint256 returnAmt)`

```solidity
function repayByTokenThroughFt(
        address recipient,
        ITermMaxMarket market,
        uint256 gtId,
        ITermMaxOrder[] memory orders,
        uint128[] memory ftAmtsWantBuy,
        uint128 maxTokenIn,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256 returnAmt) {
        (IERC20 ft,, IGearingToken gt,, IERC20 debtToken) = market.tokens();

        debtToken.safeTransferFrom(msg.sender, address(this), maxTokenIn);
        uint256 netCost =
            _swapTokenToExactToken(debtToken, ft, address(this), orders, ftAmtsWantBuy, maxTokenIn, deadline);
        uint256 totalFtAmt = sum(ftAmtsWantBuy);
        (, uint128 repayAmt,) = gt.loanInfo(gtId);

        if (totalFtAmt < repayAmt) {
            repayAmt = totalFtAmt.toUint128();
        }
        ft.safeIncreaseAllowance(address(gt), repayAmt);
        gt.repay(gtId, repayAmt, false);

        returnAmt = maxTokenIn - netCost;
        debtToken.safeTransfer(recipient, returnAmt);
        if (totalFtAmt > repayAmt) {
            ft.safeTransfer(recipient, totalFtAmt - repayAmt);
        }

        emit RepayByTokenThroughFt(market, gtId, msg.sender, recipient, repayAmt, returnAmt);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:452 `redeemAndSwap`

`external nonReentrant whenNotPaused returns (uint256)`

```solidity
function redeemAndSwap(
        address recipient,
        ITermMaxMarket market,
        uint256 ftAmount,
        SwapUnit[] memory units,
        uint256 minTokenOut
    ) external nonReentrant whenNotPaused returns (uint256) {
        (IERC20 ft,,, address collateralAddr, IERC20 debtToken) = market.tokens();
        ft.safeTransferFrom(msg.sender, address(this), ftAmount);
        ft.safeIncreaseAllowance(address(market), ftAmount);
        (uint256 redeemedAmt, bytes memory collateralData) = market.redeem(ftAmount, address(this));
        redeemedAmt += _decodeAmount(_doSwap(collateralData, units));
        if (redeemedAmt < minTokenOut) {
            revert InsufficientTokenOut(address(debtToken), redeemedAmt, minTokenOut);
        }
        debtToken.safeTransfer(recipient, redeemedAmt);
        emit RedeemAndSwap(market, ftAmount, msg.sender, recipient, redeemedAmt);
        return redeemedAmt;
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:472 `createOrderAndDeposit`

`external nonReentrant whenNotPaused returns (ITermMaxOrder order)`

```solidity
function createOrderAndDeposit(
        ITermMaxMarket market,
        address maker,
        uint256 maxXtReserve,
        ISwapCallback swapTrigger,
        uint256 debtTokenToDeposit,
        uint128 ftToDeposit,
        uint128 xtToDeposit,
        CurveCuts memory curveCuts
    ) external nonReentrant whenNotPaused returns (ITermMaxOrder order) {
        (IERC20 ft, IERC20 xt,,, IERC20 debtToken) = market.tokens();
        order = market.createOrder(maker, maxXtReserve, swapTrigger, curveCuts);
        if (debtTokenToDeposit > 0) {
            debtToken.safeTransferFrom(msg.sender, address(this), debtTokenToDeposit);
            debtToken.safeIncreaseAllowance(address(market), debtTokenToDeposit);
            market.mint(address(order), debtTokenToDeposit);
        }
        if (ftToDeposit > 0) {
            ft.safeTransferFrom(msg.sender, address(order), ftToDeposit);
        }
        if (xtToDeposit > 0) {
            xt.safeTransferFrom(msg.sender, address(order), xtToDeposit);
        }

        emit CreateOrderAndDeposit(market, order, maker, debtTokenToDeposit, ftToDeposit, xtToDeposit, curveCuts);
    }
```

## contracts/v1/router/TermMaxRouter_Repay_Gt.sol:599 `repayGt`

`external override nonReentrant whenNotPaused returns (uint128 repayAmt)`

```solidity
function repayGt(ITermMaxMarket market, uint256 gtId, uint128 maxRepayAmt, bool byDebtToken)
        external
        override
        nonReentrant
        whenNotPaused
        returns (uint128 repayAmt)
    {
        (IERC20 ft,, IGearingToken gt,, IERC20 debtToken) = market.tokens();
        (, uint128 debtAmt,) = gt.loanInfo(gtId); // Ensure gtId is valid
        if (maxRepayAmt > debtAmt) {
            repayAmt = debtAmt;
        } else {
            repayAmt = maxRepayAmt;
        }
        IERC20 repayToken = byDebtToken ? debtToken : ft;
        repayToken.safeTransferFrom(msg.sender, address(this), repayAmt);
        repayToken.safeIncreaseAllowance(address(gt), repayAmt);
        gt.repay(gtId, repayAmt, byDebtToken);
    }
```

## contracts/v1/router/TermMaxRouter_V1_1_2.sol:127 `swapExactTokenToToken`

`external nonReentrant whenNotPaused returns (uint256 netTokenOut)`

```solidity
function swapExactTokenToToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        ITermMaxOrder[] memory orders,
        uint128[] memory tradingAmts,
        uint128 minTokenOut,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256 netTokenOut) {
        uint256 totalAmtIn = sum(tradingAmts);
        tokenIn.safeTransferFrom(msg.sender, address(this), totalAmtIn);
        netTokenOut = _swapExactTokenToToken(tokenIn, tokenOut, recipient, orders, tradingAmts, minTokenOut, deadline);
        emit SwapExactTokenToToken(tokenIn, tokenOut, msg.sender, recipient, orders, tradingAmts, netTokenOut);
    }
```

## contracts/v1/router/TermMaxRouter_V1_1_2.sol:153 `swapExactTokenToTokenWithDex`

`external nonReentrant whenNotPaused returns (uint256 netTokenOut)`

```solidity
function swapExactTokenToTokenWithDex(
        IERC20 tokenIn,
        uint256 inputAmt,
        IERC20 tokenOut,
        address recipient,
        ITermMaxOrder order,
        uint128 minTokenOut,
        uint256 deadline,
        SwapUnit[] memory units
    ) external nonReentrant whenNotPaused returns (uint256 netTokenOut) {
        // transfer total input amount from user
        tokenIn.safeTransferFrom(msg.sender, address(this), inputAmt);
        IERC20 debtToken = IERC20(units[units.length - 1].tokenOut);
        // swap input token to trading tokens through dex first
        uint128 tokenToTrade = abi.decode(_doSwap(abi.encode(inputAmt), units), (uint256)).toUint128();

        ITermMaxOrder[] memory orders = new ITermMaxOrder[](1);
        orders[0] = order;
        uint128[] memory tradingAmts = new uint128[](1);
        tradingAmts[0] = tokenToTrade;

        netTokenOut = _swapExactTokenToToken(debtToken, tokenOut, recipient, orders, tradingAmts, minTokenOut, deadline);
        emit SwapExactTokenToToken(tokenIn, tokenOut, msg.sender, recipient, orders, tradingAmts, netTokenOut);
    }
```

## contracts/v1/router/TermMaxRouter_V1_1_2.sol:196 `swapTokenToExactToken`

`external nonReentrant whenNotPaused returns (uint256 netTokenIn)`

```solidity
function swapTokenToExactToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        ITermMaxOrder[] memory orders,
        uint128[] memory tradingAmts,
        uint128 maxTokenIn,
        uint256 deadline
    ) external nonReentrant whenNotPaused returns (uint256 netTokenIn) {
        tokenIn.safeTransferFrom(msg.sender, address(this), maxTokenIn);
        netTokenIn = _swapTokenToExactToken(tokenIn, tokenOut, recipient, orders, tradingAmts, maxTokenIn, deadline);
        tokenIn.safeTransfer(msg.sender, maxTokenIn - netTokenIn);
        emit SwapTokenToExactToken(tokenIn, tokenOut, msg.sender, recipient, orders, tradingAmts, netTokenIn);
    }
```

## contracts/v1/tokens/MintableERC20.sol:23 `initialize`

`public override initializer`

```solidity
function initialize(string memory name, string memory symbol, uint8 decimals_) public override initializer {
        __ERC20_init(name, symbol);
        __Ownable_init(_msgSender());
        _decimals = decimals_;
    }
```

## contracts/v1/tokens/AbstractGearingToken.sol:234 `repay`

`external override nonReentrant`

```solidity
function repay(uint256 id, uint128 repayAmt, bool byDebtToken) external override nonReentrant {
        GtConfig memory config = _config;
        if (config.maturity <= block.timestamp) {
            revert GtIsExpired(id);
        }

        if (byDebtToken) {
            config.debtToken.safeTransferFrom(msg.sender, marketAddr(), repayAmt);
        } else {
            // Those ft tokens have been approved to market and will be burn after maturity
            config.ft.safeTransferFrom(msg.sender, marketAddr(), repayAmt);
        }
        _repay(id, repayAmt);
        emit Repay(id, repayAmt, byDebtToken);
    }
```

## contracts/v1/tokens/AbstractGearingToken.sol:384 `liquidate`

`external override nonReentrant`

```solidity
function liquidate(uint256 id, uint128 repayAmt, bool byDebtToken) external override nonReentrant {
        LoanInfo memory loan = loanMapping[id];
        GtConfig memory config = _config;
        if (!config.loanConfig.liquidatable) {
            revert GtDoNotSupportLiquidation();
        }
        (bool isLiquidable, uint128 maxRepayAmt, uint128 ltvBefore, ValueAndPrice memory valueAndPrice) =
            _getLiquidationInfo(loan, config);

        if (!isLiquidable) {
            uint256 liquidationDeadline = config.maturity + Constants.LIQUIDATION_WINDOW;
            if (block.timestamp >= liquidationDeadline) {
                revert CanNotLiquidationAfterFinalDeadline(id, liquidationDeadline);
            }
            revert GtIsSafe(id);
        }
        if (repayAmt > maxRepayAmt) {
            revert RepayAmtExceedsMaxRepayAmt(id, repayAmt, maxRepayAmt);
        }
        // Transfer token
        if (byDebtToken) {
            config.debtToken.safeTransferFrom(msg.sender, marketAddr(), repayAmt);
        } else {
            config.ft.safeTransferFrom(msg.sender, marketAddr(), repayAmt);
        }

        // Do liquidate
        (bytes memory cToLiquidator, bytes memory cToTreasurer, bytes memory remainningC) =
            _calcLiquidationResult(loan, repayAmt, valueAndPrice);

        if (repayAmt == loan.debtAmt) {
            if (remainningC.length > 0) {
                _transferCollateral(ownerOf(id), remainningC);
            }
            // update storage
            _burnInternal(id);
        } else {
            loan.debtAmt -= repayAmt;
            loan.collateralData = remainningC;

            // Check ltv after partial liquidation
            {
                valueAndPrice.collateralValue = _getCollateralValue(remainningC, valueAndPrice.collateralPriceData);
                valueAndPrice.debtValueWithDecimals =
                    (loan.debtAmt * valueAndPrice.debtPrice) / valueAndPrice.debtDenominator;
                uint128 ltvAfter = _calculateLtv(valueAndPrice);
                if (ltvBefore < ltvAfter) {
                    revert LtvIncreasedAfterLiquidation(id, ltvBefore, ltvAfter);
                }
            }
          
```

## contracts/v1/test/testnet/FaucetERC20.sol:21 `mint`

`external`

```solidity
function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
```

## contracts/v1/router/swapAdapters/ERC20SwapAdapter.sol:57 `transferOutputToken`

`external override`

```solidity
function transferOutputToken(address token, address to, bytes memory tokenData) external override {
        IERC20(token).safeTransfer(to, _decodeAmount(tokenData));
    }
```

## contracts/v1/router/swapAdapters/ERC20SwapAdapter.sol:64 `transferInputTokenFrom`

`external override`

```solidity
function transferInputTokenFrom(address token, address from, address to, bytes memory tokenData)
        external
        override
    {
        IERC20(token).safeTransferFrom(from, to, _decodeAmount(tokenData));
    }
```

## contracts/v2/vault/TermMaxVaultV2.sol:719 `afterSwap`

`external virtual override whenNotPaused`

```solidity
function afterSwap(uint256 ftReserve, uint256 xtReserve, int256 deltaFt, int256 deltaXt)
        external
        virtual
        override
        whenNotPaused
    {
        _delegateCall(
            abi.encodeCall(IOrderManagerV2.afterSwap, (IERC20(asset()), ftReserve, xtReserve, deltaFt, deltaXt))
        );
    }
```

## contracts/v2/vault/OrderManagerV2.sol:132 `depositAssets`

`external onlyProxy`

```solidity
function depositAssets(IERC20 asset, uint256 amount) external onlyProxy {
        _accruedInterest();
        // deposit to lpers
        uint256 amplifiedAmt = amount * Constants.DECIMAL_BASE_SQ;
        _totalFt += amplifiedAmt;
        _accretingPrincipal += amplifiedAmt;
        _depositToPoolOrNot(asset, amount);
    }
```

## contracts/v2/vault/OrderManagerV2.sol:192 `dealBadDebt`

`external onlyProxy returns (uint256 collateralOut)`

```solidity
function dealBadDebt(address recipient, address collateral, uint256 amount)
        external
        onlyProxy
        returns (uint256 collateralOut)
    {
        _accruedInterest();
        uint256 badDebtAmt = _badDebtMapping[collateral];
        require(badDebtAmt != 0, VaultErrors.NoBadDebt(collateral));
        require(amount <= badDebtAmt, VaultErrors.InsufficientFunds(badDebtAmt, amount));
        uint256 collateralBalance = IERC20(collateral).balanceOf(address(this));
        collateralOut = (amount * collateralBalance) / badDebtAmt;
        IERC20(collateral).safeTransfer(recipient, collateralOut);

        _badDebtMapping[collateral] -= amount;
        uint256 amplifiedAmt = amount * Constants.DECIMAL_BASE_SQ;
        _accretingPrincipal -= amplifiedAmt;
        _totalFt -= amplifiedAmt;
    }
```

## contracts/v2/vault/OrderManagerV2.sol:276 `afterSwap`

`external onlyProxy`

```solidity
function afterSwap(IERC20 asset, uint256 ftReserve, uint256 xtReserve, int256 deltaFt, int256 deltaXt)
        external
        onlyProxy
    {
        address orderAddress = msg.sender;
        /// @dev Check if the order is valid
        uint256 maturity = _orderMaturityMapping[orderAddress];
        require(maturity != 0, VaultErrors.UnauthorizedOrder(orderAddress));

        /// @dev Calculate interest from last update time to now
        _accruedInterest();

        /// @dev If ft increases, interest increases, and if ft decreases,
        ///  interest decreases. Update the expected annualized return based on the change
        uint256 ftChanges;

        if (deltaFt > 0) {
            ftChanges = uint256(deltaFt) * Constants.DECIMAL_BASE_SQ;
            _totalFt += ftChanges;
            uint256 deltaAnnualizedInterest = (ftChanges * 365 days) / (maturity - block.timestamp);

            _maturityToInterest[maturity.toUint64()] += deltaAnnualizedInterest;

            _annualizedInterest += deltaAnnualizedInterest;

            /// @dev release xt if needed
            int256 finalXtReserve = xtReserve.toInt256() + deltaXt;
            if (finalXtReserve < 0) {
                _releaseLiquidity(ITermMaxOrder(orderAddress), asset, uint256(-finalXtReserve));
            }
        } else {
            ftChanges = uint256(-deltaFt) * Constants.DECIMAL_BASE_SQ;
            _totalFt -= ftChanges;
            uint256 deltaAnnualizedInterest = (ftChanges * 365 days) / (maturity - block.timestamp);
            uint256 maturityInterest = _maturityToInterest[maturity.toUint64()];
            if (maturityInterest < deltaAnnualizedInterest || _annualizedInterest < deltaAnnualizedInterest) {
                revert VaultErrors.OrderHasNegativeInterest();
            }
            _maturityToInterest[uint64(maturity)] = maturityInterest - deltaAnnualizedInterest;
            _annualizedInterest -= deltaAnnualizedInterest;
            _checkApy();

            /// @dev Make sure that the interest of order does not go negative
            int256 finalFtReserve = ftReserve.toInt256() + deltaFt;
            int256 finalXtReserve = xtReserve.toInt256() + deltaXt;
            
```

## contracts/v2/test/MockFlashRepayerV2.sol:14 `flashRepay`

`external`

```solidity
function flashRepay(uint256 id, uint128 repayAmt, bool byUnderlying, bytes calldata removedCollateral) external {
        gt.safeTransferFrom(msg.sender, address(this), id, "");
        bool repayAll = IGearingTokenV2(address(gt)).flashRepay(id, repayAmt, byUnderlying, removedCollateral, "");
        if (!repayAll) {
            gt.safeTransferFrom(address(this), msg.sender, id, "");
        }
    }
```

## contracts/v2/test/MockFlashRepayerV2.sol:22 `executeOperation`

`external override`

```solidity
function executeOperation(IERC20 repayToken, uint128 debtAmt, address, bytes memory, bytes calldata)
        external
        override
    {
        repayToken.approve(address(gt), debtAmt);
    }
```

## contracts/v2/test/MockOrderV2.sol:226 `swapExactTokenToToken`

`external override nonReentrant isOpen returns (uint256 netTokenOut)`

```solidity
function swapExactTokenToToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        uint128 tokenAmtIn,
        uint128 minTokenOut,
        uint256
    ) external override nonReentrant isOpen returns (uint256 netTokenOut) {
        if (tokenIn == tokenOut) revert CantSwapSameToken();
        uint256 feeAmt = 0;

        int256 deltaFt;
        int256 deltaXt;
        if (tokenIn == debtToken && tokenOut == ft) {
            deltaFt = -(minTokenOut - tokenAmtIn).toInt256();
            deltaXt = tokenAmtIn.toInt256();
        } else if (tokenIn == debtToken && tokenOut == xt) {
            deltaFt = tokenAmtIn.toInt256();
            deltaXt = -(minTokenOut - tokenAmtIn).toInt256();
        } else if (tokenIn == ft && tokenOut == debtToken) {
            deltaFt = (tokenAmtIn - minTokenOut).toInt256();
            deltaXt = -minTokenOut.toInt256();
        } else if (tokenIn == xt && tokenOut == debtToken) {
            deltaFt = -minTokenOut.toInt256();
            deltaXt = (tokenAmtIn - minTokenOut).toInt256();
        }

        if (address(_orderConfig.swapTrigger) != address(0)) {
            uint256 ftReserve = ft.balanceOf(address(this));
            uint256 xtReserve = xt.balanceOf(address(this));
            _orderConfig.swapTrigger.afterSwap(ftReserve, xtReserve, deltaFt, deltaXt);
        }

        tokenIn.safeTransferFrom(msg.sender, address(this), tokenAmtIn);
        if (tokenIn == debtToken) {
            tokenIn.safeIncreaseAllowance(address(market), tokenAmtIn);
            market.mint(address(this), tokenAmtIn);
        }
        if (tokenOut == debtToken) {
            ITermMaxMarketV2(address(market)).burn(address(this), address(this), minTokenOut);
        }
        tokenOut.safeTransfer(recipient, minTokenOut);

        netTokenOut = minTokenOut;
        emit SwapExactTokenToToken(
            tokenIn, tokenOut, msg.sender, recipient, tokenAmtIn, netTokenOut.toUint128(), feeAmt.toUint128()
        );
    }
```

## contracts/v2/test/MockOrderV2.sol:275 `swapTokenToExactToken`

`external nonReentrant isOpen returns (uint256 netTokenIn)`

```solidity
function swapTokenToExactToken(
        IERC20 tokenIn,
        IERC20 tokenOut,
        address recipient,
        uint128 tokenAmtOut,
        uint128 maxTokenIn,
        uint256
    ) external nonReentrant isOpen returns (uint256 netTokenIn) {
        if (tokenIn == tokenOut) revert CantSwapSameToken();
        uint256 feeAmt = 0;

        int256 deltaFt;
        int256 deltaXt;
        if (tokenIn == debtToken && tokenOut == ft) {
            deltaFt = -(tokenAmtOut - maxTokenIn).toInt256();
            deltaXt = maxTokenIn.toInt256();
        } else if (tokenIn == debtToken && tokenOut == xt) {
            deltaFt = maxTokenIn.toInt256();
            deltaXt = -(tokenAmtOut - maxTokenIn).toInt256();
        } else if (tokenIn == ft && tokenOut == debtToken) {
            deltaFt = (maxTokenIn - tokenAmtOut).toInt256();
            deltaXt = -tokenAmtOut.toInt256();
        } else if (tokenIn == xt && tokenOut == debtToken) {
            deltaFt = -tokenAmtOut.toInt256();
            deltaXt = (maxTokenIn - tokenAmtOut).toInt256();
        }

        if (address(_orderConfig.swapTrigger) != address(0)) {
            uint256 ftReserve = ft.balanceOf(address(this));
            uint256 xtReserve = xt.balanceOf(address(this));
            _orderConfig.swapTrigger.afterSwap(ftReserve, xtReserve, deltaFt, deltaXt);
        }

        tokenIn.safeTransferFrom(msg.sender, address(this), maxTokenIn);
        if (tokenIn == debtToken) {
            tokenIn.safeIncreaseAllowance(address(market), maxTokenIn);
            market.mint(address(this), maxTokenIn);
        }
        if (tokenOut == debtToken) {
            ITermMaxMarketV2(address(market)).burn(address(this), address(this), tokenAmtOut);
        }
        tokenOut.safeTransfer(recipient, tokenAmtOut);
        netTokenIn = maxTokenIn;

        emit SwapTokenToExactToken(
            tokenIn, tokenOut, msg.sender, recipient, tokenAmtOut, netTokenIn.toUint128(), feeAmt.toUint128()
        );
    }
```

## contracts/v2/test/MockOrderV2.sol:347 `initialize`

`external override initializer`

```solidity
function initialize(OrderInitialParams memory params) external override initializer {
        __Ownable_init_unchained(params.maker);
        __ReentrancyGuard_init_unchained();
        __Pausable_init_unchained();
        address _market = _msgSender();
        market = ITermMaxMarket(_market);
        maturity = params.maturity;
        ft = params.ft;
        xt = params.xt;
        debtToken = params.debtToken;
        gt = params.gt;
        _orderConfig = params.orderConfig;

        // _updateGeneralConfig(
        //     params.orderConfig.gtId,
        //     params.orderConfig.maxXtReserve,
        //     params.orderConfig.swapTrigger,
        //     params.virtualXtReserve
        // );
        emit OrderEventsV2.OrderInitialized(params.maker, _market);
    }
```

## contracts/v2/test/MockOrderV2.sol:382 `addLiquidity`

`external override`

```solidity
function addLiquidity(IERC20 asset, uint256 amount) external override {
        asset.safeTransferFrom(msg.sender, address(this), amount);
        asset.safeIncreaseAllowance(address(market), amount);
        market.mint(address(this), amount);
    }
```

## contracts/v2/test/MockAave.sol:35 `supply`

`external override`

```solidity
function supply(address asset, uint256 amount, address onBehalfOf, uint16 /* referralCode */ ) external override {
        if (amount == 0) {
            revert("MockAave: amount 0");
        }
        // Transfer tokens from sender to this contract
        IERC20(asset).transferFrom(msg.sender, address(this), amount);
        // Mint aTokens to the onBehalfOf address
        _mint(onBehalfOf, amount);
    }
```

## contracts/v2/test/MockAave.sol:45 `withdraw`

`external override returns (uint256)`

```solidity
function withdraw(address asset, uint256 amount, address to) external override returns (uint256) {
        if (amount == 0) {
            revert("MockAave: amount 0");
        }
        // Burn aTokens from sender
        _burn(msg.sender, amount);
        uint256 balance = IERC20(asset).balanceOf(address(this));
        if (balance < amount) {
            IMintableERC20(asset).mint(address(this), amount - balance);
        }
        // Transfer underlying tokens to the recipient
        IERC20(asset).transfer(to, amount);
        return amount;
    }
```

## contracts/v2/test/MockAave.sol:60 `simulateInterestAccrual`

`external`

```solidity
function simulateInterestAccrual(address to, uint256 amount) external {
        // Simulate interest accrual by minting aTokens
        _mint(to, amount);
    }
```

## contracts/v2/router/MakerHelper.sol:160 `mint`

`external`

```solidity
function mint(ITermMaxMarket market, address recipient, uint256 debtTokenToDeposit) external {
        (,,,, IERC20 debtToken) = market.tokens();
        debtToken.safeTransferFrom(msg.sender, address(this), debtTokenToDeposit);
        debtToken.safeIncreaseAllowance(address(market), debtTokenToDeposit);
        market.mint(recipient, debtTokenToDeposit);
        emit MakerHelperEvents.MintTokens(address(market), recipient, debtTokenToDeposit);
    }
```

## contracts/v2/router/MakerHelper.sol:168 `burn`

`external`

```solidity
function burn(ITermMaxMarket market, address recipient, uint256 amount) external {
        (IERC20 ft, IERC20 xt,,,) = market.tokens();
        ft.safeTransferFrom(msg.sender, address(this), amount);
        ft.safeIncreaseAllowance(address(market), amount);
        xt.safeTransferFrom(msg.sender, address(this), amount);
        xt.safeIncreaseAllowance(address(market), amount);
        market.burn(recipient, amount);
        emit MakerHelperEvents.BurnTokens(address(market), recipient, amount);
    }
```

## contracts/v2/tokenomics/PreTMX.sol:45 `transferFrom`

`public override returns (bool)`

```solidity
function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        _beforeTokenTransfer(from, to);
        return super.transferFrom(from, to, amount);
    }
```

## contracts/v2/tokenomics/TMX.sol:985 `isComposeMsgSender`

`public view virtual returns (bool)`

```solidity
function isComposeMsgSender(Origin calldata, /*_origin*/ bytes calldata, /*_message*/ address _sender)
        public
        view
        virtual
        returns (bool)
    {
        return _sender == address(this);
    }
```

## contracts/v2/tokens/AbstractGearingTokenV2.sol:529 `liquidate`

`external virtual override nonReentrant`

```solidity
function liquidate(uint256 id, uint128 repayAmt, bool byDebtToken) external virtual override nonReentrant {
        LoanInfo memory loan = loanMapping[id];
        GtConfig memory config = _config;
        if (!config.loanConfig.liquidatable) {
            revert GtDoNotSupportLiquidation();
        }
        (bool isLiquidable, uint128 maxRepayAmt,, ValueAndPrice memory valueAndPrice) =
            _getLiquidationInfo(loan, config);

        if (!isLiquidable) {
            uint256 liquidationDeadline = config.maturity + Constants.LIQUIDATION_WINDOW;
            if (block.timestamp >= liquidationDeadline) {
                revert CanNotLiquidationAfterFinalDeadline(id, liquidationDeadline);
            }
            revert GtIsSafe(id);
        }
        if (repayAmt > maxRepayAmt) {
            repayAmt = maxRepayAmt;
        }
        // Transfer token
        if (byDebtToken) {
            config.debtToken.safeTransferFrom(msg.sender, marketAddr(), repayAmt);
        } else {
            config.ft.safeTransferFrom(msg.sender, marketAddr(), repayAmt);
        }

        // Do liquidate
        (bytes memory cToLiquidator, bytes memory cToTreasurer, bytes memory remainningC) =
            _calcLiquidationResult(loan, repayAmt, valueAndPrice);

        if (repayAmt == loan.debtAmt) {
            if (remainningC.length > 0) {
                _transferCollateral(ownerOf(id), remainningC);
            }
            // update storage
            _burnInternal(id);
        } else {
            loan.debtAmt -= repayAmt;
            loan.collateralData = remainningC;
            // update storage
            loanMapping[id] = loan;
        }
        // Transfer collateral
        if (cToTreasurer.length > 0) {
            _transferCollateral(config.treasurer, cToTreasurer);
        }
        _transferCollateral(msg.sender, cToLiquidator);

        emit Liquidate(id, msg.sender, repayAmt, byDebtToken, cToLiquidator, cToTreasurer, remainningC);
    }
```

## contracts/v2/tokens/StableERC4626ForAave.sol:103 `burnToAToken`

`external nonReentrant`

```solidity
function burnToAToken(address to, uint256 amount) external nonReentrant {
        _burn(msg.sender, amount);
        aToken.safeTransfer(to, amount);
    }
```

## contracts/v2/tokens/StableERC4626ForCustomize.sol:107 `totalIncomeAssets`

`external view returns (uint256)`

```solidity
function totalIncomeAssets() external view returns (uint256) {
        IERC20 _underlying = IERC20(asset());
        uint256 assetInPool = _assetInPool(address(_underlying));
        uint256 underlyingBalance = _underlying.balanceOf(address(this));
        uint256 totalSupply_ = totalSupply();
        uint256 assetsWithIncome = assetInPool + underlyingBalance + withdawedIncomeAssets;
        if (assetsWithIncome < totalSupply_) {
            // If total assets with income is less than total supply, return 0
            return 0;
        } else {
            return assetsWithIncome - totalSupply_;
        }
    }
```

## contracts/v2/tokens/StableERC4626ForCustomize.sol:121 `currentIncomeAssets`

`external view returns (uint256)`

```solidity
function currentIncomeAssets() external view returns (uint256) {
        IERC20 _underlying = IERC20(asset());
        uint256 assetInPool = _assetInPool(address(_underlying));
        uint256 underlyingBalance = _underlying.balanceOf(address(this));
        uint256 totalSupply_ = totalSupply();
        uint256 assetsWithIncome = assetInPool + underlyingBalance;
        if (assetsWithIncome < totalSupply_) {
            // If total assets with income is less than total supply, return 0
            return 0;
        } else {
            return assetsWithIncome - totalSupply_;
        }
    }
```

## contracts/v2/activity/TermMaxRewardContract.sol:61 `claimRewards`

`external payable nonReentrant whenNotPaused onlyAvailableUser`

```solidity
function claimRewards(IERC20[] calldata tokens, address to)
        external
        payable
        nonReentrant
        whenNotPaused
        onlyAvailableUser
    {
        UserProfile storage profile = userProfiles[msg.sender];

        uint256[] memory amounts = new uint256[](tokens.length);
        for (uint256 i = 0; i < tokens.length; ++i) {
            IERC20 token = tokens[i];
            amounts[i] = profile.rewards[token];
            if (amounts[i] == 0) {
                continue; // Skip if no rewards for this token
            }
            delete profile.rewards[token];
            if (address(token) == ETH_ADDRESS) {
                payable(to).transfer(amounts[i]);
            } else {
                token.safeTransfer(to, amounts[i]);
            }
        }
        emit RewardClaimed(msg.sender, to, tokens, amounts);
    }
```
