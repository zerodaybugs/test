// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { SynthetixDepositContract } from "../src/SynthetixDepositContract.sol";
import { ISynthetixDepositContract } from "../src/interfaces/ISynthetixDepositContract.sol";
import { IPermit2, ISignatureTransfer } from "../src/interfaces/IPermit2.sol";
import { AggregatorV3Interface } from "../src/interfaces/AggregatorV3Interface.sol";
import { CowOrder } from "../src/libraries/CowProtocol.sol";
import { IERC20 } from "../lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "../lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol";

interface Vm {
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function warp(uint256 newTimestamp) external;
    function etch(address target, bytes calldata code) external;
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
}

contract MinimalERC1967Proxy {
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address implementation, bytes memory initializationCall) payable {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, implementation)
        }
        if (initializationCall.length != 0) {
            (bool success, bytes memory returndata) = implementation.delegatecall(initializationCall);
            if (!success) {
                assembly {
                    revert(add(returndata, 32), mload(returndata))
                }
            }
        }
    }

    fallback() external payable {
        _delegate();
    }

    receive() external payable {
        _delegate();
    }

    function _delegate() private {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            let implementation := sload(slot)
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch success
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

contract MockERC20 is IERC20Metadata {
    string public override name;
    string public override symbol;
    uint8 public override decimals;
    uint256 public override totalSupply;
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;

    bool public configured;
    uint256 public feeBps;
    address public callbackTarget;
    bytes public callbackData;
    bool public callbackOnTransferFrom;
    bool public callbackSuccess;

    function configure(string memory name_, string memory symbol_, uint8 decimals_) external {
        require(!configured, "already configured");
        configured = true;
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    function setFeeBps(uint256 value) external {
        require(value <= 10_000, "fee");
        feeBps = value;
    }

    function setTransferFromCallback(address target, bytes calldata data, bool enabled) external {
        callbackTarget = target;
        callbackData = data;
        callbackOnTransferFrom = enabled;
        callbackSuccess = false;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "allowance");
            unchecked {
                allowance[from][msg.sender] = currentAllowance - amount;
            }
            emit Approval(from, msg.sender, allowance[from][msg.sender]);
        }

        _transfer(from, to, amount);

        if (callbackOnTransferFrom && callbackTarget != address(0)) {
            (callbackSuccess,) = callbackTarget.call(callbackData);
        }
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(to != address(0), "zero recipient");
        require(balanceOf[from] >= amount, "balance");
        unchecked {
            balanceOf[from] -= amount;
        }
        uint256 fee = amount * feeBps / 10_000;
        uint256 received = amount - fee;
        balanceOf[to] += received;
        if (fee != 0) {
            totalSupply -= fee;
            emit Transfer(from, address(0), fee);
        }
        emit Transfer(from, to, received);
    }
}

contract MockPermit2 is IPermit2 {
    address public lastOwner;
    address public lastToken;
    address public lastRecipient;
    uint256 public lastRequestedAmount;
    uint256 public callCount;

    function permitTransferFrom(
        ISignatureTransfer.PermitTransferFrom memory permit,
        ISignatureTransfer.SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata
    ) external override {
        lastOwner = owner;
        lastToken = permit.permitted.token;
        lastRecipient = transferDetails.to;
        lastRequestedAmount = transferDetails.requestedAmount;
        callCount++;
        require(
            IERC20(permit.permitted.token).transferFrom(owner, transferDetails.to, transferDetails.requestedAmount),
            "transfer failed"
        );
    }
}

contract MockAggregator is AggregatorV3Interface {
    uint8 public immutable override decimals;
    int256 public answer;
    uint256 public updatedAt;
    uint80 public roundId;

    constructor(uint8 decimals_, int256 answer_) {
        decimals = decimals_;
        answer = answer_;
        updatedAt = block.timestamp;
        roundId = 1;
    }

    function setAnswer(int256 answer_, uint256 updatedAt_) external {
        answer = answer_;
        updatedAt = updatedAt_;
        roundId++;
    }

    function latestRoundData()
        external
        view
        override
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (roundId, answer, updatedAt, updatedAt, roundId);
    }
}

contract SynthetixDepositLocalTest {
    using CowOrder for CowOrder.Data;

    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address private constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address private constant COW_VAULT_RELAYER = 0xC92E8bdf79f0507f65a392b0ab4667716BFE0110;
    bytes32 private constant COW_DOMAIN_SEPARATOR =
        0xc078f884a2676e1345748b1feace7b0abee5d00ecadb6e574dcdd109a63e8943;

    address private constant USER = address(0x1001);
    address private constant VICTIM = address(0x1002);
    address private constant ATTACKER = address(0x1003);
    address private constant DESTINATION_A = address(0x1004);
    address private constant DESTINATION_B = address(0x1005);
    address private constant RELAYER = address(0x2001);
    address private constant WATCHER = address(0x2002);
    address private constant TELLER = address(0x2003);
    address private constant GUARDIAN = address(0x2004);
    uint256 private constant TRADER_PRIVATE_KEY = 0xA11CE;

    SynthetixDepositContract private target;
    MockERC20 private sellToken;
    MockERC20 private usdt;
    MockAggregator private sellFeed;
    MockAggregator private usdtFeed;
    address private trader;

    function setUp() public {
        SynthetixDepositContract implementation = new SynthetixDepositContract();
        MinimalERC1967Proxy proxy = new MinimalERC1967Proxy(
            address(implementation), abi.encodeCall(SynthetixDepositContract.initialize, (address(this)))
        );
        target = SynthetixDepositContract(payable(address(proxy)));

        sellToken = new MockERC20();
        sellToken.configure("Local Collateral", "LOCAL", 18);

        MockERC20 usdtTemplate = new MockERC20();
        vm.etch(USDT, address(usdtTemplate).code);
        usdt = MockERC20(USDT);
        usdt.configure("Local USDT", "USDT", 6);

        MockPermit2 permitTemplate = new MockPermit2();
        vm.etch(PERMIT2, address(permitTemplate).code);

        ISynthetixDepositContract.CollateralConfig memory config = ISynthetixDepositContract.CollateralConfig({
            enabled: true,
            globalMaximum: type(uint128).max,
            userMinimum: 1,
            userMaximum: type(uint128).max,
            withdrawalMinimum: 1
        });
        target.addCollateral(address(sellToken), config);

        target.grantRole(target.RELAYER_ROLE(), RELAYER);
        target.grantRole(target.WATCHER_ROLE(), WATCHER);
        target.grantRole(target.TELLER_ROLE(), TELLER);
        target.grantRole(target.GUARDIAN_ROLE(), GUARDIAN);
        target.setWatcherQuorum(1);

        trader = vm.addr(TRADER_PRIVATE_KEY);
        target.grantAuthorizedTraderRole(trader);

        sellFeed = new MockAggregator(8, 1e8);
        usdtFeed = new MockAggregator(8, 1e8);
        target.setPriceFeed(address(sellToken), address(sellFeed));
        target.setPriceFeed(USDT, address(usdtFeed));

        sellToken.mint(USER, 1e30);
        sellToken.mint(VICTIM, 1e30);

        vm.prank(USER);
        sellToken.approve(address(target), type(uint256).max);
        vm.prank(VICTIM);
        sellToken.approve(address(target), type(uint256).max);
    }

    function _emptyPermitDetails()
        internal
        pure
        returns (ISynthetixDepositContract.PermitDetails memory details)
    {
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: address(0), amount: 0 }),
            nonce: 0,
            deadline: 0
        });
        details = ISynthetixDepositContract.PermitDetails({ permit: permit, signature: hex"" });
    }

    function _depositEntry(address token, uint256 amount, address beneficiary)
        internal
        pure
        returns (ISynthetixDepositContract.DepositEntry memory)
    {
        return ISynthetixDepositContract.DepositEntry({
            token: token,
            amount: amount,
            beneficiary: beneficiary,
            subAccountId: 0,
            permitDetails: _emptyPermitDetails()
        });
    }

    function _deposit(address sender, address beneficiary, uint256 amount) internal {
        ISynthetixDepositContract.DepositEntry[] memory entries =
            new ISynthetixDepositContract.DepositEntry[](1);
        entries[0] = _depositEntry(address(sellToken), amount, beneficiary);
        vm.prank(sender);
        target.deposit(entries);
    }

    function _requestWithdrawal(address destination, uint256 amount) internal returns (uint256 requestId) {
        address[] memory tokens = new address[](1);
        tokens[0] = address(sellToken);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;
        ISynthetixDepositContract.WithdrawalEntry[] memory entries =
            new ISynthetixDepositContract.WithdrawalEntry[](1);
        entries[0] = ISynthetixDepositContract.WithdrawalEntry({
            beneficiary: destination,
            tokens: tokens,
            amounts: amounts
        });
        vm.prank(RELAYER);
        target.requestWithdrawal(entries);
        requestId = target.getWithdrawalRequestCounter();
    }

    function _validate(uint256 requestId) internal {
        uint256[] memory ids = new uint256[](1);
        ids[0] = requestId;
        vm.prank(WATCHER);
        target.castWatcherVotes(ids);
    }

    function _disburse(uint256 requestId) internal {
        uint256[] memory ids = new uint256[](1);
        ids[0] = requestId;
        vm.prank(TELLER);
        target.disburseWithdrawals(ids);
    }

    function _signOrder(CowOrder.Data memory order) internal returns (bytes32 digest, bytes memory signature) {
        digest = order.hash(COW_DOMAIN_SEPARATOR);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TRADER_PRIVATE_KEY, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function _fairOrder(uint256 sellAmount, uint256 feeAmount, uint256 buyAmount)
        internal
        view
        returns (CowOrder.Data memory order)
    {
        order = CowOrder.Data({
            sellToken: IERC20(address(sellToken)),
            buyToken: IERC20(USDT),
            receiver: address(target),
            sellAmount: sellAmount,
            buyAmount: buyAmount,
            validTo: uint32(block.timestamp + 1 hours),
            appData: bytes32(0),
            feeAmount: feeAmount,
            kind: keccak256("sell"),
            partiallyFillable: false,
            sellTokenBalance: keccak256("erc20"),
            buyTokenBalance: keccak256("erc20")
        });
    }

    function testFuzz_DepositConservation(uint96 seed) public {
        uint256 amount = uint256(seed) % 1e24 + 1;
        uint256 userBefore = sellToken.balanceOf(USER);
        _deposit(USER, DESTINATION_A, amount);

        require(sellToken.balanceOf(USER) == userBefore - amount, "sender debit mismatch");
        require(sellToken.balanceOf(address(target)) == amount, "custody balance mismatch");
        require(target.getTotalDeposited(address(sellToken)) == amount, "global ledger mismatch");
        require(target.getUserBalance(DESTINATION_A, address(sellToken)) == int256(amount), "user ledger mismatch");
    }

    function test_BatchDepositRollsBackIfLaterEntryFails() public {
        uint256 amount = 10e18;
        ISynthetixDepositContract.DepositEntry[] memory entries =
            new ISynthetixDepositContract.DepositEntry[](2);
        entries[0] = _depositEntry(address(sellToken), amount, USER);
        entries[1] = _depositEntry(address(sellToken), 0, USER);

        uint256 userBefore = sellToken.balanceOf(USER);
        vm.prank(USER);
        (bool success,) = address(target).call(abi.encodeWithSelector(target.deposit.selector, entries));
        require(!success, "invalid batch unexpectedly succeeded");
        require(sellToken.balanceOf(USER) == userBefore, "partial token debit survived revert");
        require(sellToken.balanceOf(address(target)) == 0, "partial custody credit survived revert");
        require(target.getTotalDeposited(address(sellToken)) == 0, "partial global ledger survived revert");
        require(target.getUserBalance(USER, address(sellToken)) == 0, "partial user ledger survived revert");
    }

    function test_DepositReentrancyFromTokenCallbackIsBlocked() public {
        ISynthetixDepositContract.DepositEntry[] memory nested =
            new ISynthetixDepositContract.DepositEntry[](1);
        nested[0] = _depositEntry(address(sellToken), 1, USER);
        sellToken.setTransferFromCallback(
            address(target), abi.encodeWithSelector(target.deposit.selector, nested), true
        );

        _deposit(USER, USER, 10e18);
        require(!sellToken.callbackSuccess(), "reentrant deposit succeeded");
        require(target.getUserBalance(USER, address(sellToken)) == int256(10e18), "unexpected nested credit");
        require(target.getTotalDeposited(address(sellToken)) == 10e18, "unexpected nested total");
    }

    function test_Permit2PathPinsTokenOwnerToTransactionCaller() public {
        uint256 amount = 25e18;
        vm.prank(USER);
        sellToken.approve(PERMIT2, amount);

        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: address(sellToken), amount: amount }),
            nonce: 7,
            deadline: block.timestamp + 1 hours
        });
        ISynthetixDepositContract.PermitDetails memory details =
            ISynthetixDepositContract.PermitDetails({ permit: permit, signature: hex"01" });
        ISynthetixDepositContract.DepositEntry[] memory entries =
            new ISynthetixDepositContract.DepositEntry[](1);
        entries[0] = ISynthetixDepositContract.DepositEntry({
            token: address(sellToken),
            amount: amount,
            beneficiary: DESTINATION_A,
            subAccountId: 123,
            permitDetails: details
        });

        vm.prank(USER);
        target.deposit(entries);

        MockPermit2 permit2 = MockPermit2(PERMIT2);
        require(permit2.lastOwner() == USER, "Permit2 owner was not msg.sender");
        require(permit2.lastRecipient() == address(target), "Permit2 recipient mismatch");
        require(permit2.lastRequestedAmount() == amount, "Permit2 requested amount mismatch");
        require(target.getUserBalance(DESTINATION_A, address(sellToken)) == int256(amount), "beneficiary credit mismatch");

        uint256 victimBefore = sellToken.balanceOf(VICTIM);
        vm.prank(VICTIM);
        sellToken.approve(PERMIT2, 50e18);

        permit.permitted.amount = 50e18;
        details = ISynthetixDepositContract.PermitDetails({ permit: permit, signature: hex"02" });
        entries[0] = ISynthetixDepositContract.DepositEntry({
            token: address(sellToken),
            amount: 50e18,
            beneficiary: ATTACKER,
            subAccountId: 456,
            permitDetails: details
        });
        vm.prank(ATTACKER);
        (bool success,) = address(target).call(abi.encodeWithSelector(target.deposit.selector, entries));
        require(!success, "attacker pulled victim tokens through Permit2");
        require(sellToken.balanceOf(VICTIM) == victimBefore, "victim tokens changed");
    }

    function test_FeeOnTransferCollateralCreatesImmediateLedgerDeficit() public {
        MockERC20 feeToken = new MockERC20();
        feeToken.configure("Fee Token", "FEE", 18);
        feeToken.setFeeBps(1_000);
        ISynthetixDepositContract.CollateralConfig memory config = ISynthetixDepositContract.CollateralConfig({
            enabled: true,
            globalMaximum: type(uint128).max,
            userMinimum: 1,
            userMaximum: type(uint128).max,
            withdrawalMinimum: 1
        });
        target.addCollateral(address(feeToken), config);
        feeToken.mint(USER, 100e18);
        vm.prank(USER);
        feeToken.approve(address(target), type(uint256).max);

        ISynthetixDepositContract.DepositEntry[] memory entries =
            new ISynthetixDepositContract.DepositEntry[](1);
        entries[0] = _depositEntry(address(feeToken), 100e18, USER);
        vm.prank(USER);
        target.deposit(entries);

        require(feeToken.balanceOf(address(target)) == 90e18, "fee-token control failed");
        require(target.getTotalDeposited(address(feeToken)) == 100e18, "tracked total did not over-credit");
        require(target.getUserBalance(USER, address(feeToken)) == int256(100e18), "user ledger did not over-credit");
    }

    function test_WithdrawalDestinationIsUsedAsLedgerDebtor() public {
        _deposit(USER, USER, 100e18);
        uint256 requestId = _requestWithdrawal(DESTINATION_A, 60e18);
        _validate(requestId);
        _disburse(requestId);

        require(sellToken.balanceOf(DESTINATION_A) == 60e18, "destination was not paid");
        require(target.getUserBalance(USER, address(sellToken)) == int256(100e18), "source ledger changed");
        require(
            target.getUserBalance(DESTINATION_A, address(sellToken)) == -int256(60e18),
            "destination ledger was not made negative"
        );
        require(target.getTotalDeposited(address(sellToken)) == 40e18, "global total mismatch");
        require(sellToken.balanceOf(address(target)) == 40e18, "physical balance mismatch");
    }

    function test_DifferentDestinationsPermitParallelOverbooking() public {
        _deposit(USER, USER, 100e18);
        uint256 first = _requestWithdrawal(DESTINATION_A, 80e18);
        uint256 second = _requestWithdrawal(DESTINATION_B, 80e18);
        require(first != second, "request IDs collided");

        uint256[] memory ids = new uint256[](2);
        ids[0] = first;
        ids[1] = second;
        vm.prank(WATCHER);
        target.castWatcherVotes(ids);

        _disburse(first);
        require(sellToken.balanceOf(address(target)) == 20e18, "first disbursement mismatch");

        uint256[] memory secondOnly = new uint256[](1);
        secondOnly[0] = second;
        vm.prank(TELLER);
        (bool success,) = address(target).call(
            abi.encodeWithSelector(target.disburseWithdrawals.selector, secondOnly)
        );
        require(!success, "overbooked second withdrawal unexpectedly paid");
        ISynthetixDepositContract.WithdrawalRequest memory request = target.getWithdrawalRequest(second);
        require(request.status == ISynthetixDepositContract.Status.Validated, "failed disbursement mutated status");
        require(target.getActiveWithdrawalId(DESTINATION_B) == second, "active slot unexpectedly cleared");
    }

    function test_DisputedWithdrawalDoesNotExpireOrReleaseActiveSlot() public {
        _deposit(USER, USER, 100e18);
        uint256 requestId = _requestWithdrawal(DESTINATION_A, 10e18);
        uint256[] memory ids = new uint256[](1);
        ids[0] = requestId;
        uint256[] memory reasons = new uint256[](1);
        reasons[0] = 999;
        vm.prank(WATCHER);
        target.disputeWithdrawals(ids, reasons);

        vm.warp(block.timestamp + target.withdrawalExpiryTimeout() + 1 days);
        vm.prank(TELLER);
        target.cancelStaleWithdrawals(ids);

        ISynthetixDepositContract.WithdrawalRequest memory request = target.getWithdrawalRequest(requestId);
        require(request.status == ISynthetixDepositContract.Status.Disputed, "disputed request expired");
        require(target.getActiveWithdrawalId(DESTINATION_A) == requestId, "disputed request released active slot");
    }

    function test_CowFeeAmountIsExcludedFromOracleBoundAndCanConsumeFullAllowance() public {
        uint256 custody = 100e18;
        uint256 pricedSellAmount = 1e18;
        uint256 uncheckedFeeAmount = 99e18;
        uint256 minimumBuyAmount = 950_000;

        _deposit(USER, USER, custody);
        target.approveCowVaultRelayer(address(sellToken), custody);

        CowOrder.Data memory order = _fairOrder(pricedSellAmount, uncheckedFeeAmount, minimumBuyAmount);
        (bytes32 digest, bytes memory traderSignature) = _signOrder(order);
        bytes4 magic = target.isValidSignature(digest, abi.encode(order, traderSignature));
        require(magic == 0x1626ba7e, "order with unpriced fee was rejected");

        vm.prank(COW_VAULT_RELAYER);
        bool pulled = sellToken.transferFrom(address(target), ATTACKER, pricedSellAmount + uncheckedFeeAmount);
        require(pulled, "relayer could not consume sell plus fee allowance");
        require(sellToken.balanceOf(address(target)) == 0, "custody was not fully consumed");
        require(sellToken.balanceOf(ATTACKER) == custody, "attacker did not receive full custody");
    }

    function test_CowFeeAmountCanExceedCustodyWhileSignatureStillValid() public {
        _deposit(USER, USER, 100e18);
        CowOrder.Data memory order = _fairOrder(1e18, 1_000_000e18, 950_000);
        (bytes32 digest, bytes memory traderSignature) = _signOrder(order);
        bytes4 magic = target.isValidSignature(digest, abi.encode(order, traderSignature));
        require(magic == 0x1626ba7e, "unbounded fee was checked unexpectedly");
    }

    function test_CowOracleBoundStillRejectsUnderpricedBuyAmount() public {
        CowOrder.Data memory order = _fairOrder(1e18, 0, 949_999);
        (bytes32 digest, bytes memory traderSignature) = _signOrder(order);
        (bool success,) = address(target).staticcall(
            abi.encodeWithSelector(target.isValidSignature.selector, digest, abi.encode(order, traderSignature))
        );
        require(!success, "oracle minimum accepted an underpriced buy amount");
    }
}
