// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console2} from "forge-std/Test.sol";

interface IERC20View {
    function balanceOf(address account) external view returns (uint256);
}

interface ISynthetixDepositDeep {
    enum Status {
        Requested,
        Validated,
        Disbursed,
        Denied,
        Disputed,
        Cancelled,
        Expired
    }

    struct WithdrawalEntry {
        address[] tokens;
        uint256[] amounts;
        address beneficiary;
    }

    struct WithdrawalRequest {
        address user;
        Status status;
        uint8 watcherCount;
        uint32 requestTime;
        uint32 processedTime;
        uint16 reasonCode;
        address[] tokens;
        uint256[] amounts;
    }

    struct GuardianApprovalLimit {
        address token;
        uint256 limit;
    }

    error ActiveWithdrawalExists();
    error InvalidStateForAction(uint256 id, Status currentStatus);
    error GuardianApprovalLimitExceeded(address token, uint256 amount, uint256 limit);
    error InsufficientContractBalance(address token, uint256 requested, uint256 available);

    function requestWithdrawal(WithdrawalEntry[] calldata withdrawals) external;
    function disputeWithdrawals(uint256[] calldata ids, uint256[] calldata reasonCodes) external;
    function castWatcherVotes(uint256[] calldata requestIds) external;
    function disburseWithdrawals(uint256[] calldata requestIds) external;
    function cancelStaleWithdrawals(uint256[] calldata requestIds) external;
    function cancelWithdrawal(uint256 id) external;
    function resolveDisputedWithdrawal(uint256 requestId, bool approve, uint256 reasonCode) external;
    function setGuardianApprovalLimits(address guardian, GuardianApprovalLimit[] calldata limits) external;

    function RELAYER_ROLE() external view returns (bytes32);
    function WATCHER_ROLE() external view returns (bytes32);
    function TELLER_ROLE() external view returns (bytes32);
    function GUARDIAN_ROLE() external view returns (bytes32);
    function OWNER_ROLE() external view returns (bytes32);
    function watcherQuorum() external view returns (uint256);
    function withdrawalExpiryTimeout() external view returns (uint256);
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
    function getRoleMember(bytes32 role, uint256 index) external view returns (address);
    function getGuardianApprovalLimit(address guardian, address token) external view returns (uint256);
    function getWithdrawalRequestCounter() external view returns (uint256);
    function getWithdrawalRequest(uint256 id) external view returns (WithdrawalRequest memory);
    function getActiveWithdrawalId(address user) external view returns (uint256);
    function getUserBalance(address user, address token) external view returns (int256);
    function getTotalDeposited(address token) external view returns (uint256);
}

contract SynthetixWithdrawalDeepInvariantsTest is Test {
    address internal constant DEPOSIT_PROXY = 0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B;
    address internal constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    uint256 internal constant LIMIT = 100_000_000; // 100 USDT
    uint256 internal constant SMALL = 1_000_000; // 1 USDT

    ISynthetixDepositDeep internal constant deposit = ISynthetixDepositDeep(DEPOSIT_PROXY);
    IERC20View internal constant usdt = IERC20View(USDT);

    address internal relayer;
    address internal teller;
    address internal guardian;
    address internal owner;
    bytes32 internal watcherRole;

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        bytes32 relayerRole = deposit.RELAYER_ROLE();
        watcherRole = deposit.WATCHER_ROLE();
        bytes32 tellerRole = deposit.TELLER_ROLE();
        bytes32 guardianRole = deposit.GUARDIAN_ROLE();
        bytes32 ownerRole = deposit.OWNER_ROLE();

        assertGt(deposit.getRoleMemberCount(relayerRole), 0, "missing relayer");
        assertGt(deposit.getRoleMemberCount(watcherRole), 0, "missing watcher");
        assertGt(deposit.getRoleMemberCount(tellerRole), 0, "missing teller");
        assertGt(deposit.getRoleMemberCount(guardianRole), 0, "missing guardian");
        assertGt(deposit.getRoleMemberCount(ownerRole), 0, "missing owner");

        relayer = deposit.getRoleMember(relayerRole, 0);
        teller = deposit.getRoleMember(tellerRole, 0);
        guardian = deposit.getRoleMember(guardianRole, 0);
        owner = deposit.getRoleMember(ownerRole, 0);

        assertGt(deposit.watcherQuorum(), 0, "zero watcher quorum");
        assertGe(deposit.getRoleMemberCount(watcherRole), deposit.watcherQuorum(), "insufficient watchers");
        assertGt(usdt.balanceOf(DEPOSIT_PROXY), LIMIT * 4, "custody too small for isolated fork tests");

        console2.log("fork block", block.number);
        console2.log("withdrawal expiry", deposit.withdrawalExpiryTimeout());
        console2.log("live guardian limit", deposit.getGuardianApprovalLimit(guardian, USDT));
    }

    /// @dev The configured guardian cap is checked independently for each array element. Repeating
    /// the same token therefore lets one approval authorize an aggregate payout above the cap.
    /// This is a real safety-control invariant failure, but the production exploitability gate still
    /// depends on whether an unprivileged user can cause duplicate token entries to reach the relayer.
    function testDuplicateTokenEntriesBypassAggregateGuardianLimit() public {
        _setGuardianLimit(LIMIT);
        address beneficiary = makeAddr("guardian-limit-beneficiary");

        uint256 requestId = _requestDuplicate(beneficiary, LIMIT, LIMIT);
        _dispute(requestId);

        vm.prank(guardian);
        deposit.resolveDisputedWithdrawal(requestId, true, 777);

        ISynthetixDepositDeep.WithdrawalRequest memory validated = deposit.getWithdrawalRequest(requestId);
        assertEq(uint256(validated.status), uint256(ISynthetixDepositDeep.Status.Validated));

        uint256 beforeBalance = usdt.balanceOf(beneficiary);
        _disburse(requestId);

        assertEq(usdt.balanceOf(beneficiary) - beforeBalance, LIMIT * 2, "aggregate payout mismatch");
        assertEq(deposit.getUserBalance(beneficiary, USDT), -int256(LIMIT * 2));
        assertGt(LIMIT * 2, deposit.getGuardianApprovalLimit(guardian, USDT));
    }

    function testSingleEntryAboveGuardianLimitIsRejected() public {
        _setGuardianLimit(LIMIT);
        address beneficiary = makeAddr("guardian-limit-negative-control");
        uint256 requestId = _requestSingle(beneficiary, LIMIT + 1);
        _dispute(requestId);

        vm.expectRevert(ISynthetixDepositDeep.GuardianApprovalLimitExceeded.selector);
        vm.prank(guardian);
        deposit.resolveDisputedWithdrawal(requestId, true, 778);

        ISynthetixDepositDeep.WithdrawalRequest memory req = deposit.getWithdrawalRequest(requestId);
        assertEq(uint256(req.status), uint256(ISynthetixDepositDeep.Status.Disputed));
    }

    /// @dev Disputed requests are excluded from the expiry predicate. The user cannot cancel them,
    /// the teller cannot expire them, and a replacement request to the same destination is blocked.
    function testDisputedRequestNeverExpiresAndBlocksDestination() public {
        address beneficiary = makeAddr("permanent-dispute-beneficiary");
        uint256 requestId = _requestSingle(beneficiary, SMALL);
        _dispute(requestId);

        vm.warp(block.timestamp + deposit.withdrawalExpiryTimeout() + 1 days);

        uint256[] memory ids = _one(requestId);
        vm.prank(teller);
        deposit.cancelStaleWithdrawals(ids);

        ISynthetixDepositDeep.WithdrawalRequest memory afterStale = deposit.getWithdrawalRequest(requestId);
        assertEq(uint256(afterStale.status), uint256(ISynthetixDepositDeep.Status.Disputed));
        assertEq(deposit.getActiveWithdrawalId(beneficiary), requestId);

        vm.expectRevert(ISynthetixDepositDeep.InvalidStateForAction.selector);
        vm.prank(beneficiary);
        deposit.cancelWithdrawal(requestId);

        ISynthetixDepositDeep.WithdrawalEntry[] memory replacement =
            new ISynthetixDepositDeep.WithdrawalEntry[](1);
        replacement[0] = _entry(beneficiary, _singleToken(), _singleAmount(SMALL));
        vm.expectRevert(ISynthetixDepositDeep.ActiveWithdrawalExists.selector);
        vm.prank(relayer);
        deposit.requestWithdrawal(replacement);
    }

    function testValidatedRequestExpiresAndReplacementCanBeCreated() public {
        address beneficiary = makeAddr("validated-expiry-negative-control");
        uint256 firstId = _requestSingle(beneficiary, SMALL);
        _validate(firstId);
        vm.warp(block.timestamp + deposit.withdrawalExpiryTimeout() + 1);

        uint256 counterBefore = deposit.getWithdrawalRequestCounter();
        ISynthetixDepositDeep.WithdrawalEntry[] memory replacement =
            new ISynthetixDepositDeep.WithdrawalEntry[](1);
        replacement[0] = _entry(beneficiary, _singleToken(), _singleAmount(SMALL));
        vm.prank(relayer);
        deposit.requestWithdrawal(replacement);

        ISynthetixDepositDeep.WithdrawalRequest memory oldReq = deposit.getWithdrawalRequest(firstId);
        uint256 secondId = counterBefore + 1;
        assertEq(uint256(oldReq.status), uint256(ISynthetixDepositDeep.Status.Expired));
        assertEq(deposit.getActiveWithdrawalId(beneficiary), secondId);
        assertEq(uint256(deposit.getWithdrawalRequest(secondId).status), uint256(ISynthetixDepositDeep.Status.Requested));
    }

    /// @dev requestWithdrawal checks each duplicate entry against the same pre-transfer physical
    /// balance, not the aggregate. The impossible aggregate request reaches Validated, then the
    /// teller transaction reverts atomically on the second transfer.
    function testDuplicateTokenAggregateBalanceIsNotReservedAtRequestTime() public {
        address beneficiary = makeAddr("aggregate-balance-beneficiary");
        uint256 custodyBefore = usdt.balanceOf(DEPOSIT_PROXY);
        uint256 perEntry = custodyBefore / 2 + 1;
        assertLe(perEntry, custodyBefore);
        assertGt(perEntry * 2, custodyBefore);

        uint256 requestId = _requestDuplicate(beneficiary, perEntry, perEntry);
        _validate(requestId);

        uint256[] memory ids = _one(requestId);
        vm.expectRevert(ISynthetixDepositDeep.InsufficientContractBalance.selector);
        vm.prank(teller);
        deposit.disburseWithdrawals(ids);

        ISynthetixDepositDeep.WithdrawalRequest memory req = deposit.getWithdrawalRequest(requestId);
        assertEq(uint256(req.status), uint256(ISynthetixDepositDeep.Status.Validated));
        assertEq(deposit.getActiveWithdrawalId(beneficiary), requestId);
        assertEq(usdt.balanceOf(DEPOSIT_PROXY), custodyBefore);
        assertEq(usdt.balanceOf(beneficiary), 0);
        assertEq(deposit.getUserBalance(beneficiary, USDT), 0);
    }

    /// @dev A teller can finalize a nonexistent future ID because default storage looks like an old
    /// Requested request. When the counter later reaches the ID, request creation does not clear the
    /// stale processedTime. This is an integrity defect only; no unprivileged fund impact is asserted.
    function testPhantomFutureIdLeavesStaleProcessedTimeOnLaterRealRequest() public {
        uint256 counterBefore = deposit.getWithdrawalRequestCounter();
        uint256 futureId = counterBefore + 3;
        uint256[] memory phantom = _one(futureId);

        vm.prank(teller);
        deposit.cancelStaleWithdrawals(phantom);
        ISynthetixDepositDeep.WithdrawalRequest memory phantomReq = deposit.getWithdrawalRequest(futureId);
        assertEq(uint256(phantomReq.status), uint256(ISynthetixDepositDeep.Status.Expired));
        assertGt(phantomReq.processedTime, 0);
        uint32 phantomProcessed = phantomReq.processedTime;
        assertEq(deposit.getWithdrawalRequestCounter(), counterBefore);

        ISynthetixDepositDeep.WithdrawalEntry[] memory batch =
            new ISynthetixDepositDeep.WithdrawalEntry[](3);
        for (uint256 i = 0; i < 3; ++i) {
            batch[i] = _entry(makeAddr(string.concat("future-beneficiary-", vm.toString(i))), _singleToken(), _singleAmount(SMALL));
        }
        vm.prank(relayer);
        deposit.requestWithdrawal(batch);

        ISynthetixDepositDeep.WithdrawalRequest memory realReq = deposit.getWithdrawalRequest(futureId);
        assertEq(uint256(realReq.status), uint256(ISynthetixDepositDeep.Status.Requested));
        assertTrue(realReq.user != address(0));
        assertEq(realReq.processedTime, phantomProcessed, "request creation unexpectedly cleared stale processedTime");
    }

    function _setGuardianLimit(uint256 amount) internal {
        ISynthetixDepositDeep.GuardianApprovalLimit[] memory limits =
            new ISynthetixDepositDeep.GuardianApprovalLimit[](1);
        limits[0] = ISynthetixDepositDeep.GuardianApprovalLimit({token: USDT, limit: amount});
        vm.prank(owner);
        deposit.setGuardianApprovalLimits(guardian, limits);
        assertEq(deposit.getGuardianApprovalLimit(guardian, USDT), amount);
    }

    function _requestSingle(address beneficiary, uint256 amount) internal returns (uint256 id) {
        uint256 counterBefore = deposit.getWithdrawalRequestCounter();
        ISynthetixDepositDeep.WithdrawalEntry[] memory withdrawals =
            new ISynthetixDepositDeep.WithdrawalEntry[](1);
        withdrawals[0] = _entry(beneficiary, _singleToken(), _singleAmount(amount));
        vm.prank(relayer);
        deposit.requestWithdrawal(withdrawals);
        id = counterBefore + 1;
    }

    function _requestDuplicate(address beneficiary, uint256 first, uint256 second) internal returns (uint256 id) {
        uint256 counterBefore = deposit.getWithdrawalRequestCounter();
        address[] memory tokens = new address[](2);
        tokens[0] = USDT;
        tokens[1] = USDT;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = first;
        amounts[1] = second;
        ISynthetixDepositDeep.WithdrawalEntry[] memory withdrawals =
            new ISynthetixDepositDeep.WithdrawalEntry[](1);
        withdrawals[0] = _entry(beneficiary, tokens, amounts);
        vm.prank(relayer);
        deposit.requestWithdrawal(withdrawals);
        id = counterBefore + 1;
    }

    function _dispute(uint256 id) internal {
        uint256[] memory ids = _one(id);
        uint256[] memory reasons = _one(9001);
        vm.prank(relayer);
        deposit.disputeWithdrawals(ids, reasons);
        assertEq(uint256(deposit.getWithdrawalRequest(id).status), uint256(ISynthetixDepositDeep.Status.Disputed));
    }

    function _validate(uint256 id) internal {
        uint256[] memory ids = _one(id);
        uint256 quorum = deposit.watcherQuorum();
        for (uint256 i = 0; i < quorum; ++i) {
            vm.prank(deposit.getRoleMember(watcherRole, i));
            deposit.castWatcherVotes(ids);
        }
        assertEq(uint256(deposit.getWithdrawalRequest(id).status), uint256(ISynthetixDepositDeep.Status.Validated));
    }

    function _disburse(uint256 id) internal {
        vm.prank(teller);
        deposit.disburseWithdrawals(_one(id));
    }

    function _entry(
        address beneficiary,
        address[] memory tokens,
        uint256[] memory amounts
    ) internal pure returns (ISynthetixDepositDeep.WithdrawalEntry memory) {
        return ISynthetixDepositDeep.WithdrawalEntry({tokens: tokens, amounts: amounts, beneficiary: beneficiary});
    }

    function _singleToken() internal pure returns (address[] memory tokens) {
        tokens = new address[](1);
        tokens[0] = USDT;
    }

    function _singleAmount(uint256 amount) internal pure returns (uint256[] memory amounts) {
        amounts = new uint256[](1);
        amounts[0] = amount;
    }

    function _one(uint256 value) internal pure returns (uint256[] memory values) {
        values = new uint256[](1);
        values[0] = value;
    }
}
