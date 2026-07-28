// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Staker} from "../src/Staker.sol";
import {ZenStaker} from "../src/ZenStaker.sol";
import {RewardAccumulator} from "../src/RewardAccumulator.sol";
import {IdentityEarningPowerCalculator} from
  "../src/calculators/IdentityEarningPowerCalculator.sol";
import {ERC20VotesMock} from "./mocks/MockERC20Votes.sol";

/// @dev Public-source, local-only invariant harness. It performs no public-network write.
contract HorizenDeepAudit is Test {
  ERC20VotesMock internal token;
  IdentityEarningPowerCalculator internal calculator;
  ZenStaker internal staker;
  RewardAccumulator internal accumulator;

  address internal constant ADMIN = address(0xA11CE);
  address internal constant ALICE = address(0xA11C3);
  address internal constant BOB = address(0xB0B);
  address internal constant ACTOR = address(0xBAD);
  address internal constant FUNDER = address(0xF00D);
  address internal constant DELEGATEE = address(0xD311);

  function setUp() public {
    vm.warp(1_000_000);
    token = new ERC20VotesMock();
    calculator = new IdentityEarningPowerCalculator();
    staker = new ZenStaker(IERC20(address(token)), calculator, 0, ADMIN);
    accumulator = new RewardAccumulator(
      Staker(address(staker)), ERC20(address(token)), 5 days, false
    );
    vm.prank(ADMIN);
    staker.setRewardNotifier(address(accumulator), true);
  }

  function _stake(address owner, uint256 amount, address delegatee)
    internal
    returns (Staker.DepositIdentifier depositId)
  {
    token.mint(owner, amount);
    vm.prank(owner);
    token.approve(address(staker), type(uint256).max);
    vm.prank(owner);
    depositId = staker.stake(amount, delegatee);
  }

  function _stakeWithClaimer(address owner, uint256 amount, address delegatee, address claimer)
    internal
    returns (Staker.DepositIdentifier depositId)
  {
    token.mint(owner, amount);
    vm.prank(owner);
    token.approve(address(staker), type(uint256).max);
    vm.prank(owner);
    depositId = staker.stake(amount, delegatee, claimer);
  }

  function _fund(uint256 amount) internal {
    token.mint(FUNDER, amount);
    vm.prank(FUNDER);
    token.approve(address(accumulator), amount);
    vm.prank(FUNDER);
    accumulator.transferAndNotifyRewards(amount);
  }

  function _flush() internal {
    uint256 next = accumulator.nextRewardTime();
    if (block.timestamp < next) vm.warp(next);
    accumulator.sendRewardsToStaker();
  }

  function _claim(address caller, Staker.DepositIdentifier id) internal returns (uint256 amount) {
    vm.prank(caller);
    amount = staker.claimReward(id);
  }

  function test_StakeMorePreservesAlreadyAccruedReward() public {
    Staker.DepositIdentifier aliceId = _stake(ALICE, 100e18, ALICE);
    Staker.DepositIdentifier bobId = _stake(BOB, 100e18, BOB);
    _fund(3_000e18);
    _flush();
    vm.warp(block.timestamp + 10 days);
    uint256 beforeReward = staker.unclaimedReward(aliceId);
    token.mint(BOB, 900e18);
    vm.prank(BOB);
    staker.stakeMore(bobId, 900e18);
    assertApproxEqAbs(staker.unclaimedReward(aliceId), beforeReward, 1);
  }

  function test_AlterDelegateePreservesRewardAndPrincipal() public {
    Staker.DepositIdentifier id = _stake(ALICE, 400e18, DELEGATEE);
    address oldSurrogate = address(staker.surrogates(DELEGATEE));
    _fund(1_000e18);
    _flush();
    vm.warp(block.timestamp + 8 days);
    uint256 beforeReward = staker.unclaimedReward(id);
    address nextDelegatee = address(0xD312);
    vm.prank(ALICE);
    staker.alterDelegatee(id, nextDelegatee);
    assertApproxEqAbs(staker.unclaimedReward(id), beforeReward, 1);
    assertEq(token.balanceOf(oldSurrogate), 0);
    assertEq(token.balanceOf(address(staker.surrogates(nextDelegatee))), 400e18);
  }

  function test_FullWithdrawalRewardRemainsClaimableOnChain() public {
    Staker.DepositIdentifier id = _stake(ALICE, 500e18, ALICE);
    _fund(1_500e18);
    _flush();
    vm.warp(block.timestamp + 7 days);
    uint256 rewardBefore = staker.unclaimedReward(id);
    vm.prank(ALICE);
    staker.withdraw(id, 500e18);
    (uint96 balance,,,,, uint256 rewardAfter) = staker.getDepositInfo(id);
    assertEq(balance, 0);
    assertApproxEqAbs(rewardAfter, rewardBefore, 1);
    uint256 walletBefore = token.balanceOf(ALICE);
    uint256 claimed = _claim(ALICE, id);
    assertGt(claimed, 0);
    assertEq(token.balanceOf(ALICE), walletBefore + claimed);
  }

  function test_SharedSurrogateIsolatesRecordedPrincipal() public {
    Staker.DepositIdentifier aliceId = _stake(ALICE, 100e18, DELEGATEE);
    Staker.DepositIdentifier bobId = _stake(BOB, 200e18, DELEGATEE);
    address surrogate = address(staker.surrogates(DELEGATEE));
    vm.prank(ALICE);
    staker.withdraw(aliceId, 100e18);
    assertEq(token.balanceOf(surrogate), 200e18);
    (uint96 bobBalance,,,,,) = staker.getDepositInfo(bobId);
    assertEq(bobBalance, 200e18);
    vm.prank(BOB);
    staker.withdraw(bobId, 200e18);
    assertEq(token.balanceOf(surrogate), 0);
  }

  function test_DonationToSurrogateIsNotAssignedToDeposits() public {
    Staker.DepositIdentifier aliceId = _stake(ALICE, 100e18, DELEGATEE);
    Staker.DepositIdentifier bobId = _stake(BOB, 200e18, DELEGATEE);
    address surrogate = address(staker.surrogates(DELEGATEE));
    token.mint(ACTOR, 7e18);
    vm.prank(ACTOR);
    token.transfer(surrogate, 7e18);
    vm.prank(ALICE);
    staker.withdraw(aliceId, 100e18);
    vm.prank(BOB);
    staker.withdraw(bobId, 200e18);
    assertEq(token.balanceOf(surrogate), 7e18);
    assertEq(staker.totalStaked(), 0);
  }

  function test_ZeroAmountDepositsDoNotAlterExistingAccounting() public {
    Staker.DepositIdentifier aliceId = _stake(ALICE, 1_000e18, ALICE);
    _fund(3_000e18);
    _flush();
    vm.warp(block.timestamp + 2 days);
    uint256 rewardBefore = staker.unclaimedReward(aliceId);
    uint256 totalStakedBefore = staker.totalStaked();
    uint256 totalPowerBefore = staker.totalEarningPower();
    for (uint160 i = 1; i <= 64; i++) {
      vm.prank(ACTOR);
      staker.stake(0, address(uint160(0x1000) + i));
    }
    assertEq(staker.totalStaked(), totalStakedBefore);
    assertEq(staker.totalEarningPower(), totalPowerBefore);
    assertApproxEqAbs(staker.unclaimedReward(aliceId), rewardBefore, 1);
  }

  function test_UnauthorizedDepositOperationsRevert() public {
    Staker.DepositIdentifier id = _stake(ALICE, 100e18, ALICE);
    vm.startPrank(ACTOR);
    vm.expectRevert();
    staker.withdraw(id, 1);
    vm.expectRevert();
    staker.stakeMore(id, 1);
    vm.expectRevert();
    staker.alterDelegatee(id, ACTOR);
    vm.expectRevert();
    staker.alterClaimer(id, ACTOR);
    vm.expectRevert();
    staker.claimReward(id);
    vm.stopPrank();
  }

  function test_ClaimerCannotWithdrawPrincipal() public {
    Staker.DepositIdentifier id = _stakeWithClaimer(ALICE, 100e18, ALICE, BOB);
    _fund(900e18);
    _flush();
    vm.warp(block.timestamp + 10 days);
    vm.prank(BOB);
    vm.expectRevert();
    staker.withdraw(id, 1);
    uint256 beforeBalance = token.balanceOf(BOB);
    uint256 claimed = _claim(BOB, id);
    assertGt(claimed, 0);
    assertEq(token.balanceOf(BOB), beforeBalance + claimed);
  }

  function test_RepeatedFlushAndClaimOrderingConservesRewards() public {
    Staker.DepositIdentifier aliceId = _stake(ALICE, 300e18, ALICE);
    Staker.DepositIdentifier bobId = _stake(BOB, 700e18, BOB);
    uint256 totalFunding;
    uint256 totalClaimed;
    _fund(300e18);
    totalFunding += 300e18;
    _flush();
    vm.warp(block.timestamp + 9 days);
    totalClaimed += _claim(ALICE, aliceId);
    _fund(111e18);
    totalFunding += 111e18;
    _flush();
    vm.warp(block.timestamp + 11 days);
    totalClaimed += _claim(BOB, bobId);
    _fund(777e18);
    totalFunding += 777e18;
    _flush();
    vm.warp(block.timestamp + 40 days);
    totalClaimed += _claim(ALICE, aliceId);
    totalClaimed += _claim(BOB, bobId);
    uint256 remaining = token.balanceOf(address(staker)) + token.balanceOf(address(accumulator));
    assertEq(totalClaimed + remaining, totalFunding);
  }

  function testFuzz_FlushAndClaimConservation(
    uint96 rawAliceStake,
    uint96 rawBobStake,
    uint96 rawReward1,
    uint96 rawReward2,
    uint32 rawDelay1,
    uint32 rawDelay2
  ) public {
    uint256 aliceStake = bound(uint256(rawAliceStake), 1e12, 1e24);
    uint256 bobStake = bound(uint256(rawBobStake), 1e12, 1e24);
    uint256 reward1 = bound(uint256(rawReward1), 1e12, 1e24);
    uint256 reward2 = bound(uint256(rawReward2), 1e12, 1e24);
    uint256 delay1 = bound(uint256(rawDelay1), 0, 20 days);
    uint256 delay2 = bound(uint256(rawDelay2), 0, 20 days);
    Staker.DepositIdentifier aliceId = _stake(ALICE, aliceStake, ALICE);
    Staker.DepositIdentifier bobId = _stake(BOB, bobStake, BOB);
    _fund(reward1);
    _flush();
    vm.warp(block.timestamp + delay1);
    uint256 extra = aliceStake / 3;
    token.mint(ALICE, extra);
    vm.prank(ALICE);
    staker.stakeMore(aliceId, extra);
    _fund(reward2);
    _flush();
    vm.warp(block.timestamp + delay2 + 31 days);
    uint256 claimed = _claim(ALICE, aliceId) + _claim(BOB, bobId);
    uint256 remaining = token.balanceOf(address(staker)) + token.balanceOf(address(accumulator));
    assertEq(claimed + remaining, reward1 + reward2);
  }
}
