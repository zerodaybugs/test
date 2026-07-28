// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Staker} from "../src/Staker.sol";
import {ZenStaker} from "../src/ZenStaker.sol";
import {RewardAccumulator} from "../src/RewardAccumulator.sol";

/// @dev Read-only production-state census executed exclusively on a local mainnet fork.
contract HorizenLiveCensus is Test {
  address internal constant STAKER_ADDRESS = 0x6BF7CF29a8bcE11Aa62Cf593d165C244fA4d3E31;
  address internal constant ACCUMULATOR_ADDRESS = 0x06f5555fee73EDdc385b6d76FE00DB2D96ccDaE8;
  address internal constant TOKEN_ADDRESS = 0x57da2D504bf8b83Ef304759d9f2648522D7a9280;
  address internal constant CALCULATOR_ADDRESS = 0xf518b3c7Cd5cc1595D10E7268677Da0Fe364E191;
  address internal constant SAFE_ADDRESS = 0x1Afb144aaD0aE02f3Bb04C1eae4AC6020a727A21;

  uint256 internal constant SCALE_FACTOR = 1e36;

  ZenStaker internal staker;
  RewardAccumulator internal accumulator;
  IERC20 internal token;

  function setUp() public {
    vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), vm.envUint("PINNED_BLOCK"));
    staker = ZenStaker(STAKER_ADDRESS);
    accumulator = RewardAccumulator(ACCUMULATOR_ADDRESS);
    token = IERC20(TOKEN_ADDRESS);
  }

  function test_CompleteProductionStateCensus() public view {
    uint256 next = Staker.DepositIdentifier.unwrap(staker.nextDepositId());
    assertLt(next, 10_000, "unexpected deposit count; census bound must be reviewed");

    address[] memory owners = new address[](next);
    address[] memory delegatees = new address[](next);
    uint256[] memory ownerBalances = new uint256[](next);
    uint256[] memory ownerPowers = new uint256[](next);
    uint256 ownerCount;
    uint256 delegateeCount;

    uint256 depositBalanceSum;
    uint256 depositPowerSum;
    uint256 unclaimedSum;
    uint256 zeroBalanceResidualCount;
    uint256 zeroBalanceResidualReward;

    for (uint256 i = 0; i < next; i++) {
      Staker.DepositIdentifier id = Staker.DepositIdentifier.wrap(i);
      (
        uint96 balance,
        address owner,
        uint96 earningPower,
        address delegatee,
        ,
        uint256 unclaimed
      ) = staker.getDepositInfo(id);

      assertTrue(owner != address(0), "sequential deposit ID has zero owner");
      assertTrue(delegatee != address(0), "deposit has zero delegatee");

      depositBalanceSum += uint256(balance);
      depositPowerSum += uint256(earningPower);
      unclaimedSum += unclaimed;

      if (balance == 0 && unclaimed > 0) {
        zeroBalanceResidualCount++;
        zeroBalanceResidualReward += unclaimed;
      }

      uint256 ownerIndex = type(uint256).max;
      for (uint256 j = 0; j < ownerCount; j++) {
        if (owners[j] == owner) {
          ownerIndex = j;
          break;
        }
      }
      if (ownerIndex == type(uint256).max) {
        ownerIndex = ownerCount++;
        owners[ownerIndex] = owner;
      }
      ownerBalances[ownerIndex] += uint256(balance);
      ownerPowers[ownerIndex] += uint256(earningPower);

      bool seenDelegatee;
      for (uint256 j = 0; j < delegateeCount; j++) {
        if (delegatees[j] == delegatee) {
          seenDelegatee = true;
          break;
        }
      }
      if (!seenDelegatee) delegatees[delegateeCount++] = delegatee;
    }

    assertEq(depositBalanceSum, staker.totalStaked(), "deposit/global principal mismatch");
    assertEq(depositPowerSum, staker.totalEarningPower(), "deposit/global power mismatch");
    assertEq(staker.totalStaked(), staker.totalEarningPower(), "identity calculator invariant broken");

    for (uint256 i = 0; i < ownerCount; i++) {
      assertEq(
        ownerBalances[i], staker.depositorTotalStaked(owners[i]), "owner principal aggregate mismatch"
      );
      assertEq(
        ownerPowers[i],
        staker.depositorTotalEarningPower(owners[i]),
        "owner power aggregate mismatch"
      );
    }

    uint256 surrogateBalanceSum;
    uint256 emptySurrogates;
    for (uint256 i = 0; i < delegateeCount; i++) {
      address surrogate = address(staker.surrogates(delegatees[i]));
      assertTrue(surrogate != address(0), "delegatee missing surrogate");
      uint256 balance = token.balanceOf(surrogate);
      surrogateBalanceSum += balance;
      if (balance == 0) emptySurrogates++;
    }
    assertGe(surrogateBalanceSum, staker.totalStaked(), "surrogates undercollateralized");

    uint256 stakerBalance = token.balanceOf(STAKER_ADDRESS);
    uint256 accumulatorBalance = token.balanceOf(ACCUMULATOR_ADDRESS);
    uint256 accountedAccumulator = accumulator.accumulatedRewards();
    assertGe(accumulatorBalance, accountedAccumulator, "accumulator accounting exceeds balance");

    uint256 remainingScaled;
    if (block.timestamp < staker.rewardEndTime()) {
      remainingScaled = staker.scaledRewardRate() * (staker.rewardEndTime() - block.timestamp);
    }
    uint256 remainingReward = remainingScaled / SCALE_FACTOR;
    assertLe(unclaimedSum + remainingReward, stakerBalance, "reward obligations exceed balance");

    assertEq(address(staker.STAKE_TOKEN()), TOKEN_ADDRESS, "wrong stake token");
    assertEq(address(staker.REWARD_TOKEN()), TOKEN_ADDRESS, "wrong reward token");
    assertEq(address(staker.earningPowerCalculator()), CALCULATOR_ADDRESS, "wrong calculator");
    assertEq(staker.admin(), SAFE_ADDRESS, "wrong admin");
    assertEq(accumulator.owner(), SAFE_ADDRESS, "wrong accumulator owner");
    assertEq(address(accumulator.staker()), STAKER_ADDRESS, "wrong accumulator staker");
    assertEq(address(accumulator.rewardToken()), TOKEN_ADDRESS, "wrong accumulator token");
    assertTrue(staker.isRewardNotifier(ACCUMULATOR_ADDRESS), "accumulator not authorized");

    emit log_named_uint("CENSUS_BLOCK", block.number);
    emit log_named_uint("CENSUS_DEPOSITS", next);
    emit log_named_uint("CENSUS_UNIQUE_OWNERS", ownerCount);
    emit log_named_uint("CENSUS_UNIQUE_DELEGATEES", delegateeCount);
    emit log_named_uint("CENSUS_TOTAL_STAKED_WEI", staker.totalStaked());
    emit log_named_uint("CENSUS_TOTAL_POWER_WEI", staker.totalEarningPower());
    emit log_named_uint("CENSUS_SURROGATE_BALANCE_WEI", surrogateBalanceSum);
    emit log_named_uint("CENSUS_SURROGATE_SURPLUS_WEI", surrogateBalanceSum - staker.totalStaked());
    emit log_named_uint("CENSUS_EMPTY_SURROGATES", emptySurrogates);
    emit log_named_uint("CENSUS_UNCLAIMED_WEI", unclaimedSum);
    emit log_named_uint("CENSUS_REMAINING_STREAM_WEI", remainingReward);
    emit log_named_uint("CENSUS_STAKER_BALANCE_WEI", stakerBalance);
    emit log_named_uint("CENSUS_REWARD_SURPLUS_WEI", stakerBalance - unclaimedSum - remainingReward);
    emit log_named_uint("CENSUS_ACC_BALANCE_WEI", accumulatorBalance);
    emit log_named_uint("CENSUS_ACC_ACCOUNTED_WEI", accountedAccumulator);
    emit log_named_uint("CENSUS_ZERO_BALANCE_RESIDUAL_COUNT", zeroBalanceResidualCount);
    emit log_named_uint("CENSUS_ZERO_BALANCE_RESIDUAL_REWARD_WEI", zeroBalanceResidualReward);
  }
}
