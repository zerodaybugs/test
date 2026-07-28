// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Staker} from "../src/Staker.sol";
import {ZenStaker} from "../src/ZenStaker.sol";
import {RewardAccumulator} from "../src/RewardAccumulator.sol";

interface ISafeLike {
  function VERSION() external view returns (string memory);
  function getOwners() external view returns (address[] memory);
  function getThreshold() external view returns (uint256);
  function nonce() external view returns (uint256);
}

/// @dev Read-only production census executed exclusively on a pinned local mainnet fork.
contract HorizenLiveCensusV2 is Test {
  address internal constant STAKER_ADDRESS = 0x6BF7CF29a8bcE11Aa62Cf593d165C244fA4d3E31;
  address internal constant ACCUMULATOR_ADDRESS = 0x06f5555fee73EDdc385b6d76FE00DB2D96ccDaE8;
  address internal constant TOKEN_ADDRESS = 0x57da2D504bf8b83Ef304759d9f2648522D7a9280;
  address internal constant CALCULATOR_ADDRESS = 0xf518b3c7Cd5cc1595D10E7268677Da0Fe364E191;
  address internal constant SAFE_ADDRESS = 0x1Afb144aaD0aE02f3Bb04C1eae4AC6020a727A21;
  address internal constant DEPLOYER_ADDRESS = 0x9B264B21ca7659C256aD09171f827976Acd5a1C3;

  uint256 internal constant SCALE_FACTOR = 1e36;
  bytes32 internal constant NEXT_DEPOSIT_ID_SLOT = bytes32(uint256(0));

  ZenStaker internal staker;
  RewardAccumulator internal accumulator;
  IERC20 internal token;

  address[] internal owners;
  address[] internal delegatees;
  mapping(address => bool) internal ownerSeen;
  mapping(address => bool) internal delegateeSeen;
  mapping(address => uint256) internal ownerBalanceSum;
  mapping(address => uint256) internal ownerPowerSum;

  uint256 internal currentRewardPerToken;
  uint256 internal depositBalanceSum;
  uint256 internal depositPowerSum;
  uint256 internal depositUnclaimedSum;
  uint256 internal depositScaledUnclaimedSum;
  uint256 internal zeroBalanceResidualCount;
  uint256 internal zeroBalanceResidualReward;
  uint256 internal zeroBalanceResidualScaled;

  function setUp() public {
    vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), vm.envUint("PINNED_BLOCK"));
    staker = ZenStaker(STAKER_ADDRESS);
    accumulator = RewardAccumulator(ACCUMULATOR_ADDRESS);
    token = IERC20(TOKEN_ADDRESS);
  }

  function test_CompleteProductionStateCensus() public {
    // nextDepositId is the first regular storage variable in the exact pinned Staker source.
    uint256 nextDepositId = uint256(vm.load(STAKER_ADDRESS, NEXT_DEPOSIT_ID_SLOT));
    assertGt(nextDepositId, 0, "no production deposits");
    assertLt(nextDepositId, 10_000, "census bound requires review");

    currentRewardPerToken = staker.rewardPerTokenAccumulated();
    for (uint256 i = 0; i < nextDepositId; i++) _scanDeposit(i);

    _assertSequentialBoundary(nextDepositId);
    _assertGlobalAndOwnerAccounting();
    (uint256 surrogateBalanceSum, uint256 emptySurrogates) = _assertSurrogateAccounting();
    (
      uint256 stakerBalance,
      uint256 accumulatorBalance,
      uint256 accountedAccumulator,
      uint256 remainingScaled,
      uint256 totalScaledObligations
    ) = _assertRewardCoverage();
    (uint256 safeThreshold, uint256 safeOwnerCount, uint256 safeNonce, string memory safeVersion) =
      _assertConfigurationAndSafe();

    emit log_named_uint("CENSUS_BLOCK", block.number);
    emit log_named_uint("CENSUS_DEPOSITS", nextDepositId);
    emit log_named_uint("CENSUS_UNIQUE_OWNERS", owners.length);
    emit log_named_uint("CENSUS_UNIQUE_DELEGATEES", delegatees.length);
    emit log_named_uint("CENSUS_TOTAL_STAKED_WEI", staker.totalStaked());
    emit log_named_uint("CENSUS_TOTAL_POWER_WEI", staker.totalEarningPower());
    emit log_named_uint("CENSUS_SURROGATE_BALANCE_WEI", surrogateBalanceSum);
    emit log_named_uint("CENSUS_SURROGATE_SURPLUS_WEI", surrogateBalanceSum - staker.totalStaked());
    emit log_named_uint("CENSUS_EMPTY_SURROGATES", emptySurrogates);
    emit log_named_uint("CENSUS_UNCLAIMED_WEI", depositUnclaimedSum);
    emit log_named_uint("CENSUS_SCALED_UNCLAIMED", depositScaledUnclaimedSum);
    emit log_named_uint("CENSUS_REMAINING_STREAM_SCALED", remainingScaled);
    emit log_named_uint("CENSUS_TOTAL_SCALED_OBLIGATIONS", totalScaledObligations);
    emit log_named_uint("CENSUS_STAKER_BALANCE_WEI", stakerBalance);
    emit log_named_uint(
      "CENSUS_REWARD_SURPLUS_SCALED", stakerBalance * SCALE_FACTOR - totalScaledObligations
    );
    emit log_named_uint("CENSUS_ACC_BALANCE_WEI", accumulatorBalance);
    emit log_named_uint("CENSUS_ACC_ACCOUNTED_WEI", accountedAccumulator);
    emit log_named_uint("CENSUS_ZERO_BALANCE_RESIDUAL_COUNT", zeroBalanceResidualCount);
    emit log_named_uint("CENSUS_ZERO_BALANCE_RESIDUAL_REWARD_WEI", zeroBalanceResidualReward);
    emit log_named_uint("CENSUS_ZERO_BALANCE_RESIDUAL_SCALED", zeroBalanceResidualScaled);
    emit log_named_uint("CENSUS_SAFE_THRESHOLD", safeThreshold);
    emit log_named_uint("CENSUS_SAFE_OWNER_COUNT", safeOwnerCount);
    emit log_named_uint("CENSUS_SAFE_NONCE", safeNonce);
    emit log_named_string("CENSUS_SAFE_VERSION", safeVersion);
  }

  function _scanDeposit(uint256 rawId) internal {
    Staker.DepositIdentifier id = Staker.DepositIdentifier.wrap(rawId);
    (
      uint96 balance,
      address owner,
      uint96 earningPower,
      address delegatee,
      ,
      uint256 unclaimed
    ) = staker.getDepositInfo(id);
    (,,,,, uint256 rewardPerTokenCheckpoint, uint256 scaledCheckpoint) = staker.deposits(id);

    assertTrue(owner != address(0), "sequential deposit has zero owner");
    assertTrue(delegatee != address(0), "deposit has zero delegatee");
    assertLe(rewardPerTokenCheckpoint, currentRewardPerToken, "deposit checkpoint exceeds global");

    uint256 scaledLive = scaledCheckpoint
      + uint256(earningPower) * (currentRewardPerToken - rewardPerTokenCheckpoint);
    assertEq(scaledLive / SCALE_FACTOR, unclaimed, "view/raw reward mismatch");

    depositBalanceSum += uint256(balance);
    depositPowerSum += uint256(earningPower);
    depositUnclaimedSum += unclaimed;
    depositScaledUnclaimedSum += scaledLive;

    if (balance == 0 && scaledLive > 0) {
      zeroBalanceResidualCount++;
      zeroBalanceResidualReward += unclaimed;
      zeroBalanceResidualScaled += scaledLive;
    }

    if (!ownerSeen[owner]) {
      ownerSeen[owner] = true;
      owners.push(owner);
    }
    ownerBalanceSum[owner] += uint256(balance);
    ownerPowerSum[owner] += uint256(earningPower);

    if (!delegateeSeen[delegatee]) {
      delegateeSeen[delegatee] = true;
      delegatees.push(delegatee);
    }
  }

  function _assertSequentialBoundary(uint256 nextDepositId) internal view {
    (, address lastOwner,,,,) =
      staker.getDepositInfo(Staker.DepositIdentifier.wrap(nextDepositId - 1));
    (, address futureOwner,,,,) =
      staker.getDepositInfo(Staker.DepositIdentifier.wrap(nextDepositId));
    assertTrue(lastOwner != address(0), "last allocated deposit missing");
    assertEq(futureOwner, address(0), "slot-0 nextDepositId binding incorrect");
  }

  function _assertGlobalAndOwnerAccounting() internal view {
    assertEq(depositBalanceSum, staker.totalStaked(), "deposit/global principal mismatch");
    assertEq(depositPowerSum, staker.totalEarningPower(), "deposit/global power mismatch");
    assertEq(staker.totalStaked(), staker.totalEarningPower(), "identity invariant broken");

    for (uint256 i = 0; i < owners.length; i++) {
      address owner = owners[i];
      assertEq(
        ownerBalanceSum[owner], staker.depositorTotalStaked(owner), "owner principal mismatch"
      );
      assertEq(
        ownerPowerSum[owner], staker.depositorTotalEarningPower(owner), "owner power mismatch"
      );
    }
  }

  function _assertSurrogateAccounting()
    internal
    view
    returns (uint256 surrogateBalanceSum, uint256 emptySurrogates)
  {
    for (uint256 i = 0; i < delegatees.length; i++) {
      address surrogate = address(staker.surrogates(delegatees[i]));
      assertTrue(surrogate != address(0), "delegatee missing surrogate");
      uint256 balance = token.balanceOf(surrogate);
      surrogateBalanceSum += balance;
      if (balance == 0) emptySurrogates++;
    }
    assertGe(surrogateBalanceSum, staker.totalStaked(), "surrogates undercollateralized");
  }

  function _assertRewardCoverage()
    internal
    view
    returns (
      uint256 stakerBalance,
      uint256 accumulatorBalance,
      uint256 accountedAccumulator,
      uint256 remainingScaled,
      uint256 totalScaledObligations
    )
  {
    stakerBalance = token.balanceOf(STAKER_ADDRESS);
    accumulatorBalance = token.balanceOf(ACCUMULATOR_ADDRESS);
    accountedAccumulator = accumulator.accumulatedRewards();
    assertGe(accumulatorBalance, accountedAccumulator, "accumulator accounting exceeds balance");

    if (block.timestamp < staker.rewardEndTime()) {
      remainingScaled = staker.scaledRewardRate() * (staker.rewardEndTime() - block.timestamp);
    }
    totalScaledObligations = depositScaledUnclaimedSum + remainingScaled;
    assertLe(totalScaledObligations, stakerBalance * SCALE_FACTOR, "reward insolvency");
  }

  function _assertConfigurationAndSafe()
    internal
    view
    returns (uint256 threshold, uint256 ownerCount, uint256 safeNonce, string memory version)
  {
    assertEq(address(staker.STAKE_TOKEN()), TOKEN_ADDRESS, "wrong stake token");
    assertEq(address(staker.REWARD_TOKEN()), TOKEN_ADDRESS, "wrong reward token");
    assertEq(address(staker.earningPowerCalculator()), CALCULATOR_ADDRESS, "wrong calculator");
    assertEq(staker.admin(), SAFE_ADDRESS, "wrong admin");
    assertEq(accumulator.owner(), SAFE_ADDRESS, "wrong accumulator owner");
    assertEq(address(accumulator.staker()), STAKER_ADDRESS, "wrong accumulator staker");
    assertEq(address(accumulator.rewardToken()), TOKEN_ADDRESS, "wrong accumulator token");
    assertEq(accumulator.timeWindow(), 431_700, "unexpected time window");
    assertFalse(accumulator.whitelistEnabled(), "unexpected whitelist mode");
    assertTrue(staker.isRewardNotifier(ACCUMULATOR_ADDRESS), "accumulator not authorized");
    assertFalse(staker.isRewardNotifier(DEPLOYER_ADDRESS), "deployer still authorized");
    assertEq(staker.maxBumpTip(), 0, "bumping unexpectedly enabled");
    assertEq(staker.MAX_CLAIM_FEE(), 0, "claim fee cap unexpectedly nonzero");
    (uint96 feeAmount, address feeCollector) = staker.claimFeeParameters();
    assertEq(uint256(feeAmount), 0, "claim fee unexpectedly nonzero");
    assertEq(feeCollector, address(0), "claim fee collector unexpectedly set");

    assertGt(SAFE_ADDRESS.code.length, 0, "admin/owner is not a contract");
    ISafeLike safe = ISafeLike(SAFE_ADDRESS);
    version = safe.VERSION();
    address[] memory safeOwners = safe.getOwners();
    threshold = safe.getThreshold();
    safeNonce = safe.nonce();
    ownerCount = safeOwners.length;
    assertGt(threshold, 0, "Safe threshold is zero");
    assertGe(ownerCount, threshold, "Safe threshold exceeds owner count");
    for (uint256 i = 0; i < ownerCount; i++) {
      assertTrue(safeOwners[i] != address(0), "Safe contains zero owner");
      for (uint256 j = 0; j < i; j++) {
        assertTrue(safeOwners[i] != safeOwners[j], "Safe contains duplicate owner");
      }
    }
  }
}
