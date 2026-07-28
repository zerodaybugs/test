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

/// @dev Local-only stateful handler for the exact Horizen Phase B integration.
contract HorizenHandlerOnly is Test {
  ERC20VotesMock public immutable token;
  ZenStaker public immutable staker;
  RewardAccumulator public immutable accumulator;

  uint256 internal constant MAX_AMOUNT = 21_000_000e18;
  uint256 internal constant MAX_DEPOSITS = 96;
  address internal constant FUNDER = address(0xF00D);
  address internal constant ATTACKER = address(0xBAD0);

  address[] internal actors;
  address[] internal delegatees;
  Staker.DepositIdentifier[] internal depositIds;

  uint256 public ghostRewardFunding;
  uint256 public ghostRewardClaimed;
  uint256 public ghostSurrogateDonations;
  uint256 public ghostUnauthorizedSuccesses;
  uint256 public ghostLastRewardPerToken;

  uint256 public callsStake;
  uint256 public callsStakeMore;
  uint256 public callsWithdraw;
  uint256 public callsClaim;
  uint256 public callsFund;
  uint256 public callsFlush;

  constructor(ERC20VotesMock _token, ZenStaker _staker, RewardAccumulator _accumulator) {
    token = _token;
    staker = _staker;
    accumulator = _accumulator;

    actors.push(address(0xA11CE));
    actors.push(address(0xB0B));
    actors.push(address(0xCA11));
    actors.push(address(0xD00D));

    delegatees.push(address(0xD311));
    delegatees.push(address(0xD312));
    delegatees.push(address(0xD313));
    delegatees.push(address(0xD314));
    delegatees.push(address(0xD315));
    delegatees.push(address(0xD316));
    delegatees.push(address(0xD317));
    delegatees.push(address(0xD318));
  }

  function initializeApprovals() external {
    for (uint256 i = 0; i < actors.length; i++) {
      vm.startPrank(actors[i]);
      token.approve(address(staker), type(uint256).max);
      token.approve(address(accumulator), type(uint256).max);
      vm.stopPrank();
    }
    vm.prank(FUNDER);
    token.approve(address(accumulator), type(uint256).max);
    ghostLastRewardPerToken = staker.rewardPerTokenAccumulatedCheckpoint();
  }

  function actorCount() external view returns (uint256) {
    return actors.length;
  }

  function actorAt(uint256 index) external view returns (address) {
    return actors[index];
  }

  function delegateeCount() external view returns (uint256) {
    return delegatees.length;
  }

  function delegateeAt(uint256 index) external view returns (address) {
    return delegatees[index];
  }

  function depositCount() external view returns (uint256) {
    return depositIds.length;
  }

  function depositAt(uint256 index) external view returns (Staker.DepositIdentifier) {
    return depositIds[index];
  }

  function stake(uint256 actorSeed, uint256 amountSeed, uint256 delegateeSeed, uint256 claimerSeed)
    external
  {
    callsStake++;
    if (depositIds.length >= MAX_DEPOSITS) {
      _recordRewardPerToken();
      return;
    }

    address owner = actors[actorSeed % actors.length];
    address delegatee = delegatees[delegateeSeed % delegatees.length];
    address claimer = actors[claimerSeed % actors.length];
    uint256 amount = bound(amountSeed, 0, MAX_AMOUNT);

    if (amount > 0) token.mint(owner, amount);
    vm.prank(owner);
    try staker.stake(amount, delegatee, claimer) returns (Staker.DepositIdentifier id) {
      depositIds.push(id);
    } catch {}
    _recordRewardPerToken();
  }

  function stakeMore(uint256 idSeed, uint256 amountSeed) external {
    callsStakeMore++;
    if (depositIds.length == 0) {
      _recordRewardPerToken();
      return;
    }

    Staker.DepositIdentifier id = depositIds[idSeed % depositIds.length];
    (uint96 balance, address owner,,,,) = staker.getDepositInfo(id);
    uint256 maxAdd = type(uint96).max - uint256(balance);
    if (maxAdd > MAX_AMOUNT) maxAdd = MAX_AMOUNT;
    uint256 amount = bound(amountSeed, 0, maxAdd);

    if (amount > 0) token.mint(owner, amount);
    vm.prank(owner);
    try staker.stakeMore(id, amount) {} catch {}
    _recordRewardPerToken();
  }

  function withdraw(uint256 idSeed, uint256 amountSeed) external {
    callsWithdraw++;
    if (depositIds.length == 0) {
      _recordRewardPerToken();
      return;
    }

    Staker.DepositIdentifier id = depositIds[idSeed % depositIds.length];
    (uint96 balance, address owner,,,,) = staker.getDepositInfo(id);
    uint256 amount = bound(amountSeed, 0, uint256(balance));

    vm.prank(owner);
    try staker.withdraw(id, amount) {} catch {}
    _recordRewardPerToken();
  }

  function claim(uint256 idSeed, uint256 callerSeed) external {
    callsClaim++;
    if (depositIds.length == 0) {
      _recordRewardPerToken();
      return;
    }

    Staker.DepositIdentifier id = depositIds[idSeed % depositIds.length];
    (, address owner,,, address claimer,) = staker.getDepositInfo(id);
    address caller = callerSeed % 2 == 0 ? owner : claimer;
    uint256 beforeBalance = token.balanceOf(caller);

    vm.prank(caller);
    try staker.claimReward(id) returns (uint256 claimed) {
      claimed;
      uint256 afterBalance = token.balanceOf(caller);
      if (afterBalance >= beforeBalance) ghostRewardClaimed += afterBalance - beforeBalance;
    } catch {}
    _recordRewardPerToken();
  }

  function alterDelegatee(uint256 idSeed, uint256 delegateeSeed) external {
    if (depositIds.length == 0) {
      _recordRewardPerToken();
      return;
    }

    Staker.DepositIdentifier id = depositIds[idSeed % depositIds.length];
    (, address owner,,,,) = staker.getDepositInfo(id);
    address newDelegatee = delegatees[delegateeSeed % delegatees.length];

    vm.prank(owner);
    try staker.alterDelegatee(id, newDelegatee) {} catch {}
    _recordRewardPerToken();
  }

  function alterClaimer(uint256 idSeed, uint256 claimerSeed) external {
    if (depositIds.length == 0) {
      _recordRewardPerToken();
      return;
    }

    Staker.DepositIdentifier id = depositIds[idSeed % depositIds.length];
    (, address owner,,,,) = staker.getDepositInfo(id);
    address newClaimer = actors[claimerSeed % actors.length];

    vm.prank(owner);
    try staker.alterClaimer(id, newClaimer) {} catch {}
    _recordRewardPerToken();
  }

  function fund(uint256 amountSeed) external {
    callsFund++;
    uint256 amount = bound(amountSeed, 0, MAX_AMOUNT);
    if (amount > 0) token.mint(FUNDER, amount);

    vm.prank(FUNDER);
    try accumulator.transferAndNotifyRewards(amount) {
      ghostRewardFunding += amount;
    } catch {}
    _recordRewardPerToken();
  }

  function directAccumulatorTransfer(uint256 amountSeed) external {
    uint256 amount = bound(amountSeed, 0, MAX_AMOUNT);
    if (amount > 0) token.mint(FUNDER, amount);

    vm.prank(FUNDER);
    bool success = token.transfer(address(accumulator), amount);
    if (success) ghostRewardFunding += amount;
    _recordRewardPerToken();
  }

  function creditUnaccountedAccumulatorBalance(uint256 amountSeed) external {
    uint256 balance = token.balanceOf(address(accumulator));
    uint256 accounted = accumulator.accumulatedRewards();
    if (balance < accounted) {
      _recordRewardPerToken();
      return;
    }
    uint256 unaccounted = balance - accounted;
    uint256 amount = bound(amountSeed, 0, unaccounted);

    vm.prank(actors[amountSeed % actors.length]);
    try accumulator.notifyAlreadyTransferredRewards(amount) {} catch {}
    _recordRewardPerToken();
  }

  function directStakerDonation(uint256 amountSeed) external {
    uint256 amount = bound(amountSeed, 0, MAX_AMOUNT);
    if (amount > 0) token.mint(FUNDER, amount);

    vm.prank(FUNDER);
    bool success = token.transfer(address(staker), amount);
    if (success) ghostRewardFunding += amount;
    _recordRewardPerToken();
  }

  function donateToSurrogate(uint256 delegateeSeed, uint256 amountSeed) external {
    address delegatee = delegatees[delegateeSeed % delegatees.length];
    address surrogate = address(staker.surrogates(delegatee));
    if (surrogate == address(0)) {
      _recordRewardPerToken();
      return;
    }

    uint256 amount = bound(amountSeed, 0, MAX_AMOUNT);
    if (amount > 0) token.mint(FUNDER, amount);
    vm.prank(FUNDER);
    bool success = token.transfer(surrogate, amount);
    if (success) ghostSurrogateDonations += amount;
    _recordRewardPerToken();
  }

  function flush(uint256 modeSeed) external {
    callsFlush++;
    uint256 next = accumulator.nextRewardTime();
    if (modeSeed % 2 == 0 && block.timestamp < next) vm.warp(next);
    try accumulator.sendRewardsToStaker() {} catch {}
    _recordRewardPerToken();
  }

  function warpAhead(uint256 deltaSeed) external {
    uint256 delta = bound(deltaSeed, 0, 180 days);
    vm.warp(block.timestamp + delta);
    _recordRewardPerToken();
  }

  function unauthorizedMatrix(uint256 idSeed) external {
    if (depositIds.length > 0) {
      Staker.DepositIdentifier id = depositIds[idSeed % depositIds.length];
      _attemptAsAttacker(
        address(staker),
        abi.encodeWithSignature("withdraw(uint256,uint256)", Staker.DepositIdentifier.unwrap(id), 0)
      );
      _attemptAsAttacker(
        address(staker),
        abi.encodeWithSignature("stakeMore(uint256,uint256)", Staker.DepositIdentifier.unwrap(id), 0)
      );
      _attemptAsAttacker(
        address(staker),
        abi.encodeWithSignature(
          "alterDelegatee(uint256,address)", Staker.DepositIdentifier.unwrap(id), ATTACKER
        )
      );
      _attemptAsAttacker(
        address(staker),
        abi.encodeWithSignature(
          "alterClaimer(uint256,address)", Staker.DepositIdentifier.unwrap(id), ATTACKER
        )
      );
      _attemptAsAttacker(
        address(staker),
        abi.encodeWithSignature("claimReward(uint256)", Staker.DepositIdentifier.unwrap(id))
      );
    }

    _attemptAsAttacker(address(staker), abi.encodeWithSignature("setAdmin(address)", ATTACKER));
    _attemptAsAttacker(
      address(staker), abi.encodeWithSignature("setRewardNotifier(address,bool)", ATTACKER, true)
    );
    _attemptAsAttacker(
      address(accumulator), abi.encodeWithSignature("setTimeWindow(uint256)", uint256(1))
    );
    _attemptAsAttacker(
      address(accumulator), abi.encodeWithSignature("setWhitelistEnabled(bool)", true)
    );
    _attemptAsAttacker(
      address(accumulator), abi.encodeWithSignature("setWhitelist(address,bool)", ATTACKER, true)
    );
    _recordRewardPerToken();
  }

  function _attemptAsAttacker(address target, bytes memory data) internal {
    vm.prank(ATTACKER);
    (bool success,) = target.call(data);
    if (success) ghostUnauthorizedSuccesses++;
  }

  function _recordRewardPerToken() internal {
    uint256 current = staker.rewardPerTokenAccumulatedCheckpoint();
    if (current > ghostLastRewardPerToken) ghostLastRewardPerToken = current;
  }
}

contract HorizenHandlerOnlyInvariants is Test {
  ERC20VotesMock internal token;
  IdentityEarningPowerCalculator internal calculator;
  ZenStaker internal staker;
  RewardAccumulator internal accumulator;
  HorizenHandlerOnly internal handler;

  address internal constant ADMIN = address(0xA11D);
  uint256 internal constant SCALE_FACTOR = 1e36;

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

    handler = new HorizenHandlerOnly(token, staker, accumulator);
    handler.initializeApprovals();

    bytes4[] memory selectors = new bytes4[](14);
    selectors[0] = HorizenHandlerOnly.stake.selector;
    selectors[1] = HorizenHandlerOnly.stakeMore.selector;
    selectors[2] = HorizenHandlerOnly.withdraw.selector;
    selectors[3] = HorizenHandlerOnly.claim.selector;
    selectors[4] = HorizenHandlerOnly.alterDelegatee.selector;
    selectors[5] = HorizenHandlerOnly.alterClaimer.selector;
    selectors[6] = HorizenHandlerOnly.fund.selector;
    selectors[7] = HorizenHandlerOnly.directAccumulatorTransfer.selector;
    selectors[8] = HorizenHandlerOnly.creditUnaccountedAccumulatorBalance.selector;
    selectors[9] = HorizenHandlerOnly.directStakerDonation.selector;
    selectors[10] = HorizenHandlerOnly.donateToSurrogate.selector;
    selectors[11] = HorizenHandlerOnly.flush.selector;
    selectors[12] = HorizenHandlerOnly.warpAhead.selector;
    selectors[13] = HorizenHandlerOnly.unauthorizedMatrix.selector;

    targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    targetContract(address(handler));
  }

  function invariant_RewardFundingIsConservedExactly() public view {
    uint256 systemBalance =
      token.balanceOf(address(staker)) + token.balanceOf(address(accumulator));
    assertEq(handler.ghostRewardFunding(), systemBalance + handler.ghostRewardClaimed());
  }

  function invariant_AccumulatorNeverAccountsForMoreThanItsBalance() public view {
    assertGe(token.balanceOf(address(accumulator)), accumulator.accumulatedRewards());
  }

  function invariant_DepositSumsMatchGlobalAccounting() public view {
    uint256 balanceSum;
    uint256 earningPowerSum;
    uint256 unclaimedSum;
    uint256 count = handler.depositCount();

    for (uint256 i = 0; i < count; i++) {
      Staker.DepositIdentifier id = handler.depositAt(i);
      (uint96 balance,, uint96 earningPower,,, uint256 unclaimed) = staker.getDepositInfo(id);
      balanceSum += uint256(balance);
      earningPowerSum += uint256(earningPower);
      unclaimedSum += unclaimed;
    }

    assertEq(balanceSum, staker.totalStaked());
    assertEq(earningPowerSum, staker.totalEarningPower());
    assertLe(unclaimedSum, token.balanceOf(address(staker)));
  }

  function invariant_PerOwnerAccountingMatchesDeposits() public view {
    uint256 actorCount_ = handler.actorCount();
    uint256 depositCount_ = handler.depositCount();

    for (uint256 a = 0; a < actorCount_; a++) {
      address actor = handler.actorAt(a);
      uint256 balanceSum;
      uint256 earningPowerSum;

      for (uint256 i = 0; i < depositCount_; i++) {
        Staker.DepositIdentifier id = handler.depositAt(i);
        (uint96 balance, address owner, uint96 earningPower,,,) = staker.getDepositInfo(id);
        if (owner == actor) {
          balanceSum += uint256(balance);
          earningPowerSum += uint256(earningPower);
        }
      }

      assertEq(balanceSum, staker.depositorTotalStaked(actor));
      assertEq(earningPowerSum, staker.depositorTotalEarningPower(actor));
    }
  }

  function invariant_SurrogateBalancesEqualPrincipalPlusExplicitDonations() public view {
    uint256 surrogateBalanceSum;
    uint256 count = handler.delegateeCount();

    for (uint256 i = 0; i < count; i++) {
      address surrogate = address(staker.surrogates(handler.delegateeAt(i)));
      if (surrogate != address(0)) surrogateBalanceSum += token.balanceOf(surrogate);
    }

    assertEq(
      surrogateBalanceSum,
      staker.totalStaked() + handler.ghostSurrogateDonations()
    );
  }

  function invariant_AccruedAndScheduledRewardObligationsRemainCovered() public view {
    uint256 unclaimedSum;
    uint256 count = handler.depositCount();
    for (uint256 i = 0; i < count; i++) {
      unclaimedSum += staker.unclaimedReward(handler.depositAt(i));
    }

    uint256 remainingScaled;
    if (block.timestamp < staker.rewardEndTime()) {
      remainingScaled = staker.scaledRewardRate() * (staker.rewardEndTime() - block.timestamp);
    }
    uint256 remainingReward = remainingScaled / SCALE_FACTOR;
    assertLe(unclaimedSum + remainingReward, token.balanceOf(address(staker)));
  }

  function invariant_IdentityCalculatorKeepsStakeAndPowerEqual() public view {
    assertEq(staker.totalStaked(), staker.totalEarningPower());
  }

  function invariant_RewardPerTokenCheckpointIsMonotonic() public view {
    assertGe(staker.rewardPerTokenAccumulatedCheckpoint(), handler.ghostLastRewardPerToken());
  }

  function invariant_UnauthorizedCallsNeverSucceed() public view {
    assertEq(handler.ghostUnauthorizedSuccesses(), 0);
  }

  function invariant_CallSummary() public view {
    handler.callsStake();
    handler.callsStakeMore();
    handler.callsWithdraw();
    handler.callsClaim();
    handler.callsFund();
    handler.callsFlush();
  }
}
