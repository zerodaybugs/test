# Public Sample: ERC-4626 Inflation / Donation Invariant Harness

A small, standalone, self-contained Foundry project that demonstrates **how an
accounting-invariant harness proves it can actually catch a bug** — not just that
"the tests are green."

It targets the classic ERC-4626 **first-depositor / donation inflation** attack:
the bug class that has repeatedly rounded a real depositor down to **zero shares**
and captured their deposit.

This is a public, sanitized sample. It contains no client code and no
contest-specific data. The only dependency is `forge-std`.

---

## Why this exists: the negative-control method

Pointing a fuzzer at a contract and getting "PASS" is nearly worthless on its own.
A test suite that can never fail is indistinguishable from one that found nothing.
The question that matters is:

> Would this harness have **failed** if the bug were present?

This sample answers that question by construction. It ships **two reference
contracts** and runs the **same** attack and the **same** invariant against both:

| Reference | What it is | Expected result | Meaning |
|---|---|---|---|
| `VulnerableVault` | `totalAssets()` reads the raw token balance, no virtual offset | invariant **FAILS** (victim rounds to 0 shares) | proves the harness can SEE the bug |
| `DefendedVault` | OpenZeppelin-style virtual shares/assets offset | invariant **PASSES** under the same attack | proves the invariant is not a false-positive generator |

A vulnerable reference that **FAILS** plus a defended reference that **PASSES** is
the whole point. It proves the harness detects **signal** (a real accounting break)
rather than **noise** (any fuzzer can print failures). If the vulnerable
reference ever started passing, the harness would have gone blind, and every
"green" result on real code would be meaningless.

In a real engagement, you replace `DefendedVault` with the actual target vault
(behind the `IVault` adapter, or by fork-deploying it) and run the same invariant.
A normal depositor receiving 0 shares — or a profitable deposit -> redeem
round-trip — is a shrunk, executable counterexample: a candidate finding.

---

## The bug class (public precedent)

The ERC-4626 inflation attack is well documented. The attacker:

1. Deposits **1 wei** of the underlying asset and receives **1 share**.
2. **Donates** a large amount of the underlying directly to the vault (a plain
   `transfer`, no `deposit`). `totalAssets()` now reports a large balance, but no
   new shares were minted — the price-per-share is now enormous.
3. The next honest depositor deposits a normal amount, but
   `shares = assets * totalSupply / totalAssets()` **rounds down to 0**. Their
   assets are absorbed by the vault and effectively captured by the attacker's
   single share.

The enabler is always the same shape:

- `totalAssets()` reads the raw asset balance (`asset.balanceOf(address(this))`), **and**
- some path increases that balance **without minting shares** (a direct donation,
  a `depositRewards`-style call, etc.), **and**
- there is **no** virtual-offset / minimum-shares / dead-shares guard.

The standard mitigation is OpenZeppelin's **virtual shares/assets offset**, which
`DefendedVault` implements (`+1e6` virtual shares, `+1` virtual asset). It makes
the share price impossible to inflate to the point where a normal deposit rounds
to zero.

---

## What the harness checks

Three tests in `test/Erc4626InflationSample.t.sol`:

1. **`test_negControl_vulnerableVaultIsExploitable`** — the negative control.
   Runs the donation attack on `VulnerableVault` and asserts the victim gets
   **exactly 0 shares**. This must hold, otherwise the harness can't see the bug.

2. **`test_invariant_defendedVaultResistsInflation`** — the invariant.
   Runs the **same** attack on `DefendedVault` and asserts the victim gets
   **> 0 shares**. This is the property you run against real code.

3. **`testFuzz_noRoundTripProfit`** — share conservation.
   5000 fuzz runs asserting that `deposit` then `redeem` can never return more
   than was put in (no value leak / vault drain) on the defended vault.

---

## Run it

Requires [Foundry](https://book.getfoundry.sh/) (`forge`).

```
forge test -vv
```

Expected output (all green):

```
Ran 3 tests for test/Erc4626InflationSample.t.sol:Erc4626InflationSample
[PASS] testFuzz_noRoundTripProfit(uint256) (runs: 5000, ...)
[PASS] test_invariant_defendedVaultResistsInflation() (gas: ...)
[PASS] test_negControl_vulnerableVaultIsExploitable() (gas: ...)
Suite result: ok. 3 passed; 0 failed; 0 skipped
```

### Prove the harness is not blind (30-second check)

You can verify the detection claim yourself. In
`test_invariant_defendedVaultResistsInflation`, change:

```solidity
DefendedVault v = new DefendedVault(usdc);
```

to:

```solidity
VulnerableVault v = new VulnerableVault(usdc);
```

and re-run. The invariant now **FAILS**:

```
[FAIL: victim received 0 shares -> INFLATION/DONATION ATTACK: 0 <= 0]
test_invariant_defendedVaultResistsInflation()
```

That failure is the proof. The harness catches the bug the moment the bug is
present. Revert the one-line change to return to green.

---

## Layout

```
.
|- foundry.toml                         # solc 0.8.28, cancun, fuzz=5000
|- remappings.txt                       # forge-std/=lib/forge-std/src/
|- test/
|  `- Erc4626InflationSample.t.sol      # the two refs + the 3 tests
`- lib/
   `- forge-std/                        # only external dependency
```

---

## Scope honesty

This sample checks **one** accounting property of **one** bug class. It is a
demonstration of method, not a full audit. A green result here proves only that
the inflation/donation and round-trip-profit properties held against the
**exercised** call sequences for the references shown. It does not cover access
control, oracle integration, upgradeability, governance, or any path the harness
did not model. Use a real audit for breadth; this is a focused tool for one
high-severity, frequently under-tested seam.

---

MIT licensed. `forge-std` retains its own license under `lib/forge-std/`.
