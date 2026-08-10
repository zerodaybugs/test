# Bucket Protocol — R16–R21 final release gate

**Date:** 2026-08-10
**Verdict:** `NO_NEW_SUBMIT_READY_HIGH_OR_CRITICAL`
**Safe to submit now:** `false`
**Strongest candidate:** `NONE`
**Required next gate:** `NEW_ROOT_CAUSE_REQUIRED`

## Non-negotiable release decision

No candidate passed every mandatory release gate. **Do not submit this research checkpoint as a vulnerability report.**

## Strict gate matrix

| Gate | Result | Value |
|---|---|---:|
| `r16WithdrawWithoutOwnedInput` | **FAIL** | `False` |
| `r16AllWithdrawsWithoutOwnedInput` | **FAIL** | `False` |
| `r16PublicWithdrawExposed` | **FAIL** | `False` |
| `r16StaticAuthorizationSignalFound` | **FAIL** | `False` |
| `r17ArbitrarySenderSuccess` | **FAIL** | `False` |
| `r17ArbitrarySenderPositiveRecipient` | **FAIL** | `False` |
| `r17ExploitConfirmed` | **FAIL** | `False` |
| `r18ToleranceAtLeastOneDay` | **FAIL** | `False` |
| `r18MultipleSameFeedPriceInfo` | **FAIL** | `False` |
| `r18PsmActivitySeen` | **FAIL** | `False` |
| `r19AlternateAccepted` | **FAIL** | `False` |
| `r19DifferentOracleReturn` | **FAIL** | `False` |
| `r19ExactCandidateCount` | **FAIL** | `0` |
| `r20ViableCurrentSource` | **FAIL** | `False` |
| `r20CanonicalBaselineSuccess` | **FAIL** | `False` |
| `r20WrongFeedControlPass` | **FAIL** | `False` |
| `r20ControlledPositiveCaseCount` | **FAIL** | `0` |
| `r20RepeatablePositiveCandidateCount` | **FAIL** | `0` |
| `r20MaxAdvantageBps` | **FAIL** | `0` |
| `r20ExploitConfirmed` | **FAIL** | `False` |
| `r20EconomicImpactProven` | **FAIL** | `False` |
| `r21UnambiguousExposure` | **FAIL** | `False` |
| `r21AuditDuplicateClean` | **FAIL** | `False` |
| `r21MaterialHighOrCritical` | **FAIL** | `False` |
| `r21ScopeVerified` | **FAIL** | `False` |

## Candidate decisions

- Shared Account authorization mechanic: **FAIL**
- Pyth PriceInfo oracle differential: **FAIL**
- Repeatable PSM economic exploit: **FAIL**
- Material High/Critical + scope + duplicate: **FAIL**

## Integrity

- Production transactions submitted: **0**
- Private keys or seed phrases used: **0**
- Evidence methods: public source, public mainnet state, read-only RPC and simulation.
- Severity is not upgraded without measured impact.
