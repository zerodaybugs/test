# Proof Card — strongest Bucket research wedges

## Wedge A — shared vault-owned Bucket Account capability

- Three Account objects were traced through dynamic fields to shared third-party USDC vaults.
- Production transactions use the deterministic `bucket_account` protocol-cap key.
- Two Accounts have live Saving positions.
- Promotion requires an unrelated sender to succeed and receive value without an owned authorization input.
- Final mechanic gate: **FAIL**.

## Wedge B — Pyth tolerance and alternate PriceInfo domain

- USDC and BUCK tolerance configuration, same-feed object multiplicity and live PSM use were bound independently.
- Promotion requires canonical-vs-alternate oracle output difference, full PSM economic advantage, wrong-feed rejection, repeatability and material exposure.
- Oracle mechanic gate: **FAIL**.
- Economic exploit gate: **FAIL**.

## Release rule

A differentiator is not a bounty finding until exact exploitability, material impact, scope and duplicate gates all pass.
