# Monad v0.16.0 canonical high-S control v2

## Decision

**CANONICALIZATION_SECP_REGRESSION_FAILURE**

- Canonical transport control: False
- Canonical recovery control: False
- Full monad-secp suite: False
- Full monad-raptorcast suite: False
- Official consensus/finality halt: false
- Submit-ready: false

The mitigation canonicalizes the high-S recoverable alias to low-S and flips the recovery
parity bit, preserving the authenticated signer while collapsing raw packet identity.
A High submission still requires an actual consensus/full-node finality A/B.
