# Monad v0.16.0 RaptorCast V1 high-S consensus gate

## Decision

**CONSENSUS_OR_CONTROL_GATE_INCOMPLETE_OR_NEGATIVE**

- Exact transport repeated poisoning and low-S control: **True**
- Exact four-validator consensus/ledger A-B, 3/3: **False**
- Full monad-secp canonical low-S regression, 3/3: **False**
- Existing mock-swarm RaptorCast regressions: **False**
- Official monad-node + execution halt: **false**
- Submit-ready: **false**

The vulnerable consensus model has one Byzantine first-hop relay and three honest
validators. In every honest-proposer round, the relay races the publicly computable
high-S signature alias to the two honest non-proposers before authentic chunks. The
proposer has the block locally, but the other honest validators never reconstruct it;
the Byzantine withholds its vote. The exact ledger remains at zero finalized blocks.

The matched canonical commitment control restores synchronized finality. The actual
parser mitigation separately rejects high-S signatures and passes the full monad-secp
library suite.

This is a strong High candidate, not yet a submission. The program's public-entrypoint
gate still requires official monad-node + execution A-B evidence.
