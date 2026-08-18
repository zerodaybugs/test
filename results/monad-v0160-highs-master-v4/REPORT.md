# Monad v0.16.0 V1 high-S master-v4 gate

## Decision

**REPEATED_TRANSPORT_POISONING_LOW_S_CONTROL_INCOMPLETE**

The exact release is checked in three layers:

1. an honest V1 proposer sends a first-hop chunk to a Byzantine relay; the relay creates the
   high-S alias and poisons two honest receivers, which are then measured again in the next
   clean honest-proposer round;
2. the relay repeats the same assigned-chunk alias race for twelve consecutive honest
   proposer rounds;
3. the twelve-round matrix is repeated after canonical low-S rejection at
   `SecpSignature::deserialize`, followed by the full `monad-secp` unit suite.

- Both poisoned receivers recover when the attacker stops: **True**
- Repeated transport poisoning while the attacker continues: **True**
- Canonical low-S transport control: **True**
- Low-S regression suite: **False**
- Official RaptorCast consensus/full-node finality halt: **false**
- Critical proven: **false**
- Submit-ready: **false**

Transport-level repeated poisoning is only a High candidate. Submission requires a
RaptorCast-aware consensus or official full-node A/B showing that the realistic first-hop
race prevents QC/finality across repeated rounds and disappears under low-S rejection.
