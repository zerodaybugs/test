from __future__ import annotations

from pathlib import Path

TARGET = Path("monad-bft/monad-raptorcast/src/udp.rs")

text = TARGET.read_text()

old_import = """            packet::MessageBuilder,
            util::{
                BuildTarget, FullNodeGroupMap, PrimaryBroadcastGroup, Redundancy,
                StubProposerSchedule,
            },
"""
new_import = """            packet::{deterministic::PrimaryEncoding, MessageBuilder},
            util::{
                BuildTarget, EncodingScheme, FullNodeGroupMap, PrimaryBroadcastGroup,
                Redundancy, StubProposerSchedule,
            },
"""
if old_import not in text:
    raise SystemExit("recovery-test import block not found")
text = text.replace(old_import, new_import, 1)

old_build = """        let poisoned_group =
            PrimaryBroadcastGroup::of_epoch(epoch, &byzantine, &validator_map).unwrap();
        let poisoned_message = vec![0xA5u8; 128 * 1024];
        let poisoned_packets = MessageBuilder::<SecpSignature>::new(&byzantine_key)
            .unix_ts_ms(1_700_000_000_000u64)
"""
new_build = """        let poisoned_group =
            PrimaryBroadcastGroup::of_epoch(epoch, &byzantine, &validator_map).unwrap();
        let poisoned_message = vec![0xA5u8; 128 * 1024];
        let poisoned_timestamp = 1_700_000_000_000u64;
        let poisoned_packets = MessageBuilder::<SecpSignature>::new(&byzantine_key)
            .unix_ts_ms(poisoned_timestamp)
"""
if old_build not in text:
    raise SystemExit("poisoned-message build block not found")
text = text.replace(old_build, new_build, 1)

old_alias = """        let alias = research_malleate_recoverable_signature(&poisoned_packets[0].payload);
        assert_ne!(alias, poisoned_packets[0].payload);
"""
new_alias = """        // Use a first-hop chunk which the deterministic assignment routes to
        // the Byzantine validator. The attacker can legitimately receive this
        // chunk, malleate only its recoverable signature, then forward it to
        // the two honest non-proposer receivers.
        let assignment_group =
            PrimaryBroadcastGroup::of_epoch(epoch, &byzantine, &validator_map).unwrap();
        let encoding = PrimaryEncoding::new(
            EncodingScheme::Deterministic25(poisoned_round),
            &assignment_group,
            poisoned_message.len(),
            poisoned_timestamp,
        )
        .expect("primary deterministic encoding builds");
        let assignment = encoding.make_assignment().expect("assignment builds");
        let poison_index = (0usize..assignment.num_chunks())
            .find(|chunk_id| {
                assignment
                    .resolve_chunk_id(*chunk_id)
                    .is_some_and(|routing| routing.recipient() == &byzantine)
            })
            .expect("Byzantine validator receives at least one first-hop chunk");

        let alias = research_malleate_recoverable_signature(
            &poisoned_packets[poison_index].payload,
        );
        assert_ne!(alias, poisoned_packets[poison_index].payload);
"""
if old_alias not in text:
    raise SystemExit("recovery-test alias block not found")
text = text.replace(old_alias, new_alias, 1)

text = text.replace(
    "poisoned_packets[0].stride,\n                byzantine,",
    "poisoned_packets[poison_index].stride,\n                byzantine,",
    2,
)

TARGET.write_text(text)
print(f"Corrected recovery test assignment in {TARGET}")
