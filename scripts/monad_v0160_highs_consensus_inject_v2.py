from __future__ import annotations

from pathlib import Path

ROUTER = Path("monad-bft/monad-mock-swarm/src/raptorcast.rs")
TEST = Path("monad-bft/monad-mock-swarm/tests/raptorcast_highs_network.rs")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"exact anchor count for {label}: expected 1, got {count}")
    return text.replace(old, new, 1)


text = ROUTER.read_text()

text = replace_once(
    text,
    """    pub proposer_schedule: PS,\n\n    pub _phantom: PhantomData<(IM, OM)>,\n""",
    """    pub proposer_schedule: PS,\n\n    // Research-only transport adversary. The exact MonadBFT state machine is\n    // unchanged; this models a Byzantine first-hop validator racing the\n    // recoverable high-S alias before authentic chunks arrive.\n    pub research_high_s_byzantine: Option<NodeId<PT>>,\n    pub research_canonical_commitment: bool,\n\n    pub _phantom: PhantomData<(IM, OM)>,\n""",
    "config fields",
)

text = replace_once(
    text,
    """            proposer_schedule,\n            _phantom: PhantomData,\n""",
    """            proposer_schedule,\n            research_high_s_byzantine: None,\n            research_canonical_commitment: false,\n            _phantom: PhantomData,\n""",
    "config defaults",
)

text = replace_once(
    text,
    """        }\n    }\n}\n\nimpl<PT, IM, OM, PS> RouterSchedulerBuilder for RaptorcastRouterConfig<PT, IM, OM, PS>\n""",
    """        }\n    }\n\n    pub fn with_research_high_s_attack(\n        mut self,\n        byzantine: NodeId<PT>,\n        canonical_commitment: bool,\n    ) -> Self {\n        self.research_high_s_byzantine = Some(byzantine);\n        self.research_canonical_commitment = canonical_commitment;\n        self\n    }\n}\n\nimpl<PT, IM, OM, PS> RouterSchedulerBuilder for RaptorcastRouterConfig<PT, IM, OM, PS>\n""",
    "inherent config builder",
)

text = replace_once(
    text,
    """            decoding_states: HashMap::new(),\n            validator_sets: BTreeMap::new(),\n""",
    """            decoding_states: HashMap::new(),\n            research_commitments: HashMap::new(),\n            validator_sets: BTreeMap::new(),\n""",
    "scheduler initialization",
)

text = replace_once(
    text,
    """    pub mode: ChunkMode,\n    pub payload: Arc<Bytes>,\n""",
    """    pub mode: ChunkMode,\n    // False is the authentic low-S packet identity; true is the\n    // recoverable high-S alias of the same proposer signature.\n    pub research_high_s_alias: bool,\n    pub payload: Arc<Bytes>,\n""",
    "chunk alias field",
)

text = replace_once(
    text,
    """    decoding_states: HashMap<(NodeId<PT>, Round, u64), DecodingState>,\n    validator_sets: BTreeMap<Epoch, ValidatorSet<PT>>,\n""",
    """    decoding_states: HashMap<(NodeId<PT>, Round, u64), DecodingState>,\n    research_commitments: HashMap<(NodeId<PT>, Round), bool>,\n    validator_sets: BTreeMap<Epoch, ValidatorSet<PT>>,\n""",
    "commitment state",
)

text = replace_once(
    text,
    """                mode: ChunkMode::Unicast,\n                author: self.config.self_id,\n""",
    """                mode: ChunkMode::Unicast,\n                research_high_s_alias: false,\n                author: self.config.self_id,\n""",
    "unicast initializer",
)

text = replace_once(
    text,
    """            mode: ChunkMode::Raptorcast,\n            author: self_id,\n""",
    """            mode: ChunkMode::Raptorcast,\n            research_high_s_alias: false,\n            author: self_id,\n""",
    "raptorcast initializer",
)

text = replace_once(
    text,
    """        chunk_msg.total_chunks = chunks.len();\n\n        // raptorcast does not build chunks for the publisher, so we\n""",
    """        chunk_msg.total_chunks = chunks.len();\n\n        // Research-only first-hop race: an honest proposal assigns at least\n        // one signed V1 chunk to the Byzantine validator. The attacker can\n        // transform that recoverable signature to its high-S alias without the\n        // proposer key and race it to the two non-proposer honest validators.\n        if let Some(byzantine) = self.config.research_high_s_byzantine {\n            if self_id != byzantine {\n                if let Some(poison_chunk) = chunks\n                    .iter()\n                    .find(|chunk| *chunk.recipient().node_id() == byzantine)\n                {\n                    let alias = ChunkMsg {\n                        chunk_id: poison_chunk.chunk_id(),\n                        research_high_s_alias: true,\n                        ..chunk_msg.clone()\n                    };\n                    let alias_targets: Vec<_> = validator_set\n                        .get_members()\n                        .keys()\n                        .copied()\n                        .filter(|target| *target != self_id && *target != byzantine)\n                        .collect();\n                    for target in alias_targets {\n                        self.push_tx_event(time, target, WireMsg::Chunk(alias.clone()));\n                    }\n                }\n            }\n        }\n\n        // raptorcast does not build chunks for the publisher, so we\n""",
    "alias race injection",
)

text = replace_once(
    text,
    """        let Some((epoch, validator_set)) = self.validator_set_for_round(message.round) else {\n            return;\n        };\n\n        if self\n            .config\n            .proposer_schedule\n            .check_proposer(&message.author, message.round)\n            != Some(true)\n        {\n            return;\n        }\n\n        let encoding = self.primary_encoding(&message, epoch, validator_set);\n""",
    """        if self\n            .config\n            .proposer_schedule\n            .check_proposer(&message.author, message.round)\n            != Some(true)\n        {\n            return;\n        }\n\n        // Exact RoundInfo semantics: the first valid commitment for the\n        // (author, round) slot wins. The vulnerable model uses raw recoverable\n        // signature identity; the patched A/B canonicalizes low-S/high-S aliases.\n        let commitment_identity = if self.config.research_canonical_commitment {\n            false\n        } else {\n            message.research_high_s_alias\n        };\n        let commitment_key = (message.author, message.round);\n        if let Some(existing) = self.research_commitments.get(&commitment_key) {\n            if *existing != commitment_identity {\n                return;\n            }\n        } else {\n            self.research_commitments\n                .insert(commitment_key, commitment_identity);\n        }\n\n        // Resolve the epoch mapping only after mutating the commitment table,\n        // so its mutable borrow does not overlap the validator-set reference.\n        let Some((epoch, validator_set)) = self.validator_set_for_round(message.round) else {\n            return;\n        };\n\n        let encoding = self.primary_encoding(&message, epoch, validator_set);\n""",
    "commitment check and borrow order",
)

text = replace_once(
    text,
    """            RouterTarget::Raptorcast { round, epoch } => {\n                self.emit_raptorcast(time, msg_id, round, epoch, &payload);\n            }\n""",
    """            RouterTarget::Raptorcast { round, epoch } => {\n                if self.config.research_high_s_byzantine == Some(self.config.self_id) {\n                    // The Byzantine validator withholds proposals in its own\n                    // scheduled rounds; this remains within the <1/3 model.\n                    return;\n                }\n                self.emit_raptorcast(time, msg_id, round, epoch, &payload);\n            }\n""",
    "Byzantine proposal withholding",
)

text = replace_once(
    text,
    """        let cutoff = round.saturating_sub(PROPOSER_SCHEDULE_CACHE_MAX_PAST_ROUNDS);\n        self.config.proposer_schedule.prune_below(cutoff);\n""",
    """        let cutoff = round.saturating_sub(PROPOSER_SCHEDULE_CACHE_MAX_PAST_ROUNDS);\n        self.config.proposer_schedule.prune_below(cutoff);\n        self.research_commitments\n            .retain(|(_, message_round), _| *message_round >= cutoff);\n""",
    "commitment pruning",
)

ROUTER.write_text(text)

TEST.write_text(r'''// Copyright (C) 2025 Category Labs, Inc.
// Research-only exact v0.16.0 regression.

#![cfg(feature = "raptorcast")]

use std::time::Duration;

use monad_chain_config::{revision::ChainParams, MockChainConfig};
use monad_consensus_types::{block::PassthruBlockPolicy, block_validator::MockValidator};
use monad_crypto::certificate_signature::CertificateKeyPair;
use monad_execution_state_read::InMemoryStateInner;
use monad_executor::Executor;
use monad_mock_swarm::{
    mock::TimestamperConfig,
    mock_swarm::SwarmBuilder,
    node::NodeBuilder,
    raptorcast::{RaptorcastRouterConfig, RaptorcastSwarm},
    swarm::make_state_configs,
    terminator::UntilTerminator,
};
use monad_router_scheduler::RouterSchedulerBuilder;
use monad_transformer::{GenericTransformer, LatencyTransformer, ID};
use monad_types::{NodeId, Round, SeqNum};
use monad_updaters::{
    ledger::{MockLedger, MockableLedger},
    statesync::MockStateSyncExecutor,
    txpool::MockTxPoolExecutor,
    val_set::MockValSetUpdaterNop,
};
use monad_validator::{simple_round_robin::SimpleRoundRobin, validator_set::ValidatorSetFactory};

static CHAIN_PARAMS: ChainParams = ChainParams {
    tx_limit: 10_000,
    proposal_gas_limit: 300_000_000,
    proposal_byte_limit: 4_000_000,
    max_reserve_balance: 1_000_000_000_000_000_000,
    vote_pace: Duration::from_millis(5),
};

fn run_case(canonical_commitment: bool) -> Vec<usize> {
    let delta = Duration::from_millis(25);
    let epoch_length = SeqNum(10_000);
    let epoch_start_delay = Round(5_000);
    let state_configs = make_state_configs::<RaptorcastSwarm>(
        4,
        ValidatorSetFactory::default,
        SimpleRoundRobin::default,
        || MockValidator,
        || PassthruBlockPolicy,
        || InMemoryStateInner::genesis(SeqNum(4)),
        SeqNum(4),
        delta,
        MockChainConfig::new_with_epoch_params(&CHAIN_PARAMS, epoch_length, epoch_start_delay),
        SeqNum(100),
    );
    let byzantine = NodeId::new(state_configs[0].key.pubkey());

    let swarm_config = SwarmBuilder::<RaptorcastSwarm>(
        state_configs
            .into_iter()
            .enumerate()
            .map(|(seed, state_builder)| {
                let state_backend = state_builder.state_read.clone();
                let validators = state_builder.locked_epoch_validators[0].clone();
                let self_id = NodeId::new(state_builder.key.pubkey());
                let router_config = RaptorcastRouterConfig::<_, _, _>::new(self_id)
                    .with_research_high_s_attack(byzantine, canonical_commitment);
                NodeBuilder::<RaptorcastSwarm>::new(
                    ID::new(self_id),
                    state_builder,
                    router_config.build(),
                    MockValSetUpdaterNop::new(validators.validators, epoch_length),
                    MockTxPoolExecutor::default().with_chain_params(&CHAIN_PARAMS),
                    MockLedger::new(state_backend.clone()),
                    MockStateSyncExecutor::new(state_backend),
                    vec![GenericTransformer::Latency(LatencyTransformer::new(delta))],
                    vec![],
                    TimestamperConfig::default(),
                    seed.try_into().unwrap(),
                )
            })
            .collect(),
    );

    let mut swarm = swarm_config.build();
    let mut terminator = UntilTerminator::new().until_tick(Duration::from_secs(8));
    while swarm.step_until(&mut terminator).is_some() {}

    swarm
        .states()
        .values()
        .map(|node| node.executor.ledger().get_finalized_blocks().len())
        .collect()
}

#[test]
fn high_s_alias_relay_halts_finality_without_canonical_commitment() {
    let vulnerable = run_case(false);
    let patched = run_case(true);

    eprintln!("MARKER_NETWORK_VULNERABLE_LEDGER_LENGTHS={vulnerable:?}");
    eprintln!("MARKER_NETWORK_PATCHED_LEDGER_LENGTHS={patched:?}");
    eprintln!("MARKER_NETWORK_TEST_COMPLETE=1");

    assert_eq!(vulnerable, vec![0, 0, 0, 0]);
    assert!(patched.iter().all(|length| *length >= 80));
    let min = patched.iter().min().copied().unwrap();
    let max = patched.iter().max().copied().unwrap();
    assert!(max - min <= 1, "patched ledgers should remain synchronized");
}
''')

print(f"Injected corrected exact scheduler model into {ROUTER}")
print(f"Created {TEST}")
