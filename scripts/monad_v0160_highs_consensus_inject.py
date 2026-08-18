from __future__ import annotations

from pathlib import Path

ROUTER = Path("monad-bft/monad-mock-swarm/src/raptorcast.rs")
TEST = Path("monad-bft/monad-mock-swarm/tests/raptorcast_highs_network.rs")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"missing exact source anchor: {label}")
    return text.replace(old, new, 1)


text = ROUTER.read_text()

text = replace_once(
    text,
    """    pub proposer_schedule: PS,

    pub _phantom: PhantomData<(IM, OM)>,
""",
    """    pub proposer_schedule: PS,

    // Research-only transport adversary. The exact MonadBFT state machine is
    // unchanged; this models a Byzantine first-hop validator racing the
    // recoverable high-S alias before authentic chunks arrive.
    pub research_high_s_byzantine: Option<NodeId<PT>>,
    pub research_canonical_commitment: bool,

    pub _phantom: PhantomData<(IM, OM)>,
""",
    "config fields",
)

text = replace_once(
    text,
    """            proposer_schedule,
            _phantom: PhantomData,
""",
    """            proposer_schedule,
            research_high_s_byzantine: None,
            research_canonical_commitment: false,
            _phantom: PhantomData,
""",
    "config defaults",
)

text = replace_once(
    text,
    """        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum WireMsg<PT: PubKey> {
""",
    """        }
    }

    pub fn with_research_high_s_attack(
        mut self,
        byzantine: NodeId<PT>,
        canonical_commitment: bool,
    ) -> Self {
        self.research_high_s_byzantine = Some(byzantine);
        self.research_canonical_commitment = canonical_commitment;
        self
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum WireMsg<PT: PubKey> {
""",
    "config builder",
)

text = replace_once(
    text,
    """            decoding_states: HashMap::new(),
            validator_sets: BTreeMap::new(),
""",
    """            decoding_states: HashMap::new(),
            research_commitments: HashMap::new(),
            validator_sets: BTreeMap::new(),
""",
    "scheduler initialization",
)

text = replace_once(
    text,
    """    pub mode: ChunkMode,
    pub payload: Arc<Bytes>,
""",
    """    pub mode: ChunkMode,
    // False is the authentic low-S packet identity; true is the
    // recoverable high-S alias of the same proposer signature.
    pub research_high_s_alias: bool,
    pub payload: Arc<Bytes>,
""",
    "chunk alias field",
)

text = replace_once(
    text,
    """    decoding_states: HashMap<(NodeId<PT>, Round, u64), DecodingState>,
    validator_sets: BTreeMap<Epoch, ValidatorSet<PT>>,
""",
    """    decoding_states: HashMap<(NodeId<PT>, Round, u64), DecodingState>,
    research_commitments: HashMap<(NodeId<PT>, Round), bool>,
    validator_sets: BTreeMap<Epoch, ValidatorSet<PT>>,
""",
    "commitment state",
)

text = replace_once(
    text,
    """                mode: ChunkMode::Unicast,
                author: self.config.self_id,
""",
    """                mode: ChunkMode::Unicast,
                research_high_s_alias: false,
                author: self.config.self_id,
""",
    "unicast initializer",
)

text = replace_once(
    text,
    """            mode: ChunkMode::Raptorcast,
            author: self_id,
""",
    """            mode: ChunkMode::Raptorcast,
            research_high_s_alias: false,
            author: self_id,
""",
    "raptorcast initializer",
)

text = replace_once(
    text,
    """        chunk_msg.total_chunks = chunks.len();

        // raptorcast does not build chunks for the publisher, so we
""",
    """        chunk_msg.total_chunks = chunks.len();

        // Research-only first-hop race: an honest proposal assigns at least
        // one signed V1 chunk to the Byzantine validator. The attacker can
        // transform that recoverable signature to its high-S alias without the
        // proposer key and race it to the two non-proposer honest validators.
        if let Some(byzantine) = self.config.research_high_s_byzantine {
            if self_id != byzantine {
                if let Some(poison_chunk) = chunks
                    .iter()
                    .find(|chunk| *chunk.recipient().node_id() == byzantine)
                {
                    let alias = ChunkMsg {
                        chunk_id: poison_chunk.chunk_id(),
                        research_high_s_alias: true,
                        ..chunk_msg.clone()
                    };
                    let alias_targets: Vec<_> = validator_set
                        .get_members()
                        .keys()
                        .copied()
                        .filter(|target| *target != self_id && *target != byzantine)
                        .collect();
                    for target in alias_targets {
                        self.push_tx_event(time, target, WireMsg::Chunk(alias.clone()));
                    }
                }
            }
        }

        // raptorcast does not build chunks for the publisher, so we
""",
    "alias race injection",
)

text = replace_once(
    text,
    """        let encoding = self.primary_encoding(&message, epoch, validator_set);
""",
    """        // Exact RoundInfo semantics: the first valid commitment for the
        // (author, round) slot wins. The vulnerable model uses raw recoverable
        // signature identity; the patched A/B canonicalizes low-S/high-S aliases.
        let commitment_identity = if self.config.research_canonical_commitment {
            false
        } else {
            message.research_high_s_alias
        };
        let commitment_key = (message.author, message.round);
        if let Some(existing) = self.research_commitments.get(&commitment_key) {
            if *existing != commitment_identity {
                return;
            }
        } else {
            self.research_commitments
                .insert(commitment_key, commitment_identity);
        }

        let encoding = self.primary_encoding(&message, epoch, validator_set);
""",
    "commitment check",
)

text = replace_once(
    text,
    """            RouterTarget::Raptorcast { round, epoch } => {
                self.emit_raptorcast(time, msg_id, round, epoch, &payload);
            }
""",
    """            RouterTarget::Raptorcast { round, epoch } => {
                if self.config.research_high_s_byzantine == Some(self.config.self_id) {
                    // The Byzantine validator withholds proposals in its own
                    // scheduled rounds; this remains within the <1/3 model.
                    return;
                }
                self.emit_raptorcast(time, msg_id, round, epoch, &payload);
            }
""",
    "Byzantine proposal withholding",
)

text = replace_once(
    text,
    """        self.config.proposer_schedule.prune_below(cutoff);
""",
    """        self.config.proposer_schedule.prune_below(cutoff);
        self.research_commitments
            .retain(|(_, message_round), _| *message_round >= cutoff);
""",
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

print(f"Injected exact scheduler model into {ROUTER}")
print(f"Created {TEST}")
