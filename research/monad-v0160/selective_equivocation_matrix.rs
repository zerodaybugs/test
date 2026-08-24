use std::{
    any::Any,
    collections::BTreeMap,
    fs,
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};

use monad_mock_swarm::swarm_relation::MonadMessageNoSerSwarm;
use monad_twins_utils::{
    run_twins_test,
    twin_reader::{read_twins_test, TwinsTestCase},
};
use monad_types::Round;

#[derive(Clone, Debug)]
struct RoundSpec {
    // Per honest sender: 0 -> original persona, 1 -> twin persona, 2 -> both.
    inbound: [u8; 3],
    // Three-bit target mask over the honest validators.
    original_targets: u8,
    twin_targets: u8,
}

#[derive(Clone, Debug)]
struct Scenario {
    name: String,
    rounds: Vec<RoundSpec>,
}

fn panic_text(payload: Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    "non-string panic payload".to_string()
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn next_u64(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

fn scenarios() -> Vec<Scenario> {
    let mut out = Vec::new();
    let constant = |inbound, original_targets, twin_targets| RoundSpec {
        inbound,
        original_targets,
        twin_targets,
    };

    out.push(Scenario {
        name: "control_all_connected".into(),
        rounds: vec![constant([2, 2, 2], 7, 7); 12],
    });
    out.push(Scenario {
        name: "control_original_only".into(),
        rounds: vec![constant([0, 0, 0], 7, 0); 12],
    });
    out.push(Scenario {
        name: "control_twin_only".into(),
        rounds: vec![constant([1, 1, 1], 0, 7); 12],
    });

    let inbound_patterns = [
        [0, 1, 1],
        [1, 0, 1],
        [1, 1, 0],
        [0, 0, 1],
        [0, 1, 0],
        [1, 0, 0],
        [0, 1, 2],
        [1, 0, 2],
        [2, 0, 1],
    ];
    for (pi, inbound) in inbound_patterns.into_iter().enumerate() {
        for original_targets in 0u8..8 {
            let twin_targets = 7 ^ original_targets;
            out.push(Scenario {
                name: format!(
                    "constant_split_p{}_o{}_t{}",
                    pi, original_targets, twin_targets
                ),
                rounds: vec![constant(inbound, original_targets, twin_targets); 18],
            });
        }
    }

    // Every ordered pair of outbound target masks, alternating across rounds.
    for first in 0u8..8 {
        for second in 0u8..8 {
            let mut rounds = Vec::new();
            for r in 0..20 {
                let original_targets = if r % 2 == 0 { first } else { second };
                let twin_targets = 7 ^ original_targets;
                let inbound = if r % 2 == 0 {
                    [0, 1, 2]
                } else {
                    [1, 0, 2]
                };
                rounds.push(constant(inbound, original_targets, twin_targets));
            }
            out.push(Scenario {
                name: format!("alternating_masks_{}_{}", first, second),
                rounds,
            });
        }
    }

    // Deterministic longer schedules with arbitrary per-recipient receive/send choices.
    for seed in 1u64..=128 {
        let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15);
        let mut rounds = Vec::new();
        for _ in 0..32 {
            let mut inbound = [0u8; 3];
            for v in &mut inbound {
                *v = (next_u64(&mut state) % 3) as u8;
            }
            let original_targets = (next_u64(&mut state) & 7) as u8;
            let twin_targets = (next_u64(&mut state) & 7) as u8;
            rounds.push(constant(inbound, original_targets, twin_targets));
        }
        out.push(Scenario {
            name: format!("random32_seed_{seed:03}"),
            rounds,
        });
    }

    out
}

fn configure(case: &mut TwinsTestCase<MonadMessageNoSerSwarm>, scenario: &Scenario) {
    let byzantine_peer = case
        .duplicates
        .iter()
        .find_map(|(peer, ids)| (ids.len() == 2).then_some(*peer))
        .expect("exactly one twinned Byzantine identity required");

    let mut byzantine_ids: Vec<_> = case
        .nodes
        .keys()
        .copied()
        .filter(|id| *id.get_peer_id() == byzantine_peer)
        .collect();
    byzantine_ids.sort_by_key(|id| *id.get_identifier());
    assert_eq!(byzantine_ids.len(), 2);
    let original = byzantine_ids[0];
    let twin = byzantine_ids[1];

    let mut honest: Vec<_> = case
        .nodes
        .keys()
        .copied()
        .filter(|id| *id.get_peer_id() != byzantine_peer)
        .collect();
    honest.sort();
    assert_eq!(honest.len(), 3);
    let all_ids: Vec<_> = case.nodes.keys().copied().collect();

    for cfg in case.nodes.values_mut() {
        cfg.partition = BTreeMap::new();
        cfg.default_partition = all_ids.clone();
    }

    for (idx, spec) in scenario.rounds.iter().enumerate() {
        let round = Round(idx as u64 + 1);

        // Every honest sender always reaches every honest recipient. Only the
        // attacker's two same-key local personas receive different subsets.
        for (sender_index, sender) in honest.iter().copied().enumerate() {
            let mut group = honest.clone();
            match spec.inbound[sender_index] {
                0 => group.push(original),
                1 => group.push(twin),
                2 => {
                    group.push(original);
                    group.push(twin);
                }
                _ => panic!("invalid inbound selector"),
            }
            case.nodes
                .get_mut(&sender)
                .expect("honest sender config")
                .partition
                .insert(round, group);
        }

        let mut original_group = vec![original];
        let mut twin_group = vec![twin];
        for (bit, honest_id) in honest.iter().copied().enumerate() {
            if spec.original_targets & (1 << bit) != 0 {
                original_group.push(honest_id);
            }
            if spec.twin_targets & (1 << bit) != 0 {
                twin_group.push(honest_id);
            }
        }
        case.nodes
            .get_mut(&original)
            .expect("original Byzantine config")
            .partition
            .insert(round, original_group);
        case.nodes
            .get_mut(&twin)
            .expect("twin Byzantine config")
            .partition
            .insert(round, twin_group);
    }
}

#[test]
fn selective_equivocation_matrix() {
    let result_path = std::env::var("MONAD_SELECTIVE_EQUIVOCATION_RESULT")
        .expect("MONAD_SELECTIVE_EQUIVOCATION_RESULT is required");
    let scenarios = scenarios();
    assert!(scenarios.len() >= 250);

    let mut records = Vec::with_capacity(scenarios.len());
    let mut failure_count = 0usize;

    for scenario in scenarios {
        let started = Instant::now();
        let name = scenario.name.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut case = read_twins_test::<MonadMessageNoSerSwarm>(
                "tests/selective_equivocation_base.json",
            );
            configure(&mut case, &scenario);
            run_twins_test::<_, _, _, MonadMessageNoSerSwarm>(1, case);
        }));
        let elapsed_ms = started.elapsed().as_millis();
        let (pass, panic) = match result {
            Ok(()) => (true, String::new()),
            Err(payload) => {
                failure_count += 1;
                (false, panic_text(payload))
            }
        };
        records.push(format!(
            "{{\"case\":\"{}\",\"pass\":{},\"elapsed_ms\":{},\"panic\":\"{}\"}}",
            json_escape(&name),
            if pass { "true" } else { "false" },
            elapsed_ms,
            json_escape(&panic),
        ));
    }

    let document = format!(
        "{{\n  \"source_commit\": \"c616743d1358186605e1c1b74a3d6c4fdd9dd48c\",\n  \"scenario_count\": {},\n  \"failure_count\": {},\n  \"attacker_stake_fraction\": \"1/4\",\n  \"honest_to_honest_links_always_intact\": true,\n  \"records\": [\n    {}\n  ]\n}}\n",
        records.len(),
        failure_count,
        records.join(",\n    "),
    );
    fs::write(&result_path, document).expect("write campaign result");

    assert_eq!(
        failure_count,
        0,
        "candidate signal: selective same-key equivocation failed; inspect result JSON"
    );
}
