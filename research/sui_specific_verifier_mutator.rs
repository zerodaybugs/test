// Copyright (c) ZeroDayBugs.com
// SPDX-License-Identifier: Apache-2.0
//
// Local-only, exact-source mutator for the Sui-specific verifier passes.
//
// Publication order under the active new VM is:
//   binary deserialization -> core Move verification/JIT -> Sui-specific verifier.
// A Sui verifier panic after the prior layers accept an attacker-controlled package is therefore
// materially different from a clean verification error. Every candidate is replayed with fresh
// runtime state under the same mainnet protocol configuration before it is retained.

use move_binary_format::{
    binary_config::BinaryConfig,
    file_format::{
        CompiledModule, basic_test_module, basic_test_module_with_enum, empty_module,
    },
};
use move_bytecode_verifier::verify_module_with_config_unmetered;
use move_core_types::vm_status::StatusType;
use move_vm_config::{
    runtime::{VMConfig, VMRuntimeLimitsConfig},
    verifier::VerifierConfig,
};
use move_vm_runtime::{
    dev_utils::{
        gas_schedule::GasStatus,
        storage::{InMemoryStorage, StoredPackage},
    },
    natives::{extensions::NativeExtensions, functions::NativeFunctions},
    runtime::MoveRuntime,
};
use serde::Serialize;
use std::{
    any::Any,
    collections::BTreeMap,
    env, fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
};
use sui_protocol_config::{Chain, ProtocolConfig, ProtocolVersion};
use sui_verifier_latest::verifier::sui_verify_module_unmetered;

const PROTOCOL_VERSIONS: &[u64] = &[118, 119, 120, 122, 124, 125, 127, 128, 129, 130, 131, 132, 133];

#[derive(Clone)]
struct ExactConfig {
    version: u64,
    verifier: VerifierConfig,
    binary: BinaryConfig,
    vm: VMConfig,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "class", rename_all = "snake_case")]
enum DangerousOutcome {
    CoreVerifierPanic { version: u64, message: String },
    RuntimePanic { version: u64, message: String },
    RuntimeInvariantViolation {
        version: u64,
        major_status: String,
        message: Option<String>,
    },
    SuiVerifierPanic { version: u64, message: String },
}

#[derive(Clone, Debug, Default, Serialize)]
struct VersionCounters {
    deserialized: u64,
    core_verified: u64,
    runtime_accepted: u64,
    sui_accepted: u64,
    sui_rejected_cleanly: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Counters {
    cases: u64,
    deterministic_candidates: u64,
    unstable_candidates: u64,
    versions: BTreeMap<u64, VersionCounters>,
}

#[derive(Clone, Debug, Serialize)]
struct Candidate {
    case_id: u64,
    label: String,
    bytes: usize,
    fingerprint: String,
    binary_file: String,
    outcome: DangerousOutcome,
}

#[derive(Clone, Debug, Serialize)]
struct CorpusRecord {
    name: String,
    bytes: usize,
    accepted_versions: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct Report {
    harness: &'static str,
    source_contract: &'static str,
    seed: u64,
    requested_random_cases: u64,
    protocol_versions: Vec<u64>,
    corpus: Vec<CorpusRecord>,
    counters: Counters,
    candidates: Vec<Candidate>,
    gate: &'static str,
}

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn index(&mut self, len: usize) -> usize {
        if len == 0 { 0 } else { self.next() as usize % len }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned())
}

fn fingerprint(bytes: &[u8]) -> String {
    let mut a = 0xcbf29ce484222325u64;
    let mut b = 0x9e3779b185ebca87u64;
    for (index, byte) in bytes.iter().enumerate() {
        a = (a ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        b = (b ^ ((u64::from(*byte)) << ((index % 8) * 8)) ^ index as u64)
            .rotate_left(11)
            .wrapping_mul(0xd6e8feb86659fd93);
    }
    format!("{a:016x}{b:016x}")
}

fn exact_vm_config(protocol: &ProtocolConfig) -> VMConfig {
    VMConfig {
        verifier: protocol.verifier_config(None),
        max_binary_format_version: protocol.move_binary_format_version(),
        runtime_limits_config: VMRuntimeLimitsConfig {
            vector_len_max: protocol.max_move_vector_len(),
            max_value_nest_depth: protocol.max_move_value_depth_as_option(),
            hardened_otw_check: protocol.hardened_otw_check(),
        },
        enable_invariant_violation_check_in_swap_loc: !protocol
            .disable_invariant_violation_check_in_swap_loc(),
        check_no_extraneous_bytes_during_deserialization: protocol.no_extraneous_module_bytes(),
        error_execution_state: false,
        binary_config: protocol.binary_config(None),
        rethrow_serialization_type_layout_errors: protocol
            .rethrow_serialization_type_layout_errors(),
        max_type_to_layout_nodes: protocol.max_type_to_layout_nodes_as_option(),
        variant_nodes: protocol.variant_nodes(),
        deprecate_global_storage_ops_during_deserialization: protocol
            .deprecate_global_storage_ops_during_deserialization(),
        normalize_depth_formula: protocol.normalize_depth_formula(),
    }
}

fn configs() -> Vec<ExactConfig> {
    PROTOCOL_VERSIONS
        .iter()
        .copied()
        .map(|version| {
            let protocol = ProtocolConfig::get_for_version(
                ProtocolVersion::new(version),
                Chain::Mainnet,
            );
            ExactConfig {
                version,
                verifier: protocol.verifier_config(None),
                binary: protocol.binary_config(None),
                vm: exact_vm_config(&protocol),
            }
        })
        .collect()
}

fn serialize(module: &CompiledModule) -> Vec<u8> {
    let mut bytes = Vec::new();
    module
        .serialize_with_version(module.version, &mut bytes)
        .expect("built-in corpus module serialization");
    bytes
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    vec![
        ("empty".to_owned(), serialize(&empty_module())),
        ("basic".to_owned(), serialize(&basic_test_module())),
        (
            "enum".to_owned(),
            serialize(&basic_test_module_with_enum()),
        ),
    ]
}

fn classify(
    bytes: &[u8],
    configs: &[ExactConfig],
    counters: Option<&mut Counters>,
) -> Option<DangerousOutcome> {
    let mut counters = counters;
    for cfg in configs {
        let module = match catch_unwind(AssertUnwindSafe(|| {
            CompiledModule::deserialize_with_config(bytes, &cfg.binary)
        })) {
            Err(_) | Ok(Err(_)) => continue,
            Ok(Ok(module)) => module,
        };
        if let Some(c) = counters.as_deref_mut() {
            c.versions.entry(cfg.version).or_default().deserialized += 1;
        }

        match catch_unwind(AssertUnwindSafe(|| {
            verify_module_with_config_unmetered(&cfg.verifier, &module)
        })) {
            Err(payload) => {
                return Some(DangerousOutcome::CoreVerifierPanic {
                    version: cfg.version,
                    message: panic_message(payload.as_ref()),
                });
            }
            Ok(Err(_)) => continue,
            Ok(Ok(())) => {}
        }
        if let Some(c) = counters.as_deref_mut() {
            c.versions.entry(cfg.version).or_default().core_verified += 1;
        }

        // Publication cannot reach the Sui verifier unless exact runtime validation succeeds.
        if !module.immediate_dependencies().is_empty() {
            continue;
        }
        let package = match StoredPackage::from_modules_for_testing(
            *module.self_id().address(),
            vec![module.clone()],
        ) {
            Ok(package) => package.into_serialized_package(),
            Err(_) => continue,
        };
        let runtime_result = catch_unwind(AssertUnwindSafe(|| {
            let natives = NativeFunctions::empty_for_testing().expect("empty native table");
            let runtime = MoveRuntime::new(natives, cfg.vm.clone());
            let storage = InMemoryStorage::new();
            let mut gas = GasStatus::new_unmetered();
            runtime.validate_package(
                &storage,
                package.original_id,
                package,
                &mut gas,
                NativeExtensions::default(),
            )
        }));
        match runtime_result {
            Err(payload) => {
                return Some(DangerousOutcome::RuntimePanic {
                    version: cfg.version,
                    message: panic_message(payload.as_ref()),
                });
            }
            Ok(Err(error)) if error.status_type() == StatusType::InvariantViolation => {
                return Some(DangerousOutcome::RuntimeInvariantViolation {
                    version: cfg.version,
                    major_status: format!("{:?}", error.major_status()),
                    message: error.message().map(str::to_owned),
                });
            }
            Ok(Err(_)) => continue,
            Ok(Ok(_)) => {}
        }
        if let Some(c) = counters.as_deref_mut() {
            c.versions.entry(cfg.version).or_default().runtime_accepted += 1;
        }

        let sui_result = catch_unwind(AssertUnwindSafe(|| {
            sui_verify_module_unmetered(&module, &BTreeMap::new(), &cfg.verifier)
        }));
        match sui_result {
            Err(payload) => {
                return Some(DangerousOutcome::SuiVerifierPanic {
                    version: cfg.version,
                    message: panic_message(payload.as_ref()),
                });
            }
            Ok(Err(_)) => {
                if let Some(c) = counters.as_deref_mut() {
                    c.versions
                        .entry(cfg.version)
                        .or_default()
                        .sui_rejected_cleanly += 1;
                }
            }
            Ok(Ok(())) => {
                if let Some(c) = counters.as_deref_mut() {
                    c.versions.entry(cfg.version).or_default().sui_accepted += 1;
                }
            }
        }
    }
    None
}

fn process(
    out: &Path,
    configs: &[ExactConfig],
    counters: &mut Counters,
    candidates: &mut Vec<Candidate>,
    case_id: u64,
    label: &str,
    bytes: &[u8],
) {
    counters.cases += 1;
    let first = classify(bytes, configs, Some(counters));
    let Some(outcome) = first else { return };
    let second = classify(bytes, configs, None);
    if second.as_ref() == Some(&outcome) {
        counters.deterministic_candidates += 1;
        if candidates.len() < 128 {
            let safe: String = label
                .chars()
                .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
                .take(72)
                .collect();
            let binary_file = format!("candidate-{case_id:08}-{safe}.mv");
            fs::write(out.join(&binary_file), bytes).expect("write candidate");
            candidates.push(Candidate {
                case_id,
                label: label.to_owned(),
                bytes: bytes.len(),
                fingerprint: fingerprint(bytes),
                binary_file,
                outcome,
            });
        }
    } else {
        counters.unstable_candidates += 1;
    }
}

fn parse_args() -> (PathBuf, u64, u64) {
    let mut out = PathBuf::from("sui-verifier-results");
    let mut random_cases = 60_000u64;
    let mut seed = 0x5a17_5a11_2026_0808u64;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = PathBuf::from(args.next().expect("--out value")),
            "--random-cases" => {
                random_cases = args.next().expect("count").parse().expect("integer")
            }
            "--seed" => {
                let raw = args.next().expect("seed");
                seed = raw
                    .strip_prefix("0x")
                    .map(|v| u64::from_str_radix(v, 16).expect("hex seed"))
                    .unwrap_or_else(|| raw.parse().expect("integer seed"));
            }
            other => panic!("unknown argument {other}"),
        }
    }
    (out, random_cases, seed)
}

fn main() {
    let (out, random_cases, seed) = parse_args();
    fs::create_dir_all(&out).expect("create output");
    let configs = configs();
    let corpus = corpus();
    let mut counters = Counters::default();
    let mut candidates = Vec::new();
    let mut corpus_records = Vec::new();
    let mut case_id = 0u64;

    for (name, bytes) in &corpus {
        let mut accepted_versions = Vec::new();
        for cfg in &configs {
            let Ok(module) = CompiledModule::deserialize_with_config(bytes, &cfg.binary) else {
                continue;
            };
            if verify_module_with_config_unmetered(&cfg.verifier, &module).is_ok()
                && sui_verify_module_unmetered(&module, &BTreeMap::new(), &cfg.verifier).is_ok()
            {
                accepted_versions.push(cfg.version);
            }
        }
        corpus_records.push(CorpusRecord {
            name: name.clone(),
            bytes: bytes.len(),
            accepted_versions,
        });
        process(
            &out,
            &configs,
            &mut counters,
            &mut candidates,
            case_id,
            &format!("baseline-{name}"),
            bytes,
        );
        case_id += 1;
    }

    const BOUNDARY: [u8; 5] = [0, 1, 0x7f, 0x80, 0xff];
    for (name, base) in &corpus {
        for position in 0..base.len() {
            for bit in 0..8 {
                let mut bytes = base.clone();
                bytes[position] ^= 1 << bit;
                process(
                    &out,
                    &configs,
                    &mut counters,
                    &mut candidates,
                    case_id,
                    &format!("{name}-flip-{position}-{bit}"),
                    &bytes,
                );
                case_id += 1;
            }
            for replacement in BOUNDARY {
                let mut bytes = base.clone();
                bytes[position] = replacement;
                process(
                    &out,
                    &configs,
                    &mut counters,
                    &mut candidates,
                    case_id,
                    &format!("{name}-replace-{position}-{replacement:02x}"),
                    &bytes,
                );
                case_id += 1;
            }
        }
        for length in 0..base.len() {
            process(
                &out,
                &configs,
                &mut counters,
                &mut candidates,
                case_id,
                &format!("{name}-truncate-{length}"),
                &base[..length],
            );
            case_id += 1;
        }
    }

    let mut rng = XorShift64::new(seed);
    for index in 0..random_cases {
        let (name, base) = &corpus[rng.index(corpus.len())];
        let mut bytes = base.clone();
        for _ in 0..(1 + rng.index(14)) {
            match rng.index(6) {
                0 | 1 if !bytes.is_empty() => {
                    let pos = rng.index(bytes.len());
                    bytes[pos] ^= 1 << rng.index(8);
                }
                2 if !bytes.is_empty() => {
                    let pos = rng.index(bytes.len());
                    bytes[pos] = rng.next() as u8;
                }
                3 if bytes.len() < 65_536 => {
                    let pos = rng.index(bytes.len() + 1);
                    bytes.insert(pos, rng.next() as u8);
                }
                4 if !bytes.is_empty() => {
                    let pos = rng.index(bytes.len());
                    bytes.remove(pos);
                }
                _ if !bytes.is_empty() && bytes.len() < 65_536 => {
                    let start = rng.index(bytes.len());
                    let width = 1 + rng.index((bytes.len() - start).min(32).max(1));
                    let fragment = bytes[start..start + width].to_vec();
                    let pos = rng.index(bytes.len() + 1);
                    bytes.splice(pos..pos, fragment);
                }
                _ => {}
            }
        }
        process(
            &out,
            &configs,
            &mut counters,
            &mut candidates,
            case_id,
            &format!("{name}-random-{index}"),
            &bytes,
        );
        case_id += 1;
    }

    let gate = if candidates.is_empty() {
        "PASS_NO_REACHABLE_SUI_VERIFIER_PANIC"
    } else {
        "CANDIDATE_REQUIRES_EXACT_TRANSACTIONAL_PUBLICATION_REPLAY"
    };
    let report = Report {
        harness: "sui_specific_verifier_mutator_v1",
        source_contract: "only modules accepted by exact binary/core/runtime validation are passed to the Sui verifier; any panic is replayed with fresh state",
        seed,
        requested_random_cases: random_cases,
        protocol_versions: PROTOCOL_VERSIONS.to_vec(),
        corpus: corpus_records,
        counters,
        candidates,
        gate,
    };
    let json = serde_json::to_vec_pretty(&report).expect("serialize report");
    fs::write(out.join("SUI_VERIFIER_MUTATOR_RESULT.json"), &json).expect("write report");
    println!("{}", String::from_utf8(json).expect("utf8"));
    if gate.starts_with("CANDIDATE_") {
        std::process::exit(42);
    }
}
