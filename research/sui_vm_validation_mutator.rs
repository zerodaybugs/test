// Exact-source, local-only Sui Move VM publication-validation mutator.
//
// Security contract under test: attacker-controlled module bytes that fail deserialization or
// verification must return user errors. They must not panic, and a verifier-accepted, self-contained
// module must not produce a VM invariant violation during publication validation/JIT translation.

use move_binary_format::{
    file_format::{
        CompiledModule, basic_test_module, basic_test_module_with_enum, empty_module,
    },
};
use move_bytecode_verifier::verify_module_unmetered;
use move_core_types::vm_status::StatusType;
use move_vm_config::runtime::VMConfig;
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
    env,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "class", rename_all = "snake_case")]
enum DangerousOutcome {
    DeserializerPanic { message: String },
    VerifierPanic { message: String },
    RuntimePanic { message: String },
    RuntimeInvariantViolation {
        major_status: String,
        message: Option<String>,
    },
}

#[derive(Clone, Debug, Default, Serialize)]
struct Counters {
    cases: u64,
    deserialized: u64,
    verifier_accepted: u64,
    self_contained: u64,
    package_metadata_constructed: u64,
    runtime_accepted: u64,
    runtime_user_errors: u64,
    helper_rejections: u64,
    dependency_cases_skipped: u64,
    deterministic_candidates: u64,
    unstable_candidates: u64,
}

#[derive(Clone, Debug, Serialize)]
struct CandidateRecord {
    case_id: u64,
    label: String,
    byte_len: usize,
    byte_fingerprint: String,
    binary_file: String,
    outcome: DangerousOutcome,
}

#[derive(Clone, Debug, Serialize)]
struct Report {
    harness: &'static str,
    security_contract: &'static str,
    random_seed: u64,
    requested_random_cases: u64,
    corpus: Vec<CorpusRecord>,
    counters: Counters,
    candidates: Vec<CandidateRecord>,
    gate: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct CorpusRecord {
    name: String,
    bytes: usize,
    baseline_deserializes: bool,
    baseline_verifies: bool,
    baseline_runtime_accepts: bool,
}

#[derive(Clone, Debug, Default)]
struct Observation {
    deserialized: bool,
    verifier_accepted: bool,
    self_contained: bool,
    package_metadata_constructed: bool,
    runtime_accepted: bool,
    runtime_user_error: bool,
    helper_rejection: bool,
    dependency_skipped: bool,
    dangerous: Option<DangerousOutcome>,
}

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            (self.next_u64() as usize) % len
        }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

fn fingerprint(bytes: &[u8]) -> String {
    // Deterministic 128-bit FNV-style diagnostic fingerprint. The exact bytes are also retained.
    let mut a = 0xcbf29ce484222325u64;
    let mut b = 0x84222325cbf29ce4u64;
    for (index, byte) in bytes.iter().enumerate() {
        a ^= u64::from(*byte);
        a = a.wrapping_mul(0x100000001b3);
        b ^= (u64::from(*byte) << ((index % 8) * 8)) ^ index as u64;
        b = b.rotate_left(9).wrapping_mul(0x9e3779b185ebca87);
    }
    format!("{a:016x}{b:016x}")
}

fn serialize_module(module: &CompiledModule) -> Vec<u8> {
    let mut bytes = Vec::new();
    module
        .serialize_with_version(module.version, &mut bytes)
        .expect("built-in corpus module must serialize");
    bytes
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    vec![
        ("empty_module".to_owned(), serialize_module(&empty_module())),
        (
            "basic_test_module".to_owned(),
            serialize_module(&basic_test_module()),
        ),
        (
            "basic_test_module_with_enum".to_owned(),
            serialize_module(&basic_test_module_with_enum()),
        ),
    ]
}

fn classify(bytes: &[u8]) -> Observation {
    let mut observation = Observation::default();

    let deserialized = catch_unwind(AssertUnwindSafe(|| {
        CompiledModule::deserialize_with_defaults(bytes)
    }));
    let module = match deserialized {
        Err(payload) => {
            observation.dangerous = Some(DangerousOutcome::DeserializerPanic {
                message: panic_message(payload.as_ref()),
            });
            return observation;
        }
        Ok(Err(_)) => return observation,
        Ok(Ok(module)) => {
            observation.deserialized = true;
            module
        }
    };

    let verifier = catch_unwind(AssertUnwindSafe(|| verify_module_unmetered(&module)));
    match verifier {
        Err(payload) => {
            observation.dangerous = Some(DangerousOutcome::VerifierPanic {
                message: panic_message(payload.as_ref()),
            });
            return observation;
        }
        Ok(Err(_)) => return observation,
        Ok(Ok(())) => observation.verifier_accepted = true,
    }

    if !module.immediate_dependencies().is_empty() {
        observation.dependency_skipped = true;
        return observation;
    }
    observation.self_contained = true;

    let version_id = *module.self_id().address();
    let package = catch_unwind(AssertUnwindSafe(|| {
        StoredPackage::from_modules_for_testing(version_id, vec![module])
    }));
    let package = match package {
        Err(_) | Ok(Err(_)) => {
            // This helper is not the production trust boundary. Keep the case in statistics but
            // never promote a helper-only failure to a candidate.
            observation.helper_rejection = true;
            return observation;
        }
        Ok(Ok(package)) => {
            observation.package_metadata_constructed = true;
            package.into_serialized_package()
        }
    };

    let original_id = package.original_id;
    let runtime_result = catch_unwind(AssertUnwindSafe(|| {
        let natives = NativeFunctions::empty_for_testing().expect("empty native table");
        let runtime = MoveRuntime::new(natives, VMConfig::default());
        let storage = InMemoryStorage::new();
        let mut gas = GasStatus::new_unmetered();
        match runtime.validate_package(
            &storage,
            original_id,
            package,
            &mut gas,
            NativeExtensions::default(),
        ) {
            Ok(_) => Ok(()),
            Err(error) => Err((
                error.status_type(),
                format!("{:?}", error.major_status()),
                error.message().map(str::to_owned),
            )),
        }
    }));

    match runtime_result {
        Err(payload) => {
            observation.dangerous = Some(DangerousOutcome::RuntimePanic {
                message: panic_message(payload.as_ref()),
            });
        }
        Ok(Ok(())) => observation.runtime_accepted = true,
        Ok(Err((StatusType::InvariantViolation, major_status, message))) => {
            observation.dangerous = Some(DangerousOutcome::RuntimeInvariantViolation {
                major_status,
                message,
            });
        }
        Ok(Err(_)) => observation.runtime_user_error = true,
    }

    observation
}

fn apply_observation(counters: &mut Counters, observation: &Observation) {
    counters.cases += 1;
    counters.deserialized += u64::from(observation.deserialized);
    counters.verifier_accepted += u64::from(observation.verifier_accepted);
    counters.self_contained += u64::from(observation.self_contained);
    counters.package_metadata_constructed +=
        u64::from(observation.package_metadata_constructed);
    counters.runtime_accepted += u64::from(observation.runtime_accepted);
    counters.runtime_user_errors += u64::from(observation.runtime_user_error);
    counters.helper_rejections += u64::from(observation.helper_rejection);
    counters.dependency_cases_skipped += u64::from(observation.dependency_skipped);
}

fn save_candidate(
    out: &Path,
    case_id: u64,
    label: &str,
    bytes: &[u8],
    outcome: DangerousOutcome,
) -> CandidateRecord {
    let safe_label: String = label
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .take(80)
        .collect();
    let file_name = format!("candidate-{case_id:08}-{safe_label}.mv");
    fs::write(out.join(&file_name), bytes).expect("write candidate bytes");
    CandidateRecord {
        case_id,
        label: label.to_owned(),
        byte_len: bytes.len(),
        byte_fingerprint: fingerprint(bytes),
        binary_file: file_name,
        outcome,
    }
}

fn process_case(
    out: &Path,
    counters: &mut Counters,
    candidates: &mut Vec<CandidateRecord>,
    case_id: u64,
    label: &str,
    bytes: &[u8],
) {
    let first = classify(bytes);
    apply_observation(counters, &first);
    let Some(dangerous) = first.dangerous.clone() else {
        return;
    };

    // Require exact deterministic reproduction with fresh runtime/cache state.
    let second = classify(bytes);
    if second.dangerous.as_ref() == Some(&dangerous) {
        counters.deterministic_candidates += 1;
        if candidates.len() < 128 {
            candidates.push(save_candidate(
                out,
                case_id,
                label,
                bytes,
                dangerous,
            ));
        }
    } else {
        counters.unstable_candidates += 1;
    }
}

fn parse_args() -> (PathBuf, u64, u64) {
    let mut out = PathBuf::from("mutation-results");
    let mut random_cases = 50_000u64;
    let mut seed = 0x5a17_2026_0808_cafeu64;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = PathBuf::from(args.next().expect("--out value")),
            "--random-cases" => {
                random_cases = args
                    .next()
                    .expect("--random-cases value")
                    .parse()
                    .expect("integer random case count")
            }
            "--seed" => {
                let raw = args.next().expect("--seed value");
                seed = if let Some(hex) = raw.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).expect("hex seed")
                } else {
                    raw.parse().expect("integer seed")
                };
            }
            other => panic!("unknown argument: {other}"),
        }
    }
    (out, random_cases, seed)
}

fn main() {
    let (out, random_cases, seed) = parse_args();
    fs::create_dir_all(&out).expect("create output directory");

    let corpus = corpus();
    let mut counters = Counters::default();
    let mut candidates = Vec::new();
    let mut corpus_records = Vec::new();
    let mut case_id = 0u64;

    for (name, bytes) in &corpus {
        let baseline = classify(bytes);
        corpus_records.push(CorpusRecord {
            name: name.clone(),
            bytes: bytes.len(),
            baseline_deserializes: baseline.deserialized,
            baseline_verifies: baseline.verifier_accepted,
            baseline_runtime_accepts: baseline.runtime_accepted,
        });
        process_case(
            &out,
            &mut counters,
            &mut candidates,
            case_id,
            &format!("baseline-{name}"),
            bytes,
        );
        case_id += 1;
    }

    // Systematic one-byte bit flips and replacements cover table tags, ULEB lengths, indexes,
    // signatures, jump tables and bytecodes close to a known-valid corpus.
    const REPLACEMENTS: [u8; 5] = [0x00, 0x01, 0x7f, 0x80, 0xff];
    for (name, bytes) in &corpus {
        for position in 0..bytes.len() {
            for bit in 0..8 {
                let mut mutated = bytes.clone();
                mutated[position] ^= 1u8 << bit;
                process_case(
                    &out,
                    &mut counters,
                    &mut candidates,
                    case_id,
                    &format!("{name}-flip-{position}-{bit}"),
                    &mutated,
                );
                case_id += 1;
            }
            for replacement in REPLACEMENTS {
                if bytes[position] == replacement {
                    continue;
                }
                let mut mutated = bytes.clone();
                mutated[position] = replacement;
                process_case(
                    &out,
                    &mut counters,
                    &mut candidates,
                    case_id,
                    &format!("{name}-replace-{position}-{replacement:02x}"),
                    &mutated,
                );
                case_id += 1;
            }
        }

        // Every truncation boundary must be a clean deserialization error, never a panic.
        for length in 0..bytes.len() {
            process_case(
                &out,
                &mut counters,
                &mut candidates,
                case_id,
                &format!("{name}-truncate-{length}"),
                &bytes[..length],
            );
            case_id += 1;
        }

        // Insert boundary bytes and duplicate short table/code fragments.
        for position in 0..=bytes.len() {
            for inserted in REPLACEMENTS {
                let mut mutated = bytes.clone();
                mutated.insert(position, inserted);
                process_case(
                    &out,
                    &mut counters,
                    &mut candidates,
                    case_id,
                    &format!("{name}-insert-{position}-{inserted:02x}"),
                    &mutated,
                );
                case_id += 1;
            }
            for width in [1usize, 2, 4, 8, 16] {
                if position + width > bytes.len() {
                    continue;
                }
                let mut mutated = bytes.clone();
                let fragment = bytes[position..position + width].to_vec();
                mutated.splice(position..position, fragment);
                process_case(
                    &out,
                    &mut counters,
                    &mut candidates,
                    case_id,
                    &format!("{name}-duplicate-{position}-{width}"),
                    &mutated,
                );
                case_id += 1;
            }
        }
    }

    // Deterministic multi-byte mutations explore interactions that single-byte mutation misses.
    let mut rng = XorShift64::new(seed);
    for random_index in 0..random_cases {
        let (name, base) = &corpus[rng.index(corpus.len())];
        let mut mutated = base.clone();
        let operations = 1 + rng.index(12);
        for _ in 0..operations {
            match rng.index(6) {
                0 | 1 => {
                    if !mutated.is_empty() {
                        let position = rng.index(mutated.len());
                        mutated[position] ^= 1u8 << rng.index(8);
                    }
                }
                2 => {
                    if !mutated.is_empty() {
                        let position = rng.index(mutated.len());
                        mutated[position] = rng.next_u64() as u8;
                    }
                }
                3 => {
                    if mutated.len() < 65_536 {
                        let position = rng.index(mutated.len() + 1);
                        mutated.insert(position, rng.next_u64() as u8);
                    }
                }
                4 => {
                    if !mutated.is_empty() {
                        let position = rng.index(mutated.len());
                        mutated.remove(position);
                    }
                }
                _ => {
                    if !mutated.is_empty() && mutated.len() < 65_536 {
                        let start = rng.index(mutated.len());
                        let max_width = (mutated.len() - start).min(32);
                        let width = 1 + rng.index(max_width.max(1));
                        let fragment = mutated[start..start + width].to_vec();
                        let insert_at = rng.index(mutated.len() + 1);
                        mutated.splice(insert_at..insert_at, fragment);
                    }
                }
            }
        }
        process_case(
            &out,
            &mut counters,
            &mut candidates,
            case_id,
            &format!("{name}-random-{random_index}"),
            &mutated,
        );
        case_id += 1;
    }

    let gate = if candidates.is_empty() {
        "PASS_NO_DETERMINISTIC_PANIC_OR_INVARIANT"
    } else {
        "CANDIDATE_REQUIRES_SUI_PUBLICATION_AND_MAINNET_CONFIG_GATE"
    };
    let report = Report {
        harness: "sui_vm_validation_mutator_v1",
        security_contract: "malformed modules return user errors; verifier-accepted self-contained modules never panic or return invariant violations during publication validation/JIT",
        random_seed: seed,
        requested_random_cases: random_cases,
        corpus: corpus_records,
        counters,
        candidates,
        gate,
    };
    let json = serde_json::to_vec_pretty(&report).expect("serialize report");
    fs::write(out.join("VALIDATION_MUTATOR_RESULT.json"), &json).expect("write report");
    println!("{}", String::from_utf8(json).expect("JSON is UTF-8"));

    if gate.starts_with("CANDIDATE_") {
        std::process::exit(42);
    }
}
