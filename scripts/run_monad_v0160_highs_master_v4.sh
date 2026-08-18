#!/usr/bin/env bash
set -Eeuo pipefail

: "${BFT_COMMIT:=c616743d1358186605e1c1b74a3d6c4fdd9dd48c}"
: "${EXEC_COMMIT:=e81ffe31cd30fe3455d1233e4ee6c9b3f017bad0}"
: "${EVIDENCE_DIR:=evidence}"

RECOVERY_TEST="udp::tests_deterministic::research_honest_proposer_high_s_relay_poison_recovers_next_round"
SUSTAINED_TEST="udp::tests_deterministic::research_malicious_relay_repeats_high_s_alias_across_honest_rounds"

mkdir -p \
  "$EVIDENCE_DIR/recovery" \
  "$EVIDENCE_DIR/sustained-vulnerable" \
  "$EVIDENCE_DIR/sustained-low-s-control" \
  "$EVIDENCE_DIR/low-s-regression"

sha256sum monad-bft/monad-raptorcast/src/udp.rs > "$EVIDENCE_DIR/udp.rs.pristine.sha256"
sha256sum monad-bft/monad-secp/src/secp.rs > "$EVIDENCE_DIR/secp.rs.pristine.sha256"

python3 scripts/monad_v0160_highs_recovery_v3.py
python3 scripts/monad_v0160_highs_sustained_v2.py
cargo fmt --manifest-path monad-bft/Cargo.toml --all
git -C monad-bft diff --check
git -C monad-bft diff -- monad-raptorcast/src/udp.rs \
  > "$EVIDENCE_DIR/MONAD_V0160_RAPTORCAST_V1_HIGHS_MASTER_V4_TEST.patch"
sha256sum monad-bft/monad-raptorcast/src/udp.rs > "$EVIDENCE_DIR/udp.rs.injected.sha256"
test -s "$EVIDENCE_DIR/MONAD_V0160_RAPTORCAST_V1_HIGHS_MASTER_V4_TEST.patch"

for attempt in 1 2 3 4 5; do
  cargo fetch --manifest-path monad-bft/Cargo.toml --locked && break
  if [ "$attempt" = 5 ]; then exit 1; fi
  sleep $((attempt * 5))
done

run_phase() {
  local directory="$1"
  local package="$2"
  local test_name="$3"
  : > "$directory/status.tsv"
  for repetition in 1 2 3; do
    set +e
    cargo test --manifest-path monad-bft/Cargo.toml --locked \
      -p "$package" "$test_name" \
      -- --exact --nocapture --test-threads=1 \
      2>&1 | tee "$directory/run-${repetition}.log"
    status=${PIPESTATUS[0]}
    set -e
    printf '%s\t%s\n' "$repetition" "$status" >> "$directory/status.tsv"
  done
}

run_phase "$EVIDENCE_DIR/recovery" monad-raptorcast "$RECOVERY_TEST"
run_phase "$EVIDENCE_DIR/sustained-vulnerable" monad-raptorcast "$SUSTAINED_TEST"

python3 scripts/monad_v0160_reject_high_s_signatures.py
cargo fmt --manifest-path monad-bft/Cargo.toml --all
git -C monad-bft diff --check
git -C monad-bft diff -- monad-secp/src/secp.rs \
  > "$EVIDENCE_DIR/MONAD_V0160_CANONICAL_LOW_S_NETWORK_CONTROL.patch"
sha256sum monad-bft/monad-secp/src/secp.rs > "$EVIDENCE_DIR/secp.rs.low-s-control.sha256"
test -s "$EVIDENCE_DIR/MONAD_V0160_CANONICAL_LOW_S_NETWORK_CONTROL.patch"

run_phase "$EVIDENCE_DIR/sustained-low-s-control" monad-raptorcast "$SUSTAINED_TEST"

set +e
cargo test --manifest-path monad-bft/Cargo.toml --locked \
  -p monad-secp --lib -- --nocapture --test-threads=1 \
  2>&1 | tee "$EVIDENCE_DIR/low-s-regression/monad-secp-lib.log"
low_s_regression_status=${PIPESTATUS[0]}
set -e
printf '%s\n' "$low_s_regression_status" > "$EVIDENCE_DIR/low-s-regression/exitcode"

python3 - <<'PY'
from pathlib import Path
import hashlib
import json
import re

root = Path("evidence")


def read_status(directory: Path):
    status = {}
    for line in (directory / "status.tsv").read_text().splitlines():
        rep, code = line.split("\t")
        status[int(rep)] = int(code)
    return status


def parse_recovery():
    status = read_status(root / "recovery")
    names = [
        "V3_DEFAULT_STAGE_V1_CONTROL_ROUND42",
        "V3_POISONED_HONEST_ONE_ROUND42",
        "V3_POISONED_HONEST_TWO_ROUND42",
        "V3_RECOVERED_HONEST_ONE_ROUND43",
        "V3_RECOVERED_HONEST_TWO_ROUND43",
        "V3_TEST_COMPLETE",
    ]
    runs = []
    for rep in (1, 2, 3):
        text = (root / "recovery" / f"run-{rep}.log").read_text(errors="replace")
        markers = {}
        for name in names:
            values = re.findall(rf"MARKER_{name}=([0-9]+)", text)
            markers[name] = int(values[-1]) if values else None
        runs.append({
            "repetition": rep,
            "exit_code": status.get(rep),
            "markers": markers,
        })
    return runs


def parse_sustained(phase: str):
    directory = root / phase
    status = read_status(directory)
    runs = []
    for rep in (1, 2, 3):
        text = (directory / f"run-{rep}.log").read_text(errors="replace")
        rows = []
        for match in re.finditer(
            r"MARKER_SUSTAINED_ROUND_([0-9]+)_PROPOSER=([0-2])_COUNTS=([0-9]+),([0-9]+),([0-9]+)",
            text,
        ):
            rows.append({
                "round": int(match.group(1)),
                "proposer": int(match.group(2)),
                "counts": [
                    int(match.group(3)),
                    int(match.group(4)),
                    int(match.group(5)),
                ],
            })
        runs.append({
            "repetition": rep,
            "exit_code": status.get(rep),
            "complete": "MARKER_SUSTAINED_TEST_COMPLETE=1" in text,
            "rounds": rows,
        })
    return runs


recovery = parse_recovery()
vulnerable = parse_sustained("sustained-vulnerable")
control = parse_sustained("sustained-low-s-control")

recovery_expected = {
    "V3_DEFAULT_STAGE_V1_CONTROL_ROUND42": 1,
    "V3_POISONED_HONEST_ONE_ROUND42": 0,
    "V3_POISONED_HONEST_TWO_ROUND42": 0,
    "V3_RECOVERED_HONEST_ONE_ROUND43": 1,
    "V3_RECOVERED_HONEST_TWO_ROUND43": 1,
    "V3_TEST_COMPLETE": 1,
}
recovery_pass = all(
    run["exit_code"] == 0
    and all(run["markers"].get(key) == value for key, value in recovery_expected.items())
    for run in recovery
)


def vulnerable_ok(run):
    return (
        run["exit_code"] == 0
        and run["complete"]
        and len(run["rounds"]) == 12
        and all(row["counts"] == [0, 0, 0] for row in run["rounds"])
    )


def control_ok(run):
    if run["exit_code"] != 0 or not run["complete"] or len(run["rounds"]) != 12:
        return False
    for row in run["rounds"]:
        expected = [1, 1, 1]
        expected[row["proposer"]] = 0
        if row["counts"] != expected:
            return False
    return True


vulnerable_pass = all(vulnerable_ok(run) for run in vulnerable)
control_pass = all(control_ok(run) for run in control)
low_s_regression_status = int((root / "low-s-regression" / "exitcode").read_text().strip())
low_s_regression_pass = low_s_regression_status == 0

if recovery_pass and vulnerable_pass and control_pass and low_s_regression_pass:
    decision = "REPEATED_V1_ALIAS_TRANSPORT_POISONING_LOW_S_CONTROL_PASS_FULLNODE_GATE_MISSING"
elif recovery_pass and not vulnerable_pass:
    decision = "ONE_ROUND_ONLY_REPEATED_ATTACK_NOT_REPRODUCED"
elif vulnerable_pass and (not control_pass or not low_s_regression_pass):
    decision = "REPEATED_TRANSPORT_POISONING_LOW_S_CONTROL_INCOMPLETE"
else:
    decision = "INCOMPLETE_OR_NEGATIVE_MASTER_V4_GATE"

result = {
    "bft_commit": "c616743d1358186605e1c1b74a3d6c4fdd9dd48c",
    "execution_commit": "e81ffe31cd30fe3455d1233e4ee6c9b3f017bad0",
    "decision": decision,
    "recovery_runs": recovery,
    "vulnerable_runs": vulnerable,
    "low_s_control_runs": control,
    "one_round_recovery": recovery_pass,
    "repeated_transport_poisoning": vulnerable_pass,
    "canonical_low_s_control": control_pass,
    "low_s_regression_suite": low_s_regression_pass,
    "official_consensus_finality_halt": False,
    "critical_proven": False,
    "submit_ready": False,
}
(root / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
(root / "REPORT.md").write_text(f"""# Monad v0.16.0 V1 high-S master-v4 gate

## Decision

**{decision}**

The exact release is checked in three layers:

1. an honest V1 proposer sends a first-hop chunk to a Byzantine relay; the relay creates the
   high-S alias and poisons two honest receivers, which are then measured again in the next
   clean honest-proposer round;
2. the relay repeats the same assigned-chunk alias race for twelve consecutive honest
   proposer rounds;
3. the twelve-round matrix is repeated after canonical low-S rejection at
   `SecpSignature::deserialize`, followed by the full `monad-secp` unit suite.

- Both poisoned receivers recover when the attacker stops: **{recovery_pass}**
- Repeated transport poisoning while the attacker continues: **{vulnerable_pass}**
- Canonical low-S transport control: **{control_pass}**
- Low-S regression suite: **{low_s_regression_pass}**
- Official RaptorCast consensus/full-node finality halt: **false**
- Critical proven: **false**
- Submit-ready: **false**

Transport-level repeated poisoning is only a High candidate. Submission requires a
RaptorCast-aware consensus or official full-node A/B showing that the realistic first-hop
race prevents QC/finality across repeated rounds and disappears under low-S rejection.
""")
manifest = []
for path in sorted(root.rglob("*")):
    if path.is_file() and path.name != "SHA256SUMS":
        manifest.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}"
        )
(root / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
print(json.dumps(result, indent=2))
PY
