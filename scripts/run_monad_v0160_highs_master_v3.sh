#!/usr/bin/env bash
set -Eeuo pipefail

: "${BFT_COMMIT:=c616743d1358186605e1c1b74a3d6c4fdd9dd48c}"
: "${EXEC_COMMIT:=e81ffe31cd30fe3455d1233e4ee6c9b3f017bad0}"
: "${EVIDENCE_DIR:=evidence}"

RECOVERY_TEST="udp::tests_deterministic::malicious_v1_high_s_alias_is_one_round_only_under_accept_both_publish_v0"
SUSTAINED_TEST="udp::tests_deterministic::research_malicious_relay_repeats_high_s_alias_across_honest_rounds"

mkdir -p \
  "$EVIDENCE_DIR/recovery" \
  "$EVIDENCE_DIR/sustained-vulnerable" \
  "$EVIDENCE_DIR/sustained-low-s-control"

sha256sum monad-bft/monad-raptorcast/src/udp.rs > "$EVIDENCE_DIR/udp.rs.pristine.sha256"
sha256sum monad-bft/monad-secp/src/secp.rs > "$EVIDENCE_DIR/secp.rs.pristine.sha256"

python3 scripts/monad_v0160_highs_recovery_v2.py
python3 scripts/monad_v0160_highs_sustained_v2.py
cargo fmt --manifest-path monad-bft/Cargo.toml --all
git -C monad-bft diff --check
git -C monad-bft diff -- monad-raptorcast/src/udp.rs \
  > "$EVIDENCE_DIR/MONAD_V0160_RAPTORCAST_V1_HIGHS_MASTER_V3_TEST.patch"
test -s "$EVIDENCE_DIR/MONAD_V0160_RAPTORCAST_V1_HIGHS_MASTER_V3_TEST.patch"

for attempt in 1 2 3 4 5; do
  cargo fetch --manifest-path monad-bft/Cargo.toml --locked && break
  if [ "$attempt" = 5 ]; then exit 1; fi
  sleep $((attempt * 5))
done

run_phase() {
  local directory="$1"
  local test_name="$2"
  : > "$directory/status.tsv"
  for repetition in 1 2 3; do
    set +e
    cargo test --manifest-path monad-bft/Cargo.toml --locked \
      -p monad-raptorcast "$test_name" \
      -- --exact --nocapture --test-threads=1 \
      2>&1 | tee "$directory/run-${repetition}.log"
    status=${PIPESTATUS[0]}
    set -e
    printf '%s\t%s\n' "$repetition" "$status" >> "$directory/status.tsv"
  done
}

run_phase "$EVIDENCE_DIR/recovery" "$RECOVERY_TEST"
run_phase "$EVIDENCE_DIR/sustained-vulnerable" "$SUSTAINED_TEST"

python3 scripts/monad_v0160_reject_high_s_signatures.py
cargo fmt --manifest-path monad-bft/Cargo.toml --all
git -C monad-bft diff --check
git -C monad-bft diff -- monad-secp/src/secp.rs \
  > "$EVIDENCE_DIR/MONAD_V0160_CANONICAL_LOW_S_NETWORK_CONTROL.patch"
test -s "$EVIDENCE_DIR/MONAD_V0160_CANONICAL_LOW_S_NETWORK_CONTROL.patch"
sha256sum monad-bft/monad-secp/src/secp.rs > "$EVIDENCE_DIR/secp.rs.low-s-control.sha256"

run_phase "$EVIDENCE_DIR/sustained-low-s-control" "$SUSTAINED_TEST"

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
        "DEFAULT_STAGE_V1_CONTROL_ROUND42",
        "POISONED_HONEST_ONE_ROUND42",
        "POISONED_HONEST_TWO_ROUND42",
        "RECOVERED_HONEST_ONE_ROUND43",
        "RECOVERED_HONEST_TWO_ROUND43",
        "RECOVERED_HONEST_THREE_ROUND43",
        "TEST_COMPLETE",
    ]
    runs=[]
    for rep in (1,2,3):
        text=(root/"recovery"/f"run-{rep}.log").read_text(errors="replace")
        markers={}
        for name in names:
            values=re.findall(rf"MARKER_{name}=([0-9]+)",text)
            markers[name]=int(values[-1]) if values else None
        runs.append({"repetition":rep,"exit_code":status.get(rep),"markers":markers})
    return runs

def parse_sustained(phase):
    directory=root/phase
    status=read_status(directory)
    runs=[]
    for rep in (1,2,3):
        text=(directory/f"run-{rep}.log").read_text(errors="replace")
        rows=[]
        for m in re.finditer(
            r"MARKER_SUSTAINED_ROUND_([0-9]+)_PROPOSER=([0-2])_COUNTS=([0-9]+),([0-9]+),([0-9]+)",
            text,
        ):
            rows.append({
                "round":int(m.group(1)),
                "proposer":int(m.group(2)),
                "counts":[int(m.group(3)),int(m.group(4)),int(m.group(5))],
            })
        runs.append({
            "repetition":rep,
            "exit_code":status.get(rep),
            "complete":"MARKER_SUSTAINED_TEST_COMPLETE=1" in text,
            "rounds":rows,
        })
    return runs

recovery=parse_recovery()
vulnerable=parse_sustained("sustained-vulnerable")
control=parse_sustained("sustained-low-s-control")

recovery_expected={
    "DEFAULT_STAGE_V1_CONTROL_ROUND42":1,
    "POISONED_HONEST_ONE_ROUND42":0,
    "POISONED_HONEST_TWO_ROUND42":0,
    "RECOVERED_HONEST_ONE_ROUND43":1,
    "RECOVERED_HONEST_TWO_ROUND43":1,
    "RECOVERED_HONEST_THREE_ROUND43":0,
    "TEST_COMPLETE":1,
}
recovery_pass=all(
    run["exit_code"]==0
    and all(run["markers"].get(k)==v for k,v in recovery_expected.items())
    for run in recovery
)

def vulnerable_ok(run):
    return (
        run["exit_code"]==0
        and run["complete"]
        and len(run["rounds"])==12
        and all(row["counts"]==[0,0,0] for row in run["rounds"])
    )

def control_ok(run):
    if run["exit_code"]!=0 or not run["complete"] or len(run["rounds"])!=12:
        return False
    for row in run["rounds"]:
        expected=[1,1,1]
        expected[row["proposer"]]=0
        if row["counts"]!=expected:
            return False
    return True

vulnerable_pass=all(vulnerable_ok(run) for run in vulnerable)
control_pass=all(control_ok(run) for run in control)

if recovery_pass and vulnerable_pass and control_pass:
    decision="REPEATED_V1_ALIAS_TRANSPORT_POISONING_LOW_S_CONTROL_PASS_FULLNODE_GATE_MISSING"
elif recovery_pass and not vulnerable_pass:
    decision="ONE_ROUND_ONLY_REPEATED_ATTACK_NOT_REPRODUCED"
elif vulnerable_pass and not control_pass:
    decision="REPEATED_TRANSPORT_POISONING_LOW_S_CONTROL_INCOMPLETE"
else:
    decision="INCOMPLETE_OR_NEGATIVE_MASTER_V3_GATE"

result={
    "bft_commit":"c616743d1358186605e1c1b74a3d6c4fdd9dd48c",
    "execution_commit":"e81ffe31cd30fe3455d1233e4ee6c9b3f017bad0",
    "decision":decision,
    "recovery_runs":recovery,
    "vulnerable_runs":vulnerable,
    "low_s_control_runs":control,
    "one_round_recovery":recovery_pass,
    "repeated_transport_poisoning":vulnerable_pass,
    "canonical_low_s_control":control_pass,
    "official_consensus_finality_halt":False,
    "critical_proven":False,
    "submit_ready":False,
}
(root/"RESULT.json").write_text(json.dumps(result,indent=2)+"\n")
(root/"REPORT.md").write_text(f"""# Monad v0.16.0 V1 high-S master-v3 gate

## Decision

**{decision}**

The exact release is checked in three layers:

1. two poisoned honest receivers recover as real network receivers in the next clean
   honest-proposer round;
2. a Byzantine relay repeats the signature alias race for twelve consecutive honest
   proposer rounds using a first-hop chunk assigned to itself;
3. the same twelve-round matrix runs after canonical low-S rejection at
   `SecpSignature::deserialize`.

- One-round recovery when the attacker stops: **{recovery_pass}**
- Repeated transport poisoning while the attacker continues: **{vulnerable_pass}**
- Canonical low-S control: **{control_pass}**
- Official RaptorCast consensus/full-node finality halt: **false**
- Critical proven: **false**
- Submit-ready: **false**

Transport-level repeated poisoning is only a High candidate. Submission requires a
RaptorCast-aware consensus or official full-node A/B showing that the first-hop race
prevents QC/finality across repeated rounds under realistic routing and disappears under
low-S rejection.
""")
manifest=[]
for path in sorted(root.rglob("*")):
    if path.is_file() and path.name!="SHA256SUMS":
        manifest.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}")
(root/"SHA256SUMS").write_text("\n".join(manifest)+"\n")
print(json.dumps(result,indent=2))
PY
