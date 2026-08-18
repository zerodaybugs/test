#!/usr/bin/env bash
set -Eeuo pipefail

: "${BFT_COMMIT:=c616743d1358186605e1c1b74a3d6c4fdd9dd48c}"
: "${EXEC_COMMIT:=e81ffe31cd30fe3455d1233e4ee6c9b3f017bad0}"
: "${EVIDENCE_DIR:=evidence-canonical-v2}"

SUSTAINED_TEST="udp::tests_deterministic::research_malicious_relay_repeats_high_s_alias_across_honest_rounds"
RECOVERY_TEST="udp::tests_deterministic::research_honest_proposer_high_s_relay_poison_recovers_next_round"

rm -rf "$EVIDENCE_DIR"
mkdir -p \
  "$EVIDENCE_DIR/sustained-canonical" \
  "$EVIDENCE_DIR/recovery-canonical" \
  "$EVIDENCE_DIR/secp-regression" \
  "$EVIDENCE_DIR/raptorcast-regression"

sha256sum monad-bft/monad-raptorcast/src/udp.rs > "$EVIDENCE_DIR/udp.rs.pristine.sha256"
sha256sum monad-bft/monad-secp/src/secp.rs > "$EVIDENCE_DIR/secp.rs.pristine.sha256"

python3 scripts/monad_v0160_highs_recovery_v3.py
python3 scripts/monad_v0160_highs_sustained_v2.py
python3 scripts/monad_v0160_canonicalize_high_s_v2.py
cargo fmt --manifest-path monad-bft/Cargo.toml --all
git -C monad-bft diff --check

git -C monad-bft diff -- monad-raptorcast/src/udp.rs \
  > "$EVIDENCE_DIR/MONAD_V0160_RAPTORCAST_V1_HIGHS_TESTS.patch"
git -C monad-bft diff -- monad-secp/src/secp.rs \
  > "$EVIDENCE_DIR/MONAD_V0160_CANONICAL_HIGH_S_CONTROL_V2.patch"
test -s "$EVIDENCE_DIR/MONAD_V0160_RAPTORCAST_V1_HIGHS_TESTS.patch"
test -s "$EVIDENCE_DIR/MONAD_V0160_CANONICAL_HIGH_S_CONTROL_V2.patch"
sha256sum monad-bft/monad-raptorcast/src/udp.rs > "$EVIDENCE_DIR/udp.rs.injected.sha256"
sha256sum monad-bft/monad-secp/src/secp.rs > "$EVIDENCE_DIR/secp.rs.canonical.sha256"

for attempt in 1 2 3 4 5; do
  cargo fetch --manifest-path monad-bft/Cargo.toml --locked && break
  if [ "$attempt" = 5 ]; then exit 1; fi
  sleep $((attempt * 5))
done

run_exact() {
  local directory="$1"
  local package="$2"
  local test_name="$3"
  local count="$4"
  : > "$directory/status.tsv"
  for repetition in $(seq 1 "$count"); do
    set +e
    /usr/bin/time -v cargo test --manifest-path monad-bft/Cargo.toml --locked \
      -p "$package" "$test_name" \
      -- --exact --nocapture --test-threads=1 \
      > "$directory/run-${repetition}.log" 2>&1
    status=$?
    set -e
    printf '%s\t%s\n' "$repetition" "$status" >> "$directory/status.tsv"
  done
}

run_exact "$EVIDENCE_DIR/sustained-canonical" monad-raptorcast "$SUSTAINED_TEST" 3
run_exact "$EVIDENCE_DIR/recovery-canonical" monad-raptorcast "$RECOVERY_TEST" 3

set +e
/usr/bin/time -v cargo test --manifest-path monad-bft/Cargo.toml --locked \
  -p monad-secp --lib -- --nocapture --test-threads=1 \
  > "$EVIDENCE_DIR/secp-regression/full-suite.log" 2>&1
secp_status=$?
/usr/bin/time -v cargo test --manifest-path monad-bft/Cargo.toml --locked \
  -p monad-raptorcast --lib -- --test-threads=1 \
  > "$EVIDENCE_DIR/raptorcast-regression/full-suite.log" 2>&1
raptor_status=$?
set -e
printf '%s\n' "$secp_status" > "$EVIDENCE_DIR/secp-regression/exitcode"
printf '%s\n' "$raptor_status" > "$EVIDENCE_DIR/raptorcast-regression/exitcode"

python3 - <<'PY'
from pathlib import Path
import hashlib
import json
import re

root = Path('evidence-canonical-v2')


def status(directory: Path):
    out = {}
    for line in (directory / 'status.tsv').read_text().splitlines():
        rep, code = line.split('\t')
        out[int(rep)] = int(code)
    return out


def parse_sustained():
    directory = root / 'sustained-canonical'
    codes = status(directory)
    runs = []
    for rep in (1, 2, 3):
        text = (directory / f'run-{rep}.log').read_text(errors='replace')
        rows = []
        for m in re.finditer(
            r'MARKER_SUSTAINED_ROUND_([0-9]+)_PROPOSER=([0-2])_COUNTS=([0-9]+),([0-9]+),([0-9]+)',
            text,
        ):
            rows.append({
                'round': int(m.group(1)),
                'proposer': int(m.group(2)),
                'counts': [int(m.group(3)), int(m.group(4)), int(m.group(5))],
            })
        runs.append({
            'repetition': rep,
            'exit_code': codes.get(rep),
            'complete': 'MARKER_SUSTAINED_TEST_COMPLETE=1' in text,
            'rounds': rows,
        })
    return runs


def parse_recovery():
    directory = root / 'recovery-canonical'
    codes = status(directory)
    names = [
        'V3_DEFAULT_STAGE_V1_CONTROL_ROUND42',
        'V3_POISONED_HONEST_ONE_ROUND42',
        'V3_POISONED_HONEST_TWO_ROUND42',
        'V3_RECOVERED_HONEST_ONE_ROUND43',
        'V3_RECOVERED_HONEST_TWO_ROUND43',
        'V3_TEST_COMPLETE',
    ]
    runs = []
    for rep in (1, 2, 3):
        text = (directory / f'run-{rep}.log').read_text(errors='replace')
        markers = {}
        for name in names:
            vals = re.findall(rf'MARKER_{name}=([0-9]+)', text)
            markers[name] = int(vals[-1]) if vals else None
        runs.append({'repetition': rep, 'exit_code': codes.get(rep), 'markers': markers})
    return runs

sustained = parse_sustained()
recovery = parse_recovery()


def canonical_ok(run):
    if run['exit_code'] != 0 or not run['complete'] or len(run['rounds']) != 12:
        return False
    for row in run['rounds']:
        expected = [1, 1, 1]
        expected[row['proposer']] = 0
        if row['counts'] != expected:
            return False
    return True

canonical_transport_pass = all(canonical_ok(run) for run in sustained)
recovery_pass = all(
    run['exit_code'] == 0
    and run['markers'].get('V3_DEFAULT_STAGE_V1_CONTROL_ROUND42') == 1
    and run['markers'].get('V3_POISONED_HONEST_ONE_ROUND42') == 1
    and run['markers'].get('V3_POISONED_HONEST_TWO_ROUND42') == 1
    and run['markers'].get('V3_RECOVERED_HONEST_ONE_ROUND43') == 1
    and run['markers'].get('V3_RECOVERED_HONEST_TWO_ROUND43') == 1
    and run['markers'].get('V3_TEST_COMPLETE') == 1
    for run in recovery
)
secp_status = int((root / 'secp-regression/exitcode').read_text().strip())
raptor_status = int((root / 'raptorcast-regression/exitcode').read_text().strip())
secp_pass = secp_status == 0
raptor_pass = raptor_status == 0

if canonical_transport_pass and recovery_pass and secp_pass and raptor_pass:
    decision = 'CANONICAL_HIGH_S_CONTROL_PASS_ALL_REGRESSIONS_CONSENSUS_GATE_MISSING'
elif not secp_pass:
    decision = 'CANONICALIZATION_SECP_REGRESSION_FAILURE'
elif not raptor_pass:
    decision = 'CANONICALIZATION_RAPTORCAST_REGRESSION_FAILURE'
else:
    decision = 'CANONICALIZATION_TRANSPORT_CONTROL_FAILURE'

result = {
    'decision': decision,
    'bft_commit': 'c616743d1358186605e1c1b74a3d6c4fdd9dd48c',
    'execution_commit': 'e81ffe31cd30fe3455d1233e4ee6c9b3f017bad0',
    'canonical_transport_pass': canonical_transport_pass,
    'canonical_recovery_pass': recovery_pass,
    'monad_secp_full_suite_pass': secp_pass,
    'monad_raptorcast_full_suite_pass': raptor_pass,
    'secp_exit_code': secp_status,
    'raptorcast_exit_code': raptor_status,
    'sustained_runs': sustained,
    'recovery_runs': recovery,
    'official_consensus_finality_halt': False,
    'submit_ready': False,
}
(root / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
(root / 'REPORT.md').write_text(f'''# Monad v0.16.0 canonical high-S control v2

## Decision

**{decision}**

- Canonical transport control: {canonical_transport_pass}
- Canonical recovery control: {recovery_pass}
- Full monad-secp suite: {secp_pass}
- Full monad-raptorcast suite: {raptor_pass}
- Official consensus/finality halt: false
- Submit-ready: false

The mitigation canonicalizes the high-S recoverable alias to low-S and flips the recovery
parity bit, preserving the authenticated signer while collapsing raw packet identity.
A High submission still requires an actual consensus/full-node finality A/B.
''')
manifest = []
for p in sorted(root.rglob('*')):
    if p.is_file() and p.name != 'SHA256SUMS':
        manifest.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root)}')
(root / 'SHA256SUMS').write_text('\n'.join(manifest) + '\n')
print(json.dumps(result, indent=2))
PY

cat "$EVIDENCE_DIR/RESULT.json"
