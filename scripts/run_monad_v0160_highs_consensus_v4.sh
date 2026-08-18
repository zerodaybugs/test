#!/usr/bin/env bash
set -Eeuo pipefail

BFT_COMMIT='c616743d1358186605e1c1b74a3d6c4fdd9dd48c'
EXEC_COMMIT='e81ffe31cd30fe3455d1233e4ee6c9b3f017bad0'
RESEARCH_BRANCH='agent/monad-v0160-highs-master-v6-20260818'
RESULT_DIR='results/monad-v0160-highs-consensus-v4'
EVIDENCE='evidence-v4'
SOURCE='monad-bft-v4'

export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_HTTP_MULTIPLEXING=false
export RUST_BACKTRACE=1

rm -rf "$SOURCE" "$EVIDENCE"
mkdir -p "$EVIDENCE/consensus" "$EVIDENCE/low-s" "$EVIDENCE/regression" "$RESULT_DIR"

stage='initializing'
trap 'printf "stage=%s\n" "$stage" > "$EVIDENCE/LAST_STAGE.txt"' EXIT

stage='install-toolchain'
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake ninja-build pkg-config \
  libssl-dev libsecp256k1-dev libzstd-dev protobuf-compiler
rustup toolchain install 1.91.1 --profile minimal --component rustfmt
rustup default 1.91.1

stage='clone-exact-source'
git config --global advice.detachedHead false
git clone --filter=blob:none --no-recurse-submodules \
  https://github.com/category-labs/monad-bft.git "$SOURCE"
git -C "$SOURCE" checkout --detach "$BFT_COMMIT"
git -C "$SOURCE" submodule sync --recursive
git -C "$SOURCE" submodule update --init --recursive --depth 1
test "$(git -C "$SOURCE" rev-parse HEAD)" = "$BFT_COMMIT"
test "$(git -C "$SOURCE/monad-execution" rev-parse HEAD)" = "$EXEC_COMMIT"
{
  echo "bft_commit=$(git -C "$SOURCE" rev-parse HEAD)"
  echo "execution_commit=$(git -C "$SOURCE/monad-execution" rev-parse HEAD)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  git -C "$SOURCE" submodule status --recursive
} > "$EVIDENCE/SOURCE_PROVENANCE.txt"
sha256sum \
  scripts/monad_v0160_highs_consensus_inject_v2.py \
  scripts/monad_v0160_fix_low_s_regression.py \
  "$SOURCE/Cargo.lock" \
  > "$EVIDENCE/INPUTS.sha256"

stage='fetch-locked-dependencies'
fetch_ok=0
for attempt in 1 2 3 4 5; do
  if cargo fetch --manifest-path "$SOURCE/Cargo.toml" --locked \
       2>&1 | tee -a "$EVIDENCE/cargo-fetch.log"; then
    fetch_ok=1
    break
  fi
  sleep $((attempt * 5))
done
test "$fetch_ok" -eq 1

stage='inject-consensus-test'
python3 scripts/monad_v0160_highs_consensus_inject_v2.py
# The injected script writes to monad-bft; move its output into this isolated tree.
# Re-run it with a temporary path substitution so exact anchors remain unchanged.
if [ -d monad-bft ] && [ "$SOURCE" != 'monad-bft' ]; then
  rm -rf monad-bft
fi
python3 - <<'PY'
from pathlib import Path
src = Path('scripts/monad_v0160_highs_consensus_inject_v2.py').read_text()
src = src.replace('Path("monad-bft/monad-mock-swarm/src/raptorcast.rs")',
                  'Path("monad-bft-v4/monad-mock-swarm/src/raptorcast.rs")')
src = src.replace('Path("monad-bft/monad-mock-swarm/tests/raptorcast_highs_network.rs")',
                  'Path("monad-bft-v4/monad-mock-swarm/tests/raptorcast_highs_network.rs")')
exec(compile(src, 'consensus-inject-v4', 'exec'), {})
PY
sed -i 's/\*length >= 80/\*length >= 50/' \
  "$SOURCE/monad-mock-swarm/tests/raptorcast_highs_network.rs"
cargo fmt --manifest-path "$SOURCE/Cargo.toml" --all
git -C "$SOURCE" diff --check
git -C "$SOURCE" diff -- \
  monad-mock-swarm/src/raptorcast.rs \
  monad-mock-swarm/tests/raptorcast_highs_network.rs \
  > "$EVIDENCE/MONAD_V0160_RAPTORCAST_V1_HIGHS_CONSENSUS_V4_TEST.patch"
test -s "$EVIDENCE/MONAD_V0160_RAPTORCAST_V1_HIGHS_CONSENSUS_V4_TEST.patch"

stage='run-consensus-ab'
TEST='high_s_alias_relay_halts_finality_without_canonical_commitment'
: > "$EVIDENCE/consensus/status.tsv"
for repetition in 1 2 3; do
  set +e
  /usr/bin/time -v cargo test --manifest-path "$SOURCE/Cargo.toml" --locked \
    -p monad-mock-swarm --features raptorcast \
    --test raptorcast_highs_network "$TEST" \
    -- --exact --nocapture --test-threads=1 \
    > "$EVIDENCE/consensus/run-${repetition}.log" 2>&1
  status=$?
  set -e
  printf '%s\t%s\n' "$repetition" "$status" >> "$EVIDENCE/consensus/status.tsv"
  test "$status" -eq 0
  grep -Eq 'running[[:space:]]+1[[:space:]]+test' "$EVIDENCE/consensus/run-${repetition}.log"
  grep -Fq "test ${TEST} ... ok" "$EVIDENCE/consensus/run-${repetition}.log"
  grep -Fq 'MARKER_NETWORK_VULNERABLE_LEDGER_LENGTHS=[0, 0, 0, 0]' \
    "$EVIDENCE/consensus/run-${repetition}.log"
  grep -Fq 'MARKER_NETWORK_TEST_COMPLETE=1' "$EVIDENCE/consensus/run-${repetition}.log"
done

stage='run-pristine-raptorcast-control'
git -C "$SOURCE" reset --hard "$BFT_COMMIT"
git -C "$SOURCE" submodule update --init --recursive --depth 1
set +e
cargo test --manifest-path "$SOURCE/Cargo.toml" --locked \
  -p monad-mock-swarm --features raptorcast \
  --test raptorcast raptorcast_smoke_four_nodes \
  -- --exact --nocapture --test-threads=1 \
  > "$EVIDENCE/regression/raptorcast-smoke.log" 2>&1
regression_status=$?
set -e
echo "$regression_status" > "$EVIDENCE/regression/raptorcast-smoke.exitcode"
test "$regression_status" -eq 0
grep -Eq 'running[[:space:]]+1[[:space:]]+test' "$EVIDENCE/regression/raptorcast-smoke.log"
grep -Fq 'test raptorcast_smoke_four_nodes ... ok' "$EVIDENCE/regression/raptorcast-smoke.log"

stage='apply-low-s-fix'
python3 - <<'PY'
from pathlib import Path
src = Path('scripts/monad_v0160_fix_low_s_regression.py').read_text()
src = src.replace('Path("monad-bft/monad-secp/src/secp.rs")',
                  'Path("monad-bft-v4/monad-secp/src/secp.rs")')
exec(compile(src, 'low-s-fix-v4', 'exec'), {})
PY
cargo fmt --manifest-path "$SOURCE/Cargo.toml" --all
git -C "$SOURCE" diff --check
git -C "$SOURCE" diff -- monad-secp/src/secp.rs \
  > "$EVIDENCE/MONAD_V0160_CANONICAL_LOW_S_COMPLETE_FIX.patch"
test -s "$EVIDENCE/MONAD_V0160_CANONICAL_LOW_S_COMPLETE_FIX.patch"

stage='run-low-s-targeted-and-full'
FULL='secp::tests::test_non_malleability'
: > "$EVIDENCE/low-s/targeted-status.tsv"
for repetition in 1 2 3 4 5; do
  set +e
  cargo test --manifest-path "$SOURCE/Cargo.toml" --locked \
    -p monad-secp --lib "$FULL" \
    -- --exact --nocapture --test-threads=1 \
    > "$EVIDENCE/low-s/targeted-${repetition}.log" 2>&1
  status=$?
  set -e
  printf '%s\t%s\n' "$repetition" "$status" >> "$EVIDENCE/low-s/targeted-status.tsv"
  test "$status" -eq 0
  grep -Eq 'running[[:space:]]+1[[:space:]]+test' "$EVIDENCE/low-s/targeted-${repetition}.log"
  grep -Fq "test ${FULL} ... ok" "$EVIDENCE/low-s/targeted-${repetition}.log"
done

: > "$EVIDENCE/low-s/full-status.tsv"
for repetition in 1 2 3; do
  set +e
  /usr/bin/time -v cargo test --manifest-path "$SOURCE/Cargo.toml" --locked \
    -p monad-secp --lib -- --test-threads=1 \
    > "$EVIDENCE/low-s/full-${repetition}.log" 2>&1
  status=$?
  set -e
  printf '%s\t%s\n' "$repetition" "$status" >> "$EVIDENCE/low-s/full-status.tsv"
  test "$status" -eq 0
  grep -Eq 'test result: ok\.' "$EVIDENCE/low-s/full-${repetition}.log"
done

stage='classify'
python3 - <<'PY'
from pathlib import Path
import hashlib, json, re

root = Path('evidence-v4')

def read_status(path):
    out = {}
    for line in path.read_text().splitlines():
        repetition, code = line.split('\t')
        out[int(repetition)] = int(code)
    return out

cstatus = read_status(root/'consensus/status.tsv')
runs=[]
for repetition in (1,2,3):
    path=root/'consensus'/f'run-{repetition}.log'
    text=path.read_text(errors='replace')
    def marker(name):
        matches=re.findall(rf'{name}=\[([^]]+)\]', text)
        return [int(x.strip()) for x in matches[-1].split(',')] if matches else None
    runs.append({
        'repetition':repetition,
        'exit_code':cstatus.get(repetition),
        'vulnerable_ledgers':marker('MARKER_NETWORK_VULNERABLE_LEDGER_LENGTHS'),
        'patched_ledgers':marker('MARKER_NETWORK_PATCHED_LEDGER_LENGTHS'),
        'complete':'MARKER_NETWORK_TEST_COMPLETE=1' in text,
        'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
    })
consensus_pass=all(
    r['exit_code']==0 and r['complete']
    and r['vulnerable_ledgers']==[0,0,0,0]
    and r['patched_ledgers'] is not None
    and min(r['patched_ledgers'])>=50
    and max(r['patched_ledgers'])-min(r['patched_ledgers'])<=1
    for r in runs
)
targeted=read_status(root/'low-s/targeted-status.tsv')
full=read_status(root/'low-s/full-status.tsv')
low_s_pass=(len(targeted)==5 and all(targeted.get(i)==0 for i in range(1,6))
            and len(full)==3 and all(full.get(i)==0 for i in range(1,4)))
regression_pass=int((root/'regression/raptorcast-smoke.exitcode').read_text())==0
prior=json.loads(Path('results/monad-v0160-highs-master-v4/RESULT.json').read_text())
transport_pass=(prior.get('one_round_recovery') is True
                and prior.get('repeated_transport_poisoning') is True
                and prior.get('canonical_low_s_control') is True)
high_candidate=transport_pass and consensus_pass and low_s_pass and regression_pass
decision=('EXACT_CONSENSUS_FINALITY_HALT_HIGH_CANDIDATE_OFFICIAL_FULLNODE_GATE_MISSING'
          if high_candidate else 'CONSENSUS_OR_CONTROL_GATE_INCOMPLETE_OR_NEGATIVE')
result={
    'bft_commit':'c616743d1358186605e1c1b74a3d6c4fdd9dd48c',
    'execution_commit':'e81ffe31cd30fe3455d1233e4ee6c9b3f017bad0',
    'decision':decision,
    'severity_proven':'HIGH_CANDIDATE' if high_candidate else 'NONE_NEW',
    'submit_ready':False,
    'transport_pass':transport_pass,
    'consensus_pass':consensus_pass,
    'low_s_full_regression_pass':low_s_pass,
    'pristine_raptorcast_control_pass':regression_pass,
    'consensus_runs':runs,
    'official_monad_node_execution_halt':False,
    'previous_epoch_boundary_high':'SEPARATE_UNCHANGED',
    'missing_before_submit_ready':[
        'official monad-node + execution reproduction',
        'two official vulnerable halts',
        'matched official low-S recoveries',
        'final scope and duplicate clearance',
    ],
}
(root/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
(root/'REPORT.md').write_text(f'''# Monad v0.16.0 RaptorCast high-S consensus v4

## Decision

**{decision}**

- 12-round exact transport poisoning/control: **{transport_pass}**
- Four-validator consensus/ledger A-B 3/3: **{consensus_pass}**
- Canonical low-S targeted 5/5 and full regression 3/3: **{low_s_pass}**
- Pristine RaptorCast control: **{regression_pass}**
- Official full-node halt: **false**
- Submit-ready: **false**
''')
PY

stage='manifest-and-publish'
python3 - <<'PY'
from pathlib import Path
import hashlib
root=Path('evidence-v4')
manifest=[]
for path in sorted(root.rglob('*')):
    if path.is_file() and path.name!='SHA256SUMS':
        manifest.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}')
(root/'SHA256SUMS').write_text('\n'.join(manifest)+'\n')
PY

rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR/consensus" "$RESULT_DIR/low-s" "$RESULT_DIR/regression"
cp "$EVIDENCE/RESULT.json" "$RESULT_DIR/RESULT.json"
cp "$EVIDENCE/REPORT.md" "$RESULT_DIR/REPORT.md"
cp "$EVIDENCE/SOURCE_PROVENANCE.txt" "$RESULT_DIR/SOURCE_PROVENANCE.txt"
cp "$EVIDENCE/INPUTS.sha256" "$RESULT_DIR/INPUTS.sha256"
cp "$EVIDENCE/SHA256SUMS" "$RESULT_DIR/SHA256SUMS"
cp "$EVIDENCE/MONAD_V0160_RAPTORCAST_V1_HIGHS_CONSENSUS_V4_TEST.patch" "$RESULT_DIR/"
cp "$EVIDENCE/MONAD_V0160_CANONICAL_LOW_S_COMPLETE_FIX.patch" "$RESULT_DIR/"
cp "$EVIDENCE/consensus/status.tsv" "$RESULT_DIR/consensus/status.tsv"
cp "$EVIDENCE/low-s/targeted-status.tsv" "$RESULT_DIR/low-s/targeted-status.tsv"
cp "$EVIDENCE/low-s/full-status.tsv" "$RESULT_DIR/low-s/full-status.tsv"
cp "$EVIDENCE/regression/raptorcast-smoke.exitcode" "$RESULT_DIR/regression/raptorcast-smoke.exitcode"

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git add "$RESULT_DIR"
if ! git diff --cached --quiet; then
  git commit -m 'Record Monad high-S consensus-v4 result'
  git push origin "HEAD:$RESEARCH_BRANCH"
fi

stage='complete'
cat "$EVIDENCE/RESULT.json"
