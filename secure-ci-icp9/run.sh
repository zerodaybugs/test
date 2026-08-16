#!/usr/bin/env bash
set -euo pipefail
: "${SECURE_RESULT_DIR:?}"
WORK="$RUNNER_TEMP/icp9-work"
mkdir -p "$WORK" "$SECURE_RESULT_DIR"
exec > >(tee "$SECURE_RESULT_DIR/run.stdout.log") 2> >(tee "$SECURE_RESULT_DIR/run.stderr.log" >&2)

echo '[1/5] clone pinned repositories'
git clone --filter=blob:none --no-tags https://github.com/dfinity/ic.git "$WORK/ic"
git -C "$WORK/ic" checkout --detach eb55873567bcda6cdcf3c0a573d4db13daaa2c8e
git clone --filter=blob:none --no-tags https://github.com/dfinity/nns-dapp.git "$WORK/nns-dapp"
git -C "$WORK/nns-dapp" checkout --detach 95b2c526520e058c2adb125accab8b60016d1ee9

echo '[2/5] run security scan'
SCAN_ROOT="$WORK" python3 "$(dirname "$0")/scan.py" | tee "$SECURE_RESULT_DIR/SCAN_SUMMARY.json"

echo '[3/5] focused neighborhoods'
for spec in \
  minimum_incoming_canister_call_cycles \
  validate_status_visibility \
  validate_snapshot_visibility \
  ready_for_migration \
  CanisterHttpAsyncSpent \
  CanisterHttpInitialSpent \
  clean_canister \
  DestinationInvalid \
  set_exclusive_controller \
  module_hash_ref; do
  rg -n -C 22 --hidden -g '!target/**' -g '!node_modules/**' "$spec" "$WORK/ic" "$WORK/nns-dapp" \
    > "$SECURE_RESULT_DIR/FOCUS_${spec}.txt" || true
done

echo '[4/5] lightweight test gates'
set +e
(
  cd "$WORK/ic"
  timeout 1500 cargo test -p ic-wasm-types --lib --no-fail-fast
) > "$SECURE_RESULT_DIR/test_wasm_types.log" 2>&1
printf '%s\n' "$?" > "$SECURE_RESULT_DIR/test_wasm_types.exit"
(
  cd "$WORK/ic"
  timeout 1800 cargo test -p ic-replicated-state --lib --no-fail-fast
) > "$SECURE_RESULT_DIR/test_replicated_state.log" 2>&1
printf '%s\n' "$?" > "$SECURE_RESULT_DIR/test_replicated_state.exit"
set -e

echo '[5/5] manifest'
find "$SECURE_RESULT_DIR" -type f -print0 | sort -z | xargs -0 sha256sum > "$SECURE_RESULT_DIR/SHA256SUMS.txt"
echo ICP9_SCAN_COMPLETE
