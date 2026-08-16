#!/usr/bin/env bash
set -euo pipefail

rm -rf repo export
mkdir -p export

git clone --filter=blob:none --no-tags https://github.com/microsoft/hcsshim.git repo
cd repo
git checkout c4bdd7c8b5acf04abb6ac990e29ecbb8416523f8
test "$(git rev-parse HEAD)" = 'c4bdd7c8b5acf04abb6ac990e29ecbb8416523f8'
go version | tee ../export/go-version.txt
git rev-parse HEAD | tee ../export/source-commit.txt

go test -mod=vendor ./internal/guest/bridge -count=1 -timeout=180s 2>&1 \
  | tee ../export/unmodified-full-bridge-tests.log
cd ..

python3 .github/scripts/zdb_patch_hcsshim_reconnect.py
cp .github/scripts/zdb_hcsshim_reconnect_fix_test.go \
  repo/internal/guest/bridge/zdb_reconnect_fix_test.go

cd repo
git diff -- internal/guest/bridge/bridge.go \
  internal/guest/bridge/zdb_reconnect_fix_test.go \
  > ../export/natural-fix-and-regression.patch
cp internal/guest/bridge/zdb_reconnect_fix_test.go ../export/

go test -mod=vendor ./internal/guest/bridge -count=1 -timeout=180s 2>&1 \
  | tee ../export/patched-full-bridge-tests.log

go test -mod=vendor ./internal/guest/bridge \
  -run '^TestZDBBridgeReconnectPreservesSequentialEpochBoundary$' \
  -count=20 -v -timeout=180s 2>&1 \
  | tee ../export/patched-fix-kill-stress.log

cd ..
grep -c 'ZDB_FIXED_CROSS_CONNECTION_OVERLAP_BLOCKED=true' \
  export/patched-fix-kill-stress.log | tee export/fixed-overlap-blocked-count.txt
grep -c 'ZDB_FIXED_OLD_RESPONSE_DROPPED=true' \
  export/patched-fix-kill-stress.log | tee export/fixed-stale-dropped-count.txt
grep -c 'ZDB_PATCHED_RECONNECT_EPOCH_INVARIANT=PASS' \
  export/patched-fix-kill-stress.log | tee export/fixed-pass-count.txt

test "$(cat export/fixed-overlap-blocked-count.txt)" -eq 20
test "$(cat export/fixed-stale-dropped-count.txt)" -eq 20
test "$(cat export/fixed-pass-count.txt)" -eq 20

python3 - <<'PY'
import json
from pathlib import Path
p = Path('export')
verdict = {
    'source_commit': 'c4bdd7c8b5acf04abb6ac990e29ecbb8416523f8',
    'unmodified_full_suite_pass': 'FAIL' not in (p/'unmodified-full-bridge-tests.log').read_text(errors='ignore'),
    'patched_full_suite_pass': 'FAIL' not in (p/'patched-full-bridge-tests.log').read_text(errors='ignore'),
    'fixed_overlap_blocked_runs': int((p/'fixed-overlap-blocked-count.txt').read_text().strip()),
    'fixed_stale_response_dropped_runs': int((p/'fixed-stale-dropped-count.txt').read_text().strip()),
    'fixed_invariant_pass_runs': int((p/'fixed-pass-count.txt').read_text().strip()),
}
verdict['decision'] = 'FIX_DIFFERENTIAL_PASS' if (
    verdict['unmodified_full_suite_pass'] and
    verdict['patched_full_suite_pass'] and
    verdict['fixed_overlap_blocked_runs'] == 20 and
    verdict['fixed_stale_response_dropped_runs'] == 20 and
    verdict['fixed_invariant_pass_runs'] == 20
) else 'FIX_DIFFERENTIAL_FAIL'
(p/'FIX_DIFFERENTIAL_VERDICT.json').write_text(json.dumps(verdict, indent=2) + '\n')
print(json.dumps(verdict, indent=2))
PY

sha256sum export/* > export/SHA256SUMS.txt
find export -maxdepth 1 -type f -printf '%f %s bytes\n' | sort > export/INVENTORY.txt
grep -q 'FIX_DIFFERENTIAL_PASS' export/FIX_DIFFERENTIAL_VERDICT.json
