#!/usr/bin/env bash
set -euo pipefail
OUT=synthetix_withdrawal_project_inventory
rm -rf "$OUT"
mkdir -p "$OUT"
{
  echo '# foundry files'
  find . -path './.git' -prune -o -name foundry.toml -print
  echo
  echo '# solidity files'
  find . -path './.git' -prune -o -type f -name '*.sol' -print | sort
  echo
  echo '# workflow files'
  find .github/workflows -type f -maxdepth 1 -print 2>/dev/null | sort || true
} > "$OUT/files.txt"

# Store public source coordinates and function signatures only; no private material.
grep -RInE --include='*.sol' 'function (create|validate|vote|disburse|finalize|cancel|expire|deposit|withdraw)|contract .*Test|Deposit|WithdrawalEntry|WithdrawalRequest' . \
  --exclude-dir=.git --exclude-dir=lib --exclude-dir=node_modules \
  | head -n 2000 > "$OUT/solidity-index.txt" || true

grep -RInE --include='*.yml' --include='*.yaml' --include='*.sh' 'forge|anvil|fork-url|RPC|withdrawal|synthetix' . \
  --exclude-dir=.git | head -n 2000 > "$OUT/runtime-index.txt" || true

python - <<'PY'
import hashlib, json, pathlib
out=pathlib.Path('synthetix_withdrawal_project_inventory')
records=[]
for p in sorted(out.glob('*.txt')):
    b=p.read_bytes()
    records.append({'file':p.name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'lines':len(b.splitlines())})
(out/'summary.json').write_text(json.dumps({'safety':'Public repository inventory only','records':records},indent=2),encoding='utf-8')
print(json.dumps(records,indent=2))
PY
