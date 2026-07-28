#!/usr/bin/env bash
# Public-chain reads only. This script never signs or broadcasts a transaction.
set +e

OUT=${1:-collected}
mkdir -p "$OUT"

MAIN_OFFICIAL='https://horizen.calderachain.xyz/http'
MAIN_THIRDWEB='https://26514.rpc.thirdweb.com'
TEST_OFFICIAL='https://horizen-testnet.rpc.caldera.xyz/http'

STAKER='0x6BF7CF29a8bcE11Aa62Cf593d165C244fA4d3E31'
ACC='0x06f5555fee73EDdc385b6d76FE00DB2D96ccDaE8'
TOKEN='0x57da2D504bf8b83Ef304759d9f2648522D7a9280'
DEPLOYER='0x9B264B21ca7659C256aD09171f827976Acd5a1C3'

MAIN_HASHES=(
  0x2f437f3e0a65a64d80bc5a9f1a3651568be4904a71c7df4c3bfd6fd2961b229c
  0xa15debdc97611ed00da57678cc641388186bf1ee4be4ffb9b78bf2c779a15e71
  0xe5f94f38dc4244a3117e722ebac81bdf002633e9466e26339f6f9c5bf4cca542
  0x80caea5cdf26182cc7faf4f9cd2afb2658e7340ac595f009838d1ab6cdb2e3d5
  0x41e2b719be2a130cb764d0d112fb0b2da8f8c87cf644204a1daeb3770fee046b
)
TEST_HASHES=(
  0x2a4fdaa0897d3e969657f606c14ec068aa73e081139a5e95e995ed23179107c3
  0x1efb9d7d1a4e5adca74556b8ac7a77db363b18a6712c7215a5fd0dd29adc5aea
  0x32ff16b230d7d6135b04a57fab8fca9bf22542b15563135ceb1874dc08982b08
  0xbacf4ffed00671d1fdfb967e43b9363539816254be793ef33aa17c8f493683a5
  0x2f70c562425cd6b7e7238ce7bb26818ef2045d4e993bb060d9a21cc1f144d16e
  0x8e08201ca0cf67bd01c1eaa89c103897585ab59ed81728ea878d9164729c5fff
)

rpc_json() {
  local url="$1" method="$2" params="$3"
  curl --silent --show-error --fail --max-time 30 \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" \
    "$url"
}

collect_calls() {
  local name="$1" url="$2"
  local out="$OUT/${name}-calls.log"
  {
    echo "endpoint=${url}"
    echo "chain_id=$(timeout 30 cast chain-id --rpc-url "$url" 2>&1)"
    echo "block=$(timeout 30 cast block-number --rpc-url "$url" 2>&1)"
    echo "staker_code_size=$(timeout 30 cast codesize "$STAKER" --rpc-url "$url" 2>&1)"
    echo "acc_code_size=$(timeout 30 cast codesize "$ACC" --rpc-url "$url" 2>&1)"
    echo "token_code_size=$(timeout 30 cast codesize "$TOKEN" --rpc-url "$url" 2>&1)"
    echo "admin=$(timeout 30 cast call "$STAKER" 'admin()(address)' --rpc-url "$url" 2>&1)"
    echo "acc_owner=$(timeout 30 cast call "$ACC" 'owner()(address)' --rpc-url "$url" 2>&1)"
    echo "acc_staker=$(timeout 30 cast call "$ACC" 'staker()(address)' --rpc-url "$url" 2>&1)"
    echo "acc_token=$(timeout 30 cast call "$ACC" 'rewardToken()(address)' --rpc-url "$url" 2>&1)"
    echo "acc_window=$(timeout 30 cast call "$ACC" 'timeWindow()(uint256)' --rpc-url "$url" 2>&1)"
    echo "acc_last=$(timeout 30 cast call "$ACC" 'lastRewardTime()(uint256)' --rpc-url "$url" 2>&1)"
    echo "acc_rewards=$(timeout 30 cast call "$ACC" 'accumulatedRewards()(uint256)' --rpc-url "$url" 2>&1)"
    echo "acc_whitelist=$(timeout 30 cast call "$ACC" 'whitelistEnabled()(bool)' --rpc-url "$url" 2>&1)"
    echo "notifier_acc=$(timeout 30 cast call "$STAKER" 'isRewardNotifier(address)(bool)' "$ACC" --rpc-url "$url" 2>&1)"
    echo "notifier_deployer=$(timeout 30 cast call "$STAKER" 'isRewardNotifier(address)(bool)' "$DEPLOYER" --rpc-url "$url" 2>&1)"
    echo "calculator=$(timeout 30 cast call "$STAKER" 'earningPowerCalculator()(address)' --rpc-url "$url" 2>&1)"
    echo "max_bump_tip=$(timeout 30 cast call "$STAKER" 'maxBumpTip()(uint256)' --rpc-url "$url" 2>&1)"
    echo "total_staked=$(timeout 30 cast call "$STAKER" 'totalStaked()(uint256)' --rpc-url "$url" 2>&1)"
    echo "total_power=$(timeout 30 cast call "$STAKER" 'totalEarningPower()(uint256)' --rpc-url "$url" 2>&1)"
    echo "reward_end=$(timeout 30 cast call "$STAKER" 'rewardEndTime()(uint256)' --rpc-url "$url" 2>&1)"
    echo "scaled_rate=$(timeout 30 cast call "$STAKER" 'scaledRewardRate()(uint256)' --rpc-url "$url" 2>&1)"
    echo "staker_token_balance=$(timeout 30 cast call "$TOKEN" 'balanceOf(address)(uint256)' "$STAKER" --rpc-url "$url" 2>&1)"
    echo "acc_token_balance=$(timeout 30 cast call "$TOKEN" 'balanceOf(address)(uint256)' "$ACC" --rpc-url "$url" 2>&1)"
    echo "deployer_nonce=$(timeout 30 cast nonce "$DEPLOYER" --rpc-url "$url" 2>&1)"
  } > "$out"

  timeout 45 cast logs --rpc-url "$url" --from-block 21317418 --to-block latest \
    --address "$ACC" 'OwnershipTransferred(address,address)' \
    > "$OUT/${name}-ownership-events.log" 2>&1

  timeout 45 cast logs --rpc-url "$url" --from-block 21317418 --to-block latest \
    --address "$STAKER" 'AdminSet(address,address)' \
    > "$OUT/${name}-admin-events.log" 2>&1

  timeout 30 cast code "$STAKER" --rpc-url "$url" > "$OUT/${name}-staker-code.hex" 2>&1
  timeout 30 cast code "$ACC" --rpc-url "$url" > "$OUT/${name}-acc-code.hex" 2>&1
}

collect_transactions() {
  local name="$1" url="$2" list_name="$3"
  local -n hashes="$list_name"
  : > "$OUT/${name}-transactions.jsonl"
  for h in "${hashes[@]}"; do
    rpc_json "$url" eth_getTransactionByHash "[\"${h}\"]" \
      | jq -c '.result | if . == null then {missing:true} else {hash,nonce,blockNumber,transactionIndex,from,to,type,chainId,v,r,s,input} end' \
      >> "$OUT/${name}-transactions.jsonl" 2>&1
  done
}

collect_calls main-official "$MAIN_OFFICIAL"
main_official_calls_rc=$?
collect_calls main-thirdweb "$MAIN_THIRDWEB"
main_thirdweb_calls_rc=$?
collect_transactions main-official "$MAIN_OFFICIAL" MAIN_HASHES
main_tx_rc=$?
collect_transactions test-official "$TEST_OFFICIAL" TEST_HASHES
test_tx_rc=$?

python3 - "$OUT" <<'PY' > "$OUT/signature-analysis.txt" 2>&1
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
rows = []
for network, path in [
    ('main', out / 'main-official-transactions.jsonl'),
    ('test', out / 'test-official-transactions.jsonl'),
]:
    if not path.exists():
        continue
    for line in path.read_text().splitlines():
        try:
            obj = json.loads(line)
        except Exception:
            continue
        obj['network'] = network
        rows.append(obj)

by_r = {}
for row in rows:
    r = row.get('r')
    if r:
        by_r.setdefault(r.lower(), []).append(row)

repeated = {r: xs for r, xs in by_r.items() if len(xs) > 1}
print(f'transactions_parsed={len(rows)}')
print(f'unique_r={len(by_r)}')
print(f'repeated_r_groups={len(repeated)}')
for r, xs in sorted(repeated.items()):
    print('r=' + r)
    for x in xs:
        print(f"  {x.get('network')} {x.get('hash')} nonce={x.get('nonce')} chainId={x.get('chainId')}")
PY

printf '%s\n' \
  "main_official_calls_rc=${main_official_calls_rc}" \
  "main_thirdweb_calls_rc=${main_thirdweb_calls_rc}" \
  "main_tx_rc=${main_tx_rc}" \
  "test_tx_rc=${test_tx_rc}" \
  > "$OUT/live-state-status.txt"
printf '%s\n' 'Read-only JSON-RPC and eth_call/log queries only; no transaction was signed or broadcast.' \
  > "$OUT/live-state-network-safety.txt"

exit 0
