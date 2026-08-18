#!/usr/bin/env bash
set -euo pipefail

: "${CAST:?CAST required}"
: "${RPC_URL:?RPC_URL required}"
mkdir -p evidence
BLOCK="$($CAST block-number --rpc-url "$RPC_URL")"
{
  echo "chain_id=$($CAST chain-id --rpc-url "$RPC_URL")"
  echo "block=$BLOCK"
  echo "block_hash=$($CAST block "$BLOCK" --rpc-url "$RPC_URL" --field hash)"
  date -u '+timestamp_utc=%Y-%m-%dT%H:%M:%SZ'
} | tee evidence/environment.txt

RTOKEN=0xCc7FF230365bD730eE4B352cC2492CEdAC49383e
EXPECTED_MAIN=0xA582985c68ED30a052Ff0b07D74931140bd5a00F
EXPECTED_BASKET=0x9306587db04E35981e57013f6E1D867eCa89e2ec
EXPECTED_BM=0xA1E1A94977ec3159DB546bf01d7a8d17DD3EbBeD
EXPECTED_STRSR=0x796d2367AF69deB3319B8E10712b8B65957371c3
COLLATERAL=0x97F9d5ed17A0C99B279887caD5254d15fb1B619B
WRAPPER=0xDB5b8cead52f77De0f6B5255f73F348AAf2CBb8D
EXPECTED_POOL=0x7A034374C89C463DD65D8C9BCfe63BcBCED41f4F
EXPECTED_GAUGE=0x793F22aB88dC91793E5Ce6ADbd7E733B0BD4733e
AERO=0x940181a94A35A4569E4529A3CDfB74e38FD98631

: > evidence/calls.tsv
call() {
  key="$1"; address="$2"; sig="$3"; shift 3
  err=$(mktemp)
  set +e
  out=$($CAST call --rpc-url "$RPC_URL" --block "$BLOCK" "$address" "$sig" "$@" 2>"$err")
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    printf '%s\tPASS\t%s\n' "$key" "$(printf '%s' "$out" | tr '\n' ';')" | tee -a evidence/calls.tsv
  else
    printf '%s\tFAIL\t%s\n' "$key" "$(tr '\n' ';' < "$err")" | tee -a evidence/calls.tsv
  fi
  rm -f "$err"
}
value() { awk -F '\t' -v k="$1" '$1==k && $2=="PASS" {sub(/;$/, "", $3); print $3; exit}' evidence/calls.tsv; }
addr() { value "$1" | grep -Eo '0x[0-9a-fA-F]{40}' | head -1 | tr '[:upper:]' '[:lower:]'; }
lower() { tr '[:upper:]' '[:lower:]'; }

call rtoken_name "$RTOKEN" 'name()(string)'
call rtoken_symbol "$RTOKEN" 'symbol()(string)'
call rtoken_main "$RTOKEN" 'main()(address)'
call rtoken_supply "$RTOKEN" 'totalSupply()(uint256)'
call rtoken_baskets_needed "$RTOKEN" 'basketsNeeded()(uint192)'
call rtoken_issuance_available "$RTOKEN" 'issuanceAvailable()(uint256)'
call rtoken_redemption_available "$RTOKEN" 'redemptionAvailable()(uint256)'
MAIN=$(addr rtoken_main); test -n "$MAIN"

call main_basket "$MAIN" 'basketHandler()(address)'
call main_bm "$MAIN" 'backingManager()(address)'
call main_strsr "$MAIN" 'stRSR()(address)'
call main_rsr "$MAIN" 'rsr()(address)'
call main_issuance_paused "$MAIN" 'issuancePaused()(bool)'
call main_issuance_paused_or_frozen "$MAIN" 'issuancePausedOrFrozen()(bool)'
call main_trading_paused_or_frozen "$MAIN" 'tradingPausedOrFrozen()(bool)'
call main_frozen "$MAIN" 'frozen()(bool)'
BASKET=$(addr main_basket); BM=$(addr main_bm); STRSR=$(addr main_strsr)
test -n "$BASKET"; test -n "$BM"; test -n "$STRSR"

call basket_premium_enabled "$BASKET" 'enableIssuancePremium()(bool)'
call basket_nonce "$BASKET" 'nonce()(uint48)'
NONCE=$(value basket_nonce | grep -Eo '^[0-9]+' | head -1)
call basket_prime "$BASKET" 'getPrimeBasket()(address[],bytes32[],uint192[])'
call basket_history_u192 "$BASKET" 'getHistoricalBasket(uint48)(address[],uint192[])' "$NONCE"
call basket_history_u256 "$BASKET" 'getHistoricalBasket(uint48)(address[],uint256[])' "$NONCE"
call basket_quantity_wrapper "$BASKET" 'quantity(address)(uint192)' "$WRAPPER"
call basket_price_no_premium "$BASKET" 'price(bool)(uint192,uint192)' false
call basket_price_with_premium "$BASKET" 'price(bool)(uint192,uint192)' true
call basket_status "$BASKET" 'status()(uint8)'
call basket_ready "$BASKET" 'isReady()(bool)'
call basket_full "$BASKET" 'fullyCollateralized()(bool)'

call collateral_erc20 "$COLLATERAL" 'erc20()(address)'
call collateral_pool "$COLLATERAL" 'pool()(address)'
call collateral_status "$COLLATERAL" 'status()(uint8)'
call collateral_saved_peg "$COLLATERAL" 'savedPegPrice()(uint192)'
call collateral_target_per_ref "$COLLATERAL" 'targetPerRef()(uint192)'
call collateral_ref_per_tok "$COLLATERAL" 'refPerTok()(uint192)'
call collateral_price "$COLLATERAL" 'price()(uint192,uint192)'
call collateral_last_save "$COLLATERAL" 'lastSave()(uint48)'

call wrapper_underlying "$WRAPPER" 'underlying()(address)'
call wrapper_gauge "$WRAPPER" 'gauge()(address)'
call wrapper_reward "$WRAPPER" 'rewardToken()(address)'
call wrapper_supply "$WRAPPER" 'totalSupply()(uint256)'
call wrapper_bm_balance "$WRAPPER" 'balanceOf(address)(uint256)' "$BM"
call wrapper_strsr_balance "$WRAPPER" 'balanceOf(address)(uint256)' "$STRSR"
POOL=$(addr wrapper_underlying); GAUGE=$(addr wrapper_gauge)

call pool_token0 "$POOL" 'token0()(address)'
call pool_token1 "$POOL" 'token1()(address)'
call pool_stable "$POOL" 'stable()(bool)'
call pool_reserve0 "$POOL" 'reserve0()(uint256)'
call pool_reserve1 "$POOL" 'reserve1()(uint256)'
call pool_supply "$POOL" 'totalSupply()(uint256)'
call pool_wrapper_idle "$POOL" 'balanceOf(address)(uint256)' "$WRAPPER"
call gauge_staking "$GAUGE" 'stakingToken()(address)'
call gauge_reward "$GAUGE" 'rewardToken()(address)'
call gauge_wrapper_balance "$GAUGE" 'balanceOf(address)(uint256)' "$WRAPPER"
call gauge_wrapper_earned "$GAUGE" 'earned(address)(uint256)' "$WRAPPER"
call aero_wrapper_balance "$AERO" 'balanceOf(address)(uint256)' "$WRAPPER"

HIST="$(value basket_history_u192)$(value basket_history_u256)"; PRIME="$(value basket_prime)"
WRAP_LC=$(echo "$WRAPPER" | lower)
hist_member=false; prime_member=false
echo "$HIST" | tr '[:upper:]' '[:lower:]' | grep -q "$WRAP_LC" && hist_member=true
echo "$PRIME" | tr '[:upper:]' '[:lower:]' | grep -q "$WRAP_LC" && prime_member=true

graph_pass=true
[ "$MAIN" = "$(echo "$EXPECTED_MAIN" | lower)" ] || graph_pass=false
[ "$BASKET" = "$(echo "$EXPECTED_BASKET" | lower)" ] || graph_pass=false
[ "$BM" = "$(echo "$EXPECTED_BM" | lower)" ] || graph_pass=false
[ "$STRSR" = "$(echo "$EXPECTED_STRSR" | lower)" ] || graph_pass=false
[ "$(addr collateral_erc20)" = "$WRAP_LC" ] || graph_pass=false
[ "$(addr collateral_pool)" = "$(echo "$EXPECTED_POOL" | lower)" ] || graph_pass=false
[ "$POOL" = "$(echo "$EXPECTED_POOL" | lower)" ] || graph_pass=false
[ "$GAUGE" = "$(echo "$EXPECTED_GAUGE" | lower)" ] || graph_pass=false
[ "$(addr wrapper_reward)" = "$(echo "$AERO" | lower)" ] || graph_pass=false
[ "$(addr gauge_staking)" = "$(echo "$EXPECTED_POOL" | lower)" ] || graph_pass=false
[ "$(addr gauge_reward)" = "$(echo "$AERO" | lower)" ] || graph_pass=false
P0=$(value basket_price_no_premium); P1=$(value basket_price_with_premium)
price_differs=false; [ "$P0" != "$P1" ] && price_differs=true

{
  echo "graph_pass=$graph_pass"
  echo "historical_basket_contains_wrapper=$hist_member"
  echo "prime_basket_contains_wrapper=$prime_member"
  echo "premium_enabled=$(value basket_premium_enabled)"
  echo "price_without_premium=$P0"
  echo "price_with_premium=$P1"
  echo "premium_price_differs=$price_differs"
  echo "issuance_paused=$(value main_issuance_paused)"
  echo "issuance_paused_or_frozen=$(value main_issuance_paused_or_frozen)"
  echo "issuance_available=$(value rtoken_issuance_available)"
  echo "total_supply=$(value rtoken_supply)"
  echo "basket_status=$(value basket_status)"
  echo "basket_ready=$(value basket_ready)"
  echo "basket_fully_collateralized=$(value basket_full)"
  echo "collateral_status=$(value collateral_status)"
  echo "collateral_saved_peg=$(value collateral_saved_peg)"
  echo "collateral_target_per_ref=$(value collateral_target_per_ref)"
  echo "collateral_ref_per_tok=$(value collateral_ref_per_tok)"
  echo "basket_quantity_wrapper=$(value basket_quantity_wrapper)"
} | tee evidence/verdict.txt
