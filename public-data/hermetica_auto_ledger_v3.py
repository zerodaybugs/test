import concurrent.futures as cf
import datetime as dt
import json
import pathlib
import re
import time
import urllib.parse
import urllib.request

OUT = pathlib.Path('/tmp/hermetica-auto-ledger-v3')
OUT.mkdir(parents=True, exist_ok=True)
API = 'https://api.hiro.so'
CONTRACT = 'SPN5AKG35QZSK2M8GAMR4AFX45659RJHDW353HSG.minting-auto-v1-2'
LIMIT = 50_000_000_000_000
RESET = 600
INITIAL_RESET = 1_757_221_858
BASES = {
    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token': 100_000_000,
    'SP120SBRBQJ00MCWS7TM5R8WJNTTKD5K0HFRC2CNE.usdcx': 1_000_000,
}


def get(url, attempts=15):
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'read-only-security-research/1.0',
                'Accept': 'application/json',
            })
            with urllib.request.urlopen(req, timeout=45) as response:
                return json.loads(response.read().decode())
        except Exception as exc:
            last = exc
            time.sleep(min(20, 1.2 * (i + 1)))
    raise RuntimeError(f'{url}: {last}')


def pages(url, max_rows=10000):
    rows, offset, limit = [], 0, 50
    while True:
        sep = '&' if '?' in url else '?'
        body = get(f'{url}{sep}{urllib.parse.urlencode({"limit": limit, "offset": offset})}')
        page = body.get('results') or []
        if not page:
            break
        rows.extend(page)
        total = body.get('total')
        if len(page) < limit or (total is not None and len(rows) >= int(total)):
            break
        offset += len(page)
        if offset > max_rows:
            raise RuntimeError(f'row cap exceeded for {url}')
    return rows


def parse_uint(text, key):
    match = re.search(rf'\({re.escape(key)} u(\d+)\)', text or '')
    return int(match.group(1)) if match else None


def parse_principal(text, key):
    match = re.search(rf'\({re.escape(key)} \'([^\s\)]+)\)', text or '')
    return match.group(1) if match else None


events = pages(f'{API}/extended/v1/contract/{urllib.parse.quote(CONTRACT, safe="")}/events')
txids = sorted({event.get('tx_id') for event in events if event.get('tx_id')})


def fetch_tx(txid):
    return txid, get(f'{API}/extended/v1/tx/{txid}')


txmap, failures = {}, []
with cf.ThreadPoolExecutor(max_workers=6) as executor:
    futures = {executor.submit(fetch_tx, txid): txid for txid in txids}
    for future in cf.as_completed(futures):
        txid = futures[future]
        try:
            key, value = future.result()
            txmap[key] = value
        except Exception as exc:
            failures.append({'tx_id': txid, 'error': str(exc)})
if failures:
    raise RuntimeError(f'transaction fetch failures: {failures[:5]} total={len(failures)}')

flows, admin = [], []
for event in events:
    log = event.get('contract_log') or {}
    if event.get('event_type') != 'smart_contract_log' or log.get('contract_id') != CONTRACT:
        continue
    rep = ((log.get('value') or {}).get('repr') or '')
    tx = txmap.get(event.get('tx_id')) or {}
    call = tx.get('contract_call') or {}
    common = {
        'tx_id': event.get('tx_id'),
        'block_height': int(tx.get('block_height') or 0),
        'tx_index': int(tx.get('tx_index') or 0),
        'event_index': int(event.get('event_index') or 0),
        'block_time': int(tx.get('block_time') or 0),
        'sender': tx.get('sender_address'),
        'top_level_contract': call.get('contract_id'),
        'top_level_function': call.get('function_name'),
        'repr': rep,
    }
    asset = parse_principal(rep, 'minting-asset')
    direction = 'mint'
    if not asset:
        asset = parse_principal(rep, 'redeeming-asset')
        direction = 'redeem'
    if asset:
        flows.append({
            **common,
            'direction': direction,
            'asset': asset,
            'amount_usdh': parse_uint(rep, 'amount-usdh-requested'),
            'amount_asset': parse_uint(rep, 'amount-asset-required'),
            'price': parse_uint(rep, 'price'),
            'price_conf': parse_uint(rep, 'price-conf'),
            'oracle_timestamp': parse_uint(rep, 'oracle-timestamp'),
            'slippage_in_price': parse_uint(rep, 'slippage-in-price'),
            'fee_amount': parse_uint(rep, 'fee-amount'),
        })
    elif 'old-value' in rep and 'new-value' in rep:
        admin.append({
            **common,
            'old_value': parse_uint(rep, 'old-value'),
            'new_value': parse_uint(rep, 'new-value'),
        })

flows.sort(key=lambda row: (row['block_height'], row['tx_index'], row['event_index']))
admin.sort(key=lambda row: (row['block_height'], row['tx_index'], row['event_index']))

# No configuration prints have occurred on this immutable deployment as of the
# capture date. Preserve them in evidence and fail closed if that assumption changes.
if admin:
    raise RuntimeError(f'unexpected admin events require explicit classification: {admin}')

current, last_reset, epochs, epoch = LIMIT, INITIAL_RESET, [], None
violations, reused, economics = [], {}, []
for row in flows:
    if row['direction'] == 'mint':
        timestamp, amount = row['oracle_timestamp'], row['amount_usdh']
        if timestamp is None or amount is None:
            violations.append({'type': 'missing_mint_fields', 'row': row})
            continue
        if timestamp >= last_reset + RESET:
            if epoch is not None:
                epochs.append(epoch)
            last_reset, current = timestamp, LIMIT
            epoch = {'reset_timestamp': timestamp, 'minted': 0, 'transactions': []}
        elif epoch is None:
            epoch = {'reset_timestamp': last_reset, 'minted': 0, 'transactions': []}
        if amount > current:
            violations.append({
                'type': 'successful_mint_exceeded_current_limit',
                'current_before': current,
                'row': row,
            })
        current -= amount
        epoch['minted'] += amount
        epoch['transactions'].append(row['tx_id'])
        if epoch['minted'] > LIMIT:
            violations.append({'type': 'epoch_above_limit', 'epoch': dict(epoch), 'row': row})
        reused.setdefault(str(timestamp), []).append(row['tx_id'])

    base = BASES.get(row['asset'])
    if base and row['price'] and row['amount_usdh'] is not None and row['amount_asset'] is not None:
        oracle_value = row['amount_asset'] * row['price'] // base
        economics.append({
            'tx_id': row['tx_id'],
            'direction': row['direction'],
            'asset': row['asset'],
            'amount_usdh': row['amount_usdh'],
            'amount_asset': row['amount_asset'],
            'price': row['price'],
            'oracle_value_usdh_base': oracle_value,
            'delta_base': oracle_value - row['amount_usdh'],
        })
if epoch is not None:
    epochs.append(epoch)

mint_econ = [row for row in economics if row['direction'] == 'mint']
redeem_econ = [row for row in economics if row['direction'] == 'redeem']
summary = {
    'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(),
    'source': 'Hiro public read-only APIs',
    'contract': CONTRACT,
    'event_count': len(events),
    'resolved_transaction_count': len(txmap),
    'parsed_flow_count': len(flows),
    'admin_event_count': len(admin),
    'mint_count': sum(row['direction'] == 'mint' for row in flows),
    'redeem_count': sum(row['direction'] == 'redeem' for row in flows),
    'simulated_current_mint_limit': current,
    'simulated_last_reset': last_reset,
    'epoch_count': len(epochs),
    'max_minted_per_epoch': max((row['minted'] for row in epochs), default=0),
    'max_epoch_utilization_bps': max(((row['minted'] * 10000) // LIMIT for row in epochs), default=0),
    'reused_oracle_timestamps': {key: value for key, value in reused.items() if len(value) > 1},
    'violation_count': len(violations),
    'violations': violations,
    'min_mint_delta_base': min((row['delta_base'] for row in mint_econ), default=None),
    'max_mint_delta_base': max((row['delta_base'] for row in mint_econ), default=None),
    'min_redeem_delta_base': min((row['delta_base'] for row in redeem_econ), default=None),
    'max_redeem_delta_base': max((row['delta_base'] for row in redeem_econ), default=None),
}
for name, obj in [
    ('events', events),
    ('transactions-by-id', txmap),
    ('flows', flows),
    ('admin-events', admin),
    ('epochs', epochs),
    ('economics', economics),
    ('summary', summary),
]:
    (OUT / f'{name}.json').write_text(json.dumps(obj, indent=2))
print(json.dumps(summary, indent=2))
