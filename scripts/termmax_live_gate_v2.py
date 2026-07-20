#!/usr/bin/env python3
import json, os, subprocess, urllib.request
from pathlib import Path

ROUTER = '0x324596C1682a5675008f6e58F9C4E0A894b079c7'
ADAPTER = '0x8fE56ef6fD4f64dd2A0eB21FB634391890455f63'
WHITELIST = '0xB84f2a39b271D92586c61232a73ee1F7adFBf317'
EIP1967_IMPL_SLOT = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc'
TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
START_BLOCK = int(os.environ.get('SCAN_START_BLOCK', '24000000'))
OUT = Path(os.environ.get('OUT_DIR', 'evidence/live'))
OUT.mkdir(parents=True, exist_ok=True)
ENDPOINTS = [x for x in os.environ.get('RPC_CANDIDATES', '').split() if x] or [
    'https://ethereum-rpc.publicnode.com',
    'https://eth.llamarpc.com',
    'https://1rpc.io/eth',
    'https://eth.drpc.org',
    'https://cloudflare-eth.com',
]
raw = {'endpointTests': [], 'rpc': []}
request_id = 0

def rpc_url(url, method, params, timeout=45):
    global request_id
    request_id += 1
    body = json.dumps({'jsonrpc':'2.0','id':request_id,'method':method,'params':params}).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type':'application/json','User-Agent':'termmax-security-readonly/2.0'})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        obj = json.loads(response.read().decode())
    raw['rpc'].append({'endpoint':url,'method':method,'params':params,'response':obj})
    if 'error' in obj:
        raise RuntimeError(f"{method}: {obj['error']}")
    return obj['result']

def choose_endpoint():
    for url in ENDPOINTS:
        try:
            chain = rpc_url(url, 'eth_chainId', [])
            latest = rpc_url(url, 'eth_blockNumber', [])
            ok = int(chain, 16) == 1
            raw['endpointTests'].append({'url':url,'chainId':chain,'latest':latest,'ok':ok})
            if ok:
                return url, int(latest, 16)
        except Exception as exc:
            raw['endpointTests'].append({'url':url,'ok':False,'error':repr(exc)})
    raise RuntimeError('No working Ethereum RPC endpoint')

def cast_sig(signature):
    return subprocess.check_output(['cast','sig',signature], text=True).strip()

def calldata(signature, *args):
    return subprocess.check_output(['cast','calldata',signature,*map(str,args)], text=True).strip()

def eth_call(url, to, data, block_hex):
    return rpc_url(url, 'eth_call', [{'to':to,'data':data}, block_hex])

def decode_address(word):
    return '0x' + word[-40:]

def decode_bool(word):
    return int(word or '0x0', 16) != 0

def decode_uint(word):
    return int(word or '0x0', 16)

def decode_string(data):
    if not data or data == '0x':
        return None
    blob = bytes.fromhex(data[2:])
    try:
        if len(blob) >= 64:
            offset = int.from_bytes(blob[:32], 'big')
            if offset + 32 <= len(blob):
                length = int.from_bytes(blob[offset:offset+32], 'big')
                return blob[offset+32:offset+32+length].decode('utf-8','replace').strip('\x00')
        return blob[:32].rstrip(b'\x00').decode('utf-8','replace')
    except Exception:
        return None

def padded_topic(address):
    return '0x' + address.lower().replace('0x','').rjust(64,'0')

def get_logs_adaptive(url, from_block, to_block, topics, label):
    logs, progress = [], []
    current, span, minimum_span = from_block, 50000, 50
    while current <= to_block:
        end = min(current + span - 1, to_block)
        filter_ = {'fromBlock':hex(current),'toBlock':hex(end),'topics':topics}
        try:
            part = rpc_url(url, 'eth_getLogs', [filter_], timeout=90)
            logs.extend(part)
            progress.append({'from':current,'to':end,'count':len(part),'span':span})
            current = end + 1
            if len(part) < 200 and span < 100000:
                span = min(span * 2, 100000)
        except Exception as exc:
            progress.append({'from':current,'to':end,'error':repr(exc),'span':span})
            if span <= minimum_span:
                raise
            span = max(span // 2, minimum_span)
        if len(progress) % 20 == 0:
            (OUT / f'{label}_progress.json').write_text(json.dumps(progress, indent=2))
    (OUT / f'{label}_progress.json').write_text(json.dumps(progress, indent=2))
    return logs

url, latest = choose_endpoint()
block_hex = hex(latest)
block = rpc_url(url, 'eth_getBlockByNumber', [block_hex, False])
block_hash = block['hash']
router_code = rpc_url(url, 'eth_getCode', [ROUTER, block_hex])
adapter_code = rpc_url(url, 'eth_getCode', [ADAPTER, block_hex])
whitelist_code = rpc_url(url, 'eth_getCode', [WHITELIST, block_hex])
impl_slot = rpc_url(url, 'eth_getStorageAt', [ROUTER, EIP1967_IMPL_SLOT, block_hex])
implementation = decode_address(impl_slot)
impl_code = rpc_url(url, 'eth_getCode', [implementation, block_hex])

calls = {}
for name, to, data in [
    ('adapterWhitelisted', WHITELIST, calldata('isWhitelisted(address,uint8)', ADAPTER, 0)),
    ('routerWhitelistManager', ROUTER, calldata('whitelistManager()')),
    ('routerDefaultWhitelistModule', ROUTER, calldata('defaultWhitelistModule()')),
    ('routerOwner', ROUTER, calldata('owner()')),
    ('routerPaused', ROUTER, calldata('paused()')),
]:
    try:
        calls[name] = eth_call(url, to, data, block_hex)
    except Exception as exc:
        calls[name] = {'error':repr(exc)}

router_topic = padded_topic(ROUTER)
in_logs = get_logs_adaptive(url, START_BLOCK, latest, [TRANSFER_TOPIC, None, router_topic], 'inbound')
out_logs = get_logs_adaptive(url, START_BLOCK, latest, [TRANSFER_TOPIC, router_topic], 'outbound')
(OUT / 'TRANSFER_LOGS_IN.json').write_text(json.dumps(in_logs, indent=2))
(OUT / 'TRANSFER_LOGS_OUT.json').write_text(json.dumps(out_logs, indent=2))

tokens = {log['address'].lower() for log in in_logs + out_logs}
tokens.update(address.lower() for address in [
    '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
    '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    '0x6B175474E89094C44Da98b954EedeAC495271d0F',
    '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
    '0x4c9EDD5852cd905f086C759E8383e09bff1E68B3',
    '0x9D39A5DE30e57443BfF2A8307A4256c8797A3497',
])

holdings = []
for token in sorted(tokens):
    try:
        balance = decode_uint(eth_call(url, token, '0x70a08231' + ROUTER.lower().replace('0x','').rjust(64,'0'), block_hex))
    except Exception:
        continue
    if balance <= 0:
        continue
    try:
        decimals = decode_uint(eth_call(url, token, cast_sig('decimals()'), block_hex))
    except Exception:
        decimals = None
    try:
        symbol = decode_string(eth_call(url, token, cast_sig('symbol()'), block_hex))
    except Exception:
        symbol = None
    try:
        name = decode_string(eth_call(url, token, cast_sig('name()'), block_hex))
    except Exception:
        name = None
    holdings.append({'token':token,'balance':str(balance),'decimals':decimals,'symbol':symbol,'name':name})

summary = {
    'endpoint':url,
    'snapshotBlock':latest,
    'snapshotBlockHex':block_hex,
    'snapshotBlockHash':block_hash,
    'scanStartBlock':START_BLOCK,
    'addresses':{'router':ROUTER,'adapter':ADAPTER,'whitelistManager':WHITELIST,'implementation':implementation},
    'codeBytes':{
        'routerProxy':max((len(router_code)-2)//2,0),
        'routerImplementation':max((len(impl_code)-2)//2,0),
        'adapter':max((len(adapter_code)-2)//2,0),
        'whitelistManager':max((len(whitelist_code)-2)//2,0),
    },
    'rawCalls':calls,
    'adapterWhitelisted':decode_bool(calls['adapterWhitelisted']) if isinstance(calls['adapterWhitelisted'],str) else None,
    'routerWhitelistManager':decode_address(calls['routerWhitelistManager']) if isinstance(calls['routerWhitelistManager'],str) else None,
    'routerDefaultWhitelistModule':decode_uint(calls['routerDefaultWhitelistModule']) if isinstance(calls['routerDefaultWhitelistModule'],str) else None,
    'routerOwner':decode_address(calls['routerOwner']) if isinstance(calls['routerOwner'],str) else None,
    'routerPaused':decode_bool(calls['routerPaused']) if isinstance(calls['routerPaused'],str) else None,
    'inboundTransferLogs':len(in_logs),
    'outboundTransferLogs':len(out_logs),
    'uniqueTokenContracts':len(tokens),
    'positiveHoldings':holdings,
    'positiveHoldingCount':len(holdings),
}
(OUT / 'SUMMARY.json').write_text(json.dumps(summary, indent=2))
(OUT / 'RPC_RAW.json').write_text(json.dumps(raw, indent=2))
print(json.dumps(summary, indent=2))
