#!/usr/bin/env python3
import json, os, re, time, urllib.parse, urllib.request
from pathlib import Path
ROUTER='0x324596C1682a5675008f6e58F9C4E0A894b079c7'
OUT=Path(os.environ.get('OUT_DIR','evidence/inventory'));OUT.mkdir(parents=True,exist_ok=True)
RPC=os.environ.get('ETH_RPC_URL','https://ethereum-rpc.publicnode.com')
rid=0; raw={}
def post(method,params):
 global rid; rid+=1
 req=urllib.request.Request(RPC,data=json.dumps({'jsonrpc':'2.0','id':rid,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json','User-Agent':'termmax-inventory/1.0'})
 with urllib.request.urlopen(req,timeout=60) as r: obj=json.loads(r.read().decode())
 if 'error' in obj: raise RuntimeError(obj['error'])
 return obj['result']
def get(url):
 req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 termmax-security-research','Accept':'application/json,text/html'})
 with urllib.request.urlopen(req,timeout=60) as r: return r.read().decode(errors='replace')
def query_api(base,params,label):
 url=base+'?'+urllib.parse.urlencode(params)
 try:
  text=get(url); obj=json.loads(text); raw[label]={'url':url,'response':obj}; return obj
 except Exception as e: raw[label]={'url':url,'error':repr(e)}; return None
latest=int(post('eth_blockNumber',[]),16); block=hex(latest); block_obj=post('eth_getBlockByNumber',[block,False])
tokens=set(); pages=[]
base='https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api'
obj=query_api(base,{'module':'account','action':'addresstokenbalance','address':ROUTER,'page':1,'offset':1000},'routescan_addresstokenbalance')
if obj and isinstance(obj.get('result'),list):
 for x in obj['result']:
  for k in ('TokenAddress','tokenAddress','contractAddress','address'):
   if isinstance(x.get(k),str) and re.fullmatch(r'0x[a-fA-F0-9]{40}',x[k]): tokens.add(x[k].lower())
for page in range(1,101):
 obj=query_api(base,{'module':'account','action':'tokentx','address':ROUTER,'startblock':0,'endblock':99999999,'page':page,'offset':100,'sort':'asc'},f'routescan_tokentx_{page}')
 if not obj or not isinstance(obj.get('result'),list): break
 items=obj['result']; pages.extend(items)
 for x in items:
  for k in ('contractAddress','tokenAddress','TokenAddress','address'):
   if isinstance(x.get(k),str) and re.fullmatch(r'0x[a-fA-F0-9]{40}',x[k]): tokens.add(x[k].lower())
 if len(items)<100: break
 time.sleep(.25)
try:
 obj=json.loads(get(f'https://api.ethplorer.io/getAddressInfo/{ROUTER}?apiKey=freekey'))
 raw['ethplorer']=obj
 for x in obj.get('tokens') or []:
  address=((x.get('tokenInfo') or {}).get('address'))
  if isinstance(address,str) and re.fullmatch(r'0x[a-fA-F0-9]{40}',address): tokens.add(address.lower())
except Exception as e: raw['ethplorer']={'error':repr(e)}
for label,url in [('etherscan_address',f'https://etherscan.io/address/{ROUTER}'),('etherscan_holdings',f'https://etherscan.io/tokenholdings?a={ROUTER}')]:
 try:
  text=get(url); raw[label]={'length':len(text),'sha256':__import__('hashlib').sha256(text.encode()).hexdigest()}
  for address in re.findall(r'0x[a-fA-F0-9]{40}',text): tokens.add(address.lower())
 except Exception as e: raw[label]={'error':repr(e)}
tokens.update(x.lower() for x in ['0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2','0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48','0xdAC17F958D2ee523a2206206994597C13D831ec7','0x6B175474E89094C44Da98b954EedeAC495271d0F','0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599','0x4c9EDD5852cd905f086C759E8383e09bff1E68B3','0x9D39A5DE30e57443BfF2A8307A4256c8797A3497'])
def call(token,data): return post('eth_call',[{'to':token,'data':data},block])
def uint(value): return int(value or '0x0',16)
def decstr(data):
 try:
  blob=bytes.fromhex(data[2:]); offset=int.from_bytes(blob[:32],'big')
  if len(blob)>=64 and offset+32<=len(blob):
   length=int.from_bytes(blob[offset:offset+32],'big');return blob[offset+32:offset+32+length].decode(errors='replace').strip('\x00')
  return blob[:32].rstrip(b'\0').decode(errors='replace')
 except Exception: return None
holdings=[]
for token in sorted(tokens):
 try: balance=uint(call(token,'0x70a08231'+ROUTER.lower()[2:].rjust(64,'0')))
 except Exception: continue
 if balance<=0: continue
 try: decimals=uint(call(token,'0x313ce567'))
 except Exception: decimals=None
 try: symbol=decstr(call(token,'0x95d89b41'))
 except Exception: symbol=None
 try: name=decstr(call(token,'0x06fdde03'))
 except Exception: name=None
 holdings.append({'token':token,'balance':str(balance),'decimals':decimals,'symbol':symbol,'name':name,'normalized':(balance/(10**decimals) if decimals is not None and decimals<80 else None)})
holdings.sort(key=lambda x:x.get('normalized') or 0,reverse=True)
summary={'rpc':RPC,'snapshotBlock':latest,'snapshotBlockHash':block_obj['hash'],'candidateTokenCount':len(tokens),'routescanTransferCount':len(pages),'positiveHoldingCount':len(holdings),'positiveHoldings':holdings}
(OUT/'SUMMARY.json').write_text(json.dumps(summary,indent=2));(OUT/'RAW.json').write_text(json.dumps(raw,indent=2));(OUT/'TOKEN_ADDRESSES.json').write_text(json.dumps(sorted(tokens),indent=2));print(json.dumps(summary,indent=2))
