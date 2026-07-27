#!/usr/bin/env python3
"""Read-only security-surface diff between the prior reviewed Exchange entry and current frontend graph."""
from __future__ import annotations
import hashlib,io,json,os,pathlib,re,urllib.parse,urllib.request,zipfile
OUT=pathlib.Path('synthetix_frontend_release_diff');OUT.mkdir(parents=True,exist_ok=True)
REPO='zerodaybugs/test';CURRENT_ARTIFACT=8660005480
OLD_CANDIDATES=(
 'https://exchange.synthetix.io/index-BJrW6h18.js',
 'https://exchange.synthetix.io/assets/index-BJrW6h18.js',
 '/index-BJrW6h18.js',
)
TERM=re.compile(r'(?:/api/[A-Za-z0-9_./?=&:-]+|wss?://[^"\'`\s]+|https?://[^"\'`\s]+|[A-Za-z][A-Za-z0-9_]{2,}(?:Order|Orders|Collateral|Signer|Session|Withdrawal|Leverage|Subaccount|SubAccount|Referral|Auth|Wallet|Delegate|Delegated)[A-Za-z0-9_]*)')
QUERY=re.compile(r'(?:searchParams|URLSearchParams\([^)]*\))\.(?:get|has)\(\s*["\']([^"\']+)["\']')
STORAGE=re.compile(r'(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(\s*["\']([^"\']+)["\']')
SENSITIVE=re.compile(r'auth|sign|private|session|delegate|withdraw|transfer|order|cancel|wallet|sub.?account|referral|leverage|api|websocket|postmessage|innerhtml|redirect',re.I)
def sha(b): return hashlib.sha256(b if isinstance(b,bytes) else b.encode()).hexdigest()
def req(url,token=None):
 h={'User-Agent':'synthetix-authorized-release-diff/1.0','Accept':'*/*'}
 if token:h.update({'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
 with urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=90) as r:return r.status,r.read(50*1024*1024),r.url

def current_texts(token):
 _,raw,_=req(f'https://api.github.com/repos/{REPO}/actions/artifacts/{CURRENT_ARTIFACT}/zip',token)
 texts=[]
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  for n in z.namelist():
   if not n.lower().endswith(('.js','.mjs','.json','.map','.html')):continue
   try:b=z.read(n)
   except Exception:continue
   if len(b)<=8*1024*1024:texts.append((n,b.decode('utf-8','ignore')))
 return texts

def old_text():
 errors=[]
 for c in OLD_CANDIDATES[:2]:
  try:
   st,b,u=req(c)
   if st==200 and len(b)>1000:return u,b.decode('utf-8','ignore'),sha(b)
  except Exception as e:errors.append(f'{c}: {type(e).__name__}')
 raise RuntimeError('old entry unavailable: '+', '.join(errors))

def extract(texts):
 terms=set();queries=set();storage=set();sink_counts={}
 for _,text in texts:
  terms.update(x.rstrip('),]}')[:300] for x in TERM.findall(text))
  queries.update(QUERY.findall(text));storage.update(STORAGE.findall(text))
  for k,p in {'innerHTML':r'innerHTML','insertAdjacentHTML':r'insertAdjacentHTML','postMessage':r'postMessage','eval':r'\beval\(','Function':r'\bFunction\('}.items():sink_counts[k]=sink_counts.get(k,0)+len(re.findall(p,text))
 return {'terms':sorted(terms),'queryKeys':sorted(queries),'storageKeys':sorted(storage),'sinkCounts':sink_counts}

def main():
 token=os.environ['GITHUB_TOKEN'];url,old,oldhash=old_text();current=current_texts(token)
 a=extract([('old',old)]);b=extract(current)
 new_terms=sorted(set(b['terms'])-set(a['terms']));new_queries=sorted(set(b['queryKeys'])-set(a['queryKeys']));new_storage=sorted(set(b['storageKeys'])-set(a['storageKeys']))
 security=[x for x in new_terms if SENSITIVE.search(x)]
 result={'oldUrl':url,'oldSha256':oldhash,'currentFileCount':len(current),'old':a,'currentSummary':{'termCount':len(b['terms']),'queryKeyCount':len(b['queryKeys']),'storageKeyCount':len(b['storageKeys']),'sinkCounts':b['sinkCounts']},'newSecuritySensitiveTerms':security[:1000],'newQueryKeys':new_queries[:500],'newStorageKeys':new_storage[:500],'gate':'TARGET_NEW_SURFACE' if (security or new_queries or new_storage) else 'NO_NEW_SECURITY_SURFACE'}
 (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
 print(json.dumps({'oldUrl':url,'currentFileCount':len(current),'newSecuritySensitiveTermCount':len(security),'newQueryKeyCount':len(new_queries),'newStorageKeyCount':len(new_storage),'gate':result['gate']},indent=2))
if __name__=='__main__':main()
