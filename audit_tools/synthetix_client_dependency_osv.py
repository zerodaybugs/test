#!/usr/bin/env python3
"""Read-only client dependency and OSV advisory inventory for Synthetix Exchange.

Downloads the current public frontend graph artifact, derives npm package names/versions from source-map
paths and package metadata, queries the public OSV API, and records advisory identifiers/severity only.
No Synthetix endpoint, wallet, account, signature, trade, or state is touched.
"""
from __future__ import annotations
import io,json,os,pathlib,re,time,urllib.request,zipfile
OUT=pathlib.Path('synthetix_client_dependency_osv');OUT.mkdir(parents=True,exist_ok=True)
REPO='zerodaybugs/test';ART=8660005480
PKG_PATH=re.compile(r'(?:^|/)node_modules/((?:@[^/]+/)?[^/]+)/')
VERSION_PATTERNS=[
 re.compile(r'([@\w./-]+)@([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)'),
 re.compile(r'"name"\s*:\s*"((?:@[^"/]+/)?[^"]+)"\s*,\s*"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"'),
]
ALLOW_HINTS={'react','react-dom','@sentry/browser','@sentry/react','posthog-js','@dynamic-labs/sdk-react-core','@dynamic-labs/wallet-connector-core','ethers','viem','wagmi','zod','axios','dompurify','marked','qrcode','jwt-decode','lodash','immer','zustand'}
def api_bytes(url,headers=None,data=None):
 req=urllib.request.Request(url,data=data,headers=headers or {},method='POST' if data is not None else 'GET')
 with urllib.request.urlopen(req,timeout=90) as r:return r.read(80*1024*1024)
def graph(token):
 raw=api_bytes(f'https://api.github.com/repos/{REPO}/actions/artifacts/{ART}/zip',{'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'synthetix-client-osv/1.0'})
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  return [(n,z.read(n)) for n in z.namelist() if n.lower().endswith(('.js','.mjs','.json','.map')) and z.getinfo(n).file_size<=10*1024*1024]
def derive(files):
 names=set();versions={}
 for n,b in files:
  text=b.decode('utf-8','ignore')
  if n.endswith('.map'):
   try:
    d=json.loads(text)
    for s in d.get('sources',[]) or []:
     m=PKG_PATH.search(s)
     if m:names.add(m.group(1))
   except Exception:pass
  for p in VERSION_PATTERNS:
   for m in p.finditer(text):
    pkg=m.group(1).strip();ver=m.group(2).strip()
    if len(pkg)<120 and len(ver)<80 and (pkg in names or pkg in ALLOW_HINTS or pkg.startswith('@')):versions.setdefault(pkg,set()).add(ver)
 return names,versions
def osv(pkg,ver):
 payload=json.dumps({'package':{'name':pkg,'ecosystem':'npm'},'version':ver}).encode()
 try:return json.loads(api_bytes('https://api.osv.dev/v1/query',{'Content-Type':'application/json','User-Agent':'synthetix-client-osv/1.0'},payload))
 except Exception as e:return {'error':f'{type(e).__name__}: {e}'}
def sev(v):
 vals=[]
 for s in v.get('severity',[]) or []:
  vals.append({'type':s.get('type'),'score':s.get('score')})
 return vals
def main():
 files=graph(os.environ['GITHUB_TOKEN']);names,versions=derive(files)
 # Query only exact versions actually recovered; cap network volume.
 pairs=sorted((p,v) for p,vs in versions.items() for v in vs)[:250]
 findings=[];errors=[]
 for i,(p,v) in enumerate(pairs):
  d=osv(p,v)
  if 'error' in d:errors.append({'package':p,'version':v,'error':d['error']})
  for adv in d.get('vulns',[]) or []:
   findings.append({'package':p,'version':v,'id':adv.get('id'),'aliases':adv.get('aliases',[])[:20],'summary':str(adv.get('summary',''))[:500],'severity':sev(adv),'modified':adv.get('modified'),'published':adv.get('published')})
  if i+1<len(pairs):time.sleep(.08)
 result={'frontendFiles':len(files),'sourceMapPackageNameCount':len(names),'exactVersionPairCount':len(pairs),'exactVersions':{p:sorted(vs) for p,vs in sorted(versions.items())},'advisoryCount':len(findings),'advisories':findings,'queryErrors':errors[:100],'gate':'REVIEW_ADVISORIES' if findings else 'NO_EXACT_VERSION_OSV_ADVISORIES'}
 (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
 print(json.dumps({'frontendFiles':len(files),'packageNames':len(names),'versionPairs':len(pairs),'advisoryCount':len(findings),'gate':result['gate']},indent=2))
if __name__=='__main__':main()
