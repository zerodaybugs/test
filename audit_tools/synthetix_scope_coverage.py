#!/usr/bin/env python3
"""Wait for the public Immunefi scope snapshot and compare it with the reviewed Synthetix surface."""
from __future__ import annotations

import io, json, os, pathlib, re, time, urllib.request, zipfile

OUT=pathlib.Path('synthetix_scope_coverage');OUT.mkdir(parents=True,exist_ok=True)
REPO='zerodaybugs/test';NAME='synthetix-current-scope-snapshot'
KNOWN_URL_PARTS=(
 'exchange.synthetix.io','synthetix.io','governance.synthetix.io',
 '0xD62595c3c23B690BAEE0935e107A209Cb1Dbd37B'.lower(),
 '0x99E61877aF9Bc6805BCc3813F655D94Ed5f3782A'.lower(),
 '0x45F91031b33Da2585932c8f1cdFF0faa6cD329ae'.lower(),
)

def api(path,token,binary=False):
 req=urllib.request.Request('https://api.github.com'+path,headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'synthetix-scope-coverage/1.0'})
 with urllib.request.urlopen(req,timeout=90) as r: return r.read(30*1024*1024) if binary else json.load(r)

def main():
 token=os.environ['GITHUB_TOKEN'];item=None
 for _ in range(40):
  payload=api(f'/repos/{REPO}/actions/artifacts?per_page=100',token)
  matches=[x for x in payload.get('artifacts',[]) if x.get('name')==NAME and not x.get('expired')]
  if matches:
   item=sorted(matches,key=lambda x:x.get('created_at',''))[-1];break
  time.sleep(20)
 if not item: raise RuntimeError('scope artifact not found')
 raw=api(f'/repos/{REPO}/actions/artifacts/{item["id"]}/zip',token,True)
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  names=[n for n in z.namelist() if n.endswith('summary.json')]
  if not names: raise RuntimeError('summary missing')
  data=json.loads(z.read(sorted(names,key=lambda n:(n.count('/'),len(n)))[0]))
 urls=data.get('allUrls',[]);addresses=data.get('allAddresses',[])
 relevant=[]
 for url in urls:
  low=url.lower()
  if any(x in low for x in ('github.com','etherscan.io','synthetix.io','immunefi.com')): relevant.append(url)
 scope_items=[]
 for value in relevant+addresses:
  low=value.lower();covered=any(part in low for part in KNOWN_URL_PARTS)
  scope_items.append({'value':value,'coveredByPriorResearch':covered})
 uncovered=[x for x in scope_items if not x['coveredByPriorResearch']]
 result={'artifactId':item['id'],'artifactDigest':item.get('digest'),'scopeItems':scope_items,'uncoveredItems':uncovered,'uncoveredCount':len(uncovered),'gate':'EXPAND_REVIEW' if uncovered else 'CURRENT_KNOWN_SURFACE_COVERED'}
 (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
 lines=['# Synthetix Current Scope Coverage','',f"**Gate: {result['gate']}**",'',f"Uncovered public scope-like items: {len(uncovered)}",'']
 for x in uncovered: lines.append(f"- `{x['value']}`")
 (OUT/'SCOPE_STATUS.md').write_text('\n'.join(lines),encoding='utf-8')
 with zipfile.ZipFile(OUT/'Synthetix_Current_Scope_Coverage.zip','w',zipfile.ZIP_DEFLATED) as a:
  for p in OUT.iterdir():
   if p.is_file() and p.suffix!='.zip': a.write(p,p.name)
 print(json.dumps({'gate':result['gate'],'uncoveredCount':len(uncovered)},indent=2))
if __name__=='__main__':main()
