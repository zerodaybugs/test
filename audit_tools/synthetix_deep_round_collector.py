#!/usr/bin/env python3
"""Poll and consolidate the current deeper Synthetix research artifacts."""
from __future__ import annotations
import io,json,os,pathlib,time,urllib.request,zipfile
OUT=pathlib.Path('synthetix_deep_round');OUT.mkdir(parents=True,exist_ok=True);E=OUT/'evidence';E.mkdir(exist_ok=True)
REPO='zerodaybugs/test'
NAMES=('synthetix-withdrawal-edge-fork','synthetix-sdk-security-drift','synthetix-frontend-release-diff')
def api(path,token,binary=False):
 req=urllib.request.Request('https://api.github.com'+path,headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'synthetix-deep-round/1.0'})
 with urllib.request.urlopen(req,timeout=90) as r:return r.read(80*1024*1024) if binary else json.load(r)
def latest(token):
 p=api(f'/repos/{REPO}/actions/artifacts?per_page=100',token);o={}
 for x in p.get('artifacts',[]):
  n=x.get('name')
  if n in NAMES and not x.get('expired') and (n not in o or x.get('created_at','')>o[n].get('created_at','')):o[n]=x
 return o
def summary(raw):
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  ns=[n for n in z.namelist() if n.endswith('summary.json')]
  if not ns:raise RuntimeError('summary missing')
  n=sorted(ns,key=lambda x:(x.count('/'),len(x)))[0];return n,json.loads(z.read(n))
def classify(n,d):
 if n=='synthetix-withdrawal-edge-fork':
  accepted=d.get('acceptedCases') or [];zero=d.get('zeroCostLockCandidates') or []
  gate='HOLD' if (accepted or zero) else 'KILL';reason='contract edge accepted; unprivileged backend reachability still required' if gate=='HOLD' else 'no tested contract edge accepted'
  metrics={'acceptedCases':accepted,'zeroCostLockCandidates':zero}
 elif n=='synthetix-sdk-security-drift':
  c=int(d.get('securityRelevantChangedLineCount') or 0);gate='REVIEW' if c else 'KILL';reason='post-release security-relevant SDK drift exists' if c else 'no security-relevant post-release drift';metrics={'changedLines':c,'commitCount':d.get('commitCount')}
 elif n=='synthetix-frontend-release-diff':
  a=len(d.get('newSecuritySensitiveTerms') or []);q=len(d.get('newQueryKeys') or []);s=len(d.get('newStorageKeys') or []);gate='REVIEW' if (a or q or s) else 'KILL';reason='new frontend surface requires targeted review' if gate=='REVIEW' else 'no new security-sensitive surface';metrics={'newTerms':a,'newQueryKeys':q,'newStorageKeys':s}
 else:gate='REVIEW';reason='unknown';metrics={}
 return {'name':n,'gate':gate,'reason':reason,'metrics':metrics,'reportedVerdict':d.get('verdict') or d.get('gate')}
def main():
 token=os.environ['GITHUB_TOKEN'];arts={}
 for i in range(60):
  arts=latest(token);missing=[n for n in NAMES if n not in arts];print(json.dumps({'poll':i+1,'found':sorted(arts),'missing':missing}))
  if not missing:break
  time.sleep(30)
 missing=[n for n in NAMES if n not in arts]
 results=[];prov=[]
 for n in NAMES:
  if n not in arts:
   results.append({'name':n,'gate':'PENDING','reason':'artifact not available before timeout','metrics':{}});continue
  x=arts[n];raw=api(f'/repos/{REPO}/actions/artifacts/{x["id"]}/zip',token,True);(E/f'{n}.zip').write_bytes(raw);sp,d=summary(raw);r=classify(n,d);r.update({'artifactId':x['id'],'artifactDigest':x.get('digest'),'summaryPath':sp});results.append(r);prov.append({'name':n,'id':x['id'],'digest':x.get('digest'),'createdAt':x.get('created_at')})
 overall='CANDIDATE' if any(r['gate']=='CANDIDATE' for r in results) else ('HOLD' if any(r['gate'] in ('HOLD','REVIEW','PENDING') for r in results) else 'NO_SUBMISSION')
 doc={'overallGate':overall,'classifications':results,'provenance':prov,'missingArtifacts':missing};(OUT/'round_summary.json').write_text(json.dumps(doc,indent=2,sort_keys=True),encoding='utf-8')
 lines=['# Synthetix Deep Research Round','',f'**Overall gate: {overall}**','']
 for r in results:lines += [f"## {r['name']}",'',f"- Gate: **{r['gate']}**",f"- Reason: {r['reason']}",f"- Metrics: `{json.dumps(r['metrics'],sort_keys=True)}`",'']
 (OUT/'ROUND_STATUS.md').write_text('\n'.join(lines),encoding='utf-8')
 zpath=OUT/'Synthetix_Deep_Research_Round_Result.zip'
 with zipfile.ZipFile(zpath,'w',zipfile.ZIP_DEFLATED) as z:
  for p in OUT.rglob('*'):
   if p.is_file() and p!=zpath:z.write(p,p.relative_to(OUT))
 print(json.dumps({'overallGate':overall,'results':results,'zipBytes':zpath.stat().st_size},indent=2))
if __name__=='__main__':main()
