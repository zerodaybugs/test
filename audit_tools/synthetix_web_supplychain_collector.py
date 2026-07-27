#!/usr/bin/env python3
"""Poll and consolidate Synthetix frameability, client advisory, and secret-pattern artifacts."""
from __future__ import annotations
import io,json,os,pathlib,time,urllib.request,zipfile
OUT=pathlib.Path('synthetix_web_supplychain_round');OUT.mkdir(parents=True,exist_ok=True);E=OUT/'evidence';E.mkdir(exist_ok=True)
REPO='zerodaybugs/test';NAMES=('synthetix-frameability-probe','synthetix-client-dependency-osv','synthetix-frontend-secret-scan')
def api(path,t,b=False):
 req=urllib.request.Request('https://api.github.com'+path,headers={'Authorization':f'Bearer {t}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'synthetix-web-supplychain/1.0'})
 with urllib.request.urlopen(req,timeout=90) as r:return r.read(80*1024*1024) if b else json.load(r)
def latest(t):
 p=api(f'/repos/{REPO}/actions/artifacts?per_page=100',t);o={}
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
 if n=='synthetix-frameability-probe':
  frame=bool(d.get('targetFrameCount')) and bool(d.get('targetRendered'));gate='HOLD' if frame else 'KILL';reason='Exchange renders cross-origin; session-clickjacking chain requires proof' if frame else 'frame blocked or not rendered';m={'targetFrameCount':d.get('targetFrameCount'),'targetRendered':d.get('targetRendered'),'reported':d.get('verdict')}
 elif n=='synthetix-client-dependency-osv':
  c=int(d.get('advisoryCount') or 0);gate='REVIEW' if c else 'KILL';reason='exact-version advisories require reachability and scope review' if c else 'no exact-version OSV advisory';m={'advisoryCount':c,'versionPairs':d.get('exactVersionPairCount')}
 elif n=='synthetix-frontend-secret-scan':
  c=int(d.get('highConfidenceNonPublicContextCount') or 0);gate='CANDIDATE' if c else 'KILL';reason='private credential-shaped material requires immediate validation' if c else 'no high-confidence private secret pattern';m={'highConfidenceCandidates':c,'candidateCount':d.get('candidateCount')}
 else:gate='REVIEW';reason='unknown';m={}
 return {'name':n,'gate':gate,'reason':reason,'metrics':m,'reportedVerdict':d.get('verdict') or d.get('gate')}
def main():
 t=os.environ['GITHUB_TOKEN'];arts={}
 for i in range(60):
  arts=latest(t);miss=[n for n in NAMES if n not in arts];print(json.dumps({'poll':i+1,'found':sorted(arts),'missing':miss}))
  if not miss:break
  time.sleep(30)
 results=[];prov=[]
 for n in NAMES:
  if n not in arts:results.append({'name':n,'gate':'PENDING','reason':'artifact unavailable','metrics':{}});continue
  x=arts[n];raw=api(f'/repos/{REPO}/actions/artifacts/{x["id"]}/zip',t,True);(E/f'{n}.zip').write_bytes(raw);sp,d=summary(raw);r=classify(n,d);r.update({'artifactId':x['id'],'artifactDigest':x.get('digest'),'summaryPath':sp});results.append(r);prov.append({'name':n,'id':x['id'],'digest':x.get('digest')})
 overall='CANDIDATE' if any(r['gate']=='CANDIDATE' for r in results) else ('HOLD' if any(r['gate'] in ('HOLD','REVIEW','PENDING') for r in results) else 'NO_SUBMISSION')
 doc={'overallGate':overall,'classifications':results,'provenance':prov};(OUT/'round_summary.json').write_text(json.dumps(doc,indent=2,sort_keys=True),encoding='utf-8')
 lines=['# Synthetix Web and Supply-Chain Round','',f'**Overall gate: {overall}**','']
 for r in results:lines += [f"## {r['name']}",'',f"- Gate: **{r['gate']}**",f"- Reason: {r['reason']}",f"- Metrics: `{json.dumps(r['metrics'],sort_keys=True)}`",'']
 (OUT/'ROUND_STATUS.md').write_text('\n'.join(lines),encoding='utf-8')
 zp=OUT/'Synthetix_Web_SupplyChain_Round_Result.zip'
 with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
  for p in OUT.rglob('*'):
   if p.is_file() and p!=zp:z.write(p,p.relative_to(OUT))
 print(json.dumps({'overallGate':overall,'results':results,'zipBytes':zp.stat().st_size},indent=2))
if __name__=='__main__':main()
