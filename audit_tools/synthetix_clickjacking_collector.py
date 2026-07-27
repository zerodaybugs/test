#!/usr/bin/env python3
from __future__ import annotations
import io,json,os,pathlib,time,urllib.request,zipfile
OUT=pathlib.Path('synthetix_clickjacking_round');OUT.mkdir(parents=True,exist_ok=True);E=OUT/'evidence';E.mkdir(exist_ok=True)
REPO='zerodaybugs/test';NAMES=('synthetix-frameability-probe','synthetix-session-frame-runtime')
def api(path,t,b=False):
 req=urllib.request.Request('https://api.github.com'+path,headers={'Authorization':f'Bearer {t}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'synthetix-clickjacking/1.0'})
 with urllib.request.urlopen(req,timeout=90) as r:return r.read(100*1024*1024) if b else json.load(r)
def latest(t):
 p=api(f'/repos/{REPO}/actions/artifacts?per_page=100',t);o={}
 for x in p.get('artifacts',[]):
  n=x.get('name')
  if n in NAMES and not x.get('expired') and (n not in o or x.get('created_at','')>o[n].get('created_at','')):o[n]=x
 return o
def summ(raw):
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  ns=[n for n in z.namelist() if n.endswith('summary.json')]
  n=sorted(ns,key=lambda x:(x.count('/'),len(x)))[0];return n,json.loads(z.read(n))
def main():
 t=os.environ['GITHUB_TOKEN'];a={}
 for i in range(50):
  a=latest(t);m=[n for n in NAMES if n not in a];print(json.dumps({'poll':i+1,'found':sorted(a),'missing':m}))
  if not m:break
  time.sleep(30)
 docs={};prov=[]
 for n in NAMES:
  if n not in a:continue
  x=a[n];raw=api(f'/repos/{REPO}/actions/artifacts/{x["id"]}/zip',t,True);(E/f'{n}.zip').write_bytes(raw);sp,d=summ(raw);docs[n]=d;prov.append({'name':n,'id':x['id'],'digest':x.get('digest'),'summaryPath':sp})
 frame=docs.get('synthetix-frameability-probe',{});session=docs.get('synthetix-session-frame-runtime',{})
 rendered=bool(frame.get('targetRendered')) and int(frame.get('targetFrameCount') or 0)>0
 signed=int(session.get('frameSignedRequestCount') or 0);sensitive=int(session.get('sensitiveButtonCount') or 0);writes=len(session.get('writeAttemptsIntercepted') or [])
 if rendered and writes:gate='CANDIDATE';reason='cross-origin frame rendered and synthetic sensitive write attempts were intercepted'
 elif rendered and signed:gate='HOLD';reason='cross-origin frame rendered with an active synthetic signed session; click-to-write proof still required'
 elif rendered and sensitive:gate='HOLD';reason='cross-origin frame rendered with sensitive controls; session/write chain not proven'
 else:gate='NO_SUBMISSION';reason='frame/session-sensitive chain not reproduced'
 result={'overallGate':gate,'reason':reason,'metrics':{'targetRendered':rendered,'frameSignedRequestCount':signed,'sensitiveButtonCount':sensitive,'writeAttempts':writes},'provenance':prov}
 (OUT/'round_summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8');(OUT/'ROUND_STATUS.md').write_text(f"# Synthetix Clickjacking / Session Round\n\n**Gate: {gate}**\n\n{reason}\n\nMetrics: `{json.dumps(result['metrics'],sort_keys=True)}`\n",encoding='utf-8')
 zp=OUT/'Synthetix_Clickjacking_Session_Round_Result.zip'
 with zipfile.ZipFile(zp,'w',zipfile.ZIP_DEFLATED) as z:
  for p in OUT.rglob('*'):
   if p.is_file() and p!=zp:z.write(p,p.relative_to(OUT))
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
