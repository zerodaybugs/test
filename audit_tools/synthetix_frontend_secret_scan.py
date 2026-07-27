#!/usr/bin/env python3
"""Read-only high-confidence secret-pattern scan for the current public Synthetix frontend graph.

Raw candidate values are never written or printed. The artifact contains only pattern class, source
file, offset, length, hash, and a heavily redacted context. Public client identifiers are classified
separately from credential-shaped material.
"""
from __future__ import annotations
import hashlib,io,json,math,os,pathlib,re,urllib.request,zipfile
OUT=pathlib.Path('synthetix_frontend_secret_scan');OUT.mkdir(parents=True,exist_ok=True)
REPO='zerodaybugs/test';ART=8660005480
PATTERNS={
 'aws_access_key':re.compile(r'(?<![A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])'),
 'github_token':re.compile(r'(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{30,255})(?![A-Za-z0-9_])'),
 'stripe_secret':re.compile(r'(?<![A-Za-z0-9_])(sk_(?:live|test)_[A-Za-z0-9]{16,})(?![A-Za-z0-9_])'),
 'openai_key':re.compile(r'(?<![A-Za-z0-9_-])(sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])'),
 'google_api_key':re.compile(r'(?<![A-Za-z0-9])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9])'),
 'slack_token':re.compile(r'(?<![A-Za-z0-9-])(xox[baprs]-[A-Za-z0-9-]{10,})(?![A-Za-z0-9-])'),
 'private_pem':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
 'jwt':re.compile(r'(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])'),
 'generic_secret_assignment':re.compile(r'(?i)(?:secret|private[_-]?key|api[_-]?key|access[_-]?token|client[_-]?secret)["\'`\s:=]{1,12}([A-Za-z0-9_+./=-]{20,200})'),
}
PUBLIC_HINTS=('sentry','posthog','walletconnect','dynamic','environmentid','projectid','dsn','publishable','publickey','clientid')
def sha(v):return hashlib.sha256(v.encode()).hexdigest()
def entropy(s):
 from collections import Counter
 c=Counter(s);n=len(s);return -sum((v/n)*math.log2(v/n) for v in c.values()) if n else 0
def download(token):
 req=urllib.request.Request(f'https://api.github.com/repos/{REPO}/actions/artifacts/{ART}/zip',headers={'Authorization':f'Bearer {token}','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'synthetix-secret-scan/1.0'})
 with urllib.request.urlopen(req,timeout=90) as r:return r.read(60*1024*1024)
def redact_context(text,start,end):
 l=max(0,start-100);r=min(len(text),end+100);ctx=text[l:start]+'<candidate>'+text[end:r]
 ctx=re.sub(r'0x[a-fA-F0-9]{40,}','<hex>',ctx);ctx=re.sub(r'[A-Za-z0-9_+./=-]{60,}','<long-token>',ctx)
 return ctx[:500]
def main():
 raw=download(os.environ['GITHUB_TOKEN']);hits=[];files=0;bytes_=0
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  for n in z.namelist():
   if not n.lower().endswith(('.js','.mjs','.json','.map','.html','.txt')):continue
   try:b=z.read(n)
   except Exception:continue
   if len(b)>10*1024*1024:continue
   files+=1;bytes_+=len(b);text=b.decode('utf-8','ignore')
   for cls,p in PATTERNS.items():
    for m in p.finditer(text):
     value=m.group(m.lastindex or 0);context=text[max(0,m.start()-140):min(len(text),m.end()+140)].lower();public=any(h in context for h in PUBLIC_HINTS)
     hits.append({'class':cls,'file':n,'offset':m.start(),'length':len(value),'valueSha256':sha(value),'entropy':round(entropy(value),3),'publicClientContext':public,'redactedContext':redact_context(text,m.start(),m.end())})
 high=[h for h in hits if not h['publicClientContext'] and h['class'] not in {'jwt'} and h['entropy']>=3.2]
 result={'filesScanned':files,'bytesScanned':bytes_,'candidateCount':len(hits),'highConfidenceNonPublicContextCount':len(high),'candidates':hits[:5000],'highConfidenceCandidates':high[:1000],'gate':'CANDIDATE_REQUIRES_VALIDATION' if high else 'NO_HIGH_CONFIDENCE_PRIVATE_SECRET_PATTERN'}
 (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
 print(json.dumps({'filesScanned':files,'candidateCount':len(hits),'highConfidenceNonPublicContextCount':len(high),'gate':result['gate']},indent=2))
if __name__=='__main__':main()
