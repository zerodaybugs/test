#!/usr/bin/env python3
"""Read-only security-relevant drift scan for the official Synthetix SDK.

Clones public history, compares the latest release tag with the default branch, and records only public
commit metadata and bounded changed-line contexts around authentication, signing, withdrawals,
delegation, nonce, account, and transport logic.
"""
from __future__ import annotations

import hashlib, json, pathlib, re, shutil, subprocess

OUT=pathlib.Path('synthetix_sdk_security_drift');OUT.mkdir(parents=True,exist_ok=True)
TMP=pathlib.Path('/tmp/synthetix-sdk-security-drift');shutil.rmtree(TMP,ignore_errors=True)
REPO='https://github.com/Synthetixio/synthetix-sdk.git'
KEY=re.compile(r'auth|sign|eip.?712|withdraw|delegat|session|nonce|sub.?account|wallet|websocket|replay|permission|destination|referral|cancel|leverage',re.I)

def run(args,cwd=None,timeout=240):
 p=subprocess.run(args,cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)
 if p.returncode: raise RuntimeError(f"command failed {args}: {p.stderr[:500]}")
 return p.stdout

def sha(s): return hashlib.sha256(s.encode()).hexdigest()

def main():
 run(['git','clone','--filter=blob:none',REPO,str(TMP)],timeout=300)
 tags=run(['git','tag','--sort=-version:refname'],cwd=TMP).splitlines()
 release=next((t for t in tags if re.fullmatch(r'v?\d+\.\d+\.\d+',t)),None)
 if not release: raise RuntimeError('release tag not found')
 head=run(['git','rev-parse','HEAD'],cwd=TMP).strip();base=run(['git','rev-parse',release],cwd=TMP).strip()
 log=run(['git','log','--date=iso-strict','--pretty=format:%H%x09%ad%x09%s',f'{release}..HEAD'],cwd=TMP)
 diff=run(['git','diff','--unified=4',release,'HEAD','--','.'],cwd=TMP,timeout=300)
 contexts=[];current_file=None
 for line in diff.splitlines():
  if line.startswith('+++ b/'): current_file=line[6:]
  if line.startswith(('+','-')) and not line.startswith(('+++','---')) and KEY.search(line):
   contexts.append({'file':current_file,'line':line[:1000],'lineSha256':sha(line)})
 open_pr_note='Open PR metadata is intentionally queried separately by GitHub connector if needed.'
 result={'repository':REPO,'release':release,'releaseCommit':base,'headCommit':head,'commitCount':len([x for x in log.splitlines() if x]),'commits':log.splitlines()[:500],'securityRelevantChangedLines':contexts[:1000],'securityRelevantChangedLineCount':len(contexts),'diffSha256':sha(diff),'note':open_pr_note,'gate':'REVIEW_DRIFT' if contexts else 'NO_POST_RELEASE_SECURITY_RELEVANT_DRIFT'}
 (OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True),encoding='utf-8')
 (OUT/'commits.txt').write_text(log,encoding='utf-8')
 print(json.dumps({'release':release,'headCommit':head,'commitCount':result['commitCount'],'securityRelevantChangedLineCount':len(contexts),'gate':result['gate']},indent=2))
if __name__=='__main__':main()
