#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

binding=json.loads(Path('index/BINDING.json').read_text())
shards=[]
for path in sorted(Path('shards').rglob('shard-*.json')):
    try:
        shards.append(json.loads(path.read_text()))
    except Exception:
        pass
expected=24
feed_map={}
positive=None
for shard in shards:
    if shard.get('positiveSol48') and positive is None:
        positive=shard['positiveSol48']
    for feed in shard.get('feedStats',[]):
        target=feed_map.setdefault(str(feed['feedId']),{
            'feedId':feed['feedId'],'observations':0,'positiveAgeCount':0,
            'maxAgeSeconds':-1,'maxAgeWitness':None,'thresholdCounts':{},'topAgeWitnesses':[]
        })
        target['observations']+=feed.get('observations',0)
        target['positiveAgeCount']+=feed.get('positiveAgeCount',0)
        for threshold,count in feed.get('thresholdCounts',{}).items():
            target['thresholdCounts'][threshold]=target['thresholdCounts'].get(threshold,0)+count
        if feed.get('maxAgeSeconds',-1)>target['maxAgeSeconds']:
            target['maxAgeSeconds']=feed['maxAgeSeconds']
            target['maxAgeWitness']=feed.get('maxAgeWitness')
        target['topAgeWitnesses'].extend(feed.get('topAgeWitnesses',[]))
for feed in feed_map.values():
    unique={}
    for row in feed['topAgeWitnesses']:
        unique[(row.get('signature'),row.get('messageSha256'),row.get('feedId'))]=row
    feed['topAgeWitnesses']=sorted(unique.values(),key=lambda row:row.get('ageSeconds',-1),reverse=True)[:100]
feed_stats=sorted(feed_map.values(),key=lambda row:row['feedId'])
sol=next((row for row in feed_stats if row['feedId']==6),None)
core=sum(max(0,row.get('coreEnd',0)-row.get('coreStart',0)) for row in shards)
sampled=max([row.get('sampledRows',0) for row in shards] or [0])
responses=sum(row.get('transactionResponses',0) for row in shards)
failures=sum(row.get('failures',0) for row in shards)
decoded=sum(row.get('decodedMessages',0) for row in shards)
coverage=core/sampled if sampled else 0
failure_rate=failures/responses if responses else 1
execution=(binding.get('exactElfMatch') is True and binding.get('exactProgramDataMatch') is True and len(shards)==expected and coverage>=0.99 and failure_rate<=0.15 and decoded>=sampled*0.30)
if not execution:
    verdict='INCOMPLETE_FAIL_CLOSED'
elif positive or (sol and sol.get('maxAgeSeconds',-1)>=48):
    verdict='POSITIVE_SOL_48S_WITNESS'
elif sol and sol.get('maxAgeSeconds',-1)>=4:
    verdict='POSITIVE_SOL_4S_WITNESS'
elif any(row.get('maxAgeSeconds',-1)>=4 for row in feed_stats):
    verdict='POSITIVE_OTHER_4S_WITNESS'
else:
    verdict='NO_MATERIAL_AGE_IN_120K_SAMPLE'
result={
    'verdict':verdict,'executionPassed':execution,'binding':binding,
    'expectedShards':expected,'receivedShards':len(shards),'sampledRows':sampled,
    'coreRowsCovered':core,'coverageRatio':coverage,'transactionResponses':responses,
    'decodedMessages':decoded,'failures':failures,'failureRate':failure_rate,
    'solMaxAgeSeconds':sol.get('maxAgeSeconds') if sol else None,
    'solMaxAgeWitness':sol.get('maxAgeWitness') if sol else None,
    'positiveSol48':positive,'feedStats':feed_stats,
    'safety':{'publicChainWrites':0,'publicTransactionsSigned':0,'publicTransactionsSent':0},
}
Path('final').mkdir(exist_ok=True)
Path('final/RESULT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
Path('final/SHARDS.json').write_text(json.dumps(shards,indent=2,sort_keys=True)+'\n')
entries=[]
for path in sorted(p for p in Path('final').iterdir() if p.is_file() and p.name not in {'MANIFEST.json','SHA256SUMS.txt'}):
    data=path.read_bytes();entries.append({'name':path.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
Path('final/MANIFEST.json').write_text(json.dumps(entries,indent=2,sort_keys=True)+'\n')
with Path('final/SHA256SUMS.txt').open('w') as handle:
    for row in entries:handle.write(f"{row['sha256']}  {row['name']}\n")
print(json.dumps({k:result[k] for k in ['verdict','executionPassed','receivedShards','sampledRows','coverageRatio','decodedMessages','failureRate','solMaxAgeSeconds']},indent=2))
if not execution:
    raise SystemExit(1)
