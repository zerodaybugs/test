import fs from 'node:fs';
import crypto from 'node:crypto';

const P = 'vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P';
const D = Buffer.from([218,237,170,245,39,143,166,33]);
const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const R = [
  'https://solana-rpc.publicnode.com',
  'https://api.mainnet-beta.solana.com',
  'https://solana.drpc.org',
  'https://1rpc.io/solana',
  'https://mainnet-beta.solflare.network',
];
const SHARD = Number(process.env.SHARD ?? 0);
const SHARDS = Number(process.env.SHARDS ?? 24);
const SAMPLE_LIMIT = Number(process.env.SAMPLE_LIMIT ?? 120000);
const BATCH = Math.max(1, Math.min(25, Number(process.env.BATCH ?? 20)));
const OUT = process.env.OUT_DIR ?? 'out';
const INDEX = process.env.INDEX_PATH ?? 'index/signatures.json';
const THRESHOLDS = [1,4,10,15,30,48,60,120,144];

fs.mkdirSync(OUT, {recursive:true});
const sleep = (ms) => new Promise((resolve)=>setTimeout(resolve,ms));
const sha = (data) => crypto.createHash('sha256').update(data).digest('hex');
const rep = (_key,value) => typeof value === 'bigint' ? value.toString() : value;
let cursor = SHARD % R.length;

function write(name,value) {
  fs.writeFileSync(`${OUT}/${name}`, JSON.stringify(value,rep,2)+'\n');
}
function b58d(s) {
  let n=0n;
  for (const c of s) {
    const i=A.indexOf(c);
    if(i<0) throw new Error('base58');
    n=n*58n+BigInt(i);
  }
  let h=n.toString(16);
  if(h.length%2)h='0'+h;
  const body=n?Buffer.from(h,'hex'):Buffer.alloc(0);
  let zeros=0;
  while(zeros<s.length && s[zeros]==='1')zeros++;
  return Buffer.concat([Buffer.alloc(zeros),body]);
}
async function postBatch(endpoint, rows, timeoutMs=90000) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),timeoutMs);
  try {
    const payload=rows.map((row,index)=>({
      jsonrpc:'2.0',
      id:index+1,
      method:'getTransaction',
      params:[row.signature,{encoding:'json',commitment:'finalized',maxSupportedTransactionVersion:0}],
    }));
    const response=await fetch(endpoint,{
      method:'POST',
      headers:{'content-type':'application/json','user-agent':`ZDB-seq-shard-${SHARD}/1`},
      body:JSON.stringify(payload),
      signal:controller.signal,
    });
    const text=await response.text();
    if(!response.ok)throw new Error(`${response.status}:${text.slice(0,160)}`);
    const body=JSON.parse(text);
    if(!Array.isArray(body))throw new Error('non-batch');
    const byId=new Map(body.map((item)=>[item.id,item]));
    return rows.map((row,index)=>({row,response:byId.get(index+1),endpoint}));
  } finally { clearTimeout(timer); }
}
async function fetchRows(rows,depth=0) {
  let last;
  for(let attempt=0;attempt<10;attempt++){
    const endpoint=R[(cursor+attempt)%R.length];
    try{
      const result=await postBatch(endpoint,rows);
      cursor=(R.indexOf(endpoint)+1)%R.length;
      return result;
    }catch(error){
      last=error;
      await sleep(Math.min(4000,120*(2**Math.min(attempt,5)))+Math.floor(Math.random()*100));
    }
  }
  if(rows.length>1 && depth<8){
    const middle=Math.floor(rows.length/2);
    return [...await fetchRows(rows.slice(0,middle),depth+1),...await fetchRows(rows.slice(middle),depth+1)];
  }
  return rows.map((row)=>({row,response:{error:{message:String(last)}},endpoint:null}));
}
function keys(tx){
  const message=tx?.transaction?.message??{};
  const staticKeys=(message.accountKeys??message.staticAccountKeys??[]).map((value)=>
    typeof value==='string'?value:value?.pubkey?String(value.pubkey):String(value)
  );
  const loaded=tx?.meta?.loadedAddresses??{writable:[],readonly:[]};
  return [...staticKeys,...(loaded.writable??[]).map(String),...(loaded.readonly??[]).map(String)];
}
function decMsg(message){
  if(message.length<102||message.readUInt32LE(0)!==2182742457)throw new Error('message');
  const payloadLength=message.readUInt16LE(100);
  if(message.length!==102+payloadLength)throw new Error('message-length');
  const payload=message.subarray(102);
  if(payload.length<14||payload.readUInt32LE(0)!==2479346549)throw new Error('payload');
  let offset=4;
  const payloadTimestampUs=payload.readBigUInt64LE(offset);offset+=8;
  const channelId=payload[offset++];
  const feedCount=payload[offset++];
  const feeds=[];
  const need=(count)=>{if(offset+count>payload.length)throw new Error('truncated')};
  const optionalI64=()=>{need(8);const value=payload.readBigInt64LE(offset);offset+=8;return value===0n?null:value};
  const optionalU64=()=>{need(1);const present=payload[offset++];if(!present)return null;need(8);const value=payload.readBigUInt64LE(offset);offset+=8;return value};
  for(let feedIndex=0;feedIndex<feedCount;feedIndex++){
    need(5);
    const feedId=payload.readUInt32LE(offset);offset+=4;
    const propertyCount=payload[offset++];
    const properties={};
    for(let propertyIndex=0;propertyIndex<propertyCount;propertyIndex++){
      need(1);
      const property=payload[offset++];
      switch(property){
        case 0:properties.price=optionalI64();break;
        case 1:properties.bid=optionalI64();break;
        case 2:properties.ask=optionalI64();break;
        case 3:need(2);properties.publishers=payload.readUInt16LE(offset);offset+=2;break;
        case 4:need(2);properties.exponent=payload.readInt16LE(offset);offset+=2;break;
        case 5:properties.confidence=optionalI64();break;
        case 6:{need(1);const present=payload[offset++];properties.fundingRate=present?payload.readBigInt64LE(offset):null;if(present)offset+=8;break}
        case 7:properties.fundingTimestamp=optionalU64();break;
        case 8:properties.fundingInterval=optionalU64();break;
        case 9:need(2);properties.marketSession=payload.readInt16LE(offset);offset+=2;break;
        case 10:properties.ema=optionalI64();break;
        case 11:properties.emaConfidence=optionalI64();break;
        case 12:properties.feedUpdateTimestamp=optionalU64();break;
        default:throw new Error(`property-${property}`);
      }
    }
    feeds.push({feedId,properties});
  }
  if(offset!==payload.length)throw new Error('payload-tail');
  return {payloadTimestampUs,channelId,feeds};
}
function extract(tx,row){
  const allKeys=keys(tx);
  const instructions=tx?.transaction?.message?.instructions??tx?.transaction?.message?.compiledInstructions??[];
  const output=[];
  for(let instructionIndex=0;instructionIndex<instructions.length;instructionIndex++){
    const instruction=instructions[instructionIndex];
    const programId=instruction.programId
      ?(typeof instruction.programId==='string'?instruction.programId:String(instruction.programId))
      :allKeys[instruction.programIdIndex];
    if(programId!==P||typeof instruction.data!=='string')continue;
    let data;
    try{data=b58d(instruction.data)}catch{continue}
    if(data.length<12||!data.subarray(0,8).equals(D))continue;
    const messageLength=data.readUInt32LE(8);
    if(messageLength<=0||12+messageLength>data.length)continue;
    const message=data.subarray(12,12+messageLength);
    try{
      output.push({
        ...decMsg(message),
        signature:row.signature,
        slot:Number(row.slot),
        blockTime:row.blockTime,
        instructionIndex,
        messageBytes:message.length,
        messageSha256:sha(message),
        messageHex:message.toString('hex'),
      });
    }catch{}
  }
  return output;
}
function sample(rows,limit){
  if(rows.length<=limit)return rows;
  const output=[];
  let prior=-1;
  for(let index=0;index<limit;index++){
    const source=Math.round(index*(rows.length-1)/(limit-1));
    if(source!==prior)output.push(rows[source]);
    prior=source;
  }
  return output;
}
function witness(update,feed){
  const ageUs=update.payloadTimestampUs-feed.properties.feedUpdateTimestamp;
  return {
    signature:update.signature,
    slot:update.slot,
    blockTime:update.blockTime,
    instructionIndex:update.instructionIndex,
    channelId:update.channelId,
    feedId:feed.feedId,
    payloadTimestampUs:update.payloadTimestampUs,
    feedUpdateTimestampUs:feed.properties.feedUpdateTimestamp,
    ageUs,
    ageSeconds:Number(ageUs)/1e6,
    price:feed.properties.price,
    exponent:feed.properties.exponent,
    bid:feed.properties.bid,
    ask:feed.properties.ask,
    confidence:feed.properties.confidence,
    publisherCount:feed.properties.publishers,
    messageBytes:update.messageBytes,
    messageSha256:update.messageSha256,
    messageHex:update.messageHex,
  };
}
function pushTop(array,value,limit=30){
  array.push(value);
  array.sort((a,b)=>b.ageSeconds-a.ageSeconds);
  if(array.length>limit)array.length=limit;
}

async function main(){
  const allRows=JSON.parse(fs.readFileSync(INDEX,'utf8'));
  const sampled=sample(allRows,SAMPLE_LIMIT);
  const coreStart=Math.floor(sampled.length*SHARD/SHARDS);
  const coreEnd=Math.floor(sampled.length*(SHARD+1)/SHARDS);
  const selected=sampled.slice(coreStart,coreEnd);
  const stats=new Map();
  const failures=[];
  let decodedMessages=0;
  let transactionResponses=0;
  let successfulTransactions=0;
  let positiveSol48=null;

  for(let offset=0;offset<selected.length&&!positiveSol48;offset+=BATCH){
    const batch=selected.slice(offset,offset+BATCH);
    const responses=await fetchRows(batch);
    for(const item of responses){
      transactionResponses++;
      const tx=item.response?.result;
      if(!tx){
        failures.push({signature:item.row.signature,slot:item.row.slot,endpoint:item.endpoint,error:item.response?.error??'null'});
        continue;
      }
      if(tx.meta?.err!==null)continue;
      successfulTransactions++;
      const updates=extract(tx,item.row);
      decodedMessages+=updates.length;
      for(const update of updates){
        for(const feed of update.feeds){
          const feedTs=feed.properties.feedUpdateTimestamp;
          if(feedTs===null||feedTs===undefined||update.payloadTimestampUs<feedTs)continue;
          const row=witness(update,feed);
          if(!stats.has(feed.feedId)){
            stats.set(feed.feedId,{
              feedId:feed.feedId,
              observations:0,
              positiveAgeCount:0,
              maxAgeSeconds:-1,
              maxAgeWitness:null,
              thresholdCounts:Object.fromEntries(THRESHOLDS.map((value)=>[String(value),0])),
              topAgeWitnesses:[],
            });
          }
          const target=stats.get(feed.feedId);
          target.observations++;
          if(row.ageSeconds>0)target.positiveAgeCount++;
          for(const threshold of THRESHOLDS)if(row.ageSeconds>=threshold)target.thresholdCounts[String(threshold)]++;
          if(row.ageSeconds>target.maxAgeSeconds){target.maxAgeSeconds=row.ageSeconds;target.maxAgeWitness=row}
          if(row.ageSeconds>0)pushTop(target.topAgeWitnesses,row);
          if(feed.feedId===6&&row.ageSeconds>=48){positiveSol48=row;break}
        }
        if(positiveSol48)break;
      }
      if(positiveSol48)break;
    }
    if(offset%500===0){
      console.log(`SHARD=${SHARD} PROGRESS=${offset}/${selected.length} DECODED=${decodedMessages} FAILURES=${failures.length} SOL_MAX=${stats.get(6)?.maxAgeSeconds??null}`);
    }
    await sleep(10);
  }

  const feedStats=[...stats.values()].sort((a,b)=>a.feedId-b.feedId);
  const sol=stats.get(6);
  const failureRate=transactionResponses?failures.length/transactionResponses:1;
  const verdict=positiveSol48
    ?'POSITIVE_SOL_48S_WITNESS'
    :sol?.maxAgeSeconds>=4
      ?'POSITIVE_SOL_4S_WITNESS'
      :feedStats.some((entry)=>entry.maxAgeSeconds>=4)
        ?'POSITIVE_OTHER_4S_WITNESS'
        :'NO_MATERIAL_AGE_IN_SHARD';
  const result={
    verdict,
    shard:SHARD,
    shards:SHARDS,
    fullIndexRows:allRows.length,
    sampledRows:sampled.length,
    coreStart,
    coreEnd,
    selectedRows:selected.length,
    transactionResponses,
    successfulTransactions,
    decodedMessages,
    failures:failures.length,
    failureRate,
    earlyStop:Boolean(positiveSol48),
    positiveSol48,
    feedStats,
    safety:{publicChainWrites:0,publicTransactionsSigned:0,publicTransactionsSent:0,rpcMethods:['getTransaction']},
  };
  write(`shard-${SHARD}.json`,result);
  write(`failures-${SHARD}.json`,failures.slice(0,500));
  console.log(`VERDICT=${verdict}`);
  console.log(`SOL_MAX=${sol?.maxAgeSeconds??null}`);
  console.log(`FAILURE_RATE=${failureRate}`);
  console.log('PUBLIC_CHAIN_TRANSACTIONS=0');
  if(failureRate>0.15||decodedMessages<Math.max(10,selected.length*0.35))process.exitCode=2;
}
main().catch((error)=>{
  write(`fatal-${SHARD}.json`,{error:String(error?.stack??error),safety:{publicChainWrites:0}});
  console.error(error?.stack??error);
  process.exit(1);
});
