'use strict';
const fs = require('fs');
const { ethers } = require('ethers');

const OUT = 'b2-transfer-v2-output';
const CHAIN_ID = 223;
const RPCS = [
  'https://rpc.bsquared.network',
  'https://223.rpc.thirdweb.com',
  'https://mainnet.b2-rpc.com',
  'https://b2-mainnet.alt.technology',
  'https://b2-mainnet-public.s.chainbase.com',
];
const ROUTERS = {
  routerA: ethers.utils.getAddress('0x3cb5fa87703c7165cc5f2087B3e80b58fb6d8CE8'),
  routerB: ethers.utils.getAddress('0x830fBad7Cd1c3Cc5B693Dc64b985f2901B253C5B'),
};
const TRANSFER = ethers.utils.id('Transfer(address,address,uint256)');
const erc20Abi = [
  'function symbol() view returns(string)',
  'function name() view returns(string)',
  'function decimals() view returns(uint8)',
  'function balanceOf(address) view returns(uint256)',
  'function allowance(address,address) view returns(uint256)',
];

function ser(x) {
  if (ethers.BigNumber.isBigNumber(x)) return x.toString();
  if (Array.isArray(x)) return x.map(ser);
  if (x && typeof x === 'object') {
    const o = {};
    for (const [k,v] of Object.entries(x)) if (!/^\d+$/.test(k)) o[k] = ser(v);
    return o;
  }
  return x;
}
async function safe(p) { try { return {ok:true,value:ser(await p)}; } catch(e) { return {ok:false,error:String(e)}; } }
function topicAddress(a) { return ethers.utils.hexZeroPad(a, 32); }
async function providers() {
  const attempts=[]; const ok=[];
  for (const url of RPCS) {
    try {
      const p=new ethers.providers.StaticJsonRpcProvider(url, CHAIN_ID);
      const [n,b]=await Promise.all([p.getNetwork(),p.getBlockNumber()]);
      if (n.chainId!==CHAIN_ID) throw Error(`wrong chain ${n.chainId}`);
      attempts.push({url,ok:true,block:b}); ok.push({url,p,block:b});
    } catch(e) { attempts.push({url,ok:false,error:String(e)}); }
  }
  if (!ok.length) throw Error('no working B2 RPC');
  return {attempts,ok,latest:Math.min(...ok.map(x=>x.block))};
}
async function creationBlock(p,address,latest) {
  let lo=0,hi=latest;
  if ((await p.getCode(address,hi))==='0x') return null;
  while (lo<hi) {
    const mid=Math.floor((lo+hi)/2);
    if ((await p.getCode(address,mid))==='0x') lo=mid+1; else hi=mid;
  }
  return lo;
}
async function scanWithFailover(ok,filter,from,to) {
  let cur=from,span=25000; const logs=[],progress=[];
  while (cur<=to) {
    const end=Math.min(to,cur+span-1); let success=false,lastErr=null;
    for (const ep of ok) {
      try {
        const part=await ep.p.getLogs({...filter,fromBlock:cur,toBlock:end});
        logs.push(...part); progress.push({from:cur,to:end,count:part.length,rpc:ep.url,span});
        cur=end+1; if (part.length<200 && span<100000) span=Math.min(100000,span*2);
        success=true; break;
      } catch(e) { lastErr=String(e); }
    }
    if (!success) {
      progress.push({from:cur,to:end,span,error:lastErr});
      if (span<=250) throw Error(`all RPCs rejected log range ${cur}-${end}: ${lastErr}`);
      span=Math.max(250,Math.floor(span/2));
    }
  }
  return {logs,progress};
}
async function price(chainToken) {
  const urls=[
    `https://coins.llama.fi/prices/current/${chainToken}`,
    `https://coins.llama.fi/prices/current/bsc:${chainToken.split(':')[1]}`,
  ];
  for (const url of urls) {
    try {
      const r=await fetch(url); if(!r.ok) continue; const j=await r.json();
      const v=Object.values(j.coins||{})[0]; if(v && Number(v.price)>0) return {url,price:Number(v.price),symbol:v.symbol||null,timestamp:v.timestamp||null};
    } catch(_) {}
  }
  return null;
}

(async()=>{
  fs.mkdirSync(OUT,{recursive:true});
  const {attempts,ok,latest}=await providers();
  const state=ok[0]; const block=await state.p.getBlock(latest);
  const results={generatedAt:new Date().toISOString(),scope:'READ-ONLY; no transaction signed or broadcast',chain:{id:CHAIN_ID,blockNumber:latest,blockHash:block.hash,timestamp:block.timestamp,rpcAttempts:attempts},routers:{}};
  for (const [label,router] of Object.entries(ROUTERS)) {
    const created=await creationBlock(state.p,router,latest);
    const padded=topicAddress(router);
    const incoming=await scanWithFailover(ok,{topics:[TRANSFER,null,padded]},created,latest);
    const outgoing=await scanWithFailover(ok,{topics:[TRANSFER,padded]},created,latest);
    const eventMap=new Map();
    for (const l of [...incoming.logs,...outgoing.logs]) eventMap.set(`${l.transactionHash}:${l.logIndex}`,l);
    const events=[...eventMap.values()].sort((a,b)=>a.blockNumber-b.blockNumber||a.transactionIndex-b.transactionIndex||a.logIndex-b.logIndex);
    const tokens=[...new Set(events.map(x=>ethers.utils.getAddress(x.address)))];
    const tokenRows=[];
    for (const token of tokens) {
      const c=new ethers.Contract(token,erc20Abi,state.p);
      const [symbol,name,decimals,currentBalance] = await Promise.all([
        c.symbol({blockTag:latest}).catch(()=>''), c.name({blockTag:latest}).catch(()=>''), c.decimals({blockTag:latest}).catch(()=>18), c.balanceOf(router,{blockTag:latest}).catch(()=>ethers.constants.Zero)
      ]);
      const tokenEvents=events.filter(x=>x.address.toLowerCase()===token.toLowerCase());
      let bal=ethers.constants.Zero,max=ethers.constants.Zero,maxBlock=null,maxTx=null;
      const endOfBlock=[]; let lastBlock=null;
      for (const l of tokenEvents) {
        const from=ethers.utils.getAddress('0x'+l.topics[1].slice(-40));
        const to=ethers.utils.getAddress('0x'+l.topics[2].slice(-40));
        const amount=ethers.BigNumber.from(l.data);
        if (lastBlock!==null && l.blockNumber!==lastBlock) endOfBlock.push({block:lastBlock,balance:bal.toString()});
        if (to.toLowerCase()===router.toLowerCase()) bal=bal.add(amount);
        if (from.toLowerCase()===router.toLowerCase()) bal=bal.gte(amount)?bal.sub(amount):ethers.constants.Zero;
        if (bal.gt(max)) { max=bal; maxBlock=l.blockNumber; maxTx=l.transactionHash; }
        lastBlock=l.blockNumber;
      }
      if(lastBlock!==null) endOfBlock.push({block:lastBlock,balance:bal.toString()});
      let maxEnd=ethers.constants.Zero,maxEndBlock=null;
      for(const e of endOfBlock){const b=ethers.BigNumber.from(e.balance);if(b.gt(maxEnd)){maxEnd=b;maxEndBlock=e.block;}}
      const p=await price(`b2:${token.toLowerCase()}`);
      const denom=10**Math.min(Number(decimals),30);
      const currentUsd=p?Number(ethers.utils.formatUnits(currentBalance,decimals))*p.price:null;
      const maxEndUsd=p?Number(ethers.utils.formatUnits(maxEnd,decimals))*p.price:null;
      tokenRows.push({token,symbol,name,decimals:Number(decimals),eventCount:tokenEvents.length,currentBalance:currentBalance.toString(),currentUsd,maxRunningBalance:max.toString(),maxRunningBlock:maxBlock,maxRunningTx:maxTx,maxEndOfBlockBalance:maxEnd.toString(),maxEndOfBlock,maxEndBlock,maxEndUsd,price:p,reconstructedFinalBalance:bal.toString(),reconstructionMatchesCurrent:bal.eq(currentBalance)});
    }
    tokenRows.sort((a,b)=>(b.currentUsd||0)-(a.currentUsd||0)||(b.maxEndUsd||0)-(a.maxEndUsd||0));
    results.routers[label]={address:router,creationBlock:created,incomingCount:incoming.logs.length,outgoingCount:outgoing.logs.length,incomingProgress:incoming.progress,outgoingProgress:outgoing.progress,nativeBalance:(await state.p.getBalance(router,latest)).toString(),tokens:tokenRows,summary:{tokenCount:tokenRows.length,currentPositive:tokenRows.filter(x=>ethers.BigNumber.from(x.currentBalance).gt(0)).length,currentUsdKnown:tokenRows.reduce((s,x)=>s+(x.currentUsd||0),0),historicalMaxEndUsdKnown:Math.max(0,...tokenRows.map(x=>x.maxEndUsd||0)),historicalMaxEndRows:tokenRows.filter(x=>(x.maxEndUsd||0)>0).sort((a,b)=>(b.maxEndUsd||0)-(a.maxEndUsd||0)).slice(0,20)}};
  }
  fs.writeFileSync(`${OUT}/transfer-inventory-v2.json`,JSON.stringify(results,null,2));
  const summary={chain:results.chain,routers:Object.fromEntries(Object.entries(results.routers).map(([k,v])=>[k,{address:v.address,creationBlock:v.creationBlock,nativeBalance:v.nativeBalance,summary:v.summary,positiveCurrent:v.tokens.filter(x=>ethers.BigNumber.from(x.currentBalance).gt(0)).map(x=>({token:x.token,symbol:x.symbol,currentBalance:x.currentBalance,currentUsd:x.currentUsd})),historicalMax:v.summary.historicalMaxEndRows.map(x=>({token:x.token,symbol:x.symbol,maxEndOfBlockBalance:x.maxEndOfBlockBalance,maxEndBlock:x.maxEndBlock,maxEndUsd:x.maxEndUsd}))}]))};
  fs.writeFileSync(`${OUT}/summary.json`,JSON.stringify(summary,null,2));
  console.log(JSON.stringify(summary,null,2));
})().catch(e=>{fs.mkdirSync(OUT,{recursive:true});fs.writeFileSync(`${OUT}/error.txt`,String(e.stack||e));console.error(e);process.exit(1);});
