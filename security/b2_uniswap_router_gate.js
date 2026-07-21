'use strict';
const fs = require('fs');
const { ethers } = require('ethers');

const RPCS = ['https://rpc.bsquared.network', 'https://213.rpc.thirdweb.com'];
const ROUTER = ethers.utils.getAddress('0x830fBad7Cd1c3Cc5B693Dc64b985f2901B253C5B');
const ADAPTER = ethers.utils.getAddress('0xBd795F755dbB5A5358D6c60AED53ceB486Fa8517');
const WHITELIST = ethers.utils.getAddress('0x03c4FCF963E5FBC0dC5851d2340624E70492acb9');
const FROM_BLOCK = 30400000;
const OUT = 'b2-uniswap-gate';
const TRANSFER_TOPIC = ethers.utils.id('Transfer(address,address,uint256)');
const EIP1967_IMPL = '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const EIP1967_ADMIN = '0xb53127684a568b3173ae13b9f8a6016e019a8c3e8ae17b8b5d6103';
const erc20Abi = ['function balanceOf(address) view returns(uint256)','function symbol() view returns(string)','function decimals() view returns(uint8)','function totalSupply() view returns(uint256)'];
const wlAbi = ['function isWhitelisted(address,uint8) view returns(bool)'];
const routerAbi = ['function paused() view returns(bool)','function owner() view returns(address)','function version() view returns(string)'];

function padded(address) { return ethers.utils.hexZeroPad(address, 32); }
async function safe(p) { try { const v=await p; return {ok:true,value:ethers.BigNumber.isBigNumber(v)?v.toString():v}; } catch(e){return {ok:false,error:String(e)}} }
async function choose() {
  const attempts=[];
  for (const url of RPCS) {
    try { const p=new ethers.providers.JsonRpcProvider(url); const [n,b]=await Promise.all([p.getNetwork(),p.getBlockNumber()]); attempts.push({url,ok:true,chainId:n.chainId,block:b}); if(n.chainId===223) return {p,url,block:b,attempts}; }
    catch(e){attempts.push({url,ok:false,error:String(e)})}
  }
  throw new Error(JSON.stringify(attempts));
}
async function scan(p, from, to, topics) {
  const logs=[]; const progress=[]; let cur=from, span=100000;
  while(cur<=to){const end=Math.min(to,cur+span-1);try{const part=await p.getLogs({fromBlock:cur,toBlock:end,topics});logs.push(...part);progress.push({from:cur,to:end,count:part.length,span});cur=end+1;if(part.length<100&&span<500000)span=Math.min(500000,span*2);}catch(e){progress.push({from:cur,to:end,span,error:String(e)});if(span<=100)throw e;span=Math.max(100,Math.floor(span/2));}}
  return {logs,progress};
}
(async()=>{
  fs.mkdirSync(OUT,{recursive:true});
  const {p,url,block,attempts}=await choose(); const hdr=await p.getBlock(block);
  const [routerCode,adapterCode,wlCode,implSlot,adminSlot,nativeBalance] = await Promise.all([
    p.getCode(ROUTER,block),p.getCode(ADAPTER,block),p.getCode(WHITELIST,block),p.getStorageAt(ROUTER,EIP1967_IMPL,block),p.getStorageAt(ROUTER,EIP1967_ADMIN,block),p.getBalance(ROUTER,block)
  ]);
  const whitelist=new ethers.Contract(WHITELIST,wlAbi,p); const router=new ethers.Contract(ROUTER,routerAbi,p);
  const [inbound,outbound] = await Promise.all([
    scan(p,FROM_BLOCK,block,[TRANSFER_TOPIC,null,padded(ROUTER)]),
    scan(p,FROM_BLOCK,block,[TRANSFER_TOPIC,padded(ROUTER)])
  ]);
  const tokens=new Map();
  for(const l of inbound.logs)tokens.set(l.address.toLowerCase(),{address:ethers.utils.getAddress(l.address),inboundCount:0,outboundCount:0});
  for(const l of outbound.logs)tokens.set(l.address.toLowerCase(),{address:ethers.utils.getAddress(l.address),inboundCount:0,outboundCount:0});
  for(const l of inbound.logs)tokens.get(l.address.toLowerCase()).inboundCount++;
  for(const l of outbound.logs)tokens.get(l.address.toLowerCase()).outboundCount++;
  const inventory=[];
  for(const x of tokens.values()){
    const t=new ethers.Contract(x.address,erc20Abi,p);
    inventory.push({address:x.address,inboundCount:x.inboundCount,outboundCount:x.outboundCount,
      balance:await safe(t.balanceOf(ROUTER,{blockTag:block})),symbol:await safe(t.symbol({blockTag:block})),decimals:await safe(t.decimals({blockTag:block})),totalSupply:await safe(t.totalSupply({blockTag:block}))});
  }
  inventory.sort((a,b)=>{try{return ethers.BigNumber.from(b.balance.value||0).gt(ethers.BigNumber.from(a.balance.value||0))?1:-1}catch{return 0}});
  const out={rpc:url,rpcAttempts:attempts,snapshot:{blockNumber:block,blockHash:hdr.hash,timestamp:hdr.timestamp},addresses:{router:ROUTER,adapter:ADAPTER,whitelist:WHITELIST},
    code:{routerBytes:(routerCode.length-2)/2,routerHash:ethers.utils.keccak256(routerCode),adapterBytes:(adapterCode.length-2)/2,adapterHash:ethers.utils.keccak256(adapterCode),whitelistBytes:(wlCode.length-2)/2,whitelistHash:ethers.utils.keccak256(wlCode),implementationSlot:implSlot,adminSlot},
    state:{adapterWhitelisted:await safe(whitelist.isWhitelisted(ADAPTER,0,{blockTag:block})),paused:await safe(router.paused({blockTag:block})),owner:await safe(router.owner({blockTag:block})),version:await safe(router.version({blockTag:block})),nativeBalance:nativeBalance.toString()},
    scans:{inboundProgress:inbound.progress,outboundProgress:outbound.progress,inboundLogs:inbound.logs.length,outboundLogs:outbound.logs.length},inventory};
  fs.writeFileSync(`${OUT}/b2-uniswap-router-gate.json`,JSON.stringify(out,null,2));
  console.log(JSON.stringify({block,adapterWhitelisted:out.state.adapterWhitelisted,paused:out.state.paused,tokenCount:inventory.length,positive:inventory.filter(x=>x.balance.ok&&x.balance.value!=='0').map(x=>({address:x.address,symbol:x.symbol,balance:x.balance,decimals:x.decimals}))},null,2));
})().catch(e=>{fs.mkdirSync(OUT,{recursive:true});fs.writeFileSync(`${OUT}/error.txt`,String(e.stack||e));console.error(e);process.exit(1)});
