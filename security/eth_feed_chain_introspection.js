'use strict';
const fs = require('fs');
const { ethers } = require('ethers');

const RPCS = [
  'https://ethereum-rpc.publicnode.com',
  'https://eth.llamarpc.com',
  'https://eth.drpc.org',
  'https://1rpc.io/eth'
];
const ROOTS = [
  '0x5FDaa369D623d86191105435c7DA03F25417753a',
  '0x095D9a341fACa8A1025Df722DBDdCe6a6f1E6184',
  '0x90ee94f8fC1362849ae861Ce68Efc1D705E529E7',
  '0x762CAacE43CD1a5a57761fFc2744be6235544f1e',
  '0x892f5d46c4291cC854820ebA04b72362794693d0',
  '0x02ae69C812DD749c32afb4F1723F6833EeF3d7a3',
  '0x26C46B7aD0012cA71F2298ada567dC9Af14E7f2A'
].map(ethers.utils.getAddress);
const OUT = 'feed-evidence';

const abi = [
  'function latestRoundData() view returns(uint80,int256,uint256,uint256,uint80)',
  'function latestAnswer() view returns(int256)',
  'function latestTimestamp() view returns(uint256)',
  'function decimals() view returns(uint8)',
  'function description() view returns(string)',
  'function version() view returns(uint256)',
  'function asset() view returns(address)',
  'function underlying() view returns(address)',
  'function vault() view returns(address)',
  'function assetPriceFeed() view returns(address)',
  'function aTokenToBTokenPriceFeed() view returns(address)',
  'function bTokenToCTokenPriceFeed() view returns(address)',
  'function PRICE_FEED() view returns(address)',
  'function MARKET() view returns(address)',
  'function DURATION() view returns(uint32)',
  'function PY_LP_ORACLE() view returns(address)',
  'function adapter() view returns(address)',
  'function PT() view returns(address)',
  'function dusdOracle() view returns(address)',
  'function uspcOracle() view returns(address)',
  'function xaueOracle() view returns(address)',
  'function ondoOracle() view returns(address)',
  'function pharosOracle() view returns(address)',
  'function pool() view returns(address)',
  'function twapPeriod() view returns(uint32)',
  'function baseToken() view returns(address)',
  'function quoteToken() view returns(address)',
  'function beefyVault() view returns(address)',
  'function lpToken() view returns(address)',
  'function token0PriceFeed() view returns(address)',
  'function token1PriceFeed() view returns(address)',
  'function maxUpdateInterval() view returns(uint256)',
  'function getSharePrice() view returns(uint256)',
  'function getLatestPriceInfo() view returns(uint256,uint256)',
  'function getLatestPrice() view returns(uint256)',
  'function lastUpdateTimestamp() view returns(uint256)',
  'function convertToAssets(uint256) view returns(uint256)',
  'function totalAssets() view returns(uint256)',
  'function totalSupply() view returns(uint256)',
  'function balanceOf(address) view returns(uint256)',
  'function symbol() view returns(string)',
  'function name() view returns(string)',
  'function getPricePerFullShare() view returns(uint256)',
  'function getRate() view returns(uint256)'
];
const addressGetters = new Set([
  'asset','underlying','vault','assetPriceFeed','aTokenToBTokenPriceFeed','bTokenToCTokenPriceFeed',
  'PRICE_FEED','MARKET','PY_LP_ORACLE','adapter','PT','dusdOracle','uspcOracle','xaueOracle',
  'ondoOracle','pharosOracle','pool','baseToken','quoteToken','beefyVault','lpToken',
  'token0PriceFeed','token1PriceFeed'
]);
const getters = [
  'latestRoundData','latestAnswer','latestTimestamp','decimals','description','version','asset','underlying',
  'vault','assetPriceFeed','aTokenToBTokenPriceFeed','bTokenToCTokenPriceFeed','PRICE_FEED','MARKET',
  'DURATION','PY_LP_ORACLE','adapter','PT','dusdOracle','uspcOracle','xaueOracle','ondoOracle',
  'pharosOracle','pool','twapPeriod','baseToken','quoteToken','beefyVault','lpToken',
  'token0PriceFeed','token1PriceFeed','maxUpdateInterval','getSharePrice','getLatestPriceInfo',
  'getLatestPrice','lastUpdateTimestamp','totalAssets','totalSupply','symbol','name','getPricePerFullShare','getRate'
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
async function provider() {
  const attempts=[];
  for (const url of RPCS) {
    try {
      const p=new ethers.providers.JsonRpcProvider(url);
      const [n,b]=await Promise.all([p.getNetwork(),p.getBlockNumber()]);
      if(n.chainId!==1) throw Error(`wrong chain ${n.chainId}`);
      attempts.push({url,ok:true,blockNumber:b});
      return {p,url,blockNumber:b,attempts};
    } catch(e) { attempts.push({url,ok:false,error:String(e)}); }
  }
  throw Error(JSON.stringify(attempts));
}

(async()=>{
  fs.mkdirSync(OUT,{recursive:true});
  const {p,url,blockNumber,attempts}=await provider();
  const block=await p.getBlock(blockNumber);
  const queue=ROOTS.map(address=>({address,depth:0,parent:null,via:'root'}));
  const seen=new Set();
  const contracts=[];
  while(queue.length){
    const item=queue.shift();
    const key=item.address.toLowerCase();
    if(seen.has(key)||item.address===ethers.constants.AddressZero) continue;
    seen.add(key);
    const code=await p.getCode(item.address,blockNumber);
    const c=new ethers.Contract(item.address,abi,p);
    const results={};
    for(const g of getters){
      if(g==='convertToAssets'||g==='balanceOf') continue;
      results[g]=await safe(c[g]({blockTag:blockNumber}));
      if(item.depth<3 && addressGetters.has(g) && results[g].ok){
        const a=results[g].value;
        if(typeof a==='string' && ethers.utils.isAddress(a) && a!==ethers.constants.AddressZero){
          queue.push({address:ethers.utils.getAddress(a),depth:item.depth+1,parent:item.address,via:g});
        }
      }
    }
    results.convertToAssets_1e18=await safe(c.convertToAssets(ethers.constants.WeiPerEther,{blockTag:blockNumber}));
    results.balanceOfSelf=await safe(c.balanceOf(item.address,{blockTag:blockNumber}));
    contracts.push({address:item.address,depth:item.depth,parent:item.parent,via:item.via,codeBytes:(code.length-2)/2,codeHash:ethers.utils.keccak256(code),results});
  }
  const out={rpc:url,rpcAttempts:attempts,snapshot:{blockNumber,blockHash:block.hash,timestamp:block.timestamp},roots:ROOTS,contracts};
  fs.writeFileSync(`${OUT}/FEED_CHAIN.json`,JSON.stringify(out,null,2));
  fs.writeFileSync(`${OUT}/SUMMARY.json`,JSON.stringify({snapshot:out.snapshot,contracts:contracts.map(x=>({address:x.address,depth:x.depth,parent:x.parent,via:x.via,codeHash:x.codeHash,description:x.results.description,name:x.results.name,symbol:x.results.symbol,latestRoundData:x.results.latestRoundData,asset:x.results.asset,adapter:x.results.adapter,PRICE_FEED:x.results.PRICE_FEED,MARKET:x.results.MARKET,uspcOracle:x.results.uspcOracle,ondoOracle:x.results.ondoOracle,vault:x.results.vault,convertToAssets_1e18:x.results.convertToAssets_1e18,totalAssets:x.results.totalAssets,totalSupply:x.results.totalSupply}))},null,2));
  console.log(JSON.stringify({status:'complete',blockNumber,count:contracts.length}));
})().catch(e=>{fs.mkdirSync(OUT,{recursive:true});fs.writeFileSync(`${OUT}/ERROR.txt`,String(e.stack||e));console.error('failed');process.exit(1)});
